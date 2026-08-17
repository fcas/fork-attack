"""
Triggers a fresh CodeQL, Dependabot, and Semgrep pass across every fork in
settings.repositories, so the next run of estige.py / reachability.py /
nvd_cpe.py extracts current data. Run fork_attack.sync_forks first: this
script only fixes and (re)triggers workflows, it does not sync fork content
with upstream.

Per repo, in order:
  1. Fix `.github/workflows/codeql.yml` if it has a hardcoded `branches: [...]`
     trigger (see fix_codeql_branch_trigger): a fork's default branch is
     `main` or `master` inconsistently across upstreams, and a hardcoded
     value here means `on: push` only fires for forks whose default branch
     happens to match it. Preserves everything else in the file (the
     auto-detected `language` matrix differs per repo).
  2. Fix `.github/dependabot.yml` if it has the invalid
     `insecure-external-code-execution` key (only valid for the `bundler`
     ecosystem, not `pip`): this key fails the whole file's schema
     validation, disabling Dependabot version updates repo-wide.
  3. Re-enable + dispatch Semgrep (`workflow_dispatch`) and re-enable CodeQL
     (GitHub auto-disables scheduled workflows after 60 days of inactivity).
  4. If neither file needed a fix, push a no-op empty commit as a fallback
     so CodeQL's `on: push` and Dependabot's dependency-graph re-evaluation
     still get a trigger.

Usage:
    poetry run python3 -m fork_attack.trigger_scans
"""
import csv
import logging
import os
import re
import subprocess
import time
from base64 import b64decode, b64encode
from datetime import date
from pathlib import Path

import requests

from fork_attack.settings import repositories, OWNER

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / ".github"


def _headers():
    token = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def get_default_branch(session, repo):
    r = session.get(f"https://api.github.com/repos/{OWNER}/{repo}")
    r.raise_for_status()
    return r.json()["default_branch"]


def get_file(session, repo, path):
    r = session.get(f"https://api.github.com/repos/{OWNER}/{repo}/contents/{path}")
    if r.status_code != 200:
        return None, None
    data = r.json()
    return data["sha"], b64decode(data["content"]).decode("utf-8", errors="replace")


def update_file(session, repo, path, new_content, sha, branch, message):
    r = session.put(
        f"https://api.github.com/repos/{OWNER}/{repo}/contents/{path}",
        json={
            "message": message,
            "content": b64encode(new_content.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": branch,
        },
    )
    return r.status_code in (200, 201), r.json().get("commit", {}).get("sha") if r.status_code in (200, 201) else r.text[:200]


BRANCH_FILTER_RE = re.compile(r"[ \t]*branches:\s*\[[^\]]*\]\s*\n")


def fix_codeql_branch_trigger(content):
    """Strips any `branches: [...]` line under the workflow's `on:` triggers,
    leaving `push:`/`pull_request:` unrestricted so both fire regardless of
    the repo's actual default branch name. Returns (new_content, changed)."""
    new_content = BRANCH_FILTER_RE.sub("", content)
    return new_content, new_content != content


def dependabot_yml_needs_fix(content):
    return "insecure-external-code-execution" in content


def trigger_all():
    session = requests.Session()
    session.headers.update(_headers())

    fixed_dependabot_template = (TEMPLATE_DIR / "dependabot.yml").read_text()

    results = []
    for i, (url, branch, clone) in enumerate(repositories, 1):
        repo_name = url.replace("https://github.com/", "").split("/")[1]
        row = {"repo": repo_name}
        made_a_commit = False
        try:
            default_branch = get_default_branch(session, repo_name)
            row["default_branch"] = default_branch

            sha, content = get_file(session, repo_name, ".github/workflows/codeql.yml")
            if content is not None:
                new_content, changed = fix_codeql_branch_trigger(content)
                if changed:
                    ok, info = update_file(session, repo_name, ".github/workflows/codeql.yml", new_content, sha,
                                            default_branch, "fix: remove hardcoded branch trigger from CodeQL workflow")
                    row["codeql_yml_fixed"] = ok
                    if ok:
                        made_a_commit = True
                else:
                    row["codeql_yml_fixed"] = "already-ok"
            else:
                row["codeql_yml_fixed"] = None

            sha, content = get_file(session, repo_name, ".github/dependabot.yml")
            if content is not None:
                if dependabot_yml_needs_fix(content):
                    ok, info = update_file(session, repo_name, ".github/dependabot.yml", fixed_dependabot_template,
                                            sha, default_branch,
                                            "fix: remove invalid insecure-external-code-execution key from dependabot.yml")
                    row["dependabot_yml_fixed"] = ok
                    if ok:
                        made_a_commit = True
                else:
                    row["dependabot_yml_fixed"] = "already-ok"
            else:
                row["dependabot_yml_fixed"] = None

            semgrep_wf = find_workflow(session, repo_name, "semgrep.yml")
            if semgrep_wf:
                if semgrep_wf["state"] != "active":
                    enable_workflow(session, repo_name, semgrep_wf["id"])
                row["semgrep_dispatched"] = dispatch_workflow(session, repo_name, semgrep_wf["id"], default_branch)
            else:
                row["semgrep_dispatched"] = None

            codeql_wf = find_workflow(session, repo_name, "codeql.yml")
            if codeql_wf and codeql_wf["state"] != "active":
                enable_workflow(session, repo_name, codeql_wf["id"])

            if not made_a_commit:
                pushed, info = push_empty_commit(session, repo_name, default_branch)
                row["empty_commit_pushed"] = pushed
            else:
                row["empty_commit_pushed"] = "not-needed"

            # A run triggered above (dispatch or push) takes a moment to
            # register; this snapshot may still read "queued"/"in_progress"
            # rather than a final conclusion for slower workflows, but it
            # catches fast failures (e.g. a broken workflow file) immediately.
            time.sleep(5)
            status, conclusion, url = latest_run_status(session, repo_name, semgrep_wf["id"]) if semgrep_wf else (None, None, None)
            row["semgrep_run_status"], row["semgrep_run_conclusion"], row["semgrep_run_url"] = status, conclusion, url

            status, conclusion, url = latest_run_status(session, repo_name, codeql_wf["id"]) if codeql_wf else (None, None, None)
            row["codeql_run_status"], row["codeql_run_conclusion"], row["codeql_run_url"] = status, conclusion, url

            dependabot_wf = find_workflow(session, repo_name, "dependabot-updates")
            status, conclusion, url = latest_run_status(session, repo_name, dependabot_wf["id"]) if dependabot_wf else (None, None, None)
            row["dependabot_run_status"], row["dependabot_run_conclusion"], row["dependabot_run_url"] = status, conclusion, url

        except Exception as e:
            row["error"] = str(e)
            logger.exception(f"{repo_name}: {e}")

        results.append(row)
        if i % 20 == 0:
            logger.info(f"[{i}/{len(repositories)}] {repo_name}: {row}")
        time.sleep(0.2)

    return results


def find_workflow(session, repo, filename):
    r = session.get(f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows")
    if r.status_code != 200:
        return None
    for wf in r.json().get("workflows", []):
        if wf["path"].endswith(filename):
            return wf
    return None


def enable_workflow(session, repo, workflow_id, timeout=10):
    r = session.put(f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{workflow_id}/enable")
    if r.status_code != 204:
        return False
    # A push/dispatch issued right after enabling can land before the state
    # change is visible on a subsequent read and silently no-op; poll until
    # it sticks.
    deadline = time.time() + timeout
    while time.time() < deadline:
        check = session.get(f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{workflow_id}")
        if check.status_code == 200 and check.json().get("state") == "active":
            return True
        time.sleep(1)
    return False


def latest_run_status(session, repo, workflow_id):
    """Returns (status, conclusion, html_url) for the most recent run of a
    workflow: status is queued/in_progress/completed while it's running,
    conclusion (success/failure/startup_failure/...) is only set once status
    is completed. Returns (None, None, None) if the workflow has no runs."""
    r = session.get(f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{workflow_id}/runs",
                     params={"per_page": 1})
    if r.status_code != 200:
        return None, None, None
    runs = r.json().get("workflow_runs", [])
    if not runs:
        return None, None, None
    run = runs[0]
    return run.get("status"), run.get("conclusion"), run.get("html_url")


def dispatch_workflow(session, repo, workflow_id, ref):
    r = session.post(
        f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{workflow_id}/dispatches",
        json={"ref": ref},
    )
    return r.status_code == 204


def push_empty_commit(session, repo, branch, message="chore: trigger CI re-run"):
    """Creates a commit identical in content to HEAD (same tree) and
    fast-forwards the branch to it, to fire push-triggered workflows and
    refresh the dependency graph without touching any file."""
    ref_url = f"https://api.github.com/repos/{OWNER}/{repo}/git/refs/heads/{branch}"
    r = session.get(ref_url)
    if r.status_code != 200:
        return False, f"ref lookup failed ({r.status_code})"
    head_sha = r.json()["object"]["sha"]

    commit_r = session.get(f"https://api.github.com/repos/{OWNER}/{repo}/git/commits/{head_sha}")
    if commit_r.status_code != 200:
        return False, f"commit lookup failed ({commit_r.status_code})"
    tree_sha = commit_r.json()["tree"]["sha"]

    new_commit_r = session.post(
        f"https://api.github.com/repos/{OWNER}/{repo}/git/commits",
        json={"message": message, "tree": tree_sha, "parents": [head_sha]},
    )
    if new_commit_r.status_code != 201:
        return False, f"commit create failed ({new_commit_r.status_code})"
    new_sha = new_commit_r.json()["sha"]

    patch_r = session.patch(ref_url, json={"sha": new_sha})
    if patch_r.status_code != 200:
        return False, f"ref update failed ({patch_r.status_code})"
    return True, new_sha


def main():
    results = trigger_all()
    out_dir = f"data/{date.today()}"
    os.makedirs(out_dir, exist_ok=True)
    out_path = f"{out_dir}/trigger_scans_log.csv"
    fieldnames = sorted({k for r in results for k in r.keys()})
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    from collections import Counter
    logger.info(f"CodeQL workflow fixed: {sum(1 for r in results if r.get('codeql_yml_fixed') is True)}/{len(results)}")
    logger.info(f"Dependabot config fixed: {sum(1 for r in results if r.get('dependabot_yml_fixed') is True)}/{len(results)}")
    logger.info(f"Semgrep dispatched: {sum(1 for r in results if r.get('semgrep_dispatched'))}/{len(results)}")
    logger.info(f"CodeQL run status: {dict(Counter(r.get('codeql_run_status') for r in results))}")
    logger.info(f"CodeQL run conclusion: {dict(Counter(r.get('codeql_run_conclusion') for r in results))}")
    logger.info(f"Semgrep run status: {dict(Counter(r.get('semgrep_run_status') for r in results))}")
    logger.info(f"Semgrep run conclusion: {dict(Counter(r.get('semgrep_run_conclusion') for r in results))}")
    logger.info(f"Dependabot Updates run status: {dict(Counter(r.get('dependabot_run_status') for r in results))}")
    logger.info(f"Dependabot Updates run conclusion: {dict(Counter(r.get('dependabot_run_conclusion') for r in results))}")
    logger.info(f"Log written to {out_path}")


if __name__ == "__main__":
    main()
