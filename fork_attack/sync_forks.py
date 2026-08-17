"""
Syncs each local clone under BASE_DIR with its upstream repository, then
pushes the result to the fork on GitHub ($GITHUB_OWNER/<repo>).

Each fork's `.github/workflows` and `.github/dependabot.yml` hold our own CI
config (see estige.py's add_ymls), separate from whatever CI config the
upstream repo keeps at the same paths. GitHub's own "Sync fork" API
(`merge-upstream`) has no way to express "merge everything except keep my
version of these paths", so it reports a conflict whenever upstream has
touched `.github/*`. This script performs the merge locally instead,
resolving any conflict under `.github/` in favor of our own version and
treating a conflict anywhere else as unresolved (skipped, not guessed at).

Usage:
    poetry run python3 -m fork_attack.sync_forks
"""
import csv
import logging
import os
import shutil
import subprocess
from datetime import date

import requests

from fork_attack.settings import repositories, OWNER

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = "/Users/felipe.dias/IdeaProjects/forks"


def _headers():
    token = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def get_default_branch(session, owner, repo):
    r = session.get(f"https://api.github.com/repos/{owner}/{repo}")
    r.raise_for_status()
    return r.json()["default_branch"]


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


KEPT_WORKFLOWS = {"codeql.yml", "semgrep.yml"}
KEPT_GITHUB_ROOT = {"workflows", "dependabot.yml"}


def _remove(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def prune_workflows(repo_dir):
    """Enforces the exact .github layout this project's CI relies on: under
    .github/, only workflows/ and dependabot.yml are kept (anything else --
    ISSUE_TEMPLATE/, CODEOWNERS, FUNDING.yml, upstream's own PR template,
    etc. -- is removed); under .github/workflows/, only codeql.yml and
    semgrep.yml are kept (upstream's own CI workflow files are removed).
    This is the gate that decides what survives sync_one()'s restore of
    .github to its pre-merge content."""
    github_dir = os.path.join(repo_dir, ".github")
    if not os.path.isdir(github_dir):
        return
    for entry in os.listdir(github_dir):
        if entry not in KEPT_GITHUB_ROOT:
            _remove(os.path.join(github_dir, entry))

    workflows_dir = os.path.join(github_dir, "workflows")
    if not os.path.isdir(workflows_dir):
        return
    for entry in os.listdir(workflows_dir):
        if entry not in KEPT_WORKFLOWS:
            _remove(os.path.join(workflows_dir, entry))


def sync_one(repo_name, upstream_url, fork_branch, upstream_branch):
    """fork_branch and upstream_branch are looked up live via the GitHub API
    (see main()), not taken from settings.py: an upstream can rename its
    default branch (e.g. master -> main) long after a fork was created, and
    the fork's own default branch never follows that rename automatically."""
    repo_dir = os.path.join(BASE_DIR, repo_name)
    if not os.path.isdir(repo_dir):
        return "no-local-clone", None

    if run(["git", "remote", "get-url", "upstream"], repo_dir).returncode != 0:
        run(["git", "remote", "add", "upstream", upstream_url], repo_dir)

    run(["git", "fetch", "origin"], repo_dir)
    fetch_upstream = run(["git", "fetch", "upstream"], repo_dir)
    if fetch_upstream.returncode != 0:
        return "upstream-fetch-failed", fetch_upstream.stderr[:300]

    run(["git", "merge", "--abort"], repo_dir)  # clears any stale in-progress merge
    # `-B ... origin/<branch>` names the source ref explicitly: a plain
    # `git checkout <branch>` is ambiguous whenever no local branch of that
    # name exists yet but both origin and upstream have a remote-tracking
    # branch with the same name (e.g. fork_branch is the fork's current
    # default branch, discovered live, and a local branch was never created
    # for it because the clone predates a default-branch rename upstream).
    checkout = run(["git", "checkout", "-B", fork_branch, f"origin/{fork_branch}"], repo_dir)
    if checkout.returncode != 0:
        return "checkout-failed", checkout.stderr[:300]

    pre_merge_sha = run(["git", "rev-parse", "HEAD"], repo_dir).stdout.strip()

    merge = run(["git", "merge", f"upstream/{upstream_branch}", "--no-edit"], repo_dir)
    if merge.returncode != 0:
        # A conflict under .github/ is irrelevant: the block below always
        # rewrites .github to our own pre-merge content regardless of what
        # upstream did there, so only conflicts elsewhere block the sync.
        status = run(["git", "status", "--porcelain"], repo_dir).stdout
        conflicted = [line[3:] for line in status.splitlines() if line[:2] in ("UU", "AA", "DU", "UD", "AU", "UA")]
        non_github = [p for p in conflicted if not p.startswith(".github/")]
        if non_github or not conflicted:
            run(["git", "merge", "--abort"], repo_dir)
            return "conflict", non_github or merge.stderr[:300]

    # Replaces .github with exactly its pre-merge content: `git checkout
    # <ref> -- <dir>` only updates paths <ref> actually has, so a file
    # upstream added under .github/ (no conflict, since we never had it)
    # would otherwise survive the merge untouched. Removing the whole
    # directory first guarantees nothing upstream-added lingers.
    run(["git", "rm", "-r", "-q", "--ignore-unmatch", ".github"], repo_dir)
    run(["git", "checkout", pre_merge_sha, "--", ".github"], repo_dir)
    prune_workflows(repo_dir)
    run(["git", "add", ".github"], repo_dir)

    if run(["git", "rev-parse", "-q", "--verify", "MERGE_HEAD"], repo_dir).returncode == 0:
        commit = run(["git", "commit", "--no-edit"], repo_dir)
        if commit.returncode != 0:
            run(["git", "merge", "--abort"], repo_dir)
            return "resolve-failed", commit.stderr[:300]
    elif run(["git", "status", "--porcelain"], repo_dir).stdout.strip():
        run(["git", "commit", "-m", "chore: keep our own CI config under .github"], repo_dir)

    ahead = run(["git", "rev-list", f"origin/{fork_branch}..HEAD", "--count"], repo_dir).stdout.strip()
    if ahead == "0":
        return "none", None

    push = run(["git", "push", "origin", fork_branch], repo_dir)
    if push.returncode != 0:
        return "push-failed", push.stderr[:300]
    return "synced", ahead


def main():
    session = requests.Session()
    session.headers.update(_headers())

    results = []
    for i, (url, branch, clone) in enumerate(repositories, 1):
        repo_name = url.replace("https://github.com/", "").split("/")[1]
        upstream_owner = url.replace("https://github.com/", "").split("/")[0]
        try:
            fork_branch = get_default_branch(session, OWNER, repo_name)
            upstream_branch = get_default_branch(session, upstream_owner, repo_name)
        except Exception as e:
            results.append({"repo": repo_name, "fork_branch": None, "upstream_branch": None,
                             "status": "branch-lookup-failed", "detail": str(e)[:300]})
            continue

        status, detail = sync_one(repo_name, url, fork_branch, upstream_branch)
        results.append({"repo": repo_name, "fork_branch": fork_branch, "upstream_branch": upstream_branch,
                         "status": status, "detail": detail})
        if i % 20 == 0 or status not in ("synced", "none"):
            logger.info(f"[{i}/{len(repositories)}] {repo_name}: {status} {detail if status not in ('synced', 'none') else ''}")

    out_dir = f"data/{date.today()}"
    os.makedirs(out_dir, exist_ok=True)
    out_path = f"{out_dir}/sync_forks_log.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["repo", "fork_branch", "upstream_branch", "status", "detail"])
        writer.writeheader()
        writer.writerows(results)

    from collections import Counter
    counts = Counter(r["status"] for r in results)
    logger.info(f"Summary: {dict(counts)}")
    logger.info(f"Log written to {out_path}")


if __name__ == "__main__":
    main()
