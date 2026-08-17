"""
Polls CodeQL, Dependabot, and Semgrep run status across every fork in
settings.repositories until all three have completed, retrying failures
in place. Meant to run between trigger_scans.py and the data-extraction
step: extraction must only start once every run's final state is known,
so that alerts reflect the fresh scan rather than a stale pre-trigger
snapshot.

Completion policy:
  - CodeQL and Dependabot must reach status=completed, conclusion=success.
    A completed-but-failed run is retried (CodeQL: empty commit push;
    Dependabot: workflow_dispatch on "dependabot-updates") up to
    MAX_RETRIES times, then left flagged for manual attention -- some
    failures (e.g. a bug in GitHub's own Dependabot updater image) are
    not fixable by retriggering.
  - Semgrep only needs to reach status=completed; its conclusion is
    reported but does not block completion.

Usage:
    poetry run python3 -m fork_attack.wait_for_scans
"""
import csv
import logging
import subprocess
import time
from datetime import date

import requests

from fork_attack.settings import repositories
from fork_attack.trigger_scans import (
    OWNER,
    _headers,
    find_workflow,
    dispatch_workflow,
    get_default_branch,
    push_empty_commit,
    latest_run_status,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MAX_RETRIES = 3
# GitHub's REST API budget is 5000 calls/hour for an authenticated token; this
# loop makes 3 calls/repo/poll (one latest_run_status per workflow, ids cached
# after the first poll), so 273 repos * 3 * (3600/POLL_INTERVAL) must stay
# well under that budget alongside the extraction step's own calls.
POLL_INTERVAL = 600


def dedupe_active_runs(session, wf_ids):
    """Cancels every queued/in_progress run of a workflow beyond the most
    recent one, per repo. Each retry (and every push from other scripts
    touching these forks) can queue a fresh run on top of one already
    in flight; without this, the Actions queue fills with redundant runs
    for the same commit instead of draining."""
    for repo_name, keys in wf_ids.items():
        for wf_id in keys.values():
            active = []
            for status in ("queued", "in_progress"):
                r = session.get(f"https://api.github.com/repos/{OWNER}/{repo_name}/actions/workflows/{wf_id}/runs",
                                 params={"status": status, "per_page": 100})
                if r.status_code == 200:
                    active.extend(r.json().get("workflow_runs", []))
            if len(active) <= 1:
                continue
            active.sort(key=lambda run: run["created_at"], reverse=True)
            for run in active[1:]:
                session.post(f"https://api.github.com/repos/{OWNER}/{repo_name}/actions/runs/{run['id']}/cancel")


def poll_all(session, wf_ids):
    """Returns one row per repo with each workflow's current status/conclusion.
    wf_ids caches {repo: {key: workflow_id}} across polls: workflow ids never
    change for the lifetime of this run, so only the first poll looks them up."""
    rows = []
    for url, _, _ in repositories:
        repo_name = url.replace("https://github.com/", "").split("/")[1]
        row = {"repo": repo_name}
        repo_wf_ids = wf_ids.setdefault(repo_name, {})
        for key, filename in (("codeql", "codeql.yml"), ("semgrep", "semgrep.yml"),
                               ("dependabot", "dependabot-updates")):
            wf_id = repo_wf_ids.get(key)
            if wf_id is None:
                wf = find_workflow(session, repo_name, filename)
                if not wf:
                    row[f"{key}_status"], row[f"{key}_conclusion"] = None, None
                    continue
                wf_id = wf["id"]
                repo_wf_ids[key] = wf_id
            status, conclusion, _ = latest_run_status(session, repo_name, wf_id)
            row[f"{key}_status"], row[f"{key}_conclusion"] = status, conclusion
            row[f"{key}_wf_id"] = wf_id
        rows.append(row)
    return rows


def needs_retry(row, key):
    return row[f"{key}_status"] == "completed" and row[f"{key}_conclusion"] != "success"


def still_running(row, key):
    return row[f"{key}_status"] in (None, "queued", "in_progress", "waiting", "requested", "pending")


def retry_codeql(session, repo_name):
    default_branch = get_default_branch(session, repo_name)
    ok, info = push_empty_commit(session, repo_name, default_branch, "chore: retry CodeQL run")
    return ok


def retry_dependabot(session, repo_name, wf_id):
    return dispatch_workflow(session, repo_name, wf_id, get_default_branch(session, repo_name))


def run():
    session = requests.Session()
    session.headers.update(_headers())

    retries = {repo_name: {"codeql": 0, "dependabot": 0} for (url, _, _) in repositories
               for repo_name in [url.replace("https://github.com/", "").split("/")[1]]}
    # Repos already known to fail Dependabot's pip-ecosystem requirements for
    # a reason retrying can't fix (e.g. a dependency conflict in the fork's
    # own pyproject.toml that blocks lockfile generation) -- see
    # data/<date>/dependabot_requirements_report.csv. Pre-flagging these
    # skips wasting retry attempts on a failure that dispatch/push can't cure.
    flagged = {"dependabot": {"topicwizard"}}
    wf_ids = {}

    while True:
        try:
            rows = poll_all(session, wf_ids)
        except requests.exceptions.RequestException as e:
            # Transient network errors (DNS hiccup, local port exhaustion,
            # a dropped connection) shouldn't kill an hours-long poll loop;
            # skip this cycle and retry on the next one.
            logger.warning(f"poll cycle failed, retrying next cycle: {e}")
            time.sleep(POLL_INTERVAL)
            continue

        try:
            dedupe_active_runs(session, wf_ids)
        except requests.exceptions.RequestException as e:
            logger.warning(f"dedupe cycle failed, continuing anyway: {e}")

        pending = 0
        for row in rows:
            repo_name = row["repo"]

            for key in ("codeql", "semgrep", "dependabot"):
                if still_running(row, key):
                    pending += 1

            if needs_retry(row, "codeql") and repo_name not in flagged.get("codeql", set()):
                if retries[repo_name]["codeql"] < MAX_RETRIES:
                    retries[repo_name]["codeql"] += 1
                    logger.info(f"{repo_name}: retrying CodeQL (attempt {retries[repo_name]['codeql']})")
                    try:
                        retry_codeql(session, repo_name)
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"{repo_name}: CodeQL retry request failed, will retry next cycle: {e}")
                    pending += 1
                else:
                    flagged.setdefault("codeql", set()).add(repo_name)
                    logger.warning(f"{repo_name}: CodeQL failed {MAX_RETRIES}x, flagging as unfixable-by-retry")

            if needs_retry(row, "dependabot") and repo_name not in flagged.get("dependabot", set()):
                if retries[repo_name]["dependabot"] < MAX_RETRIES and row.get("dependabot_wf_id"):
                    retries[repo_name]["dependabot"] += 1
                    logger.info(f"{repo_name}: retrying Dependabot (attempt {retries[repo_name]['dependabot']})")
                    try:
                        retry_dependabot(session, repo_name, row["dependabot_wf_id"])
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"{repo_name}: Dependabot retry request failed, will retry next cycle: {e}")
                    pending += 1
                else:
                    flagged.setdefault("dependabot", set()).add(repo_name)
                    logger.warning(f"{repo_name}: Dependabot failed {MAX_RETRIES}x, flagging as unfixable-by-retry")

        done = len(rows) * 3 - pending
        logger.info(f"Poll: {done}/{len(rows) * 3} workflow slots settled, "
                    f"{sum(len(v) for v in flagged.values())} flagged unfixable")

        if pending == 0:
            break
        time.sleep(POLL_INTERVAL)

    out_path = f"data/{date.today()}/scan_completion_log.csv"
    fieldnames = ["repo", "codeql_status", "codeql_conclusion", "semgrep_status", "semgrep_conclusion",
                  "dependabot_status", "dependabot_conclusion"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"All runs settled. Flagged unfixable: {dict((k, sorted(v)) for k, v in flagged.items())}")
    logger.info(f"Log written to {out_path}")
    return rows, flagged


if __name__ == "__main__":
    run()
