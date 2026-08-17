import ast
import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json, canonical_repo_name, is_known_repo, extraction_date, has_provenance, add_source

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
commits = fa.db.collection("commits")
codeql_rules = fa.db.collection("codeql_rules")
cwes = fa.db.collection("cwes")

codeql_rules_commits = fa.graph.edge_collection("codeql_rules_commits")
repositories_commits = fa.graph.edge_collection("repositories_commits")
cwe_commits = fa.graph.edge_collection("cwe_commits")

# GitHub only bumps an alert's updated_at on a real state transition (fixed/
# dismissed) or a NEW instance location -- a rescan that reconfirms the same
# still-open finding at an unchanged location leaves it untouched, so it is
# NOT a proxy for "seen by a scan in this study's accepted window" (verified
# empirically: repos with a confirmed 08-14/15 success in codeql_status_report.csv
# still carry "open" alerts dated as far back as 2024-12-28). This study
# independently verified per-repo scan success there, so the only filters
# needed here are the alert's own current state and its actual source
# workflow -- excluding both a leftover default-setup "phantom" analysis_key
# from before default-setup was disabled, and OSSF Scorecard alerts, which
# are a different tool entirely, out of this study's CodeQL/Dependabot/
# Semgrep scope.
OWN_CODEQL_WORKFLOW = ".github/workflows/codeql.yml:analyze"

codeql_data = pd.read_csv(f"data/{extraction_date()}/code_analysis_result.csv")
codeql_python_data = codeql_data.loc[codeql_data['most_recent_instance.category'] == "/language:python"]
codeql_python_data = codeql_python_data.loc[
    (codeql_python_data['most_recent_instance.analysis_key'] == OWN_CODEQL_WORKFLOW)
    & (codeql_python_data['state'] == 'open')
]
# Final safety net: the finding's own location must genuinely exist at the
# repo's current HEAD, regardless of what GitHub's alert state claims.
codeql_python_data = codeql_python_data.loc[
    codeql_python_data.apply(
        lambda r: has_provenance(r['repo_name'], r['most_recent_instance.location.path']), axis=1
    )
]


def load_codeql_data():
    for index, row in codeql_python_data.iterrows():
        try:
            repo_name = canonical_repo_name(row["repo_name"])
            if not is_known_repo(repo_name):
                continue
            if not repositories.has(repo_name):
                repositories.insert({"_key": repo_name})

            commit_sha = row["most_recent_instance.commit_sha"]
            most_recent_instance = row_to_json(
                row, r"most_recent_instance.(?=[^\d]|$)",
                "most_recent_instance."
            )
            commits.insert({"_key": commit_sha, **most_recent_instance}, overwrite=True,
                           overwrite_mode="replace")

            if repo_name and commit_sha:
                upsert_edge(repositories_commits, {
                    "_key": f"{repo_name}_{commit_sha}",
                    "_from": f"{repositories.name}/{repo_name}",
                    "_to": f"{commits.name}/{commit_sha}"
                })

            rule = row_to_json(row, r"rule.(?=[^\d]|$)", "rule.")
            rule_id = rule["id"].replace("/", "-")

            codeql_rules.insert({"_key": rule_id, **rule}, overwrite=True, overwrite_mode="replace")

            if commit_sha and rule_id:
                upsert_edge(codeql_rules_commits, {
                    "_key": f"{rule_id}_{commit_sha}",
                    "_from": f"{codeql_rules.name}/{rule_id}",
                    "_to": f"{commits.name}/{commit_sha}"
                })

            cwe_ids = normalize_tag(row["rule.tags"])
            if cwe_ids:
                for cwe_id in ast.literal_eval(cwe_ids):
                    cwe_id = cwe_id.upper()
                    id = int(cwe_id.split("-")[1])
                    cwe_id = f"CWE-{id}"
                    if not cwes.has(cwe_id):
                        cwes.insert({"_key": cwe_id})
                    add_source(fa.db, "cwes", cwe_id, "codeql")

                    upsert_edge(cwe_commits, {
                        "_key": f"{cwe_id}_{commit_sha}",
                        "_from": f"{cwes.name}/{cwe_id}",
                        "_to": f"{commits.name}/{commit_sha}"
                    })

        except Exception as e:
            logger.exception(e)
            pass


if __name__ == '__main__':
    load_codeql_data()
