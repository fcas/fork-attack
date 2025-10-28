import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
commits = fa.db.collection("commits")
codeql_rules = fa.db.collection("codeql_rules")
cwes = fa.db.collection("cwes")

rule_commits = fa.graph.edge_collection("rule_commits")
repositories_commits = fa.graph.edge_collection("repositories_commits")
cwe_commits = fa.graph.edge_collection("cwe_commits")

codeql_data = pd.read_csv("../../data/code_analysis_result.csv")
codeql_python_data = codeql_data.loc[codeql_data['most_recent_instance.category'] == "/language:python"]


def load_codeql_data():
    for index, row in codeql_python_data.iterrows():
        try:
            repo_name = row["repo_name"]
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
                upsert_edge(rule_commits, {
                    "_key": f"{rule_id}_{commit_sha}",
                    "_from": f"{codeql_rules.name}/{rule_id}",
                    "_to": f"{commits.name}/{commit_sha}"
                })

            cwe_ids = normalize_tag(row["rule.tags"])
            if cwe_ids:
                for cwe_id in eval(cwe_ids):
                    cwe_id = cwe_id.upper()
                    id = int(cwe_id.split("-")[1])
                    cwe_id = f"CWE-{id}"
                    if not cwes.has(cwe_id):
                        cwes.insert({"_key": cwe_id})

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
