import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
dependencies = fa.db.collection("dependencies")
advisories = fa.db.collection("github_security_advisories")
cves = fa.db.collection("cves")
cwes = fa.db.collection("cwes")

repositories_dependencies = fa.graph.edge_collection("repositories_dependencies")
gh_security_advisory = fa.graph.edge_collection("gh_security_advisory")
ghsa_cve = fa.graph.edge_collection("ghsa_cve")
cve_cwe = fa.graph.edge_collection("cve_cwe")

dependabot_data = pd.read_csv("../../data/dependabot_result.csv")
dependabot_python_data = dependabot_data.loc[dependabot_data['security_vulnerability.package.ecosystem'] == "pip"]


def load_dependabot_data():
    for index, row in dependabot_python_data.iterrows():
        try:
            repo_name = row["repo_name"]
            dependency_name = row["dependency.package.name"]
            repositories.insert({"_key": repo_name}, overwrite=True, overwrite_mode="replace")

            dependencies.insert({"_key": dependency_name}, overwrite=True, overwrite_mode="replace")

            if repo_name and dependency_name:
                try:
                    upsert_edge(repositories_dependencies, {
                        "_key": f"{repo_name}_{dependency_name}",
                        "_from": f"{repositories.name}/{repo_name}",
                        "_to": f"{dependencies.name}/{dependency_name}"
                    })
                except Exception as e:
                    print(e)

            advisory = row_to_json(
                row,
                r"security_advisory.(?=[^\d]|$)",
                "security_advisory."
            )

            vulnerability = row_to_json(
                row,
                r"security_vulnerability.(?=[^\d]|$)",
                "security_vulnerability."
            )

            advisories.insert({"_key": advisory["ghsa_id"], **advisory, **vulnerability}, overwrite=True,
                              overwrite_mode="replace")

            if dependency_name and advisory['ghsa_id']:
                upsert_edge(gh_security_advisory, {
                    "_key": f"{dependency_name}_{advisory['ghsa_id']}",
                    "_from": f"{dependencies.name}/{dependency_name}",
                    "_to": f"{advisories.name}/{advisory['ghsa_id']}"
                })

            if advisory["cve_id"]:
                cves.insert({"_key": advisory["cve_id"]}, overwrite=True, overwrite_mode="replace")

            if advisory['cve_id'] and advisory['ghsa_id']:
                upsert_edge(ghsa_cve, {
                    "_key": f"{advisory['ghsa_id']}_{advisory['cve_id']}",
                    "_from": f"{advisories.name}/{advisory['ghsa_id']}",
                    "_to": f"{cves.name}/{advisory['cve_id']}"
                })

            for cwe in eval(advisory["cwes"]):
                cwes.insert({"_key": cwe["cwe_id"], **cwe}, overwrite=True, overwrite_mode="replace")

            if advisory['cve_id'] and cwe['cwe_id']:
                upsert_edge(cve_cwe, {
                    "_key": f"{advisory['cve_id']}_{cwe['cwe_id']}",
                    "_from": f"{cves.name}/{advisory['cve_id']}",
                    "_to": f"{cwes.name}/{cwe['cwe_id']}"
                })

        except Exception as e:
            logger.exception(e)
            pass


if __name__ == '__main__':
    load_dependabot_data()
