import ast
import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json, canonical_repo_name, is_known_repo, extraction_date, has_provenance, add_source

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

# Dependabot only bumps an alert's updated_at on a real state transition
# (fixed/dismissed) -- a rescan that reconfirms the same still-open finding
# leaves it untouched, so it is NOT a proxy for "seen by a scan in this
# study's accepted window" (verified empirically: repos with a confirmed
# 08-14/15 success in dependabot_status_report.csv still carry "open" alerts
# dated as far back as 2024). This study independently verified per-repo
# scan success there, so the only filter needed here is the alert's own
# current state.
dependabot_data = pd.read_csv(f"data/{extraction_date()}/dependabot_result.csv")
dependabot_python_data = dependabot_data.loc[dependabot_data['security_vulnerability.package.ecosystem'] == "pip"]
dependabot_python_data = dependabot_python_data.loc[dependabot_python_data['state'] == 'open']
# Final safety net: the vulnerable manifest must genuinely exist at the
# repo's current HEAD, regardless of what GitHub's alert state claims.
dependabot_python_data = dependabot_python_data.loc[
    dependabot_python_data.apply(
        lambda r: has_provenance(r['repo_name'], r['dependency.manifest_path']), axis=1
    )
]


def load_dependabot_data():
    for index, row in dependabot_python_data.iterrows():
        try:
            repo_name = canonical_repo_name(row["repo_name"])
            if not is_known_repo(repo_name):
                continue
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
                # "update" merges fields instead of replacing the whole document: a
                # bare re-insert here never wipes out CVSS/EPSS/published/weaknesses
                # this same CVE holds from graph_cve_metadata.py or graph_semgrep.py,
                # regardless of which script runs against it first, the same
                # reasoning graph_cwe_levels.py applies to CWE nodes.
                cves.insert({"_key": advisory["cve_id"]}, overwrite=True, overwrite_mode="update")
                add_source(fa.db, "cves", advisory["cve_id"], "dependabot")

            if advisory['cve_id'] and advisory['ghsa_id']:
                upsert_edge(ghsa_cve, {
                    "_key": f"{advisory['ghsa_id']}_{advisory['cve_id']}",
                    "_from": f"{advisories.name}/{advisory['ghsa_id']}",
                    "_to": f"{cves.name}/{advisory['cve_id']}"
                })

            for cwe in ast.literal_eval(advisory["cwes"]):
                # "update" merges instead of replacing, so this never wipes out the
                # type/nature/description this CWE holds from graph_cwe_levels.py's
                # MITRE hierarchy expansion, regardless of run order.
                cwes.insert({"_key": cwe["cwe_id"], **cwe}, overwrite=True, overwrite_mode="update")
                add_source(fa.db, "cwes", cwe["cwe_id"], "dependabot")

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
