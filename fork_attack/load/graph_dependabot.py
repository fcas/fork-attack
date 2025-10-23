import logging
import os

import numpy as np
import pandas as pd
from arango import ArangoClient

logger = logging.getLogger(__name__)

db_name = "fork-attack"
graph_name = "cwe_cve_cpe"
collections = [
    "commits",
    "codeql_rules",
    "cwes",
    "cves",
    "dependencies",
    "github_security_advisories",
    "repositories"
]

client = ArangoClient(hosts="http://localhost:8529")

sys_db = client.db("_system", username=os.getenv("ARANGO_USERNAME"), password=os.getenv("ARANGO_PASSWORD"))

if not sys_db.has_database(db_name):
    sys_db.create_database()

db = client.db(db_name, username=os.getenv("ARANGO_USERNAME"), password=os.getenv("ARANGO_PASSWORD"))

for collection in collections:
    if not db.has_collection(collection):
        db.create_collection(collection)

repositories = db.collection("repositories")
dependencies = db.collection("dependencies")
advisories = db.collection("github_security_advisories")
cves = db.collection("cves")
cwes = db.collection("cwes")

if db.has_graph(graph_name):
    cwe_cve_cpe_graph = db.graph(graph_name)
else:
    cwe_cve_cpe_graph = db.create_graph(
        name=graph_name
    )

if cwe_cve_cpe_graph.has_edge_definition("repositories_dependencies"):
    repositories_dependencies = cwe_cve_cpe_graph.edge_collection("repositories_dependencies")
else:
    repositories_dependencies = cwe_cve_cpe_graph.create_edge_definition(
        edge_collection="repositories_dependencies",
        from_vertex_collections=["repositories"],
        to_vertex_collections=["dependencies"]
    )

if cwe_cve_cpe_graph.has_edge_definition("gh_security_advisory"):
    gh_security_advisory = cwe_cve_cpe_graph.edge_collection("gh_security_advisory")
else:
    gh_security_advisory = cwe_cve_cpe_graph.create_edge_definition(
        edge_collection="gh_security_advisory",
        from_vertex_collections=["dependencies"],
        to_vertex_collections=["github_security_advisories"]
    )

if cwe_cve_cpe_graph.has_edge_definition("ghsa_cve"):
    ghsa_cve = cwe_cve_cpe_graph.edge_collection("ghsa_cve")
else:
    ghsa_cve = cwe_cve_cpe_graph.create_edge_definition(
        edge_collection="ghsa_cve",
        from_vertex_collections=["github_security_advisories"],
        to_vertex_collections=["cves"]
    )

if cwe_cve_cpe_graph.has_edge_definition("cve_cwe"):
    cve_cwe = cwe_cve_cpe_graph.edge_collection("cve_cwe")
else:
    cve_cwe = cwe_cve_cpe_graph.create_edge_definition(
        edge_collection="cve_cwe",
        from_vertex_collections=["cves"],
        to_vertex_collections=["cwes"]
    )

dependabot_data = pd.read_csv("../../data/dependabot_result.csv")
dependabot_python_data = dependabot_data.loc[dependabot_data['security_vulnerability.package.ecosystem'] == "pip"]


def upsert_edge(edge_collection, doc):
    if not edge_collection.has(doc):
        edge_collection.insert(doc)


for index, row in dependabot_python_data.iterrows():
    try:
        repo_name = row["repo_name"]
        dependency_name = row["dependency.package.name"]
        repositories.insert({"_key": repo_name}, overwrite=True, overwrite_mode="replace")

        dependencies.insert({"_key": dependency_name}, overwrite=True, overwrite_mode="replace")

        if repo_name and dependency_name:
            upsert_edge(repositories_dependencies, {
                "_key": f"{repo_name}_{dependency_name}",
                "_from": f"{repositories.name}/{repo_name}",
                "_to": f"{dependencies.name}/{dependency_name}"
            })

        advisory = row.filter(regex=r"security_advisory.(?=[^\d]|$)")
        advisory = pd.DataFrame([advisory.to_list()], columns=advisory.index)
        advisory.columns = advisory.columns.str.replace("security_advisory.", "", regex=True)
        advisory = advisory.replace(np.nan, None)
        advisory = advisory.to_dict(orient="index")[0]

        vulnerability = row.filter(regex=r"security_vulnerability.(?=[^\d]|$)")
        vulnerability = pd.DataFrame([vulnerability.to_list()], columns=vulnerability.index)
        vulnerability.columns = vulnerability.columns.str.replace("security_vulnerability.", "", regex=True)
        vulnerability = vulnerability.replace(np.nan, None)
        vulnerability = vulnerability.to_dict(orient="index")[0]

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
