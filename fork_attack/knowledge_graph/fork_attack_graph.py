import os

from arango import ArangoClient
from fork_attack.singleton import Singleton


class ForkAttackGraph(metaclass=Singleton):
    collections = [
        "commits",
        "codeql_rules",
        "cwes",
        "cves",
        "dependencies",
        "github_security_advisories",
        "repositories"
    ]

    edge_collections = [
        "repositories_commits",
        "rule_commits",
        "cwe_commits",
        "cve_cwe",
        "ghsa_cve",
        "gh_security_advisory",
        "repositories_dependencies"
    ]

    def __init__(self):
        self.client = ArangoClient(
            hosts="http://localhost:8529"
        )
        self.sys_db = self.client.db(
            "_system", username=os.getenv("ARANGO_USERNAME"),
            password=os.getenv("ARANGO_PASSWORD")
        )
        self.db_name = "fork-attack"
        self.graph_name = "cwe_cve_cpe"

        self.create_db()
        self.create_graph()
        self.create_collections()
        self.create_edge_collections()

    def create_db(self):
        if not self.sys_db.has_database(self.db_name):
            self.sys_db.create_database(self.db_name)

        self.db = self.client.db(
            self.db_name, username=os.getenv("ARANGO_USERNAME"),
            password=os.getenv("ARANGO_PASSWORD")
        )

    def create_graph(self):
        if self.db.has_graph(self.graph_name):
            self.graph = self.db.graph(self.graph_name)
        else:
            self.graph = self.db.create_graph(name=self.graph_name)

    def create_collections(self):
        for collection in self.collections:
            if not self.db.has_collection(collection):
                self.db.create_collection(collection)

    def create_edge_collections(self):
        for edge_collection in self.edge_collections:
            if not self.graph.has_edge_definition(edge_collection):
                if edge_collection == "repositories_commits":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["repositories"],
                        to_vertex_collections=["commits"]
                    )
                elif edge_collection == "rule_commits":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["codeql_rules"],
                        to_vertex_collections=["commits"]
                    )
                elif edge_collection == "cwe_commits":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["cwes"],
                        to_vertex_collections=["commits"]
                    )
                elif edge_collection == "cve_cwe":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["cves"],
                        to_vertex_collections=["cwes"]
                    )
                elif edge_collection == "ghsa_cve":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["github_security_advisories"],
                        to_vertex_collections=["cves"]
                    )
                elif edge_collection == "gh_security_advisory":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["dependencies"],
                        to_vertex_collections=["github_security_advisories"]
                    )
                elif edge_collection == "repositories_dependencies":
                    self.graph.create_edge_definition(
                        edge_collection=edge_collection,
                        from_vertex_collections=["repositories"],
                        to_vertex_collections=["dependencies"]
                    )
