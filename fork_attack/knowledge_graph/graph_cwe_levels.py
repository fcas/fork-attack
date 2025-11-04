import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.time_machine import cwe_definitions
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

cwes = fa.db.collection("cwes")

edges = {
    "pillar": fa.graph.edge_collection("cwe_pillars"),
    "category": fa.graph.edge_collection("cwe_categories"),
    "variant": fa.graph.edge_collection("cwe_variants"),
    "base": fa.graph.edge_collection("cwe_bases"),
    "class": fa.graph.edge_collection("cwe_classes"),
    "view": fa.graph.edge_collection("cwe_views"),
    "composite": fa.graph.edge_collection("cwe_composites"),
    "chain": fa.graph.edge_collection("cwe_chains")
}

cwe_definitions_data = pd.read_csv("../../data/cwe_definitions_lib.csv")
cve_definitions_data = pd.read_csv("../../data/cve_definitions_lib.csv")
all_definitions_lib = pd.concat([cve_definitions_data, cwe_definitions_data], ignore_index=True, sort=False)


def load_cwe_data():
    for index, row in all_definitions_lib.iterrows():
        try:
            cwe_id = f"CWE-{row["cwe_id"]}"
            cwe = {"_key": cwe_id}
            cwes.insert(cwe, overwrite=True, overwrite_mode="replace")

            cwe_related_id = f"CWE-{row["id"]}"
            cwe_related_type = row["type"]
            cwe_related_nature = row["nature"]
            cwe_related_description = row["description"]
            related_cwe = {"_key": cwe_related_id, "nature": cwe_related_nature, "type": cwe_related_type,
                           "description": cwe_related_description}
            cwes.insert(related_cwe, overwrite=True, overwrite_mode="replace")

            edge_collection = edges.get(cwe_related_type)
            document = {
                "_key": f"{cwe_id}_{cwe_related_id}",
                "_from": f"{cwes.name}/{cwe_id}",
                "_to": f"{cwes.name}/{cwe_related_id}"
            }

            if not edge_collection.has(document):
                edge_collection.insert(document)

        except Exception as e:
            logger.exception(e)
            pass


if __name__ == '__main__':
    load_cwe_data()
