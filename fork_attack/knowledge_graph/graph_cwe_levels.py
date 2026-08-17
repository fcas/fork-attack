import logging

import pandas as pd
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.time_machine import cwe_definitions
from fork_attack.utils import upsert_edge, normalize_tag, row_to_json, extraction_date

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

cwe_definitions_data = pd.read_csv(f"data/{extraction_date()}/cwe_definitions_lib.csv")
cve_definitions_data = pd.read_csv(f"data/{extraction_date()}/cve_definitions_lib.csv")
all_definitions_lib = pd.concat([cve_definitions_data, cwe_definitions_data], ignore_index=True, sort=False)


def load_cwe_data():
    for index, row in all_definitions_lib.iterrows():
        try:
            cwe_id = f"CWE-{row["cwe_id"]}"
            cwe = {"_key": cwe_id}
            # "update" merges fields instead of replacing the whole document, so this
            # placeholder insert never wipes out a type/nature/description this same
            # CWE holds as a related entry elsewhere in the dataset, regardless of
            # which row this loop processes first.
            cwes.insert(cwe, overwrite=True, overwrite_mode="update")

            cwe_related_id = f"CWE-{row["id"]}"
            # pandas represents a missing string cell as float NaN, not None; json.dumps
            # emits that as a bare `NaN` token, which is valid Python/JS but not valid
            # JSON, so ArangoDB's VPack parser rejects the whole insert with a cryptic
            # "Expecting digit" error instead of storing a null field.
            cwe_related_type = row["type"] if pd.notna(row["type"]) else None
            cwe_related_nature = row["nature"] if pd.notna(row["nature"]) else None
            cwe_related_description = row["description"] if pd.notna(row["description"]) else None
            related_cwe = {"_key": cwe_related_id, "nature": cwe_related_nature, "type": cwe_related_type,
                           "description": cwe_related_description}
            cwes.insert(related_cwe, overwrite=True, overwrite_mode="update")

            # A "Self" row (see scrap.py) records cwe_id's own MITRE-stated abstraction level,
            # used as a fallback when no other CWE lists cwe_id as a related entry; it is not
            # an actual relation to another entry, so no edge should be created for it.
            if cwe_related_nature == "Self" or cwe_related_id == cwe_id:
                continue

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

    backfill_orphan_types()


def backfill_orphan_types():
    """Safety net against orphan CWE nodes (type/nature/description never set).

    A CWE can end up with only its bare {"_key": ...} placeholder (inserted by
    graph_dependabot.py/graph_codeql.py/graph_semgrep.py whenever it's tagged
    on an alert) if the load above ran against a cwe_definitions_lib.csv/
    cve_definitions_lib.csv snapshot that predates that CWE's own "Self" row
    being scraped -- e.g. a partial rerun, or the CSVs regenerated after this
    script's own load already completed. Rather than let that drift persist
    silently, re-check every untyped CWE against the in-memory definitions
    data and backfill it directly from cwe.mitre.org if still missing there.
    """
    orphans = [c["_key"] for c in cwes.find({}) if c.get("type") is None]
    if not orphans:
        return
    logger.warning(f"{len(orphans)} CWE node(s) with no type after load, backfilling: {orphans}")

    self_rows = all_definitions_lib[all_definitions_lib["nature"] == "Self"]
    self_by_cwe_id = {f"CWE-{cid}": row for cid, row in zip(self_rows["cwe_id"], self_rows.itertuples())}

    still_missing = []
    for key in orphans:
        row = self_by_cwe_id.get(key)
        if row is not None:
            cwes.update({"_key": key, "type": row.type, "nature": "Self", "description": row.type})
            continue
        still_missing.append(key)

    if still_missing:
        from fork_attack.scrap import get_definitions
        for key in still_missing:
            cid = int(key.split("-")[1])
            definitions = get_definitions(cid)
            self_row = definitions[definitions["nature"] == "Self"] if not definitions.empty else definitions
            if not self_row.empty:
                cwes.update({"_key": key, "type": self_row.iloc[0]["type"], "nature": "Self",
                            "description": self_row.iloc[0]["type"]})
            else:
                logger.error(f"{key}: could not resolve a type even from a live MITRE scrape -- "
                             f"leaving as an untyped node, investigate manually.")


if __name__ == '__main__':
    load_cwe_data()
