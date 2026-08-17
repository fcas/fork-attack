import logging
import json

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, extraction_date

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

capecs = fa.db.collection("capecs")
attack_techniques = fa.db.collection("attack_techniques")
capec_attack = fa.graph.edge_collection("capec_attack")


def load_attack_data():
    attack_path = f"data/{extraction_date()}/attack.json"
    capec_path = f"data/{extraction_date()}/capec.json"
    try:
        with open(attack_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {attack_path} não encontrado.")
        return

    try:
        with open(capec_path, "r", encoding="utf-8") as f:
            capec_entries = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {capec_path} não encontrado.")
        return

    # A ATT&CK technique is only relevant to this graph if it maps to a CAPEC
    # already ingested (i.e., connected to an existing CWE/CVE), mirroring the
    # same scope-integrity rule enforced for the CAPEC ingestion itself.
    relevant_ids = {
        technique_id
        for entry in capec_entries
        if capecs.has(entry["capec_id"])
        for technique_id in entry.get("related_attack_techniques", [])
    }
    skipped = len(entries) - len({e["technique_id"] for e in entries} & relevant_ids)

    logger.info(f"Processando {len(entries)} técnicas ATT&CK ({len(relevant_ids)} relevantes)...")

    for entry in entries:
        try:
            technique_id = entry["technique_id"]
            if technique_id not in relevant_ids:
                continue

            if not attack_techniques.has(technique_id):
                attack_techniques.insert({
                    "_key": technique_id,
                    "name": entry.get("name"),
                    "description": entry.get("description"),
                    "tactics": entry.get("tactics"),
                    "platforms": entry.get("platforms"),
                    "is_subtechnique": entry.get("is_subtechnique"),
                })
        except Exception as e:
            logger.exception(f"Erro ao inserir técnica ATT&CK {entry.get('technique_id')}: {e}")

    edges_created = 0
    for entry in capec_entries:
        capec_id = entry["capec_id"]
        if not capecs.has(capec_id):
            continue

        for technique_id in entry.get("related_attack_techniques", []):
            if not attack_techniques.has(technique_id):
                logger.warning(f"Técnica ATT&CK {technique_id} não encontrada; pulando edge {capec_id}->{technique_id}.")
                continue

            upsert_edge(capec_attack, {
                "_key": f"{capec_id}_{technique_id}",
                "_from": f"{capecs.name}/{capec_id}",
                "_to": f"{attack_techniques.name}/{technique_id}"
            })
            edges_created += 1

    logger.info(f"{edges_created} edges capec_attack criadas; {skipped} técnicas ATT&CK sem CAPEC relevante foram ignoradas.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    load_attack_data()
