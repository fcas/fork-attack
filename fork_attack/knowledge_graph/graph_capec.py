import logging
import json

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, extraction_date

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

cwes = fa.db.collection("cwes")
capecs = fa.db.collection("capecs")
cwe_capec = fa.graph.edge_collection("cwe_capec")
capec_capec = fa.graph.edge_collection("capec_capec")


def load_capec_data():
    capec_path = f"data/{extraction_date()}/capec.json"
    try:
        with open(capec_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {capec_path} não encontrado.")
        return

    logger.info(f"Processando {len(entries)} attack patterns CAPEC...")

    # A CAPEC entry is only relevant to this graph if it exploits at least one
    # CWE we've actually collected; entries with no overlap are pure catalog
    # noise for this study and must not be ingested, mirroring the same
    # scope-integrity rule already enforced for the pypi/Semgrep ingestion.
    relevant_ids = {
        entry["capec_id"]
        for entry in entries
        if any(cwes.has(cwe_id) for cwe_id in entry.get("related_weaknesses", []))
    }
    skipped = len(entries) - len(relevant_ids)

    for entry in entries:
        try:
            capec_id = entry["capec_id"]
            if capec_id not in relevant_ids:
                continue

            if not capecs.has(capec_id):
                capecs.insert({
                    "_key": capec_id,
                    "name": entry.get("name"),
                    "abstraction": entry.get("abstraction"),
                    "status": entry.get("status"),
                    "description": entry.get("description"),
                    "likelihood_of_attack": entry.get("likelihood_of_attack"),
                    "typical_severity": entry.get("typical_severity"),
                })
        except Exception as e:
            logger.exception(f"Erro ao inserir CAPEC {entry.get('capec_id')}: {e}")

    for entry in entries:
        try:
            capec_id = entry["capec_id"]
            if capec_id not in relevant_ids:
                continue

            for cwe_id in entry.get("related_weaknesses", []):
                if not cwes.has(cwe_id):
                    logger.warning(f"CWE {cwe_id} não encontrado na coleção 'cwes'; pulando edge {capec_id}->{cwe_id}.")
                    continue

                upsert_edge(cwe_capec, {
                    "_key": f"{capec_id}_{cwe_id}",
                    "_from": f"{capecs.name}/{capec_id}",
                    "_to": f"{cwes.name}/{cwe_id}"
                })

            for related_capec_id in entry.get("related_attack_patterns", []):
                if related_capec_id not in relevant_ids or not capecs.has(related_capec_id):
                    logger.warning(f"CAPEC {related_capec_id} não relevante ou não encontrado; pulando edge {capec_id}->{related_capec_id}.")
                    continue

                upsert_edge(capec_capec, {
                    "_key": f"{capec_id}_{related_capec_id}",
                    "_from": f"{capecs.name}/{capec_id}",
                    "_to": f"{capecs.name}/{related_capec_id}"
                })
        except Exception as e:
            logger.exception(f"Erro ao processar edges do CAPEC {entry.get('capec_id')}: {e}")

    logger.info(f"{skipped} attack patterns CAPEC sem CWE relacionado no grafo foram ignorados.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    load_capec_data()
