import logging
import json

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import extraction_date

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

cves = fa.db.collection("cves")


def load_cve_metadata(input_file=None):
    if input_file is None:
        input_file = f"data/{extraction_date()}/nvd_cpes.json"
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {input_file} não encontrado.")
        return

    logger.info(f"Enriquecendo metadados de {len(entries)} CVEs...")

    updated = 0
    for entry in entries:
        try:
            cve_id = entry["cve_id"]
            if not cves.has(cve_id):
                logger.warning(f"CVE {cve_id} não encontrado na coleção 'cves'; pulando.")
                continue

            cves.update({
                "_key": cve_id,
                "cvss": entry.get("cvss"),
                "vuln_status": entry.get("vuln_status"),
                "published": entry.get("published"),
                "last_modified": entry.get("last_modified"),
                "weaknesses": entry.get("weaknesses"),
                "references": entry.get("references"),
            })
            updated += 1
        except Exception as e:
            logger.exception(f"Erro ao atualizar CVE {entry.get('cve_id')}: {e}")

    logger.info(f"{updated} CVEs enriquecidos com metadados NVD (CVSS, references, status, datas, weaknesses).")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    load_cve_metadata()
