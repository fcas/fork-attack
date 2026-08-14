import logging
import json
import re

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

cves = fa.db.collection("cves")
cpes = fa.db.collection("cpes")
cve_cpe = fa.graph.edge_collection("cve_cpe")

# Caracteres permitidos em uma chave de documento do ArangoDB.
# https://docs.arangodb.com/stable/concepts/data-structure/documents/#document-keys
_INVALID_KEY_CHARS = re.compile(r"[^A-Za-z0-9_\-:.@()+,=;$!*']")


def sanitize_key(criteria):
    """
    Strings CPE 2.3 podem conter caracteres não permitidos como chave de
    documento no ArangoDB (ex: "/" em "erlang/otp", ou o escape "\\&" em
    "storage_node\\&_hci"). Substitui qualquer caractere fora do conjunto
    permitido, preservando o valor original no campo `criteria`.
    """
    return _INVALID_KEY_CHARS.sub("_", criteria)


def load_cpe_data():
    try:
        with open("data/nvd_cpes.json", 'r', encoding='utf-8') as f:
            entries = json.load(f)
    except FileNotFoundError:
        logger.error("Arquivo data/nvd_cpes.json não encontrado.")
        return

    logger.info(f"Processando CPEs de {len(entries)} CVEs...")

    for entry in entries:
        try:
            cve_id = entry.get("cve_id")
            if not cve_id or not cves.has(cve_id):
                logger.warning(f"CVE {cve_id} não encontrado na coleção 'cves'; pulando.")
                continue

            for cpe in entry.get("cpes", []):
                criteria = cpe.get("criteria")
                if not criteria:
                    continue

                key = sanitize_key(criteria)

                if not cpes.has(key):
                    cpes.insert({"_key": key, **cpe})

                upsert_edge(cve_cpe, {
                    "_key": f"{cve_id}_{key}",
                    "_from": f"{cves.name}/{cve_id}",
                    "_to": f"{cpes.name}/{key}"
                })

        except Exception as e:
            logger.exception(f"Erro ao processar CPEs do CVE {entry.get('cve_id')}: {e}")
            pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    load_cpe_data()
