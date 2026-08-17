import os
import requests
import json
import logging
import time
from datetime import date

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def get_cve_ids():
    """
    Recupera os identificadores de CVE já presentes no grafo de conhecimento
    (coleção `cves`), para os quais buscaremos as entradas CPE correspondentes.
    """
    fa = ForkAttackGraph()
    cves = fa.db.collection("cves")
    return [doc["_key"] for doc in cves.all() if doc["_key"].startswith("CVE-")]


def _extract_cvss(cve_data):
    """
    Extrai as métricas CVSS (v3.1 preferencial, com fallback para v3.0 e v2)
    já presentes na mesma resposta da API usada para CPE, sem custo de
    requisição adicional.
    """
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            return {
                "version": cvss_data.get("version"),
                "vector_string": cvss_data.get("vectorString"),
                "base_score": cvss_data.get("baseScore"),
                "base_severity": cvss_data.get("baseSeverity") or entries[0].get("baseSeverity"),
            }
    return None


def _extract_weaknesses(cve_data):
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                cwe_ids.append(value)
    return sorted(set(cwe_ids))


def _extract_references(cve_data):
    return [ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")]


def fetch_and_save_cpes(output_file=None):
    """
    Consulta a API 2.0 do NVD (https://nvd.nist.gov/developers/vulnerabilities)
    para cada CVE já coletado, extraindo as entradas CPE (Common Platform
    Enumeration) associadas via `configurations[].nodes[].cpeMatch[]`, bem
    como métricas CVSS, referências, status e datas já presentes na mesma
    resposta, sem custo de requisição adicional.
    """
    # Persisted under today's date, the raw extraction date, following the same
    # convention as the per-repo Dependabot/CodeQL dumps in data/<date>/.
    if output_file is None:
        output_file = f"data/{date.today()}/nvd_cpes.json"

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    api_key = os.getenv("NVD_API_KEY", "")
    # A default python-requests User-Agent gets flagged by NVD's Cloudflare
    # bot protection (returns a JS-challenge HTML page, not JSON); a
    # browser-like one passes through the same way curl does.
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
    if api_key:
        headers["apiKey"] = api_key

    # Sem API key: 5 requisições / 30s. Com API key: 50 requisições / 30s.
    # https://nvd.nist.gov/developers/start-here
    delay = 0.7 if api_key else 6.5

    cve_ids = get_cve_ids()

    if not cve_ids:
        logger.error("Nenhum CVE encontrado na coleção 'cves'. Nada a fazer.")
        return

    logger.info(f"Iniciando a coleta de CPEs para {len(cve_ids)} CVEs...")
    if not api_key:
        logger.warning("NVD_API_KEY não definida; aplicando rate limit mais conservador (5 req/30s).")

    results = []

    try:
        for i, cve_id in enumerate(cve_ids, start=1):
            params = {"cveId": cve_id}

            response = requests.get(base_url, headers=headers, params=params)

            if response.status_code == 404:
                logger.warning(f"CVE {cve_id} não encontrado no NVD.")
                time.sleep(delay)
                continue

            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                logger.warning(f"CVE {cve_id} sem dados de vulnerabilidade retornados pelo NVD.")
                time.sleep(delay)
                continue

            cve_data = vulnerabilities[0].get("cve", {})
            configurations = cve_data.get("configurations", [])

            cpes = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", True):
                            cpes.append({
                                "criteria": cpe_match.get("criteria"),
                                "matchCriteriaId": cpe_match.get("matchCriteriaId"),
                                "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                                "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                            })

            metadata = {
                "cve_id": cve_id,
                "cpes": cpes,
                "cvss": _extract_cvss(cve_data),
                "vuln_status": cve_data.get("vulnStatus"),
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "weaknesses": _extract_weaknesses(cve_data),
                "references": _extract_references(cve_data),
            }
            results.append(metadata)

            logger.info(f"[{i}/{len(cve_ids)}] {cve_id}: {len(cpes)} CPE(s), CVSS={metadata['cvss']}. Total acumulado: {len(results)}")

            time.sleep(delay)

        logger.info(f"Escrevendo CPEs de {len(results)} CVEs no arquivo '{output_file}'...")

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)

        logger.info(f"Arquivo '{output_file}' salvo com sucesso.")

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao acessar a API do NVD: {e}")
        if e.response is not None:
            logger.error(f"Detalhes da resposta: {e.response.text}")
    except Exception as e:
        logger.error(f"Ocorreu um erro inesperado: {e}")


if __name__ == "__main__":
    fetch_and_save_cpes()
