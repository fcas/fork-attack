import logging
import json
import urllib.parse

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
commits = fa.db.collection("commits")
semgrep_rules = fa.db.collection("semgrep_rules")
cwes = fa.db.collection("cwes")
cves = fa.db.collection("cves")
cve_cwe = fa.graph.edge_collection("cve_cwe")

semgrep_rules_commits = fa.graph.edge_collection("semgrep_rules_commits")
repositories_commits = fa.graph.edge_collection("repositories_commits")
cwe_commits = fa.graph.edge_collection("cwe_commits")

def extract_commit_sha(url):
    """
    Extrai o commit SHA a partir de uma URL do GitHub.
    Exemplo: https://github.com/user/repo/blob/3f3011585669c1e49076bb3f6fffe2c18b02cd16/...
    """
    if not url:
        return None
    try:
        parsed_url = urllib.parse.urlparse(url)
        parts = parsed_url.path.split('/')
        if 'blob' in parts:
            blob_index = parts.index('blob')
            return parts[blob_index + 1]
    except Exception as e:
        logger.warning(f"Erro ao extrair commit sha da URL {url}: {e}")
    return None

def load_semgrep_data():
    try:
        with open("../../data/semgrep_findings.json", 'r', encoding='utf-8') as f:
            findings = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {json_file_path} não encontrado.")
        return

    logger.info(f"Processando {len(findings)} findings do Semgrep...")

    for item in findings:
        try:
            repo_info = item.get("repository", {})
            repo_name = repo_info.get("name").replace("fcas/", "")

            if repo_name and not repositories.has(repo_name):
                repositories.insert({"_key": repo_name})

            url = item.get("line_of_code_url")
            commit_sha = extract_commit_sha(url)

            if not commits.has(commit_sha):
                commits.insert({"_key": commit_sha})

            if repo_name:
                upsert_edge(repositories_commits, {
                    "_key": f"{repo_name.replace('/', '_')}_{commit_sha}",
                    "_from": f"{repositories.name}/{repo_name}",
                    "_to": f"{commits.name}/{commit_sha}"
                })

            rule = item.get("rule", {})
            rule_id = rule.get("name")

            if rule_id:
                semgrep_rules.insert({"_key": rule_id, **rule, **item}, overwrite=True, overwrite_mode="replace")

                if commit_sha:
                    upsert_edge(semgrep_rules_commits, {
                        "_key": f"{rule_id}_{commit_sha}",
                        "_from": f"{semgrep_rules.name}/{rule_id}",
                        "_to": f"{commits.name}/{commit_sha}"
                    })

            cve_id = item.get("vulnerability_identifier")
            if cve_id:
                cve_key = cve_id.strip().replace(" ", "-")
                if not cves.has(cve_key):
                    cves.insert({"_key": cve_key})
            else:
                cve_key = None

            cwe_names = rule.get("cwe_names", [])
            if cwe_names:
                for cwe_str in cwe_names:
                    cwe_id = cwe_str.split(":")[0].strip().upper()

                    if not cwes.has(cwe_id):
                        cwes.insert({"_key": cwe_id, "name": cwe_str})

                    if commit_sha:
                        upsert_edge(cwe_commits, {
                            "_key": f"{cwe_id}_{commit_sha}",
                            "_from": f"{cwes.name}/{cwe_id}",
                            "_to": f"{commits.name}/{commit_sha}"
                        })

                    if cve_key:
                        upsert_edge(cve_cwe, {
                            "_key": f"{cve_key}_{cwe_id}",
                            "_from": f"{cves.name}/{cve_key}",
                            "_to": f"{cwes.name}/{cwe_id}"
                        })

        except Exception as e:
            logger.exception(f"Erro ao processar o finding ID {item.get('id')}: {e}")
            pass

if __name__ == '__main__':
    # Opcional: configurar log se for rodar standalone
    logging.basicConfig(level=logging.INFO)
    load_semgrep_data()