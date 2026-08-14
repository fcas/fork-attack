import ast
import logging
import json
import urllib.parse

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, canonical_repo_name

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
commits = fa.db.collection("commits")
semgrep_rules = fa.db.collection("semgrep_rules")
cwes = fa.db.collection("cwes")
cves = fa.db.collection("cves")
dependencies = fa.db.collection("dependencies")
github_security_advisories = fa.db.collection("github_security_advisories")
owasp = fa.db.collection("owasp")
cve_cwe = fa.graph.edge_collection("cve_cwe")
ghsa_cwe = fa.graph.edge_collection("ghsa_cwe")
ghsa_cve = fa.graph.edge_collection("ghsa_cve")
semgrep_rules_cwes = fa.graph.edge_collection("semgrep_rules_cwes")
semgrep_rules_cves = fa.graph.edge_collection("semgrep_rules_cves")
semgrep_rules_owasp = fa.graph.edge_collection("semgrep_rules_owasp")

semgrep_rules_commits = fa.graph.edge_collection("semgrep_rules_commits")
repositories_commits = fa.graph.edge_collection("repositories_commits")
repositories_dependencies = fa.graph.edge_collection("repositories_dependencies")
cwe_commits = fa.graph.edge_collection("cwe_commits")

# This study's corpus is restricted to the Python (pypi) ecosystem; Semgrep
# Supply Chain findings against non-Python dependency manifests (npm, gomod,
# etc.), occasionally present in these same repositories, are out of scope
# and must not contaminate the graph.
ALLOWED_ECOSYSTEM = "pypi"

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
        with open("data/semgrep_findings.json", 'r', encoding='utf-8') as f:
            findings = json.load(f)
    except FileNotFoundError:
        logger.error("Arquivo data/semgrep_findings.json não encontrado.")
        return

    logger.info(f"Processando {len(findings)} findings do Semgrep...")

    skipped_non_python = 0
    skipped_unknown_vuln = 0
    for item in findings:
        try:
            ecosystem = item.get("found_dependency", {}).get("ecosystem")
            if ecosystem != ALLOWED_ECOSYSTEM:
                skipped_non_python += 1
                continue

            # Semgrep SSC's role in this study is reachability triage of
            # vulnerabilities already identified by CodeQL/Dependabot, not an
            # independent source of new CVEs/GHSAs: a finding is only ingested
            # if its vulnerability identifier already exists in the graph
            # (i.e., Dependabot already flagged that dependency/advisory).
            # Findings for vulnerabilities Semgrep alone surfaced are dropped
            # entirely, before any repository/commit/rule node is created.
            vuln_id = item.get("vulnerability_identifier")
            vuln_key = vuln_id.strip().replace(" ", "-") if vuln_id else None
            is_ghsa = bool(vuln_key and vuln_key.upper().startswith("GHSA"))
            is_cve = bool(vuln_key and vuln_key.upper().startswith("CVE"))
            already_known = (is_cve and cves.has(vuln_key)) or (is_ghsa and github_security_advisories.has(vuln_key))
            if not already_known:
                skipped_unknown_vuln += 1
                continue

            repo_info = item.get("repository", {})
            repo_name = canonical_repo_name(repo_info.get("name", "").replace("fcas/", ""))

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
            # A rule's reachability verdict is per finding instance (repo/commit),
            # not a fixed property of the rule definition: the same rule_id can be
            # `reachable` against one commit's usage and `unreachable` against
            # another's. The node key must therefore combine rule_id with commit_sha,
            # or a `overwrite_mode="replace"` reload silently collapses conflicting
            # verdicts into whichever finding was processed last.
            node_key = f"{rule_id}_{commit_sha}" if rule_id and commit_sha else rule_id

            if node_key:
                semgrep_rules.insert({"_key": node_key, "rule_id": rule_id, **rule, **item}, overwrite=True, overwrite_mode="replace")

                if commit_sha:
                    upsert_edge(semgrep_rules_commits, {
                        "_key": node_key,
                        "_from": f"{semgrep_rules.name}/{node_key}",
                        "_to": f"{commits.name}/{commit_sha}"
                    })

            dependency_name = item.get("found_dependency", {}).get("package")
            if dependency_name and not dependencies.has(dependency_name):
                dependencies.insert({"_key": dependency_name})

            if repo_name and dependency_name:
                upsert_edge(repositories_dependencies, {
                    "_key": f"{repo_name.replace('/', '_')}_{dependency_name}",
                    "_from": f"{repositories.name}/{repo_name}",
                    "_to": f"{dependencies.name}/{dependency_name}"
                })

            if node_key and is_cve:
                upsert_edge(semgrep_rules_cves, {
                    "_key": f"{node_key}_{vuln_key}",
                    "_from": f"{semgrep_rules.name}/{node_key}",
                    "_to": f"{cves.name}/{vuln_key}"
                })

                # Semgrep's own finding already embeds an EPSS (Exploit Prediction
                # Scoring System) score for the CVE it flags, fetched from FIRST.org
                # at scan time; reuse it directly on the CVE node itself instead of
                # querying FIRST.org's API again independently, since it is the same
                # underlying source and this avoids a second, possibly inconsistent
                # snapshot date.
                epss = item.get("epss_score")
                if epss and epss.get("score") is not None:
                    cves.update({
                        "_key": vuln_key,
                        "epss_score": epss.get("score"),
                        "epss_percentile": epss.get("percentile"),
                    })
            elif is_ghsa:
                # No semgrep_ghsa edge: a GHSA is not a first-class finding target here,
                # it is only the vehicle through which Dependabot already flagged this
                # dependency. The finding reaches the same CVE/CWE context Dependabot
                # sees by traversing the existing ghsa_cve/ghsa_cwe edges off that GHSA
                # (repo -> dependency -> gh_security_advisory -> ghsa is already wired via
                # the repositories_dependencies edge above), not via a direct rule->GHSA edge.
                ghsa_doc = github_security_advisories.get(vuln_key)
                if ghsa_doc:
                    cve_id = ghsa_doc.get("cve_id")
                    if cve_id and cves.has(cve_id):
                        upsert_edge(ghsa_cve, {
                            "_key": f"{vuln_key}_{cve_id}",
                            "_from": f"{github_security_advisories.name}/{vuln_key}",
                            "_to": f"{cves.name}/{cve_id}"
                        })

                    ghsa_cwes_raw = ghsa_doc.get("cwes")
                    if ghsa_cwes_raw:
                        try:
                            ghsa_cwe_list = ast.literal_eval(ghsa_cwes_raw) if isinstance(ghsa_cwes_raw, str) else ghsa_cwes_raw
                        except (ValueError, SyntaxError) as e:
                            logger.warning(f"Falha ao parsear cwes de {vuln_key}: {e}")
                            ghsa_cwe_list = []
                        for ghsa_cwe_entry in ghsa_cwe_list:
                            ghsa_cwe_id = ghsa_cwe_entry.get("cwe_id")
                            if ghsa_cwe_id and cwes.has(ghsa_cwe_id):
                                upsert_edge(ghsa_cwe, {
                                    "_key": f"{vuln_key}_{ghsa_cwe_id}",
                                    "_from": f"{github_security_advisories.name}/{vuln_key}",
                                    "_to": f"{cwes.name}/{ghsa_cwe_id}"
                                })

            cwe_names = rule.get("cwe_names", [])
            cwe_ids = []
            if cwe_names:
                for cwe_str in cwe_names:
                    cwe_id = cwe_str.split(":")[0].strip().upper()

                    # Semgrep's role in this study is reachability triage of vulnerabilities
                    # already identified by CodeQL/Dependabot, not an independent source of
                    # new CWEs: a CWE tag Semgrep references is only linked if it already
                    # exists in the graph (i.e., CodeQL/Dependabot already surfaced it via
                    # their own MITRE relationship expansion). A CWE Semgrep alone tags is
                    # dropped entirely, the same "already_known" gate applied to CVE/GHSA above.
                    if not cwes.has(cwe_id):
                        continue

                    cwe_ids.append(cwe_id)

                    if commit_sha:
                        upsert_edge(cwe_commits, {
                            "_key": f"{cwe_id}_{commit_sha}",
                            "_from": f"{cwes.name}/{cwe_id}",
                            "_to": f"{commits.name}/{commit_sha}"
                        })

                    if node_key:
                        upsert_edge(semgrep_rules_cwes, {
                            "_key": f"{node_key}_{cwe_id}",
                            "_from": f"{semgrep_rules.name}/{node_key}",
                            "_to": f"{cwes.name}/{cwe_id}"
                        })

            # Unlike CVE/GHSA/CWE, OWASP Top 10 categorization is not an independent
            # vulnerability-identity or weakness-classification claim cross-checked
            # against another catalog collected elsewhere (NVD, MITRE) — it is simply
            # metadata Semgrep's own rule carries, like its `severity`/`confidence`, so
            # it is not subject to the "already_known" gate applied to CVE/GHSA/CWE above.
            owasp_names = rule.get("owasp_names", [])
            owasp_ids = []
            if owasp_names:
                for owasp_str in owasp_names:
                    owasp_id, _, category = owasp_str.partition(" - ")
                    owasp_id = owasp_id.strip()
                    category = category.strip() or None
                    if not owasp_id:
                        continue
                    owasp_key = owasp_id.replace(":", "-")
                    year = owasp_id.split(":")[-1] if ":" in owasp_id else None
                    owasp_ids.append(owasp_key)

                    owasp.insert(
                        {"_key": owasp_key, "id": owasp_id, "year": year, "category": category},
                        overwrite=True, overwrite_mode="replace"
                    )

                    if node_key:
                        upsert_edge(semgrep_rules_owasp, {
                            "_key": f"{node_key}_{owasp_key}",
                            "_from": f"{semgrep_rules.name}/{node_key}",
                            "_to": f"{owasp.name}/{owasp_key}"
                        })

            if node_key:
                # `cwe_names` (raw "CWE-n: description" strings) is replaced by a
                # clean `cwe_ids` list; the description now lives on the `cwes`
                # node itself, reachable via the `semgrep_rules_cwes` edge, following
                # the same pattern as the rest of the CWE-linked collections.
                # `found_dependency` is likewise dropped from the embedded document:
                # its `package` now lives on the same `dependencies` node already shared
                # with Dependabot, reachable via the existing `repositories_dependencies`
                # edge, instead of being duplicated here. `owasp_names` (raw "Ann:year -
                # Category" strings) is replaced by a clean `owasp_ids` list, following
                # the same pattern, with year/category living on the `owasp` node itself.
                # `epss_score` is dropped the same way: it now lives on the `cves` node
                # itself, reachable via `semgrep_rules_cves`.
                semgrep_rules.update(
                    {
                        "_key": node_key,
                        "cwe_ids": cwe_ids,
                        "cwe_names": None,
                        "found_dependency": None,
                        "owasp_ids": owasp_ids,
                        "owasp_names": None,
                        "epss_score": None
                    },
                    keep_none=False
                )

        except Exception as e:
            logger.exception(f"Erro ao processar o finding ID {item.get('id')}: {e}")
            pass

    logger.info(f"{skipped_non_python} findings fora do ecossistema '{ALLOWED_ECOSYSTEM}' foram ignorados.")
    logger.info(f"{skipped_unknown_vuln} findings sem CVE/GHSA já conhecido (Dependabot/CodeQL) foram ignorados.")

if __name__ == '__main__':
    # Opcional: configurar log se for rodar standalone
    logging.basicConfig(level=logging.INFO)
    load_semgrep_data()