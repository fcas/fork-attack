import logging
import json
import re
import urllib.parse

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.utils import upsert_edge, canonical_repo_name, is_known_repo, extraction_date, has_provenance, add_source

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories = fa.db.collection("repositories")
commits = fa.db.collection("commits")
cwes = fa.db.collection("cwes")
semgrep_sast_rules = fa.db.collection("semgrep_sast_rules")

repositories_commits = fa.graph.edge_collection("repositories_commits")
cwe_commits = fa.graph.edge_collection("cwe_commits")
semgrep_sast_rules_commits = fa.graph.edge_collection("semgrep_sast_rules_commits")
semgrep_sast_rules_cwes = fa.graph.edge_collection("semgrep_sast_rules_cwes")

# Semgrep Code (SAST) is queried via the same findings endpoint used
# elsewhere in this study (issue_type=sast); this loader ingests every
# SAST finding retrieved, not just the hard-coded-secrets subset -- the
# "sources" field on each CWE node is what lets downstream queries
# separate that Semgrep-only signal from CodeQL/Dependabot's.
#
# Scope is bounded to (a) this study's actual scan window (2026-08-14
# through 2026-08-16, the same three-day window codeql_status_report.csv
# and dependabot_status_report.csv use to decide "in-range") -- Semgrep's
# findings endpoint returns a repository's entire finding history since it
# was forked, including stale entries from long before this corpus's
# actual re-scan (e.g. from the fork's initial creation scan), which would
# otherwise silently inflate every SAST count -- and (b) Python, the same
# ecosystem CodeQL's own workflow is scoped to (Section "Static Code
# Analysis Tools"): the findings endpoint returns every language Semgrep's
# generic and language-specific rules matched, including this corpus's
# incidental non-Python files (frontend toolchains, IaC, docs).
ALLOWED_STATE = "unresolved"
DATE_MIN = "2026-08-14"
DATE_MAX = "2026-08-16"


def in_scan_window(item):
    created = item.get("created_at", "")[:10]
    return DATE_MIN <= created <= DATE_MAX


def extract_commit_sha(url):
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


def normalize_cwe_id(raw):
    """Same int-cast normalization graph_codeql.py applies to GitHub's
    zero-padded `cwe-020` tags, defensively re-applied here even though
    Semgrep's own `cwe_names` (e.g. "CWE-798: ...") are not zero-padded --
    keeps both sources landing on the exact same `cwes` node key."""
    m = re.match(r"CWE-0*(\d+)", raw.strip().upper())
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def filter_findings(findings):
    """Applies every scope gate this loader enforces (state, known-repo,
    provenance, scan-window) and returns (kept, skip_counts). Used by both
    the dry-run counter and the real load, so the two can never disagree."""
    kept = []
    skipped = {"not_unresolved": 0, "unknown_repo": 0, "no_provenance": 0, "out_of_window": 0, "non_python": 0}
    for item in findings:
        if item.get("state") != ALLOWED_STATE:
            skipped["not_unresolved"] += 1
            continue

        repo_info = item.get("repository", {})
        repo_name_raw = repo_info.get("name", "").replace("fcas/", "")
        if not is_known_repo(repo_name_raw):
            skipped["unknown_repo"] += 1
            continue

        loc = item.get("location", {})
        loc_path = loc.get("file_path")
        repo_name = canonical_repo_name(repo_name_raw)
        if not has_provenance(repo_name, loc_path):
            skipped["no_provenance"] += 1
            continue

        if not in_scan_window(item):
            skipped["out_of_window"] += 1
            continue

        if not loc_path.endswith(".py"):
            skipped["non_python"] += 1
            continue

        kept.append(item)
    return kept, skipped


def dry_run_counts():
    """Reports how many NEW cwes/cves/semgrep_sast_rules/edges an actual
    load_semgrep_sast_data() run would insert, without writing anything, so
    the ingestion can be reviewed and confirmed before it touches the graph."""
    findings_path = f"data/{extraction_date()}/semgrep_sast_findings.json"
    with open(findings_path, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    kept, skipped = filter_findings(findings)

    new_repos, new_commits, new_rules, new_cwes = set(), set(), set(), set()
    new_repo_commit_edges, new_rule_commit_edges, new_cwe_commit_edges, new_rule_cwe_edges = set(), set(), set(), set()

    for item in kept:
        repo_name_raw = item.get("repository", {}).get("name", "").replace("fcas/", "")
        repo_name = canonical_repo_name(repo_name_raw)
        commit_sha = extract_commit_sha(item.get("line_of_code_url"))

        if not repositories.has(repo_name):
            new_repos.add(repo_name)
        if commit_sha and not commits.has(commit_sha):
            new_commits.add(commit_sha)
        if repo_name and commit_sha:
            key = f"{repo_name}_{commit_sha}"
            if not repositories_commits.has(key):
                new_repo_commit_edges.add(key)

        rule = item.get("rule", {})
        rule_id = rule.get("name") or item.get("rule_name")
        node_key = f"{rule_id}_{commit_sha}" if rule_id and commit_sha else rule_id
        if node_key and not semgrep_sast_rules.has(node_key):
            new_rules.add(node_key)
        if node_key and commit_sha and not semgrep_sast_rules_commits.has(node_key):
            new_rule_commit_edges.add(node_key)

        for cwe_str in rule.get("cwe_names", []) or []:
            cwe_id = normalize_cwe_id(cwe_str.split(":")[0])
            if not cwe_id:
                continue
            if not cwes.has(cwe_id):
                new_cwes.add(cwe_id)
            if commit_sha:
                ck = f"{cwe_id}_{commit_sha}"
                if not cwe_commits.has(ck):
                    new_cwe_commit_edges.add(ck)
            if node_key:
                rk = f"{node_key}_{cwe_id}"
                if not semgrep_sast_rules_cwes.has(rk):
                    new_rule_cwe_edges.add(rk)

    print(f"Raw findings: {len(findings)}")
    print(f"Skipped: {skipped}")
    print(f"Findings that would be ingested: {len(kept)}")
    print(f"New repositories nodes: {len(new_repos)}")
    print(f"New commits nodes: {len(new_commits)}")
    print(f"New semgrep_sast_rules nodes: {len(new_rules)}")
    print(f"New cwes nodes: {len(new_cwes)} -> {sorted(new_cwes)}")
    print(f"New repositories_commits edges: {len(new_repo_commit_edges)}")
    print(f"New semgrep_sast_rules_commits edges: {len(new_rule_commit_edges)}")
    print(f"New cwe_commits edges: {len(new_cwe_commit_edges)}")
    print(f"New semgrep_sast_rules_cwes edges: {len(new_rule_cwe_edges)}")
    return {
        "kept": len(kept), "skipped": skipped,
        "new_repos": len(new_repos), "new_commits": len(new_commits),
        "new_rules": len(new_rules), "new_cwes": len(new_cwes),
    }


def load_semgrep_sast_data():
    findings_path = f"data/{extraction_date()}/semgrep_sast_findings.json"
    try:
        with open(findings_path, 'r', encoding='utf-8') as f:
            findings = json.load(f)
    except FileNotFoundError:
        logger.error(f"Arquivo {findings_path} não encontrado.")
        return

    logger.info(f"Processando {len(findings)} findings SAST do Semgrep...")

    kept, skipped = filter_findings(findings)

    for item in kept:
        try:
            repo_info = item.get("repository", {})
            repo_name_raw = repo_info.get("name", "").replace("fcas/", "")
            loc = item.get("location", {})
            loc_path = loc.get("file_path")
            repo_name = canonical_repo_name(repo_name_raw)

            if not repositories.has(repo_name):
                repositories.insert({"_key": repo_name})

            commit_sha = extract_commit_sha(item.get("line_of_code_url"))
            if commit_sha and not commits.has(commit_sha):
                commits.insert({"_key": commit_sha})

            if repo_name and commit_sha:
                upsert_edge(repositories_commits, {
                    "_key": f"{repo_name}_{commit_sha}",
                    "_from": f"{repositories.name}/{repo_name}",
                    "_to": f"{commits.name}/{commit_sha}"
                })

            rule = item.get("rule", {})
            rule_id = rule.get("name") or item.get("rule_name")
            node_key = f"{rule_id}_{commit_sha}" if rule_id and commit_sha else rule_id

            if node_key:
                semgrep_sast_rules.insert({
                    "_key": node_key,
                    "rule_id": rule_id,
                    "message": rule.get("message"),
                    "confidence": item.get("confidence"),
                    "category": rule.get("category"),
                    "subcategories": rule.get("subcategories"),
                    "vulnerability_classes": rule.get("vulnerability_classes"),
                    "severity": item.get("severity"),
                    "state": item.get("state"),
                    "repo_name": repo_name,
                }, overwrite=True, overwrite_mode="replace")

                if commit_sha:
                    upsert_edge(semgrep_sast_rules_commits, {
                        "_key": node_key,
                        "_from": f"{semgrep_sast_rules.name}/{node_key}",
                        "_to": f"{commits.name}/{commit_sha}"
                    })

            for cwe_str in rule.get("cwe_names", []) or []:
                cwe_id = normalize_cwe_id(cwe_str.split(":")[0])
                if not cwe_id:
                    continue

                if not cwes.has(cwe_id):
                    cwes.insert({"_key": cwe_id})
                add_source(fa.db, "cwes", cwe_id, "semgrep sast")

                if commit_sha:
                    upsert_edge(cwe_commits, {
                        "_key": f"{cwe_id}_{commit_sha}",
                        "_from": f"{cwes.name}/{cwe_id}",
                        "_to": f"{commits.name}/{commit_sha}"
                    })

                if node_key:
                    upsert_edge(semgrep_sast_rules_cwes, {
                        "_key": f"{node_key}_{cwe_id}",
                        "_from": f"{semgrep_sast_rules.name}/{node_key}",
                        "_to": f"{cwes.name}/{cwe_id}"
                    })

        except Exception as e:
            logger.exception(f"Erro ao processar SAST finding ID {item.get('id')}: {e}")
            pass

    logger.info(f"{skipped['not_unresolved']} findings com state != 'unresolved' foram ignorados.")
    logger.info(f"{skipped['unknown_repo']} findings de repos fora do corpus de 273 foram ignorados.")
    logger.info(f"{skipped['no_provenance']} findings sem provenance (arquivo não existe no HEAD atual) foram ignorados.")
    logger.info(f"{skipped['out_of_window']} findings fora da janela de scan ({DATE_MIN}..{DATE_MAX}) foram ignorados.")
    logger.info(f"{skipped['non_python']} findings fora do ecossistema Python (extensão != .py) foram ignorados.")


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    if "--dry-run" in sys.argv:
        dry_run_counts()
    else:
        load_semgrep_sast_data()
