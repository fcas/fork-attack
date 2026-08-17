# Fork-Attack: Análise de Vulnerabilidades em Bibliotecas de ML

![alt text](resources/logo.jpeg)

**Ferramenta para detecção de falhas de segurança em bibliotecas de aprendizado de máquina (ML)**

## 📌 Visão Geral
Este projeto visa **identificar e analisar vulnerabilidades** em bibliotecas populares de *Machine Learning* (ML), fornecendo:
- Um **conjunto de dados** de vulnerabilidades e falhas e suas correlações.
- **Scripts automatizados** para verificação de dependências inseguras.
- **Relatórios de segurança** baseados em CWE e CVEs.

O objetivo é **ajudar pesquisadores e desenvolvedores** a avaliar riscos em seus projetos e contribuir para um ecossistema de ML mais seguro.

---  
## 🔧 Funcionalidades
✔ **Análise estática de código** (SAST) para detectar vulnerabilidades e falhas comuns, usando Dependabot e CodeQL.  
✔ **Verificação de dependências** desatualizadas ou com falhas conhecidas (CVE e CWE).  
✔ **Geração de relatórios** em CSV. 

---  
## 🚀 Como Usar

### Pré-requisitos
- Python 3.9+
- `pip` (gerenciador de pacotes)
- Variáveis de ambiente: `GITHUB_TOKEN` (token com acesso aos forks) e `GITHUB_OWNER` (usuário/organização dona dos forks analisados, nunca commitado no repositório por questões de double-blind review).

### Instalação
```bash
git clone https://github.com/<>/fork-attack.git
cd fork-attack
poetry install
poetry run python fork_attack/scan.py

# HELP
poetry run python fork_attack/scan.py --help
```

---
## Project Structure / File Reference

### Raw-data pipeline (`fork_attack/`)

Run in this order by `scan.py`'s `main()`:

- **`estige.py`** — forks every repo in `settings.py`, configures Dependabot/CodeQL/Semgrep on each fork, and collects their raw findings into `data/<date>/code_analysis_result.csv` (CodeQL) and `data/<date>/dependabot_result.csv` (Dependabot).
- **`reachability.py`** — fetches Semgrep's own findings via its API (`fetch_and_save_findings` for Supply Chain/`issue_type=sca`, `fetch_and_save_sast_findings` for Code/`issue_type=sast`) into `data/<date>/semgrep_findings.json` and `semgrep_sast_findings.json`. Runs outside GitHub Actions, so `scan.py` calls it explicitly between `estige_run()` and `analysis_run()`.
- **`analysis.py`** — summarizes the raw CodeQL/Dependabot CSVs by severity and by CWE/CVE id, producing `code_analysis_severity.csv`, `code_analysis_cwe_{level}.csv`, `dependabot_severity.csv`, `dependabot_cve_{level}.csv`, and repo-level breakdowns. Must run from inside `fork_attack/` (uses `../data/<date>/...` relative paths and a bare `from utils import ...`).
- **`scrap.py`** — for every unique CWE id surfaced by `analysis.py`'s per-level CSVs, scrapes that CWE's MITRE definitions page (`cwe.mitre.org/data/definitions/<id>.html`) for its ChildOf/MemberOf/etc. relations, tagging each with the anchor CWE's occurrence count. Outputs `cwe_definitions.csv`/`cve_definitions.csv` (per-relation rows) and `cwe_definitions_agg.csv`/`cve_definitions_agg.csv`/`all_definitions_agg.csv` (summed by type/id/description — no repo/library detail). Also runs from inside `fork_attack/`.
- **`time_machine.py`** — enriches `cwe_definitions.csv`/`cve_definitions.csv` with `libraries`/`repos` columns (which repos/libraries triggered each anchor CWE), producing `cwe_definitions_lib.csv`/`cve_definitions_lib.csv` (these two are what `graph_cwe_levels.py` actually loads into the graph) and their aggregated counterparts `cwe_definitions_lib_agg.csv`/`cve_definitions_lib_agg.csv`/`all_definitions_agg_libs.csv` (the CVE+CWE-combined file — the ground truth for this study's Pillar/Category/Class/Base/Variant/View tables).
- **`scan.py`** — orchestrates the four scripts above in order (estige → reachability → analysis → scrap → time_machine) via `typer`.

### Knowledge graph (`fork_attack/knowledge_graph/`)

- **`fork_attack_graph.py`** — `ForkAttackGraph` singleton: connects to ArangoDB, declares/creates every vertex and edge collection this study's ontology needs.
- **`load.py`** — orchestrates every `graph_*.py` loader below in dependency order, then a final `backfill_orphan_types()` pass. The authoritative entry point for (re)populating the graph from the CSVs/JSONs above.
- **`graph_repositories.py`** — loads the 273-repo corpus as `repositories` nodes.
- **`graph_dependabot.py`** — loads Dependabot alerts (`pip`-ecosystem, `state==open`, `has_lastro`-filtered) into `cves`/`cwes`/`github_security_advisories`/`dependencies`, tagging each CVE/CWE's `sources` with `"dependabot"`.
- **`graph_codeql.py`** — loads CodeQL alerts (`python`-language, own workflow, `state==open`, `has_lastro`-filtered) into `codeql_rules`/`cwes`, tagging each CWE's `sources` with `"codeql"`.
- **`graph_cwe_levels.py`** — loads `cwe_definitions_lib.csv`/`cve_definitions_lib.csv` into the CWE hierarchy edges (`cwe_pillars`/`_categories`/`_classes`/`_bases`/`_variants`/`_views`/`_composites`/`_chains`); `backfill_orphan_types()` live-scrapes MITRE for any CWE that ended up without a `type` (e.g., one only a later loader introduced).
- **`graph_semgrep.py`** — loads Semgrep Supply Chain findings (`pypi`-ecosystem-filtered) into `semgrep_rules`, tagging CVEs/CWEs `sources` with `"semgrep ssc"`; treated as a first-class detection source (creates bare CVE/CWE/GHSA nodes if not already present).
- **`graph_semgrep_sast.py`** — loads Semgrep Code (SAST) findings, filtered to `state==unresolved`, `has_lastro`, and `.py`-file-extension (the only reliable Python-ecosystem gate — Semgrep's `generic.*` rules aren't language-scoped by rule name), into `semgrep_sast_rules`, tagging CWEs' `sources` with `"semgrep sast"`. Used narrowly for hard-coded-credential detection (Section "Semgrep SAST Findings" of the paper).
- **`graph_cpe.py`** / **`graph_cve_metadata.py`** — enrich `cves`/`cpes` from the NVD API (CVSS, EPSS, CPE bindings).
- **`graph_capec.py`** / **`graph_attack.py`** — load MITRE CAPEC attack patterns and ATT&CK techniques, linking them to the CWEs/CAPECs already in the graph.
- **`migrate_semgrep_edges.py`** — one-off migration script (not part of the regular pipeline).

### Utilities and one-off scripts

- **`utils.py`** — shared helpers: `extraction_date()`/`analysis_date_range()` (date-window logic), `is_known_repo()`/`KNOWN_REPOS` (273-repo corpus allowlist), `has_lastro()` (verifies a finding's file path still exists at the repo's current HEAD), `upsert_edge()`, `add_source()` (appends a tool name to a CVE/CWE's `sources` array), `normalize_tag()`, `row_to_json()`.
- **`settings.py`** — the corpus definition: the 273 `(github_url, ...)` tuples every other script iterates over.
- **`singleton.py`** — the `Singleton` metaclass `ForkAttackGraph` uses.
- **`nvd_cpe.py`** — fetches NVD CPE data into `data/<date>/nvd_cpes.json`.
- **`sync_forks.py`** — re-syncs a fork with its upstream (handles the `.github` overwrite/branch-rename logic described in the paper's "Upstream Synchronization" subsection).
- **`trigger_scans.py`** / **`wait_for_scans.py`** — dispatch and poll GitHub Actions runs (CodeQL/Dependabot) across the corpus.
- **`overnight.py`** — long-running batch driver for overnight corpus-wide operations.
- **`locki.py`** — lockfile/concurrency helper.
- **`deps_count.py`** / **`collection_counts.py`** — ad-hoc counting scripts (dependency counts, graph collection sizes) used for sanity-checking during analysis, not part of the regular pipeline.
- **`scripts/`** — operational one-offs: `run_extraction.py` (kick off a fresh estige run), `fetch_codeql_runs.py`/`fetch_semgrep_runs.py`/`fetch_runs_range.py`/`check_latest_runs.py` (GitHub Actions run-status queries), `rebuild_combined_csvs.py` (re-merge per-repo JSONs into the combined CSVs), `revert_to_daily.py` (undo a synthetic-manifest/day-symlink experiment), `reforce_cron.py` (re-arm scheduled workflows), `run_nvd_cpe.py` (standalone NVD CPE fetch), `verify_lastro.py` (audit `has_lastro` failures across the corpus).