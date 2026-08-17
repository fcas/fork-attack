"""
Populates the graph from files already produced by the raw-data pipeline
(see fork_attack/scan.py for that stage: estige -> analysis -> scrap ->
time_machine), plus nvd_cpe.py, attack.py and capec.py, which must have
already been run to produce data/<today>/{nvd_cpes,attack,capec}.json --
this script only reads those files, it does not fetch them.

Load order matters:
  1. repositories -- no dependencies, just the 273-repo corpus.
  2. dependabot/codeql -- populate cves/cwes/github_security_advisories from
     this study's own scan results (date-filtered to the accepted window).
  3. cwe_levels -- attaches the MITRE CWE hierarchy + repos/libraries
     associations on top of the cwes/cves those scans populated.
  4. semgrep -- an independent detection source, can create its own
     cves/cwes/ghsa if a finding names one dependabot/codeql didn't surface.
  5. cpe/cve_metadata -- enriches the cves collection now that it's
     populated, from nvd_cpes.json (needs get_cve_ids() to see real data).
  6. capec -- static MITRE taxonomy, linked to the cwes this run found via
     cwe_capec edges; populates the capecs collection.
  7. attack -- reads capec.json again to find which ATT&CK techniques map
     to a CAPEC just ingested (capecs.has(...)), so it must run after capec,
     not before, or every technique looks irrelevant and nothing loads.
"""
from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.knowledge_graph.graph_repositories import load_repositories_data
from fork_attack.knowledge_graph.graph_dependabot import load_dependabot_data
from fork_attack.knowledge_graph.graph_codeql import load_codeql_data
from fork_attack.knowledge_graph.graph_cwe_levels import load_cwe_data, backfill_orphan_types
from fork_attack.knowledge_graph.graph_semgrep import load_semgrep_data
from fork_attack.knowledge_graph.graph_semgrep_sast import load_semgrep_sast_data
from fork_attack.knowledge_graph.graph_cpe import load_cpe_data
from fork_attack.knowledge_graph.graph_cve_metadata import load_cve_metadata
from fork_attack.knowledge_graph.graph_capec import load_capec_data
from fork_attack.knowledge_graph.graph_attack import load_attack_data


if __name__ == '__main__':
    fa = ForkAttackGraph()
    load_repositories_data()
    load_dependabot_data()
    load_codeql_data()
    load_cwe_data()
    load_semgrep_data()
    load_semgrep_sast_data()
    load_cpe_data()
    load_cve_metadata()
    load_capec_data()
    load_attack_data()
    # Sources loaded after load_cwe_data() (semgrep, capec, attack) can each
    # create their own bare CWE placeholder if they reference one dependabot/
    # codeql/scrap didn't already surface; load_cwe_data()'s own backfill
    # pass ran before any of those existed, so it must run again here to
    # catch orphans introduced downstream of it.
    backfill_orphan_types()
    fa.client.close()