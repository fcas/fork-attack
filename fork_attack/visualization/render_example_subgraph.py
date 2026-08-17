"""Renders a small worked-example subgraph (one repository/commit with
CodeQL, Semgrep SSC, and Semgrep SAST findings converging on it) in the same
Graphviz style as the article's `images/ckg_example_*.png` figure.

This is a fixed, hand-picked example (currently: mlflow's commit
bb95dc1879b2cf5a4f2488137c9f4cac778ad9b9), not a generic renderer -- when a
node in the example goes stale (e.g. a finding drops out of scope after an
ingestion-scope change), edit NODES/EDGES below to point at a still-live
replacement instead of trying to parametrize this fully.

Usage:
    cd fork-attack && ARANGO_USERNAME=root ARANGO_PASSWORD=<pw> \
        .venv/bin/python3 -m fork_attack.visualization.render_example_subgraph \
        [output_path_without_extension]
"""
import sys

import graphviz

REPO = "mlflow"
COMMIT_LABEL = "bb95dc18\n(COMMIT)"

# (node_id, label, fillcolor, fontcolor, shape)
NODES = [
    ("repo", f"{REPO}\n(REPOSITORY)", "#8B0000", "white", "box"),
    ("commit", COMMIT_LABEL, "#222222", "white", "box"),
    ("cwe22", "CWE-22\nImproper Limitation of a Pathname\nto a Restricted Directory\n('Path Traversal')", "#4A78B0", "white", "box"),
    ("cwe23", "CWE-23\nRelative Path Traversal", "#4A78B0", "white", "box"),
    ("capec126", "CAPEC-126\nPath Traversal\n(High likelihood)", "#2E8B57", "white", "box"),
    ("ssc_rule", "ssc-parity-def5f738\n(SEMGREP_SSC_RULE)\nno reachability analysis", "#8B8B00", "white", "box"),
    ("ghsa", "GHSA-2cm6-r77w-6g96\n(GITHUB_SECURITY_ADVISORY)", "#F39C12", "white", "box"),
    ("sast_rule", "python-pyjwt-\nhardcoded-secret\n(SEMGREP_SAST_RULE)\nseverity: medium", "#1AA6A0", "white", "box"),
    ("cwe798", "CWE-798\nUse of Hard-coded\nCredentials", "#4A78B0", "white", "box"),
    ("owasp_a01_2025", "A01:2025\nBroken Access Control\n(OWASP)", "#B8860B", "white", "box"),
    ("owasp_a05_2017", "A05:2017\nBroken Access Control\n(OWASP)", "#B8860B", "white", "box"),
    ("owasp_a06_2021", "A06:2021\nVulnerable and Outdated\nComponents (OWASP)", "#B8860B", "white", "box"),
    ("owasp_a01_2021", "A01:2021\nBroken Access Control\n(OWASP)", "#B8860B", "white", "box"),
    ("capec19", "CAPEC-19\nEmbedding Scripts within Scripts\n(High likelihood)", "#2E8B57", "white", "box"),
    ("t1027", "T1027.009\nEmbedded Payloads\n(ATT&CK)", "#E07B1A", "white", "box"),
    ("cwe284", "CWE-284\nImproper Access Control\n(Pillar)", "#4A78B0", "white", "box"),
    ("cpe", "cpe:2.3:a:lfprojects:mlflow:*\n(CPE)", "#8E44AD", "white", "box"),
]

CVE_TABLE = """<
<table border="1" cellborder="1" cellspacing="0">
<tr><td bgcolor="#C0392B"><font color="white"><b>CVE-2026-8147</b></font></td></tr>
<tr><td>cvss_version</td></tr>
<tr><td>3.0</td></tr>
<tr><td>base_score</td></tr>
<tr><td>8.1 (HIGH)</td></tr>
<tr><td>attack_vector</td></tr>
<tr><td>Network</td></tr>
<tr><td>epss_score</td></tr>
<tr><td>0.00376</td></tr>
<tr><td>epss_percentile</td></tr>
<tr><td>0.30757</td></tr>
</table>>"""

EDGES = [
    ("repo", "commit", "repositories_commits"),
    ("cwe22", "commit", "cwe_commits"),
    ("cwe23", "commit", "cwe_commits"),
    ("capec126", "cwe22", "cwe_capec"),
    ("ssc_rule", "commit", "semgrep_rules_commits"),
    ("ssc_rule", "cve", "semgrep_rules_cves"),
    ("ssc_rule", "owasp_a01_2025", "semgrep_rules_owasp"),
    ("ssc_rule", "owasp_a05_2017", "semgrep_rules_owasp"),
    ("ssc_rule", "owasp_a06_2021", "semgrep_rules_owasp"),
    ("ssc_rule", "owasp_a01_2021", "semgrep_rules_owasp"),
    ("ssc_rule", "cwe284", "semgrep_rules_cwes"),
    ("ghsa", "cve", "ghsa_cve"),
    ("sast_rule", "commit", "semgrep_sast_rules_commits"),
    ("sast_rule", "cwe798", "semgrep_sast_rules_cwes"),
    ("capec19", "t1027", "capec_attack"),
    ("capec19", "cwe284", "cwe_capec"),
    ("cve", "cwe284", "cve_cwe"),
    ("cve", "cpe", "cve_cpe"),
]


def render(output_base):
    dot = graphviz.Digraph("ckg_example", format="png")
    dot.attr(rankdir="TB", dpi="300", fontsize="11",
              label=f"Cybersecurity knowledge graph example for repository `{REPO}`: "
                    f"CodeQL (CWE-22/23), Semgrep SSC (CVE-2026-8147), and Semgrep SAST (CWE-798) findings sharing the same commit",
              labelloc="t")
    dot.attr("node", style="filled,rounded", fontname="Helvetica", fontsize="11")
    dot.attr("edge", fontname="Helvetica", fontsize="9")

    for node_id, label, fill, font, shape in NODES:
        dot.node(node_id, label=label, fillcolor=fill, fontcolor=font, shape=shape)
    dot.node("cve", label=CVE_TABLE, shape="plain")

    for src, dst, label in EDGES:
        dot.edge(src, dst, label=label)

    dot.render(output_base, cleanup=True)
    print(f"saved {output_base}.png")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ckg_example_mlflow"
    render(out)
