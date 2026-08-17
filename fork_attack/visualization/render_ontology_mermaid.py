"""Renders the CKG entity-relationship ontology diagram (13 node classes, 26
relation types) as a Mermaid classDiagram, and exports PNG/SVG via
mermaid-cli (mmdc, run through `npx` -- no global install required).

This is a static description of the schema (field lists, edge labels), not
derived live from the graph -- update NODES/EDGES below if the schema itself
changes (a new collection or edge type).

Usage:
    cd fork-attack && .venv/bin/python3 \
        -m fork_attack.visualization.render_ontology_mermaid [output_base]
    # writes <output_base>.png and <output_base>.svg (requires `npx`/Node.js)
"""
import subprocess
import sys

# (node_id, LABEL, fields) -- fields are the FULL top-level attribute set
# observed on every document in the corresponding collection (nested paths,
# e.g. cvss.score/cvss.vector_string, are collapsed to their parent key,
# e.g. cvss, once), obtained by unioning ATTRIBUTES(d) across all documents
# in each collection live -- not a curated subset. Re-derive if the schema
# changes: `FOR d IN <col> RETURN d` in every collection, union the keys.
NODES = [
    ("repository", "REPOSITORY", ["_key (repo name)"]),
    ("commit", "COMMIT", ["_key (sha)", "analysis_key", "category", "classifications",
                            "commit_sha", "environment", "location", "message", "ref", "state"]),
    ("dependency", "DEPENDENCY", ["_key (package name)"]),
    ("cve", "CVE", ["_key (CVE id)", "cvss", "epss_percentile", "epss_score",
                     "last_modified", "published", "references", "sources",
                     "vuln_status", "weaknesses"]),
    ("cwe", "CWE", ["_key (CWE id)", "cwe_id", "description", "name", "nature",
                     "sources", "type"]),
    ("cpe", "CPE", ["_key (CPE URI)", "criteria", "matchCriteriaId",
                     "versionEndExcluding", "versionStartIncluding"]),
    ("capec", "CAPEC", ["_key (CAPEC id)", "abstraction", "description",
                         "likelihood_of_attack", "name", "status", "typical_severity"]),
    ("attack", "ATTACK_TECHNIQUE", ["_key (technique id)", "description",
                                      "is_subtechnique", "name", "platforms", "tactics"]),
    ("ghsa", "GITHUB_SECURITY_ADVISORY", ["_key (GHSA id)", "classification", "cve_id",
                                            "cvss", "cvss_severities", "cwes", "description",
                                            "epss", "first_patched_version", "ghsa_id",
                                            "identifiers", "package", "published_at",
                                            "references", "severity", "summary", "updated_at",
                                            "vulnerabilities", "vulnerable_version_range",
                                            "withdrawn_at"]),
    ("owasp", "OWASP", ["_key", "category", "id", "year"]),
    ("ssc_rule", "SEMGREP_SSC_RULE", ["_key (rule_commit)", "categories", "category",
                                        "confidence", "created_at", "cwe_ids",
                                        "external_ticket", "first_seen_scan_id",
                                        "fix_recommendations", "id", "is_malicious",
                                        "line_of_code_url", "location", "match_based_id",
                                        "message", "name", "owasp_ids", "reachability",
                                        "reachable_condition", "ref", "relevant_since",
                                        "repository", "review_comments", "rule", "rule_id",
                                        "rule_message", "rule_name", "severity", "state",
                                        "state_updated_at", "status", "subcategories",
                                        "syntactic_id", "triage_state", "usage",
                                        "vulnerability_classes", "vulnerability_identifier"]),
    ("sast_rule", "SEMGREP_SAST_RULE", ["_key (rule_commit)", "category", "confidence",
                                          "message", "repo_name", "rule_id", "severity",
                                          "state", "subcategories", "vulnerability_classes"]),
    ("codeql_rule", "CODEQL_RULE", ["_key (rule id)", "description", "full_description",
                                      "help", "help_uri", "id", "name",
                                      "security_severity_level", "severity", "tags"]),
]

# (src, dst, label, hierarchical?) -- directions verified live against the
# graph's own edge documents (_from/_to): cwe_capec is CAPEC -> CWE, and
# capec_capec (CAPEC's own attack-pattern hierarchy) is the 9th hierarchical
# relation, not cwe_capec.
EDGES = [
    ("repository", "commit", "repositories_commits", False),
    ("repository", "dependency", "repositories_dependencies", False),
    ("dependency", "ghsa", "gh_security_advisory", False),
    ("ghsa", "cve", "ghsa_cve", False),
    ("ghsa", "cwe", "ghsa_cwe", False),
    ("cve", "cpe", "cve_cpe", False),
    ("cve", "cwe", "cve_cwe", False),
    ("cwe", "commit", "cwe_commits", False),
    ("capec", "cwe", "cwe_capec", False),
    ("codeql_rule", "commit", "codeql_rules_commits", False),
    ("ssc_rule", "commit", "semgrep_rules_commits", False),
    ("ssc_rule", "cve", "semgrep_rules_cves", False),
    ("ssc_rule", "cwe", "semgrep_rules_cwes", False),
    ("ssc_rule", "owasp", "semgrep_rules_owasp", False),
    ("sast_rule", "commit", "semgrep_sast_rules_commits", False),
    ("sast_rule", "cwe", "semgrep_sast_rules_cwes", False),
    ("capec", "capec", "capec_capec", True),
    ("capec", "attack", "capec_attack", False),
    ("cwe", "cwe", "cwe_pillars", True),
    ("cwe", "cwe", "cwe_categories", True),
    ("cwe", "cwe", "cwe_classes", True),
    ("cwe", "cwe", "cwe_bases", True),
    ("cwe", "cwe", "cwe_variants", True),
    ("cwe", "cwe", "cwe_views", True),
    ("cwe", "cwe", "cwe_composites", True),
    ("cwe", "cwe", "cwe_chains", True),
]

N_STRUCTURAL = sum(1 for *_, h in EDGES if not h)
N_HIERARCHICAL = sum(1 for *_, h in EDGES if h)

NODE_CLASS_STYLE = "fill:#DCE6F1,stroke:#1F3864,stroke-width:1px,color:#000"


def build_mmd():
    title = (f"Cybersecurity Knowledge Graph Ontology -- {len(NODES)} node classes, "
             f"{len(EDGES)} relation types ({N_STRUCTURAL} structural + {N_HIERARCHICAL} hierarchical)")
    init_config = (
        '%%{init: {"theme": "neutral", "themeVariables": '
        '{"fontSize": "22px", "primaryTextColor": "#000"}, '
        '"classDiagram": {"nodeSpacing": 90, "rankSpacing": 90, "diagramPadding": 30}} }%%'
    )
    lines = [f"---\ntitle: {title}\n---", init_config, "classDiagram", "direction LR"]
    lines.append('note "Every relation (edge) below also carries its own _key, _from, and _to '
                  'identifiers, omitted per-edge here for readability"')

    for node_id, label, fields in NODES:
        lines.append(f"class {node_id}[\"{label}\"] {{")
        for f in fields:
            # Mermaid classDiagram treats "name(...)" as a method signature;
            # rewrite "_key (CVE id)" style annotations to "_key : CVE id"
            # so they render as plain attributes instead.
            safe = f.replace(" (", ": ").replace(")", "").replace(" ", " ")
            lines.append(f"  +{safe}")
        lines.append("}")
        lines.append(f"cssClass \"{node_id}\" ckgNode")

    # The 8 CWE-internal hierarchy edges collapse into one note attached to
    # CWE; capec_capec (CAPEC's own attack-pattern hierarchy) is the 9th
    # hierarchical relation, drawn as a real self-loop on CAPEC below.
    n_cwe_hier = sum(1 for src, dst, _l, h in EDGES if h and src == "cwe" and dst == "cwe")
    lines.append(f'note for cwe "{n_cwe_hier} hierarchical CWE relations: Pillar/Category/Class/Base/Variant/View/Composite/Chain"')

    for src, dst, label, hierarchical in EDGES:
        if hierarchical:
            if label == "capec_capec":
                lines.append(f"{src} --|> {dst} : {label}")
            continue
        lines.append(f"{src} --|> {dst} : {label}")

    lines.append(f"classDef ckgNode {NODE_CLASS_STYLE}")
    return "\n".join(lines)


def render(output_base):
    mmd_path = f"{output_base}.mmd"
    with open(mmd_path, "w") as f:
        f.write(build_mmd())

    title = (f"Cybersecurity Knowledge Graph Ontology -- {len(NODES)} node classes, "
             f"{len(EDGES)} relation types ({N_STRUCTURAL} structural + {N_HIERARCHICAL} hierarchical)")

    for fmt in ("png", "svg"):
        out_path = f"{output_base}.{fmt}"
        subprocess.run(
            ["npx", "-y", "@mermaid-js/mermaid-cli", "-i", mmd_path, "-o", out_path,
             "-b", "white", "-w", "3600", "-s", "3", "-t", "neutral"],
            check=True,
        )
    print(f"saved {output_base}.png and {output_base}.svg (from {mmd_path}); title: {title}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ckg_ontology"
    render(out)
