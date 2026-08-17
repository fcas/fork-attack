"""Renders the full cybersecurity knowledge graph as a force-directed layout
(nodes colored by collection, legend, node/edge count header), matching the
style used for the article's `images/ckg_full_graph_v*.png` figure. Re-run
this any time the graph's node/edge counts change enough to warrant a fresh
figure (e.g. after a source's ingestion scope changes).

Usage:
    cd fork-attack && ARANGO_USERNAME=root ARANGO_PASSWORD=<pw> \
        .venv/bin/python3 -m fork_attack.visualization.render_full_graph \
        [output_path]
"""
import sys

import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph

COLLECTIONS = [
    ("repositories", "repositories", "#8B0000"),
    ("commits", "commits", "#111111"),
    ("dependencies", "dependencies", "#8B8B00"),
    ("cwes", "cwes", "#6699CC"),
    ("cves", "cves", "#E31C6E"),
    ("cpes", "cpes", "#8E44AD"),
    ("capecs", "capecs", "#2E8B57"),
    ("github_security_advisories", "github security advisories", "#F39C12"),
    ("codeql_rules", "codeql rules", "#8B5A2B"),
    ("semgrep_rules", "semgrep rules (SSC)", "#1A8A7A"),
    ("semgrep_sast_rules", "semgrep sast rules", "#33CFEA"),
    ("attack_techniques", "attack techniques", "#FF33CC"),
    ("owasp", "owasp", "#1B2A6B"),
]

EDGE_COLLECTIONS = [
    "repositories_commits", "codeql_rules_commits", "cwe_commits", "cve_cwe", "cve_cpe",
    "cwe_capec", "capec_capec", "capec_attack", "semgrep_rules_cwes", "semgrep_rules_cves",
    "semgrep_rules_owasp", "ghsa_cwe", "ghsa_cve", "gh_security_advisory",
    "repositories_dependencies", "cwe_pillars", "cwe_categories", "cwe_classes",
    "cwe_variants", "cwe_bases", "cwe_views", "cwe_composites", "cwe_chains",
    "semgrep_rules_commits", "semgrep_sast_rules_commits", "semgrep_sast_rules_cwes",
]


def render(output_path):
    fa = ForkAttackGraph()
    db = fa.db

    G = nx.Graph()
    node_colors = {}
    legend_entries = []

    total_nodes = 0
    for col, label, color in COLLECTIONS:
        keys = list(db.aql.execute(f"FOR d IN {col} RETURN d._id"))
        for k in keys:
            G.add_node(k)
            node_colors[k] = color
        total_nodes += len(keys)
        legend_entries.append((label, color))

    total_edges = 0
    for ec in EDGE_COLLECTIONS:
        edges = list(db.aql.execute(f"FOR e IN {ec} RETURN [e._from, e._to]"))
        for a, b in edges:
            if a in node_colors and b in node_colors:
                G.add_edge(a, b)
        total_edges += len(edges)

    pos = nx.spring_layout(G, seed=42, iterations=30)

    fig, ax = plt.subplots(figsize=(20, 20), dpi=300)
    colors = [node_colors[n] for n in G.nodes()]
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#cccccc", width=0.2, alpha=0.4)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=8, linewidths=0)

    # G is a simple (undirected, non-multi) graph, so G.number_of_edges() is
    # the deduplicated distinct-node-pair count -- lower than total_edges
    # (the raw sum of edge documents across collections) whenever two nodes
    # are connected by more than one edge document (e.g. a CWE and a commit
    # linked by both a CodeQL and a Semgrep finding). This figure reports
    # the deduplicated count, consistent with its use elsewhere in the paper.
    dedup_edges = G.number_of_edges()
    ax.set_title("Cybersecurity Knowledge Graph -- 273 AI Library Repositories", fontsize=18, pad=30)
    fig.text(0.5, 0.965, f"{total_nodes:,} nodes / {dedup_edges:,} edges",
              ha="center", fontsize=13, color="#444444")

    legend_handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=c, markersize=10, label=l)
                       for l, c in legend_entries]
    ax.legend(handles=legend_handles, loc="upper right", ncol=2, fontsize=11, frameon=True)

    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    print(f"saved {output_path}: {total_nodes} nodes, {total_edges} raw edges, {dedup_edges} deduplicated edges")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ckg_full_graph.png"
    render(out)
