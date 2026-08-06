from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.knowledge_graph.graph_codeql import load_codeql_data
from fork_attack.knowledge_graph.graph_cwe_levels import load_cwe_data
from fork_attack.knowledge_graph.graph_semgrep import load_semgrep_data
from fork_attack.knowledge_graph.graph_dependabot import load_dependabot_data
from fork_attack.knowledge_graph.graph_repositories import load_repositories_data


if __name__ == '__main__':
    fa = ForkAttackGraph()
    load_repositories_data()
    load_dependabot_data()
    load_codeql_data()
    load_cwe_data()
    load_semgrep_data()
    fa.client.close()