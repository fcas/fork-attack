from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.knowledge_graph.graph_codeql import load_codeql_data
from fork_attack.knowledge_graph.graph_dependabot import load_dependabot_data

if __name__ == '__main__':
    fa = ForkAttackGraph()
    load_dependabot_data()
    load_codeql_data()
    fa.client.close()