import logging

from fork_attack.knowledge_graph.fork_attack_graph import ForkAttackGraph
from fork_attack.settings import repositories
from fork_attack.utils import canonical_repo_name

logger = logging.getLogger(__name__)

fa = ForkAttackGraph()

repositories_collection = fa.db.collection("repositories")


def load_repositories_data():
    for repo_url, branch, *_ in repositories:
        try:
            repo_name = canonical_repo_name(repo_url.replace("https://github.com/", "").split("/")[1])
            if not repositories_collection.has(repo_name):
                repositories_collection.insert({"_key": repo_name})
        except Exception as e:
            logger.exception(e)
            pass


if __name__ == '__main__':
    load_repositories_data()
