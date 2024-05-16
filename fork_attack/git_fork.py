import logging
import os
from pathlib import Path

import git
from github import Github

from settings import repositories

logger = logging.getLogger()

current_path = Path(os.path.dirname(os.path.realpath(__file__)))
path = current_path.parent
os.chdir(path)
token = os.getenv("GITHUB_TOKEN")
g = Github(token)
user = g.get_user()


def fork_all():
    for repo_config in repositories:
        repo_str = repo_config[0]
        branch = repo_config[1]
        url = repo_str.replace("https://github.com/", "").split("/")
        org = g.get_organization(url[0])
        repo = org.get_repo(url[1])
        user.create_fork(repo)
        try:
            repo_to_clone = f"https://github.com/{user.login}/{repo.name}.git"
            path_to_clone = os.path.join(path, str(repo.name))
            if not os.path.isdir(path_to_clone):
                local_repo = git.Repo.clone_from(repo_to_clone, path_to_clone, branch=branch)
                git.Repo.create_remote(local_repo, "upstream", f"https://github.com/{url[0]}/{url[1]}.git")
        except Exception as e:
            logger.error(e)
