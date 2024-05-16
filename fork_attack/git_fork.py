import logging
import os
from distutils.dir_util import copy_tree
from pathlib import Path

import git
from github import Github

from settings import repositories

logger = logging.getLogger()

current_path = Path(os.path.dirname(os.path.realpath(__file__)))
path = current_path.parent.parent
os.chdir(path)
token = os.getenv("GITHUB_TOKEN")
g = Github(token)
user = g.get_user()
files = os.path.join(current_path.parent, ".github")


def add_dependabot(local_repo_path, branch):
    os.chdir(local_repo_path)
    local_repo = git.Repo(f'{local_repo_path}/.git')
    copy_tree(files, f'{local_repo_path}/.github')
    local_repo.git.add("--force", local_repo_path)
    logger.info("Files added")
    local_repo.git.commit('-m', "fork attack added files")
    logger.info("Files commited")
    local_repo.git.push('--force', 'origin', branch)
    logger.info("Files pushed")


def fork_all():
    for repo_config in repositories:
        repo_str = repo_config[0]
        branch = repo_config[1]
        url = repo_str.replace("https://github.com/", "").split("/")
        repo_name_str = url[1]
        path_to_clone = os.path.join(path, repo_name_str)
        repo_to_clone = f"https://github.com/{user.login}/{repo_name_str}.git"
        if not os.path.isdir(path_to_clone):
            org = g.get_organization(url[0])
            repo = org.get_repo(url[1])
            user.create_fork(repo)
            try:
                path_to_clone = os.path.join(path, str(repo.name))
                local_repo = git.Repo.clone_from(repo_to_clone, path_to_clone, branch=branch)
                git.Repo.create_remote(local_repo, "upstream", f"https://github.com/{url[0]}/{url[1]}.git")
            except Exception as e:
                logger.error(e)
        add_dependabot(path_to_clone, branch)


fork_all()
