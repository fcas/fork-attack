import json
import logging
import os
from datetime import date
from distutils.dir_util import copy_tree
from pathlib import Path

import git
import requests
from github import Github, UnknownObjectException

from settings import repositories

logger = logging.getLogger()

current_path = Path(os.path.dirname(os.path.realpath(__file__)))
path = current_path.parent.parent
os.chdir(path)
token = os.getenv("GITHUB_TOKEN")
g = Github(token)
user = g.get_user()
files = os.path.join(current_path.parent, ".github")


def code_analysis(repo_name):
    os.chdir(f"{current_path.parent}/data")
    code_analysis_alerts_url = f"https://api.github.com/repos/fcas/{repo_name}/code-scanning/alerts"
    dependabot_alerts_url = f"https://api.github.com/repos/fcas/{repo_name}/dependabot/alerts"

    payload = {}
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28'
    }

    code_analysis_response = requests.request("GET", code_analysis_alerts_url, headers=headers, data=payload)
    dependabot_alerts_response = requests.request("GET", dependabot_alerts_url, headers=headers, data=payload)
    now = date.today()

    code_analysis_filename = f'{now}/{repo_name}_code_analysis.json'
    dependabot_alerts_filename = f'{now}/{repo_name}_dependabot_alerts.json'
    os.makedirs(os.path.dirname(code_analysis_filename), exist_ok=True)
    os.makedirs(os.path.dirname(dependabot_alerts_filename), exist_ok=True)
    with open(code_analysis_filename, 'w', encoding='utf-8') as f:
        json.dump(code_analysis_response.json(), f, ensure_ascii=False, indent=4)
    with open(dependabot_alerts_filename, 'w', encoding='utf-8') as f:
        json.dump(dependabot_alerts_response.json(), f, ensure_ascii=False, indent=4)


def add_ymls(local_repo_path, branch):
    try:
        os.chdir(local_repo_path)
        local_repo = git.Repo(f'{local_repo_path}/.git')
        copy_tree(files, f'{local_repo_path}/.github')
        local_repo.git.add("--force", local_repo_path)
        logger.info("Files added")
        local_repo.git.commit('-m', "fork attack added files")
        logger.info("Files commited")
        local_repo.git.push('--force', 'origin', branch)
        logger.info("Files pushed")
    except git.GitCommandError as e:
        if "nothing to commit" in str(e):
            logger.info(e)


def attack():
    for repo_config in repositories:
        repo_str = repo_config[0]
        branch = repo_config[1]
        clone = repo_config[2]
        url = repo_str.replace("https://github.com/", "").split("/")
        repo_name_str = url[1]
        path_to_clone = os.path.join(path, repo_name_str)
        repo_to_clone = f"https://github.com/{user.login}/{repo_name_str}.git"
        if not os.path.isdir(path_to_clone) and clone:
            try:
                repo = g.get_organization(url[0]).get_repo(url[1])
            except UnknownObjectException:
                repo = g.get_user(url[0]).get_repo(url[1])
            user.create_fork(repo)
            try:
                path_to_clone = os.path.join(path, repo_name_str)
                local_repo = git.Repo.clone_from(repo_to_clone, path_to_clone, branch=branch)
                git.Repo.create_remote(local_repo, "upstream", f"https://github.com/{url[0]}/{url[1]}.git")
            except Exception as e:
                logger.error(e)
            add_ymls(path_to_clone, branch)
        code_analysis(repo_name_str)


attack()
