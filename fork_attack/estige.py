import json
import logging
import os
from datetime import date
from distutils.dir_util import copy_tree
from pathlib import Path

import git
import pandas as pd
import requests
from git import GitCommandError
from github import Github, UnknownObjectException

from settings import repositories

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

current_path = Path(os.path.dirname(os.path.realpath(__file__)))
path = current_path.parent.parent
os.chdir(path)
token = os.getenv("GITHUB_TOKEN")
g = Github(token)
user = g.get_user()
files = os.path.join(current_path.parent, ".github")

headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': f'Bearer {token}',
    'X-GitHub-Api-Version': '2022-11-28'
}

code_analysis_result = pd.DataFrame()
dependabot_result = pd.DataFrame()
check_archive = False


def vulnerability_analysis(repo_name):
    os.chdir(f"{current_path.parent}/data")
    code_analysis_alerts_url = f"https://api.github.com/repos/fcas/{repo_name}/code-scanning/alerts"
    dependabot_alerts_url = f"https://api.github.com/repos/fcas/{repo_name}/dependabot/alerts"

    code_analysis_data = extract_data(code_analysis_alerts_url, {}, repo_name)
    dependabot_data = extract_data(dependabot_alerts_url, {}, repo_name)

    dump_data(code_analysis_data, dependabot_data, repo_name)


def extract_data(url, payload, repo_name):
    response = requests.request("GET", url, headers=headers, data=payload)
    data = response.json()
    while 'next' in response.links.keys():
        response = requests.get(response.links['next']['url'], headers=headers, data=payload)
        data.extend(response.json())
    if isinstance(data, list) and data:
        d = pd.json_normalize(data)
        d["repo_name"] = repo_name
        global code_analysis_result, dependabot_result
        if "dependabot" in url:
            dependabot_result = pd.concat([dependabot_result, d])
        else:
            code_analysis_result = pd.concat([code_analysis_result, d])
    elif isinstance(response, dict):
        logger.warning(f"{repo_name}:{response}")
    return data


def dump_data(code_analysis_data, dependabot_data, repo_name):
    now = date.today()
    code_analysis_filename = f'{now}/{repo_name}_code_analysis.json'
    dependabot_alerts_filename = f'{now}/{repo_name}_dependabot_alerts.json'
    os.makedirs(os.path.dirname(code_analysis_filename), exist_ok=True)
    os.makedirs(os.path.dirname(dependabot_alerts_filename), exist_ok=True)
    with open(code_analysis_filename, 'w', encoding='utf-8') as f:
        json.dump(code_analysis_data, f, ensure_ascii=False, indent=4)
    with open(dependabot_alerts_filename, 'w', encoding='utf-8') as f:
        json.dump(dependabot_data, f, ensure_ascii=False, indent=4)


def add_ymls(local_repo_path, branch):
    local_repo = ""
    if not os.path.isdir(f'{local_repo_path}/.github/workflows'):
        try:
            os.chdir(local_repo_path)
            local_repo = git.Repo(f'{local_repo_path}/.git')
            local_repo.git.checkout(branch)
            if os.path.isdir(f'{local_repo_path}/.github/workflows'):
                local_repo.git.rm("--force", ['.github/workflows'], r=True)
            if os.path.isdir(f'{local_repo_path}/.github/actions'):
                local_repo.git.rm("--force", ['.github/actions'], r=True)
            copy_tree(files, f'{local_repo_path}/.github')
            local_repo.git.add("--force", local_repo_path)
            local_repo.git.push('--force', 'origin', branch)
            local_repo.git.commit('-m', "fork attack added files")
            local_repo.git.push('--force', 'origin', branch)
        except git.GitCommandError:
            local_repo.git.push('--force', 'origin', branch)
        except Exception as e:
            logger.info(f"Error syspath: {local_repo_path}. {e}")


def attack():
    repo_config = ""
    try:
        for repo_config in repositories:
            repo_str = repo_config[0]
            branch = repo_config[1]
            clone = repo_config[2]

            url = repo_str.replace("https://github.com/", "").split("/")
            repo_name = url[1]
            repo_owner = url[0]

            if check_archive:
                response = requests.request("GET", f"https://api.github.com/repos/{repo_owner}/{repo_name}",
                                            headers=headers, data={}).json()
                if response.get("archived", True):
                    logger.warning(f"Repository {repo_str} is disabled")

            fork(branch, clone, repo_name, repo_owner)
            vulnerability_analysis(repo_name)

    except Exception as e:
        logger.info(f"Error processing {repo_config}. {e}")


def fork(branch, clone, repo_name_str, repo_owner):
    path_to_clone = os.path.join(path, repo_name_str)
    if not os.path.isdir(path_to_clone) and clone:
        repo_to_clone = f"https://github.com/{user.login}/{repo_name_str}.git"
        remote = f"https://github.com/{repo_owner}/{repo_name_str}.git"
        try:
            repo = g.get_organization(repo_owner).get_repo(repo_name_str)
        except UnknownObjectException:
            repo = g.get_user(repo_owner).get_repo(repo_name_str)
        user.create_fork(repo)
        try:
            local_repo = git.Repo.clone_from(repo_to_clone, path_to_clone, branch=branch)
            git.Repo.create_remote(local_repo, "upstream", remote)
            add_ymls(path_to_clone, branch)
        except GitCommandError:
            branch = "main"
            local_repo = git.Repo.clone_from(repo_to_clone, path_to_clone, branch=branch)
            git.Repo.create_remote(local_repo, "upstream", remote)
            add_ymls(path_to_clone, branch)


def main():
    attack()
    code_analysis_result.to_csv("code_analysis_result.csv")
    dependabot_result.to_csv("dependabot_result.csv")


if __name__ == '__main__':
    main()
