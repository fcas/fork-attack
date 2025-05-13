import os
from pathlib import Path

import pandas as pd

path = Path(os.path.dirname(os.path.realpath(__file__)))
base_path = str(path.parent.absolute())

cve_definitions = pd.read_csv(f"{base_path}/data/cve_definitions.csv")
cwe_definitions = pd.read_csv(f"{base_path}/data/cwe_definitions.csv")

dependabot_result = pd.read_csv(f"{base_path}/data/dependabot_result.csv")
dependabot_python_data = dependabot_result.loc[dependabot_result['security_vulnerability.package.ecosystem'] == "pip"]

code_analysis_result = pd.read_csv(f"{base_path}/data/code_analysis_result.csv")
code_analysis_python_data = code_analysis_result.loc[
    code_analysis_result['most_recent_instance.category'] == "/language:python"]


def get_dependabot_libraries_repos(cwe_id):
    regex = fr'\bCWE-{cwe_id}\b'
    cwes = dependabot_python_data[
        dependabot_python_data['security_advisory.cwes'].str.contains(regex, case=False, na=False,
                                                                      regex=True)]
    libraries = set(cwes["security_vulnerability.package.name"].tolist())
    repos = set(cwes["repo_name"].tolist())
    return {"libraries": list(libraries), "repos": list(repos)}


def get_codeql_libraries_repos(cwe_id):
    if int(cwe_id) < 100:
        cwe_id = cwe_id.zfill(3)
    regex = fr'\bCWE-{cwe_id}\b'
    cwes = code_analysis_python_data[
        code_analysis_python_data['rule.tags'].str.contains(regex, case=False, na=False,
                                                            regex=True)]
    repos = set(cwes["repo_name"].tolist())
    return {"repos": list(repos)}


def main():
    cve_definitions[["libraries", "repos"]] = cve_definitions.apply(
        lambda x: get_dependabot_libraries_repos(str(x.cwe_id)), axis='columns', result_type='expand')
    cve_definitions.to_csv(f"{base_path}/data/cve_definitions_lib.csv")

    cwe_definitions[["repos"]] = cwe_definitions.apply(
        lambda x: get_codeql_libraries_repos(str(x.cwe_id)), axis='columns', result_type='expand')
    cwe_definitions.to_csv(f"{base_path}/data/cwe_definitions_lib.csv")

    df_result = cwe_definitions.drop(["cwe_id", "Unnamed: 0", "nature"], axis=1)
    df_result_agg_cwe = df_result.groupby(
        [
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()
    df_result_agg_cwe.to_csv(f"{base_path}/data/cwe_definitions_lib_agg.csv")

    df_result = cve_definitions.drop(["cwe_id", "Unnamed: 0", "nature"], axis=1)
    df_result_agg_cve = df_result.groupby(
        [
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()
    df_result_agg_cve.to_csv(f"{base_path}/data/cve_definitions_lib_agg.csv")

    df_all = pd.concat([df_result_agg_cve, df_result_agg_cwe])
    df_all_agg = df_all.groupby(
        [
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()

    df_all_agg['libraries'] = df_all_agg['libraries'].apply(
        lambda x: list(map(str.lower, x)) if isinstance(x, list) else [])
    df_all_agg['libraries'] = df_all_agg['libraries'].apply(
        lambda x: ', '.join(sorted(list(set(x)))) if isinstance(x, list) else [])

    df_all_agg['repos'] = df_all_agg['repos'].apply(
        lambda x: list(map(str.lower, x)) if isinstance(x, list) else [])
    df_all_agg['repos'] = df_all_agg['repos'].apply(
        lambda x: ', '.join(sorted(list(set(x)))) if isinstance(x, list) else [])

    df_all_agg.to_csv(f"{base_path}/data/all_definitions_agg_libs.csv")


if __name__ == '__main__':
    main()
