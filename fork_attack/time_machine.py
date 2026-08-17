import os
from pathlib import Path

import pandas as pd

from fork_attack.utils import extraction_date, canonical_repo_name, has_provenance

path = Path(os.path.dirname(os.path.realpath(__file__)))
base_path = str(path.parent.absolute())

# Raw extraction date of the Dependabot/CodeQL corpus these files derive from.
# This enrichment pass (attaching repos/libraries columns) runs the same day,
# so its outputs are persisted alongside it under that same date.
extraction_date_str = extraction_date()
enrichment_date = extraction_date_str

cve_definitions = pd.read_csv(f"{base_path}/data/{extraction_date_str}/cve_definitions.csv")
cwe_definitions = pd.read_csv(f"{base_path}/data/{extraction_date_str}/cwe_definitions.csv")

# GitHub only bumps an alert's updated_at on a real state transition (fixed/
# dismissed), not on a rescan that reconfirms the same still-open finding --
# it is NOT a proxy for "seen by a scan in this study's accepted window"
# (verified empirically against confirmed-successful scan dates in
# dependabot_status_report.csv/codeql_status_report.csv). The alert's own
# current state (and, for CodeQL, its real source workflow) is the filter.
OWN_CODEQL_WORKFLOW = ".github/workflows/codeql.yml:analyze"

dependabot_result = pd.read_csv(f"{base_path}/data/{extraction_date_str}/dependabot_result.csv")
dependabot_python_data = dependabot_result.loc[dependabot_result['security_vulnerability.package.ecosystem'] == "pip"]
dependabot_python_data = dependabot_python_data.loc[dependabot_python_data['state'] == 'open']
dependabot_python_data = dependabot_python_data.loc[
    dependabot_python_data.apply(
        lambda r: has_provenance(canonical_repo_name(r['repo_name']), r['dependency.manifest_path']), axis=1
    )
]

code_analysis_result = pd.read_csv(f"{base_path}/data/{extraction_date_str}/code_analysis_result.csv")
code_analysis_python_data = code_analysis_result.loc[
    code_analysis_result['most_recent_instance.category'] == "/language:python"]
code_analysis_python_data = code_analysis_python_data.loc[
    (code_analysis_python_data['most_recent_instance.analysis_key'] == OWN_CODEQL_WORKFLOW)
    & (code_analysis_python_data['state'] == 'open')]
code_analysis_python_data = code_analysis_python_data.loc[
    code_analysis_python_data.apply(
        lambda r: has_provenance(canonical_repo_name(r['repo_name']), r['most_recent_instance.location.path']), axis=1
    )
]


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
    cve_definitions.to_csv(f"{base_path}/data/{enrichment_date}/cve_definitions_lib.csv")

    cwe_definitions[["repos"]] = cwe_definitions.apply(
        lambda x: get_codeql_libraries_repos(str(x.cwe_id)), axis='columns', result_type='expand')
    cwe_definitions.to_csv(f"{base_path}/data/{enrichment_date}/cwe_definitions_lib.csv")

    df_result = cwe_definitions.drop(["cwe_id", "nature"], axis=1, errors="ignore")
    df_result_agg_cwe = df_result.groupby(
        [
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()
    df_result_agg_cwe.to_csv(f"{base_path}/data/{enrichment_date}/cwe_definitions_lib_agg.csv")

    df_result = cve_definitions.drop(["cwe_id", "nature"], axis=1, errors="ignore")
    df_result_agg_cve = df_result.groupby(
        [
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()
    df_result_agg_cve.to_csv(f"{base_path}/data/{enrichment_date}/cve_definitions_lib_agg.csv")

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

    df_all_agg.to_csv(f"{base_path}/data/{enrichment_date}/all_definitions_agg_libs.csv")


if __name__ == '__main__':
    main()
