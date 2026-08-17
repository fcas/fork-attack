import ast

import pandas as pd
from utils import normalize_tag, extraction_date


def process_cwe(row):
    cwes = []
    for cwe in ast.literal_eval(row):
        cwes.append(cwe["cwe_id"])
    return str(cwes)


def main():
    # Raw extraction date of the Dependabot/CodeQL corpus; every output derived
    # from it is persisted alongside it, not loose in data/.
    extraction_date_str = extraction_date()
    # GitHub only bumps an alert's updated_at on a real state transition
    # (fixed/dismissed), not on a rescan that reconfirms the same still-open
    # finding -- it is NOT a proxy for "seen by a scan in this study's
    # accepted window" (verified empirically against confirmed-successful
    # scan dates in dependabot_status_report.csv/codeql_status_report.csv).
    # The alert's own current state is the only filter needed.
    dependabot_data = pd.read_csv(f"../data/{extraction_date_str}/dependabot_result.csv")
    dependabot_python_data = dependabot_data.loc[dependabot_data['security_vulnerability.package.ecosystem'] == "pip"]
    dependabot_python_data = dependabot_python_data.loc[dependabot_python_data['state'] == 'open']
    dependabot_python_data["security_advisory.cwes"] = dependabot_python_data["security_advisory.cwes"].apply(
        lambda x: process_cwe(x))

    dependabot_python_size = dependabot_python_data.groupby(['security_advisory.severity']).size().reset_index(
        name='counts')
    dependabot_python_size.to_csv(f"../data/{extraction_date_str}/dependabot_severity.csv")

    for level in ["critical", "high", "medium", "low"]:
        dependabot_python_data_level = dependabot_python_data.loc[
            dependabot_python_data['security_advisory.severity'] == level]
        dependabot_python_data_repo_level = dependabot_python_data_level.groupby(['repo_name']).size().reset_index(
            name='counts')
        dependabot_python_data_repo_level.to_csv(f"../data/{extraction_date_str}/dependabot_package_{level}.csv")

        dependabot_cve_id = (dependabot_python_data_level.groupby(
            [
                'security_advisory.cve_id',
                'security_advisory.cwes',
                'security_advisory.severity',
                'security_advisory.summary',
                'security_advisory.description'
            ]
        ).size().reset_index(name='counts'))
        dependabot_cve_id.to_csv(f"../data/{extraction_date_str}/dependabot_cve_{level}.csv")

    OWN_CODEQL_WORKFLOW = ".github/workflows/codeql.yml:analyze"
    codeql_data = pd.read_csv(f"../data/{extraction_date_str}/code_analysis_result.csv")
    codeql_python_data = codeql_data.loc[codeql_data['most_recent_instance.category'] == "/language:python"]
    codeql_python_data = codeql_python_data.loc[
        (codeql_python_data['most_recent_instance.analysis_key'] == OWN_CODEQL_WORKFLOW)
        & (codeql_python_data['state'] == 'open')]
    codeql_python_size = codeql_python_data.groupby(['rule.security_severity_level']).size().reset_index(name='counts')
    codeql_python_size.to_csv(f"../data/{extraction_date_str}/code_analysis_severity.csv")

    codeql_python_data['rule.tags'] = codeql_python_data['rule.tags'].apply(normalize_tag)
    for level in ["critical", "high", "medium"]:
        codeql_python_data_level = codeql_python_data.loc[codeql_python_data['rule.security_severity_level'] == level]
        codeql_python_data_repo_level = codeql_python_data_level.groupby(['repo_name']).size().reset_index(
            name='counts')
        codeql_python_data_repo_level.to_csv(f"../data/{extraction_date_str}/code_analysis_{level}.csv")

        codeql_cwe_id = (codeql_python_data_level.groupby(
            [
                'rule.tags',
                'rule.security_severity_level',
                'rule.name',
                'rule.description'
            ]
        ).size().reset_index(name='counts'))
        codeql_cwe_id.to_csv(f"../data/{extraction_date_str}/code_analysis_cwe_{level}.csv")


if __name__ == '__main__':
    main()
