import ast
import json

import pandas as pd


def process_cwe(row):
    cwes = []
    for cwe in eval(row):
        cwes.append(cwe["cwe_id"])
    return str(cwes)


dependabot_data = pd.read_csv("../data/dependabot_result.csv")
dependabot_python_data = dependabot_data.loc[dependabot_data['security_vulnerability.package.ecosystem'] == "pip"]
dependabot_python_data["security_advisory.cwes"] = dependabot_python_data["security_advisory.cwes"].apply(
    lambda x: process_cwe(x))

dependabot_python_size = dependabot_python_data.groupby(['security_advisory.severity']).size().reset_index(
    name='counts')
dependabot_python_size.to_csv("../data/dependabot_severity.csv")

for level in ["critical", "high", "medium", "low"]:
    dependabot_python_data_level = dependabot_python_data.loc[
        dependabot_python_data['security_advisory.severity'] == level]
    dependabot_python_data_repo_level = dependabot_python_data_level.groupby(['repo_name']).size().reset_index(
        name='counts')
    dependabot_python_data_repo_level.to_csv(f"../data/dependabot_package_{level}.csv")

    dependabot_cve_id = (dependabot_python_data_level.groupby(
        [
            'security_advisory.cve_id',
            'security_advisory.cwes',
            'security_advisory.severity',
            'security_advisory.summary',
            'security_advisory.description'
        ]
    ).size().reset_index(name='counts'))
    dependabot_cve_id.to_csv(f"../data/dependabot_cve_{level}.csv")

codeql_data = pd.read_csv("../data/code_analysis_result.csv")
codeql_python_data = codeql_data.loc[codeql_data['most_recent_instance.category'] == "/language:python"]
codeql_python_size = codeql_python_data.groupby(['rule.security_severity_level']).size().reset_index(name='counts')
codeql_python_size.to_csv("../data/code_analysis_severity.csv")


def normalize_tag(x):
    x = x.replace("external/cwe/", "")
    x = ast.literal_eval(x)
    if "security" in x:
        x.remove("security")
    if "correctness" in x:
        x.remove("correctness")
    if "serialization" in x:
        x.remove("serialization")
    return str(x)


codeql_python_data['rule.tags'] = codeql_python_data['rule.tags'].apply(normalize_tag)
for level in ["critical", "high", "medium"]:
    codeql_python_data_level = codeql_python_data.loc[codeql_python_data['rule.security_severity_level'] == level]
    codeql_python_data_repo_level = codeql_python_data_level.groupby(['repo_name']).size().reset_index(name='counts')
    codeql_python_data_repo_level.to_csv(f"../data/code_analysis_{level}.csv")

    codeql_cwe_id = (codeql_python_data_level.groupby(
        [
            'rule.tags',
            'rule.security_severity_level',
            'rule.name',
            'rule.description'
        ]
    ).size().reset_index(name='counts'))
    codeql_cwe_id.to_csv(f"../data/code_analysis_cwe_{level}.csv")
