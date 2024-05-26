import ast
import json

import pandas as pd

data = pd.read_csv("../data/dependabot_result.csv")
python_data = data.loc[data['security_vulnerability.package.ecosystem'] == "pip"]
python_size = python_data.groupby(['security_advisory.severity']).size().reset_index(name='counts')
python_size.to_csv("../data/dependabot_severity.csv")

for level in ["critical", "high", "medium", "low"]:
    python_data_level = python_data.loc[python_data['security_advisory.severity'] == level]
    python_data_repo_level = python_data_level.groupby(['repo_name']).size().reset_index(name='counts')
    python_data_repo_level.to_csv(f"../data/dependabot_package_{level}.csv")

    cve_id = (python_data_level.groupby(
        [
            'security_advisory.cve_id',
            'security_advisory.severity',
            'security_advisory.summary',
            'security_advisory.description'
        ]
    ).size().reset_index(name='counts'))
    cve_id.to_csv(f"../data/dependabot_cve_{level}.csv")

data = pd.read_csv("../data/code_analysis_result.csv")
python_data = data.loc[data['most_recent_instance.category'] == "/language:python"]
python_size = python_data.groupby(['rule.security_severity_level']).size().reset_index(name='counts')
python_size.to_csv("../data/code_analysis_severity.csv")


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


python_data['rule.tags'] = python_data['rule.tags'].apply(normalize_tag)
for level in ["critical", "high", "medium"]:
    python_data_level = python_data.loc[python_data['rule.security_severity_level'] == level]
    python_data_repo_level = python_data_level.groupby(['repo_name']).size().reset_index(name='counts')
    python_data_repo_level.to_csv(f"../data/code_analysis_{level}.csv")

    cwe_id = (python_data_level.groupby(
        [
            'rule.tags',
            'rule.security_severity_level',
            'rule.name',
            'rule.description'
        ]
    ).size().reset_index(name='counts'))
    cwe_id.to_csv(f"../data/code_analysis_cwe_{level}.csv")
