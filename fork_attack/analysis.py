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
