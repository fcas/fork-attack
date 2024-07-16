import glob

import pandas as pd

result = []
result_all = []


def get_definitions(cew_id):
    try:
        df = pd.read_html(
            f"https://cwe.mitre.org/data/definitions/{cew_id}.html", match="Relevant to the view", header=0)[0]
        filter_rows = df["Submissions"].str.contains('ChildOf|MemberOf|CanFollow|ParentOf|PeerOf|CanPrecede', na=False)
        df = df[filter_rows]
        df = df.rename(
            columns={'Submissions': 'nature', 'Submissions.1': 'type', 'Submissions.2': 'id',
                     'Unnamed: 3': 'description'})
        # if df['id'].str.contains('876').any():
        #     print(cew_id)
        df["type"] = df.type.apply(lambda x: 'category' if 'category - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'view' if 'view - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'class' if 'class - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'base' if 'base - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'pillar' if 'pillar - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'variant' if 'variant - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'chain' if 'chain - ' in x.lower() else x)
        df["type"] = df.type.apply(lambda x: 'composite' if 'composite - ' in x.lower() else x)
    except Exception as e:
        print(cew_id)
        return pd.DataFrame()
    return df


def process_row(row):
    cwes = dict(row).get("rule.tags", dict(row).get("security_advisory.cwes"))
    for cwe_id in eval(cwes):
        cwe_id = int(cwe_id.split("-")[1])
        definitions = get_definitions(cwe_id)
        definitions["cwe_counts"] = row["counts"]
        if not definitions.empty:
            definitions["cwe_id"] = cwe_id
            result.append(definitions)
        else:
            print(f"Error: {cwe_id}")


patterns = {
    "cwe": "../data/code_analysis_cwe_*.csv",
    "cve": "../data/dependabot_cve_*.csv"
}

for key, value in patterns.items():
    csv_files = glob.glob(value)
    filelist = []
    df = None
    for file in csv_files:
        df = pd.read_csv(file)
        filelist.append(df)
    df = pd.concat(filelist)
    df.apply(lambda x: process_row(x), axis=1)
    df_result = pd.concat(result)
    df_result.to_csv(f"../data/{key}_definitions.csv")
    df_result = df_result.drop("cwe_id", axis=1)
    df_result_agg = df_result.groupby(
        [
            'nature',
            'type',
            'id',
            "description"
        ]
    ).sum().reset_index()
    df_result_agg.to_csv(f"../data/{key}_definitions_agg.csv")
    result_all.append(df_result_agg)

df_all = pd.concat(result_all)
df_all_agg = df_all.groupby(
    [
        'nature',
        'type',
        'id',
        "description"
    ]
).sum().reset_index()
df_all_agg.to_csv("../data/all_definitions_agg.csv")
