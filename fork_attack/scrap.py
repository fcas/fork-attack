import glob
import re

import pandas as pd

result = []
result_all = []


def get_definitions(cew_id):
    try:
        raw = pd.read_html(
            f"https://cwe.mitre.org/data/definitions/{cew_id}.html", match="Relevant to the view", header=0)[0]
        df = raw.rename(
            columns={'Submissions': 'nature', 'Submissions.1': 'type', 'Submissions.2': 'id',
                     'Unnamed: 3': 'description'})

        # The CWE's own abstraction level is stated in its page's overview text, in the same
        # 'nature' cell, but never as a ChildOf/ParentOf/MemberOf/etc. relation to another entry;
        # the filter below drops that overview row along with the rest of the page's unrelated
        # boilerplate, so a CWE that is never listed as a related entry (child/member/etc.) by
        # any OTHER CWE would otherwise end up with no type at all. Pillar/Class/Base/Variant
        # entries label this "Abstraction:"; Composite/Chain entries label it "Structure:" instead.
        self_abstraction_match = df['nature'].astype(str).str.extract(
            r'(?:Abstraction|Structure):\s*(Pillar|Class|Base|Variant|Category|View|Chain|Composite)', flags=re.IGNORECASE)
        self_abstraction = self_abstraction_match[0].dropna()
        self_type = self_abstraction.iloc[0].lower() if not self_abstraction.empty else None

        filter_rows = df["nature"].str.contains('ChildOf|MemberOf|CanFollow|ParentOf|PeerOf|CanPrecede', na=False)
        df = df[filter_rows]
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

        if self_type is not None:
            self_row = pd.DataFrame([{
                'nature': 'Self', 'type': self_type, 'id': str(cew_id), 'description': None
            }])
            df = pd.concat([df, self_row], ignore_index=True)
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


def main():
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
        result = []

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


if __name__ == '__main__':
    main()
