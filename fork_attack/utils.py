import ast

import numpy as np
import pandas as pd


def row_to_json(row, pattern, column_prefix):
    rule = row.filter(regex=pattern)
    df = pd.DataFrame([rule.to_list()], columns=rule.index)
    df.columns = df.columns.str.replace(column_prefix, "", regex=True)
    df = df.replace(np.nan, None)
    return df.to_dict(orient="index")[0]


def upsert_edge(edge_collection, doc):
    if not edge_collection.has(doc):
        edge_collection.insert(doc)


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
