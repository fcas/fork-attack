import ast
import os
from datetime import date, timedelta

import numpy as np
import pandas as pd

from fork_attack.settings import repositories

FORKS_DIR = os.environ.get("FORKS_DIR")


def extraction_date():
    """Date directory this pipeline's raw extraction (estige.py) and every
    output derived from it are persisted under -- always today, so nothing
    needs a hardcoded date that goes stale the next time this runs."""
    return str(date.today())


def analysis_date_range():
    """The two calendar days this study accepts a codeql/dependabot/semgrep
    alert as coming from a run it actually executed: today and yesterday,
    covering the overnight-to-morning window these scans run in."""
    today = date.today()
    return (str(today - timedelta(days=1)), str(today))


def canonical_repo_name(repo_name):
    if not repo_name:
        return repo_name
    return repo_name.lower()


# The canonical 273-repo corpus, keyed the same way graph vertices are --
# any repo name outside this set (e.g. a stale fork left over from an
# earlier corpus iteration, still visible to org-wide API queries like
# Semgrep's findings endpoint) must never be inserted into the graph.
KNOWN_REPOS = {
    canonical_repo_name(url.replace("https://github.com/", "").split("/")[1])
    for url, _, _ in repositories
}


def is_known_repo(repo_name):
    return canonical_repo_name(repo_name) in KNOWN_REPOS


def has_provenance(repo_name, path):
    """Whether `path` genuinely exists at the current HEAD of `repo_name`'s
    local clone. CodeQL/Dependabot/Semgrep all freeze a finding's file
    location at first detection and don't necessarily re-validate it on
    every later scan that reconfirms the underlying issue -- a rescan that
    doesn't touch that exact file leaves a stale path pointing at code long
    since removed or renamed upstream. Only alerts with real backing in the
    repo's current tree belong in this graph."""
    if not path or not isinstance(path, str):
        return False
    repo_dir = os.path.join(FORKS_DIR, repo_name)
    if not os.path.isdir(repo_dir):
        return False
    return os.path.isfile(os.path.join(repo_dir, path.lstrip("/")))


def row_to_json(row, pattern, column_prefix):
    rule = row.filter(regex=pattern)
    df = pd.DataFrame([rule.to_list()], columns=rule.index)
    df.columns = df.columns.str.replace(column_prefix, "", regex=True)
    df = df.replace(np.nan, None)
    return df.to_dict(orient="index")[0]


def upsert_edge(edge_collection, doc):
    if not edge_collection.has(doc):
        edge_collection.insert(doc)


def add_source(db, collection_name, key, source):
    """Appends `source` (e.g. "codeql", "dependabot", "semgrep ssc",
    "semgrep sast") to a CVE/CWE node's `sources` array, deduplicated, without
    clobbering whatever the node's other loader already wrote there. Node-level
    (not edge-level): this study only needs to know which tools ever reported
    a given CVE/CWE, not to re-derive that per finding instance."""
    db.aql.execute(
        "FOR d IN @@col FILTER d._key == @key "
        "UPDATE d WITH { sources: APPEND(d.sources ? d.sources : [], [@source], true) } IN @@col",
        bind_vars={"@col": collection_name, "key": key, "source": source}
    )


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
