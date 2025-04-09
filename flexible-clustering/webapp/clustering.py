from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import re
import tlsh
import Levenshtein
from flexible_clustering import FISHDBC

# Load commands to help classify arguments
commands_df = pd.read_csv("commands_cleaned.csv")
valid_commands = set(commands_df["Command"].str.strip().unique())

# Load similarity matrix
similarity_matrix = pd.read_csv("finalissimoSim.csv", index_col=0)

# Load command-to-purpose mapping
purpose_df = pd.read_csv("finalissimoCommands.csv")
purpose_lookup = dict(zip(purpose_df["label"].str.strip(), purpose_df["simplified_purpose"].fillna("Unclassified")))

def classify_purpose_from_lookup(commands):
    """
    Determine the most common 'simplified_purpose' from the cluster's commands.
    """
    purpose_counts = Counter()

    for cmd in commands:
        if not cmd or not cmd.strip():
            continue  # Skip empty or None commands

        tokens = cmd.strip().split()
        if not tokens:
            continue  # Just to be extra safe

        key = tokens[0]
        purpose = purpose_lookup.get(key, "Unclassified")
        if purpose != "Unclassified":
            purpose_counts[purpose] += 1

    if not purpose_counts:
        return "Unclassified"

    return purpose_counts.most_common(1)[0][0]



def classify_argument(arg):
    if arg in valid_commands or arg in ('busybox', 'which'):
        return {'type': arg, 'value': arg}
    if arg.startswith("./"):
        return {'type': 'FILE_SCRIPT' if arg.endswith('.sh') else 'FILE_EXECUTION', 'value': arg}
    if arg in ('>', '>>', '&&', ';', '||', '|'):
        return {'type': 'OPERATOR', 'value': arg}
    if re.match(r'^https://', arg, flags=re.IGNORECASE):
        return {'type': 'SECURE_URL', 'value': arg}
    elif re.match(r'^http://', arg, flags=re.IGNORECASE):
        return {'type': 'URL', 'value': arg}
    if re.match(r'^\b\d{1,3}(?:\.\d{1,3}){3}\b$', arg):
        return {'type': 'IP', 'value': arg}
    if re.match(r'\\x[0-9a-fA-F]{2}', arg):
        return {'type': 'HEX', 'value': arg}
    if arg.startswith('/'):
        return {'type': 'FILE_SCRIPT' if arg.endswith('.sh') else 'FILE' if '.' in arg.split('/')[-1] else 'PATH', 'value': arg}
    if arg.startswith('-'):
        return {'type': arg, 'value': arg}
    if '.' in arg:
        return {'type': 'FILE', 'value': arg}
    return {'type': 'STRING', 'value': arg}


def abstract_command_line_substitution(cmd_line):
    pattern = r'(\|\||&&|\||;|>|>>)'
    parts = re.split(pattern, cmd_line)
    new_parts = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if part in ('||', '&&', '|', ';', '>', '>>'):
            new_parts.append(part)
        else:
            tokens = part.split()
            new_tokens = [classify_argument(t)['type'] for t in tokens]
            new_parts.append(" ".join(new_tokens))
    return " ".join(new_parts)


def group_commands_and_flags(abstract_cmd):
    tokens = abstract_cmd.strip().split()
    grouped = []
    skip_next = False
    for i, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        classification = classify_argument(token)
        if classification['type'] == 'OPERATOR':
            continue
        if token.startswith('-') and i > 0:
            prev_token = grouped.pop() if grouped else ''
            grouped.append(f"{prev_token} {token}")
            continue
        grouped.append(token)
    return grouped


def split_by_operators(cmd):
    return re.split(r'(\|\||&&|\||;)', cmd)


def command_tokenwise_distance(cmd1, cmd2, sim_matrix, threshold=0.1):
    chunks1 = split_by_operators(cmd1)
    chunks2 = split_by_operators(cmd2)
    if len(chunks1) != len(chunks2):
        return 1.0
    for c1, c2 in zip(chunks1, chunks2):
        c1 = c1.strip()
        c2 = c2.strip()
        if c1 in ('|', '||', '&&', ';') or not c1 or not c2:
            if c1 != c2:
                return 1.0
            continue
        units1 = group_commands_and_flags(c1)
        units2 = group_commands_and_flags(c2)
        if len(units1) != len(units2) or not units1 or not units2:
            return 1.0
        for u1, u2 in zip(units1, units2):
            if len(u1) != len(u2):
                continue
            if u1 == u2:
                continue
            try:
                sim = sim_matrix[u1][u2]
            except Exception:
                continue
            if sim < threshold:
                return 1.0
    return 0.0


def run_clustering(honeypot_type="cowrie", from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z"):
    es = Elasticsearch("https://elastic-eks.aee.vederelabs.net:443", basic_auth=("elastic",'0Tz9jmcWRq5j0kk774R421RD'))
    if not es.ping():
        raise RuntimeError("Could not connect to Elasticsearch")

    query = {
        "bool": {
            "must": [],
            "filter": [
                {
                    "bool": {
                        "filter": [
                            {
                                "bool": {
                                    "should": [
                                        {"exists": {"field": "input.keyword"}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {"match": {"type": honeypot_type}}
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "strict_date_optional_time",
                            "gte": from_date,
                            "lte": to_date
                        }
                    }
                }
            ]
        }
    }


    result = es.search(body={"query": query}, size=10000)
    df = pd.DataFrame([entry['_source'] for entry in result['hits']['hits']])
    df = df[df['input'].notna()]
    commands = df['input'].values
    abstracts = [abstract_command_line_substitution(cmd) for cmd in commands]
    distance_func = lambda a, b: command_tokenwise_distance(a, b, similarity_matrix, threshold=0.7)
    fishdbc = FISHDBC(distance_func)
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()
    clusters = defaultdict(set)
    for parent, child, lambda_val, child_size in ctree[::-1]:
        if child_size == 1:
            clusters[parent].add(child)
        else:
            clusters[parent].update(clusters[child])
    child_to_parent = {child: parent for parent, child, _, _ in ctree}
    results = []
    for cluster_id, members in sorted(clusters.items()):
        parent = child_to_parent.get(cluster_id, "ROOT")
        member_cmds = [commands[member] for member in members]
        cmd_counts = Counter(member_cmds)

        purpose = classify_purpose_from_lookup(member_cmds)

        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "commands": [(cmd, int(count)) for cmd, count in sorted(cmd_counts.items())]
        })



    # if ttp_filter:
    #     results = [c for c in results if any(ttp_filter in cmd.lower() for cmd, _ in c["commands"])]
    # Final clean conversion before returning
    for cluster in results:
        cluster['id'] = int(cluster['id'])
        cluster['parent'] = str(cluster['parent'])
        cluster['commands'] = [(cmd, int(count)) for cmd, count in cluster['commands']]

    return results
