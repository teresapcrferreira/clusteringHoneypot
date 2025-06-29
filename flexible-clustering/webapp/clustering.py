from elasticsearch import Elasticsearch
import pandas as pd
from collections import Counter, defaultdict
import re
from fish.fishdbc import FISHDBC
from dotenv import load_dotenv
load_dotenv() 
import os

# Load commands to help classify arguments
commands_df = pd.read_csv("databases/commands_cleaned.csv")
valid_commands = set(commands_df["Command"].str.strip().unique())

# Load similarity matrix
similarity_matrix = pd.read_csv("databases/UpdatedSimilarity.csv", index_col=0)
# valid_commands = set(similarity_matrix.columns)
# Load command-to-purpose mapping
purpose_df = pd.read_csv("databases/UpdatedCommandDB.csv")
purpose_lookup = dict(zip(purpose_df["label"].str.strip(), purpose_df["simplified_purpose"].fillna("Unclassified")))


KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_SPACE = os.getenv("KIBANA_SPACE")
kiburl =f"{KIBANA_URL}/app/discover#/doc/{KIBANA_SPACE}/"
url = os.getenv("ELASTICSEARCH_URL")
user = os.getenv("ELASTICSEARCH_USER")
pwd = os.getenv("ELASTICSEARCH_PASSWORD")
size = 10000

def distance_func():
    return lambda x, y: geometric_distance(x, y, similarity_matrix)


def classify_purpose_from_lookup(commands):
    """
    Determine the combined purposes of a command sequence.
    The purposes will be ordered alphabetically.
    """

    purpose_counts = Counter()

    for cmd in commands:
        if not cmd or not cmd.strip():
            continue

        # Split the command by logical/pipe operators to analyze parts
        sub_cmds = re.split(r'\s*(\|\||&&|\||;|>|>>)\s*', cmd)
        for sub in sub_cmds:
            sub = sub.strip()
            if not sub or sub in {'|', '||', '&&', ';', '>', '>>'}:
                continue

            tokens = sub.split()
            if not tokens:
                continue

            key = tokens[0]
            if key.startswith("./"):
                purpose = "Execution"
            else:
                purpose = purpose_lookup.get(key, "Unknown")
            purpose_counts[purpose] += 1

    if not purpose_counts:
        return "Unknown"

    # Collect unique purposes that are not "Unknown"
    purposes = [purpose for purpose in purpose_counts if purpose != "Unknown"]
    if not purposes:
        return "Unknown"

    # Sort the purposes alphabetically
    sorted_purposes = sorted(set(purposes))

    return " + ".join(sorted_purposes)


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
            new_tokens = []

            if tokens and tokens[0] == "echo":
                # Join everything after echo as one string
                payload = " ".join(tokens[1:])
                payload_clean = payload.strip('"\'')  # remove surrounding quotes
                new_tokens.append("echo")
                new_tokens.append(f'STRING({len(payload_clean)})')
            else:
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


def is_pure_string(cmd):
    # abstract it and see if it’s exactly one token that starts with STRING(
    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return abs_cmd.startswith("STRING(") and " " not in abs_cmd


def all_similarities(cmd1, cmd2, sim_matrix):
    # 1) ignore purely‐string commands altogether
    if is_pure_string(cmd1) or is_pure_string(cmd2):
        return []   # downstream, geometric_mean([]) → 0.0

    # 2) otherwise proceed as before
    units1 = group_commands_and_flags(cmd1.strip())
    units2 = group_commands_and_flags(cmd2.strip())
    n = min(len(units1), len(units2))
    sims = []
    for u1, u2 in zip(units1[:n], units2[:n]):
        # skip placeholders like PATH, STRING, etc.
        if u1.isupper() or u2.isupper() or '(' in u1 or '(' in u2:
            continue
        sims.append(sim_matrix.get(u1, {}).get(u2, 0.0))
    return sims


def geometric_mean(sims):
    """
    Compute geometric mean of sims. If sims is empty, return 0.0.
    """
    if not sims:
        return 0.0
    # avoid zeros collapsing product to 0
    prod = 1.0
    for s in sims:
        prod *= max(s, 1e-9)
    return prod ** (1.0 / len(sims))


def is_real_command(cmd):
    """
    Return False if cmd is empty/whitespace or its abstract form
    is exactly a lone STRING(...) token.
    """
    if not cmd or not cmd.strip():
        return False

    abs_cmd = abstract_command_line_substitution(cmd).strip()
    # a single token that starts with STRING( and has no spaces is not a real command
    if abs_cmd.startswith("STRING(") and " " not in abs_cmd:
        return False

    return True


def geometric_distance(a, b, sim_matrix):
    sims = all_similarities(a, b, sim_matrix)
    sim = geometric_mean(sims)
    # distance must be between 0 (identical) and 1 (completely different)
    return 1.0 - sim


def run_clustering_simple(honeypot_type="cowrie", from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=10000):
    es = Elasticsearch(url, basic_auth=(user, pwd))
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
    result = es.search(body={"query": query}, size=size, request_timeout=30)
    docs = result['hits']['hits']
    df = pd.DataFrame([{
        **doc['_source'],
        '_id': doc['_id'],
        '_index': doc['_index']
    } for doc in docs])

    df = df[df['input'].notna()]
    commands = df['input'].values
    # Filter out pure‐string “commands”
    filtered_commands = [cmd for cmd in commands if is_real_command(cmd)]

    # Recompute abstracts over the filtered list
    abstracts = [abstract_command_line_substitution(cmd) for cmd in filtered_commands]
    # distance_func = lambda x, y: geometric_distance(x, y, similarity_matrix)
    fishdbc = FISHDBC(distance_func())
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()
    clusters = defaultdict(set)
    # Collect leaf nodes and their direct parents
    leaf_nodes = set()
    leaf_parents = set()

    for parent, children in clusters.items():
        for child in children:
            if child not in clusters:
                leaf_nodes.add(child)
                leaf_parents.add(parent)

    for parent, child, lambdaval, child_size in ctree[::-1]:
        if child_size == 1:
            clusters[parent].add(child)
        else:
            clusters[parent].update(clusters[child])
    child_to_parent = {child: parent for parent, child, _, _ in ctree}
    results = []
    for cluster_id, members in sorted(clusters.items()):
        parent = child_to_parent.get(cluster_id, "ROOT")
        member_cmds = [filtered_commands[member] for member in members]
        cluster_size = len(members)
        unique_count = len(set(member_cmds))
        cmd_id_map = {}
        cmd_display_map = {}

        for idx in members:
            raw = filtered_commands[idx]
            cmd = raw
            cmd_display_map[cmd] = cmd_display_map.get(cmd, []) + [idx]
            doc_id = df.iloc[idx]['_id']
            index_name = df.iloc[idx]['_index']
            kibanaurl = kiburl + f"{index_name}?id={doc_id}"
            if cmd not in cmd_id_map:
                cmd_id_map[cmd] = [1, kibanaurl]
            else:
                cmd_id_map[cmd][0] += 1

        purpose = classify_purpose_from_lookup(member_cmds)

        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": cluster_size,
            "unique": unique_count,
            "commands": [
               (cmd, int(count), kibanaurl) for cmd, (count, kibanaurl) in sorted(cmd_id_map.items())]

        })

    return results, ctree



def run_clustering(honeypot_type="cowrie", from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=10000):
    es = Elasticsearch(url, basic_auth=(user, pwd))
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

    page = es.search(
        index="logstash-*",
        body={"query": query},
        scroll="2m",
        size=1000
    )

    sid = page["_scroll_id"]
    all_hits = page["hits"]["hits"]

    # 2) Keep scrolling until no more hits
    while True:
        page = es.scroll(scroll_id=sid, scroll="2m")
        hits = page["hits"]["hits"]
        if not hits:
            break
        all_hits.extend(hits)
        sid = page["_scroll_id"]

    # 3)Clear scroll context
    es.clear_scroll(body={"scroll_id": sid})

    df = pd.DataFrame([{
        **doc['_source'],
        '_id': doc['_id'],
        '_index': doc['_index']
    } for doc in all_hits])

    df = df[df['input'].notna()]
    commands = df['input'].values
    # Filter out pure‐string “commands”
    filtered_commands = [cmd for cmd in commands if is_real_command(cmd)]

    # Recompute abstracts over the filtered list
    abstracts = [abstract_command_line_substitution(cmd) for cmd in filtered_commands]
    fishdbc = FISHDBC(distance_func())
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()
    clusters = defaultdict(set)
    # Collect leaf nodes and their direct parents
    leaf_nodes = set()
    leaf_parents = set()

    for parent, children in clusters.items():
        for child in children:
            if child not in clusters:  # child has no children → it's a leaf
                leaf_nodes.add(child)
                leaf_parents.add(parent)

    for parent, child, lambdaval, child_size in ctree[::-1]:
        if child_size == 1:
            clusters[parent].add(child)
        else:
            clusters[parent].update(clusters[child])
    child_to_parent = {child: parent for parent, child, _, _ in ctree}
    results = []
    for cluster_id, members in sorted(clusters.items()):
        parent = child_to_parent.get(cluster_id, "ROOT")
        member_cmds = [filtered_commands[member] for member in members]
        cluster_size = len(members)
        unique_count = len(set(member_cmds))  # unique commands
        cmd_id_map = {}
        cmd_display_map = {}  # maps index to displayed command

        for idx in members:
            raw = filtered_commands[idx]
            cmd = raw

            cmd_display_map[cmd] = cmd_display_map.get(cmd, []) + [idx]
            doc_id = df.iloc[idx]['_id']
            index_name = df.iloc[idx]['_index']

            # Build the link
            kibanaurl = kiburl + f"{index_name}?id={doc_id}"

            # Save command → (count, link)
            if cmd not in cmd_id_map:
                cmd_id_map[cmd] = [1, kibanaurl]
            else:
                cmd_id_map[cmd][0] += 1  # increment count

        purpose = classify_purpose_from_lookup(member_cmds)

        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": cluster_size,
            "unique": unique_count,
            "commands": [
               (cmd, int(count), kibanaurl) for cmd,
               (count, kibanaurl) in sorted(cmd_id_map.items())]

        })
    return results, ctree