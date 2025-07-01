from elasticsearch import Elasticsearch
from collections import defaultdict
import pandas as pd
from fish.fishdbc import FISHDBC

from .preprocessing import is_real_command, abstract_command_line_substitution, classify_purpose_from_lookup
from .similarity import distance_func
from .load_data import kiburl, url, user, pwd


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
    # Store (original_index, command)
    filtered_commands = [(i, cmd) for i, cmd in enumerate(commands) if is_real_command(cmd)]


    # Recompute abstracts over the filtered list
    abstracts = [abstract_command_line_substitution(cmd) for i, cmd in filtered_commands]
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
        member_cmds = [cmd for _, cmd in [filtered_commands[member] for member in members]]
        cluster_size = len(members)
        unique_count = len(set(member_cmds))
        cmd_id_map = {}
        cmd_display_map = {}

        for idx in members:
            orig_idx, cmd = filtered_commands[idx]
            cmd_display_map[cmd] = cmd_display_map.get(cmd, []) + [orig_idx]
            doc_id = df.iloc[orig_idx]['_id']
            index_name = df.iloc[orig_idx]['_index']
            kibanaurl = kiburl + f"{index_name}?id={doc_id}"
            # print("alert: ", cmd, " ----> Id: ", doc_id, "  ----> IndexName: ", index_name)
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
            (cmd, int(count), kurl) for cmd, (count, kurl) in sorted(cmd_id_map.items())
            ]



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
    # Store (original_index, command)
    filtered_commands = [(i, cmd) for i, cmd in enumerate(commands) if is_real_command(cmd)]


    # Recompute abstracts over the filtered list
    abstracts = [abstract_command_line_substitution(cmd) for i, cmd in filtered_commands]
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
        member_cmds = [cmd for _, cmd in [filtered_commands[member] for member in members]]
        cluster_size = len(members)
        unique_count = len(set(member_cmds))
        cmd_id_map = {}
        cmd_display_map = {}

        for idx in members:
            orig_idx, cmd = filtered_commands[idx]
            cmd_display_map[cmd] = cmd_display_map.get(cmd, []) + [orig_idx]
            doc_id = df.iloc[orig_idx]['_id']
            index_name = df.iloc[orig_idx]['_index']
            kibanaurl = kiburl + f"{index_name}?id={doc_id}"
            # print("alert: ", cmd, " ----> Id: ", doc_id, "  ----> IndexName: ", index_name)
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
            (cmd, int(count), kurl) for cmd, (count, kurl) in sorted(cmd_id_map.items())
            ]



        })

    return results, ctree


def run_suricata(
    honeypot_type="Suricata",
    from_date="2021-04-08T00:00:00.000Z",
    to_date="2025-04-08T00:00:00.000Z",
    size=10000
):
    from collections import defaultdict

    es = Elasticsearch(url, basic_auth=(user, pwd))
    if not es.ping():
        raise RuntimeError("Could not connect to Elasticsearch")

    # ---- Suricata-specific query ----
    query = {
        "bool": {
            "must": [],
            "filter": [
                {
                    "bool": {
                        "should": [
                            {"match_phrase": {"event_type": "alert"}}
                        ],
                        "minimum_should_match": 1
                    }
                },
                {
                    "exists": {"field": "alert.signature"}
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

    result = es.search(
        index="logstash-*",
        body={"query": query},
        size=size,
        request_timeout=30
    )

    docs = result['hits']['hits']
    df = pd.DataFrame([{
        **doc['_source'],
        '_id': doc['_id'],
        '_index': doc['_index']
    } for doc in docs])

    if df.empty:
        return [], []

    # ---- Add signature + purpose ----
    df["signature"] = df["alert"].apply(lambda d: d.get("signature") if isinstance(d, dict) else None)

    # Load purpose mapping
    try:
        sig_df = pd.read_csv("databases/signature_purposes.csv")
        sig_to_purpose = dict(zip(sig_df["signature"], sig_df["purpose"]))
    except Exception:
        sig_to_purpose = {}

    df["purpose"] = df["signature"].map(sig_to_purpose).fillna("Unknown")

    commands = df["signature"].fillna("Unknown")
    abstracts = commands.values

    # ---- Distance function: trigram Jaccard similarity ----
    distance_func = lambda a, b, k=3: (
        (lambda A, B: 0.0 if not (A or B) else 1 - len(A & B) / len(A | B))(
            {a[i:i+k] for i in range(len(a) - k + 1)},
            {b[i:i+k] for i in range(len(b) - k + 1)}
        )
    )

    fishdbc = FISHDBC(distance_func)
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()

    # ---- Step 1: parent → children ----
    clusters = defaultdict(set)
    for parent_np, child_np, _, _ in ctree:
        parent = int(parent_np)
        child = int(child_np)
        clusters[parent].add(child)

    # ---- Step 2: collect members recursively ----
    def collect_members(cluster_id):
        if cluster_id < len(abstracts):  # leaf node
            return [cluster_id]
        members = []
        for child in clusters.get(cluster_id, []):
            members.extend(collect_members(child))
        return members

    # ---- Step 3: build result objects ----
    results = []
    for cluster_id in sorted(clusters.keys()):
        member_ids = collect_members(cluster_id)
        if len(member_ids) <= 1:
            continue 

        parent = next((int(p) for p, children in clusters.items() if cluster_id in children), "ROOT")
        cmd_map = {}

        for idx in member_ids:
            sig = commands.iloc[idx]
            row = df.iloc[idx]
            kurl = f"{kiburl}{row['_index']}/_source?id={row['_id']}"
            cnt, first_url = cmd_map.get(sig, (0, kurl))
            cmd_map[sig] = (cnt + 1, first_url)

        member_purposes = sorted({
            df.iloc[idx]['purpose']
            for idx in member_ids
            if df.iloc[idx].get('purpose') and df.iloc[idx]['purpose'] != "Unknown"
        })
        purpose = " + ".join(member_purposes) if member_purposes else "Unknown"

        commands_list = [
            (
                sig,
                cnt,
                first_url,
                list(dict.fromkeys(
                    df.iloc[idx]['purpose']
                    for idx in member_ids
                    if commands.iloc[idx] == sig
                    and df.iloc[idx].get('purpose')
                    and df.iloc[idx]['purpose'] != "Unknown"
                ))
            )
            for sig, (cnt, first_url) in sorted(cmd_map.items())
        ]

        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": len(member_ids),
            "unique": len(cmd_map),
            "commands": commands_list
        })

    return results, ctree
