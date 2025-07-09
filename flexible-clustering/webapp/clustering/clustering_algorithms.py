from collections import defaultdict
import pandas as pd
from fish.fishdbc import FISHDBC

from .elastic import connect_to_elasticsearch
from .preprocessing import is_real_command, abstract_command_line_substitution, classify_purpose_from_lookup
from .similarity import distance_func
from .config import kiburl
from .load_data import load_command_resources

_, _, _, suricata_purpose_lookup = load_command_resources()

fishdbc_global = None
filtered_commands_global = []
df_global = None
cluster_tree_global = []

fishdbc_suricata = None
suricata_df_global = None
suricata_tree_global = []
suricata_commands_global = []


def fetch_cowrie_data(honeypot_type, from_date, to_date, size=None):
    es = connect_to_elasticsearch()
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

    if size is not None:
        result = es.search(body={"query": query}, size=size, request_timeout=30)
        docs = result['hits']['hits']
    else:
        page = es.search(index="logstash-*", body={"query": query}, scroll="2m", size=1000)
        sid = page["_scroll_id"]
        docs = page["hits"]["hits"]

        while True:
            page = es.scroll(scroll_id=sid, scroll="2m")
            hits = page["hits"]["hits"]
            if not hits:
                break
            docs.extend(hits)
            sid = page["_scroll_id"]
        es.clear_scroll(body={"scroll_id": sid})

    return pd.DataFrame([{
        **doc['_source'],
        '_id': doc['_id'],
        '_index': doc['_index']
    } for doc in docs])


def run_clustering(honeypot_type="cowrie", from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=10000):
    global fishdbc_global, filtered_commands_global, df_global, cluster_tree_global

    df = fetch_cowrie_data(honeypot_type, from_date, to_date, size=size)
    df = df[df['input'].notna()]
    commands = df['input'].values
    filtered_commands = [(i, cmd) for i, cmd in enumerate(commands) if is_real_command(cmd)]
    abstracts = [abstract_command_line_substitution(cmd) for _, cmd in filtered_commands]

    fishdbc_global = FISHDBC(distance_func())
    fishdbc_global.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc_global.cluster()

    filtered_commands_global = filtered_commands
    df_global = df
    cluster_tree_global = ctree

    return build_cluster_results(filtered_commands, df, ctree), ctree


def update_clusters(honeypot_type, from_date, to_date):
    global fishdbc_global, filtered_commands_global, df_global, cluster_tree_global
    if fishdbc_global is None:
        return

    df_new = fetch_cowrie_data(honeypot_type, from_date, to_date)
    df_new = df_new[df_new['input'].notna()]
    commands = df_new['input'].values
    filtered_commands = [(i + len(df_global), cmd) for i, cmd in enumerate(commands) if is_real_command(cmd)]
    abstracts = [abstract_command_line_substitution(cmd) for _, cmd in filtered_commands]

    fishdbc_global.update(abstracts)
    filtered_commands_global += filtered_commands
    df_global = pd.concat([df_global, df_new], ignore_index=True)
    _, _, _, cluster_tree_global, _, _ = fishdbc_global.cluster()


# def build_cluster_results(filtered_commands, df, ctree):
#     clusters = defaultdict(set)
#     for parent, child, _, child_size in ctree[::-1]:
#         if child_size == 1:
#             clusters[parent].add(child)
#         else:
#             clusters[parent].update(clusters[child])

#     child_to_parent = {child: parent for parent, child, *_ in ctree}
#     results = []
#     for cluster_id, members in sorted(clusters.items()):
#         parent = child_to_parent.get(cluster_id, "ROOT")
#         member_cmds = [filtered_commands[member][1] for member in members]
#         cmd_id_map = {}

#         for idx in members:
#             orig_idx, cmd = filtered_commands[idx]
#             doc_id = df.iloc[orig_idx]['_id']
#             index_name = df.iloc[orig_idx]['_index']
#             kibanaurl = f"{kiburl}{index_name}?id={doc_id}"
#             if cmd not in cmd_id_map:
#                 cmd_id_map[cmd] = [1, kibanaurl]
#             else:
#                 cmd_id_map[cmd][0] += 1

#         purpose = classify_purpose_from_lookup(member_cmds)
#         results.append({
#             "id": int(cluster_id),
#             "parent": str(parent),
#             "purpose": purpose,
#             "size": len(members),
#             "unique": len(set(member_cmds)),
#             "commands": [(cmd, count, url) for cmd, (count, url) in sorted(cmd_id_map.items())]
#         })
#     return results

def build_cluster_results(filtered_commands, df, ctree):
    cluster_sets = defaultdict(set)
    for parent, child, _, child_size in reversed(ctree):
        if child_size == 1:
            cluster_sets[parent].add(child)
        else:
            cluster_sets[parent].update(cluster_sets[child])

    cluster_cmd_sets = {
        cid: set(filtered_commands[i][1] for i in members)
        for cid, members in cluster_sets.items()
    }

    child_to_parent = {child: parent for parent, child, *_ in ctree}
    parent_to_children = defaultdict(set)
    for child, parent in child_to_parent.items():
        parent_to_children[parent].add(child)

    for parent, children in parent_to_children.items():
        for child in children:
            if child in cluster_cmd_sets:
                cluster_cmd_sets[parent] -= cluster_cmd_sets[child]


    results = []
    for cluster_id, command_set in sorted(cluster_cmd_sets.items()):
        if not command_set:
            continue  


        members = cluster_sets[cluster_id]
        parent = child_to_parent.get(cluster_id, "ROOT")
        cmd_id_map = {}

        for idx in members:
            orig_idx, cmd = filtered_commands[idx]
            if cmd not in command_set:
                continue  
            doc_id = df.iloc[orig_idx]['_id']
            index_name = df.iloc[orig_idx]['_index']
            kibanaurl = f"{kiburl}{index_name}?id={doc_id}"
            # if cmd not in cmd_id_map:
            #     cmd_id_map[cmd] = [1, kibanaurl]
            # else:
            #     cmd_id_map[cmd][0] += 1

            timestamp = df.iloc[orig_idx]['@timestamp']
            source_ip = df.iloc[orig_idx].get('src_ip', 'N/A')

            if cmd not in cmd_id_map:
                cmd_id_map[cmd] = {
                    "count": 1,
                    "url": kibanaurl,
                    "timestamps": [timestamp],
                    "ips": {source_ip},
                }
            else:
                cmd_id_map[cmd]["count"] += 1
                cmd_id_map[cmd]["timestamps"].append(timestamp)
                cmd_id_map[cmd]["ips"].add(source_ip)


        purpose = classify_purpose_from_lookup(command_set)
        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": len(members),
            "unique": len(command_set),
            "commands": [
                (
                    cmd,
                    data["count"],
                    data["url"],
                    sorted(data["ips"]),
                    min(data["timestamps"]),
                    max(data["timestamps"])
                )
                for cmd, data in sorted(cmd_id_map.items())
            ]

        })

    return results




def get_current_cluster_state():
    global filtered_commands_global, df_global, cluster_tree_global
    return build_cluster_results(filtered_commands_global, df_global, cluster_tree_global), cluster_tree_global


def run_suricata(from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=None):
    global fishdbc_suricata, suricata_df_global, suricata_tree_global, suricata_commands_global

    es = connect_to_elasticsearch()
    query = {
        "bool": {
            "must": [],
            "filter": [
                {"bool": {"should": [{"match_phrase": {"event_type": "alert"}}], "minimum_should_match": 1}},
                {"exists": {"field": "alert.signature"}},
                {"range": {"@timestamp": {"format": "strict_date_optional_time", "gte": from_date, "lte": to_date}}}
            ]
        }
    }

    if size is not None:
        result = es.search(index="logstash-*", body={"query": query}, size=size, request_timeout=30)
        docs = result['hits']['hits']
    else:
        page = es.search(index="logstash-*", body={"query": query}, scroll="2m", size=1000)
        sid = page["_scroll_id"]
        docs = page["hits"]["hits"]

        while True:
            page = es.scroll(scroll_id=sid, scroll="2m")
            hits = page["hits"]["hits"]
            if not hits:
                break
            docs.extend(hits)
            sid = page["_scroll_id"]
        es.clear_scroll(body={"scroll_id": sid})

    df = pd.DataFrame([{
        **doc['_source'],
        '_id': doc['_id'],
        '_index': doc['_index']
    } for doc in docs])

    if df.empty:
        return [], []

    df["signature"] = df["alert"].apply(lambda d: d.get("signature") if isinstance(d, dict) else None)
    df["purpose"] = df["signature"].map(suricata_purpose_lookup).fillna("Unknown")
    commands = df["signature"].fillna("Unknown")
    abstracts = commands.values

    def jaccard_distance(a, b, k=3):
        A = {a[i:i+k] for i in range(len(a) - k + 1)}
        B = {b[i:i+k] for i in range(len(b) - k + 1)}
        return 1 - len(A & B) / len(A | B) if A or B else 0.0

    fishdbc_suricata = FISHDBC(jaccard_distance)
    fishdbc_suricata.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc_suricata.cluster()

    suricata_df_global = df
    suricata_commands_global = commands
    suricata_tree_global = ctree

    return build_suricata_results(df, commands, ctree), ctree


def build_suricata_results(df, commands, ctree):
    clusters = defaultdict(set)
    for parent, child, *_ in ctree:
        clusters[int(parent)].add(int(child))

    def collect_members(cluster_id):
        if cluster_id < len(commands):
            return [cluster_id]
        members = []
        for child in clusters.get(cluster_id, []):
            members.extend(collect_members(child))
        return members

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

    return results


def update_suricata_clusters(from_date, to_date):
    return run_suricata(from_date, to_date)
