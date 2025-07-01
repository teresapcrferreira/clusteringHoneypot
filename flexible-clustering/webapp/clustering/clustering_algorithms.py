from collections import defaultdict
import pandas as pd
from fish.fishdbc import FISHDBC

from .elastic import connect_to_elasticsearch
from .preprocessing import is_real_command, abstract_command_line_substitution, classify_purpose_from_lookup
from .similarity import distance_func
from .config import kiburl
from .load_data import load_command_resources

_, _, _, suricata_purpose_lookup = load_command_resources()


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
    df = fetch_cowrie_data(honeypot_type, from_date, to_date, size=size)

    df = df[df['input'].notna()]
    commands = df['input'].values
    filtered_commands = [(i, cmd) for i, cmd in enumerate(commands) if is_real_command(cmd)]
    abstracts = [abstract_command_line_substitution(cmd) for _, cmd in filtered_commands]

    fishdbc = FISHDBC(distance_func())
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()

    clusters = defaultdict(set)
    for parent, child, _, child_size in ctree[::-1]:
        if child_size == 1:
            clusters[parent].add(child)
        else:
            clusters[parent].update(clusters[child])

    child_to_parent = {child: parent for parent, child, *_ in ctree}

    results = []
    for cluster_id, members in sorted(clusters.items()):
        parent = child_to_parent.get(cluster_id, "ROOT")
        member_cmds = [filtered_commands[member][1] for member in members]
        cmd_id_map = {}

        for idx in members:
            orig_idx, cmd = filtered_commands[idx]
            doc_id = df.iloc[orig_idx]['_id']
            index_name = df.iloc[orig_idx]['_index']
            kibanaurl = f"{kiburl}{index_name}?id={doc_id}"
            if cmd not in cmd_id_map:
                cmd_id_map[cmd] = [1, kibanaurl]
            else:
                cmd_id_map[cmd][0] += 1

        purpose = classify_purpose_from_lookup(member_cmds)
        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": len(members),
            "unique": len(set(member_cmds)),
            "commands": [
                (cmd, count, url) for cmd, (count, url) in sorted(cmd_id_map.items())
            ]
        })

    return results, ctree


def run_suricata(honeypot_type="Suricata", from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=None):
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
    sig_to_purpose = suricata_purpose_lookup

    df["purpose"] = df["signature"].map(sig_to_purpose).fillna("Unknown")
    commands = df["signature"].fillna("Unknown")
    abstracts = commands.values

    distance_func_suricata = lambda a, b, k=3: (
        (lambda A, B: 0.0 if not (A or B) else 1 - len(A & B) / len(A | B))(
            {a[i:i+k] for i in range(len(a) - k + 1)},
            {b[i:i+k] for i in range(len(b) - k + 1)}
        )
    )

    fishdbc = FISHDBC(distance_func_suricata)
    fishdbc.update(abstracts)
    _, _, _, ctree, _, _ = fishdbc.cluster()

    clusters = defaultdict(set)
    for parent, child, *_ in ctree:
        clusters[int(parent)].add(int(child))

    def collect_members(cluster_id):
        if cluster_id < len(abstracts):
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

    return results, ctree
