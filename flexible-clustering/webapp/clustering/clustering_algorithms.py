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
    """
    Fetches command input logs from Elasticsearch for a specific honeypot type (e.g., Cowrie)
    within the provided date range.

    Args:
        honeypot_type (str): Honeypot type to filter (e.g., 'cowrie').
        from_date (str): Start date in ISO format.
        to_date (str): End date in ISO format.
        size (int, optional): Number of results to fetch (non-paginated). If None, uses scroll API.

    Returns:
        pd.DataFrame: DataFrame with results, each row containing `_id`, `_index`, and document content.
    """

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
    """
    Runs the FISHDBC clustering process on Cowrie honeypot command logs.

    Stores global state for future incremental updates. Filters invalid commands,
    abstracts them, clusters using semantic distance, and builds structured results.

    Returns:
        tuple: (cluster_results, cluster_tree) where cluster_results is a list of structured clusters.
    """

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

    ui_clusters = build_cluster_results(filtered_commands, df, ctree, preserve_all_alerts=False)
    full_clusters = build_cluster_results(filtered_commands, df, ctree, preserve_all_alerts=True)


    return ui_clusters, full_clusters, ctree

def update_clusters(honeypot_type, from_date, to_date):
    """
    Incrementally updates existing Cowrie clusters with new data.

    Fetches new data and abstracts commands, then updates the existing FISHDBC model.

    Args:
        honeypot_type (str): Type of honeypot (e.g., 'cowrie').
        from_date (str): Start of update range.
        to_date (str): End of update range.
    """

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

##### This next function is the original function in which the alerts are kept in the parent cluster
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

def build_cluster_results(filtered_commands, df, ctree, preserve_all_alerts=False):

    """
    Converts the raw cluster tree into human-readable structured cluster results.

    Each result contains the parent cluster ID, behavioral purpose, counts, and metadata (Kibana URLs, timestamps, IPs).

    Args:
        filtered_commands (list): List of (index, command) tuples used in clustering.
        df (pd.DataFrame): Original DataFrame with command metadata.
        ctree (list): FISHDBC-generated cluster tree (tuples of parent, child, etc.).

    Returns:
        list: Structured list of cluster dictionaries ready for display or export.
    """

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

    if not preserve_all_alerts:
        # REMOVE children from parent command sets
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
            #### this commented out block is for the original organization of alerts with all alerts in the parents
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

        purpose_to_cmds = defaultdict(list)
        for cmd, data in cmd_id_map.items():
            purpose = classify_purpose_from_lookup([cmd])
            purpose_to_cmds[purpose].append((
                cmd,
                data["count"],
                data["url"],
                len(data["ips"]),
                min(data["timestamps"]),
                max(data["timestamps"])
            ))

        # Sort commands inside each purpose by frequency
        grouped_commands = {
            purpose: sorted(cmds, key=lambda x: -x[1])  # sort by count descending
            for purpose, cmds in sorted(purpose_to_cmds.items())  # sort purposes alphabetically or by priority if needed
        }
        purpose = classify_purpose_from_lookup(command_set)
        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": len(members),
            "unique": len(command_set),
            "grouped_commands": grouped_commands
        })

    return results

def get_current_cluster_state():
    """
    Returns the most recently clustered Cowrie data (and tree) using global variables.

    Returns:
        tuple: (cluster_results, cluster_tree)
    """

    global filtered_commands_global, df_global, cluster_tree_global
    return build_cluster_results(filtered_commands_global, df_global, cluster_tree_global), cluster_tree_global

def run_suricata(from_date="2021-04-08T00:00:00.000Z", to_date="2025-04-08T00:00:00.000Z", size=None):
    """
    Runs clustering on Suricata alert logs (based on `alert.signature` field).

    Uses Jaccard distance on trigram shingles of signature text. Stores global state
    for later inspection or updates.

    Args:
        from_date (str): Start date for fetching alerts.
        to_date (str): End date for fetching alerts.
        size (int, optional): Number of results to fetch (non-paginated). If None, uses scroll API.

    Returns:
        tuple: (cluster_results, cluster_tree) where results are structured descriptions of each cluster.
    """
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
    """
    Structures the Suricata clustering output into a list of dictionaries per cluster.

    Adds command frequency, associated Kibana links, and aggregates semantic 'purpose' labels.

    Args:
        df (pd.DataFrame): DataFrame with Suricata alert logs.
        commands (pd.Series): Series of signature texts used in clustering.
        ctree (list): FISHDBC-generated hierarchical cluster tree.

    Returns:
        list: Structured clusters, each with metadata and semantic interpretation.
    """

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

        # Group by purpose (using suricata_purpose_lookup)
        purpose_to_cmds = defaultdict(list)
        for sig, (cnt, link) in cmd_map.items():
            purpose = suricata_purpose_lookup.get(sig, "Unknown")
            ip_count = len(set(df.iloc[idx].get('src_ip', 'N/A') for idx in member_ids if commands.iloc[idx] == sig))
            timestamps = [df.iloc[idx]['@timestamp'] for idx in member_ids if commands.iloc[idx] == sig]
            
            purpose_to_cmds[purpose].append((
                sig,
                cnt,
                link,
                ip_count,
                min(timestamps),
                max(timestamps)
            ))

        # Sort commands inside each purpose by frequency
        grouped_commands = {
            purpose: sorted(cmds, key=lambda x: -x[1])
            for purpose, cmds in sorted(purpose_to_cmds.items())
        }

        results.append({
            "id": int(cluster_id),
            "parent": str(parent),
            "purpose": purpose,
            "size": len(member_ids),
            "unique": len(cmd_map),
            "grouped_commands": grouped_commands
        })


    return results

def update_suricata_clusters(from_date, to_date):
    """
    Wrapper function to re-run Suricata clustering for a new time window.

    Args:
        from_date (str): Start date.
        to_date (str): End date.

    Returns:
        tuple: (cluster_results, cluster_tree)
    """

    return run_suricata(from_date, to_date)