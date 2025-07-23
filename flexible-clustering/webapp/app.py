from flask import Flask, render_template, request, jsonify
from clustering.clustering_algorithms import (
    run_clustering,
    run_suricata,
    update_clusters,
    update_suricata_clusters,
    get_current_cluster_state
)

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("clusters.html")

@app.route("/update", methods=["POST"])
def update():
    honeypot = request.form.get("honeypot")
    from_date = request.form.get("from")
    to_date = request.form.get("to")

    if not from_date or not to_date:
        return jsonify({"error": "Missing date range"}), 400

    try:
        if honeypot.lower() == "suricata":
            update_suricata_clusters(from_date, to_date)
        else:
            update_clusters(honeypot, from_date, to_date)
        return jsonify({"message": "Clusters updated successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# @app.route("/clusters")
# def clusters():
#     honeypot = request.args.get("honeypot", default="cowrie")
#     from_date = request.args.get("from") or "2021-04-08T00:00:00.000Z"
#     to_date = request.args.get("to") or "2025-04-08T00:00:00.000Z"
#     limit = request.args.get("limit")

#     if limit == "all" and honeypot.lower() != "suricata":
#         clusters_data, tree = get_current_cluster_state()
#     else:
#         size = int(limit) if limit and limit != "all" else None
#         if honeypot.lower() == "suricata":
#             clusters_data, tree = run_suricata(
#                 honeypot_type=honeypot, from_date=from_date, to_date=to_date, size=size
#             )
#         else:
#             clusters_data, tree = run_clustering(
#                 honeypot_type=honeypot, from_date=from_date, to_date=to_date, size=size
#             )

#     tree_edges = [[str(parent), str(child)] for parent, child, *_ in tree]
#     return jsonify({"clusters": clusters_data, "tree": tree_edges})


@app.route("/clusters")
def clusters():
    honeypot = request.args.get("honeypot", default="cowrie")
    from_date = request.args.get("from") or "2021-04-08T00:00:00.000Z"
    to_date = request.args.get("to") or "2025-04-08T00:00:00.000Z"
    limit = request.args.get("limit")

    if limit == "all" and honeypot.lower() != "suricata":
        # NOTE: you need to update get_current_cluster_state() to also return full_clusters
        clusters_data, full_clusters, tree = get_current_cluster_state()
    else:
        size = int(limit) if limit and limit != "all" else None
        if honeypot.lower() == "suricata":
            clusters_data, tree = run_suricata(from_date=from_date, to_date=to_date, size=size)
            full_clusters = clusters_data  # No pruning needed for Suricata
        else:
            clusters_data, full_clusters, tree = run_clustering(
                honeypot_type=honeypot, from_date=from_date, to_date=to_date, size=size
            )

    tree_edges = [[str(parent), str(child)] for parent, child, *_ in tree]
    return jsonify({
        "clusters": clusters_data,
        "full_tree_clusters": full_clusters,
        "tree": tree_edges
    })


if __name__ == "__main__":
    app.run(debug=True)
