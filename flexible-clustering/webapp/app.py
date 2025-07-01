from flask import Flask, render_template, request, jsonify
from clustering.clustering_algorithms import run_clustering, run_clustering_simple, run_suricata

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("clusters.html")

@app.route("/clusters")
def clusters():
    honeypot = request.args.get("honeypot", default="cowrie")
    from_date = request.args.get("from") or "2021-04-08T00:00:00.000Z"
    to_date = request.args.get("to") or "2025-04-08T00:00:00.000Z"
    limit = request.args.get("limit")

    if limit == "all":
        clusters, tree = run_clustering(honeypot, from_date, to_date)
    elif limit:
        size = int(limit)
        if honeypot.lower() == "suricata":
            clusters, tree = run_suricata(honeypot, from_date, to_date, size=size)
        else:
            clusters, tree = run_clustering_simple(honeypot, from_date, to_date, size=size)
    else:
        size = 1000
        clusters, tree = run_clustering_simple(honeypot, from_date, to_date, size=size)

    tree_edges = [[str(parent), str(child)] for parent, child, *_ in tree]

    return jsonify({
        "clusters": clusters,
        "tree": tree_edges
    })

if __name__ == "__main__":
    app.run(debug=True)
