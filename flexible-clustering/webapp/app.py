from flask import Flask, render_template, request, jsonify
from clustering import run_clustering, run_clustering_simple

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("clusters.html")

@app.route("/clusters")
def clusters():
    honeypot = request.args.get("honeypot", "cowrie")
    from_date = request.args.get("from") or "2021-04-08T00:00:00.000Z"
    to_date = request.args.get("to") or "2025-04-08T00:00:00.000Z"
    limit     = request.args.get("limit")
    if limit == "all":
        clusters, tree = run_clustering(honeypot, from_date, to_date)
    else:
        size = int(limit)
        clusters, tree = run_clustering_simple(honeypot, from_date, to_date, size=size)
    tree_edges = [[str(parent), str(child)] for parent, child, *_ in tree]

    return jsonify({
        "clusters": clusters,
        "tree": tree_edges
    })

if __name__ == "__main__":
    app.run(debug=True)