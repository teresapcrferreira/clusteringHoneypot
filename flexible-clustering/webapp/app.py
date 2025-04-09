from flask import Flask, render_template, request, jsonify
from clustering import run_clustering

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("clusters.html")

@app.route("/clusters")
def clusters():
    honeypot = request.args.get("honeypot", "cowrie")
    from_date = request.args.get("from") or "2021-04-08T00:00:00.000Z"
    to_date = request.args.get("to") or "2025-04-08T00:00:00.000Z"
    # ttp_filter = request.args.get("ttp_filter", "").strip.lower()

    clusters = run_clustering(honeypot, from_date, to_date)
    return jsonify(clusters)

if __name__ == "__main__":
    app.run(debug=True)
