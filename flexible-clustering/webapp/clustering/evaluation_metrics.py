# Fixed clustering/evaluation_metrics.py

import numpy as np
import pandas as pd
# removed scipy.spatial.distance imports
from sklearn.metrics import silhouette_score
from collections import Counter, defaultdict
import math


def compute_distance_matrix(abstracts, dist_func):
    """
    Given a list of abstracted commands and a distance function,
    compute the full pairwise distance matrix manually.
    abstracts: list of strings
    dist_func: callable(str, str) -> float
    """
    n = len(abstracts)
    # initialize an n x n matrix of zeros
    dist_mat = np.zeros((n, n), dtype=float)
    # fill in pairwise distances
    for i in range(n):
        for j in range(i + 1, n):
            d = dist_func(abstracts[i], abstracts[j])
            dist_mat[i, j] = d
            dist_mat[j, i] = d
    return dist_mat


def compute_silhouette(labels, dist_matrix):
    """
    labels: array of cluster-labels for each point
    dist_matrix: precomputed pairwise distance matrix
    """
    return silhouette_score(dist_matrix, labels, metric="precomputed")


def extract_labels_from_tree(cluster_tree, n_points):
    """
    Reconstruct a flat label assignment from FISHDBC's hierarchical ctree.
    """
    clusters = defaultdict(set)
    for parent, child, *_ in reversed(cluster_tree):
        clusters[parent].add(child)
        if child in clusters:
            clusters[parent].update(clusters[child])

    labels = np.full(n_points, -1, dtype=int)
    for cid, members in clusters.items():
        for m in members:
            if m < n_points:
                labels[m] = cid
    return labels


def compute_tree_metrics(cluster_tree):
    """
    Returns total_clusters, max_depth, leaf_purity.
    """
    parent_to_children = defaultdict(list)
    for parent, child, *_ in cluster_tree:
        parent_to_children[parent].append(child)

    def dfs(node):
        if node not in parent_to_children:
            return 1
        return 1 + max(dfs(c) for c in parent_to_children[node])

    # find top-level roots
    roots = [n for n in parent_to_children
             if all(n not in children for children in parent_to_children.values())]
    max_depth = max(dfs(r) for r in roots)
    total_clusters = len(parent_to_children)
    leaf_purity = sum(1 for childrens in parent_to_children.values() if not childrens)
    return {
        "total_clusters": total_clusters,
        "max_depth": max_depth,
        "leaf_purity": leaf_purity
    }


def compute_purpose_entropy(cluster_results):
    """
    cluster_results: list of dicts, each with a "purpose" key like "Recon + Exec"
    """
    entropies = []
    for c in cluster_results:
        parts = c["purpose"].split(" + ")
        cnt = Counter(parts)
        N = sum(cnt.values())
        H = -sum((v/N) * math.log2(v/N) for v in cnt.values() if v > 0)
        entropies.append(H)
    return {
        "cluster_entropies": entropies,
        "average_entropy": float(np.mean(entropies))
    }


def evaluate_clustering(abstracts, cluster_results, cluster_tree, dist_func):
    """
    Runs silhouette, tree-structure metrics, and purpose entropy
    on one clustering output.
    """
    n = len(abstracts)
    dist_mat = compute_distance_matrix(abstracts, dist_func)
    labels = extract_labels_from_tree(cluster_tree, n)

    sil = compute_silhouette(labels, dist_mat)
    tree_m = compute_tree_metrics(cluster_tree)
    ent = compute_purpose_entropy(cluster_results)

    return {
        "silhouette": sil,
        **tree_m,
        **ent
    }

# If you need to run this as a script, import run_clustering and similarity:
if __name__ == "__main__":
    from .clustering_algorithms import run_clustering
    from .similarity import distance_func
    from .preprocessing import abstract_command_line_substitution
    
    # run clustering
    cluster_results, cluster_tree = run_clustering()
    # rebuild abstracts
    from .clustering_algorithms import filtered_commands_global
    abstracts = [abstract_command_line_substitution(cmd) for _, cmd in filtered_commands_global]

    sem_metrics = evaluate_clustering(abstracts, cluster_results, cluster_tree, distance_func())

    from Levenshtein import distance as lev_dist
    baseline = lambda a,b: lev_dist(a,b)/max(len(a),len(b),1)
    base_metrics = evaluate_clustering(abstracts, cluster_results, cluster_tree, baseline)

    print(pd.Series(sem_metrics))
    print(pd.Series(base_metrics))
