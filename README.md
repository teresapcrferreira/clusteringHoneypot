# Clustering Honeypot Alerts

This repository contains the research, code, and documentation for my Master’s thesis project at TU/e in collaboration with Forescout. The goal of the project is to **automatically generate contextualized threat intelligence** by clustering indicators of compromise  extracted from honeypot alerts.

## To Run

-- update this

``python setup.py build_ext --inplace`` on webapp

``cd flexible-clustering/webapp`` 

``python app.py`` on the same folder

## Objectives

- Extract and process IoCs from honeypots
- Use unsupervised clustering methods to group related events
- Incorporate a human-in-the-loop for contextual labeling of clusters
- Support incremental data processing and time-based tracking of clusters
- Generate structured, contextualized output


## Tools

- Python 
- Elasticsearch
- FISHDBC (Flexible, Incremental, Scalable, Hierarchical Density-Based Clustering)
- Custom honeypots (Cowrie, ADBHoney and Suricata)


## Repository Structure
```
.
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── .gitignore
├── flexible-clustering/
│   └── webapp/
│       ├── clustering/          # Core functionality for clustering
│       │   ├── __init__.py
│       │   ├── config.py        # Thresholds, paths, environment settings
│       │   ├── elastic.py       # Elasticsearch-related functions
│       │   ├── load_data.py     # CSV/similarity/purpose DB loaders
│       │   ├── preprocessing.py # Command cleaning, abstraction, etc.
│       │   ├── similarity.py    # Geometric Distance Computations
│       │   └── clustering_algorithms.py  # Clustering 
│
│       ├── databases/           # Supporting data files
│       │   ├── UpdatedSimilarity.csv
│       │   ├── UpdatedCommandDB.csv
│       │   ├── signature_purposes.csv
│       │   ├── sid_to_mitre_mapping.csv
│       │   └── commands_cleaned.csv
│
│       ├── fish/                # FISHDBC implementation
│
│       ├── static/              # CSS
│       │   └── styles.css
│
│       ├── templates/           # HTML
│       │   ├── clusters.html
│       │   ├── _filters.html
│       │   ├── _head.html
│       │   ├── _scripts.html
│       │   └── _mini_map.html
|
|       ├── app.py                       # Entry point to launch Flask app
|       ├── setup.py                     # Build fishdbc if not already

```
`fish` folder contains the files for FISHDBC algorihtm.