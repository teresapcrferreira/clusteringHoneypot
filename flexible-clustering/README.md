# Clustering Honeypot Alerts

This repository contains the research, code, and documentation for my Master’s thesis project at TU/e in collaboration with Forescout. The goal of the project is to **automatically generate contextualized threat intelligence** by clustering indicators of compromise (IoCs) extracted from honeypot alerts.

## To Run

``python setup.py build_ext --inplace`` on flexible-clustering folder
``python -m webapp.app`` on the same folder

## Objectives

- Extract and process IoCs from honeypots
- Use unsupervised clustering methods (e.g., FISHDBC) to group related events
- Incorporate a human-in-the-loop for contextual labeling of clusters
- Support incremental data processing and time-based tracking of clusters
- Generate structured, contextualized output


## Tools

- Python 
- Elasticsearch
- FISHDBC (Flexible, Incremental, Scalable, Hierarchical Density-Based Clustering)
- Custom honeypots (e.g., Cowrie, ADBHoney)


## Repository Structure
```
.
├── README.md
├── flexible-clustering
│   ├── LICENSE
│   ├── README.rst
│   ├── flexible_clustering
│   │   ├── extsort.py
│   │   ├── fishdbc.py
│   │   ├── fishdbc_example.py
│   │   ├── hnsw.py
│   │   ├── hnsw_optics.py
│   │   ├── hnsw_optics_cachefile.py
│   │   ├── optics.py
│   │   ├── pdict.py
│   │   ├── plot_optics.py
│   │   ├── unionfind.c
│   │   └── unionfind.pyx
│   ├── setup.cfg
│   ├── setup.py
│   └── webapp
│       ├── SmallAnalysis-AdbHoney.ipynb
│       ├── SmallAnalysis-Cowrie.ipynb
│       ├── SmallAnalysis-Suricata.ipynb
│       ├── TFIDF thing.ipynb
│       ├── app.py
│       ├── clustering.py
│       ├── commands_cleaned.csv
│       ├── finalissimoCommands.csv
│       ├── finalissimoSim.csv
│       ├── linux commands.ipynb
│       ├── static
│       │   └── styles.css
│       └── templates
│           └── clusters.html
```
