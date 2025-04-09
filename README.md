# Clustering Honeypot Alerts

This repository contains the research, code, and documentation for my Master’s thesis project at TU/e in collaboration with Forescout. The goal of the project is to **automatically generate contextualized threat intelligence** by clustering indicators of compromise (IoCs) extracted from honeypot alerts.



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

├── README.md                     # Project overview and documentation
└── flexible-clustering/         # Main source code and clustering logic
    └── webapp/                  # Flask-based web interface for cluster exploration