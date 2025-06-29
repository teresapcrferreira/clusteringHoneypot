# Clustering Honeypot Alerts

This repository contains the research, code, and documentation for my Master’s thesis project at TU/e in collaboration with Forescout. The goal of the project is to **automatically generate contextualized threat intelligence** by clustering indicators of compromise  extracted from honeypot alerts.

## To Run

``python setup.py build_ext --inplace`` on fish folder

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
- Custom honeypots (e.g., Cowrie, ADBHoney and Suricata)


## Repository Structure
```
.
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── setup.py
├── flexible-clustering
│   └── webapp
│       ├── databases/
│       │   ├── commands_cleaned.csv
│       │   ├── sid_to_mitre_mapping.csv
│       │   ├── signature_purposes.csv
│       │   ├── UpdatedCommandDB.csv
│       │   └── UpdatedSimilarity.csv
│       ├── fish/ 
│       ├── static/
│       │   └── styles.css
│       ├── templates/
│       │   └── clusters.html
│       ├── app.py
│       ├── clustering.py
│       └── setup.py

```
`fish` folder contains the files for FISHDBC algorihtm.