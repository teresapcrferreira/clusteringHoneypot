from elasticsearch import Elasticsearch
from .config import ES_URL, ES_USER, ES_PASS

def connect():
    es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))
    if not es.ping():
        raise RuntimeError("Elasticsearch connection failed.")
    return es
