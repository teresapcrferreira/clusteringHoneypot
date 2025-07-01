from dotenv import load_dotenv
import os
load_dotenv()

KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_SPACE = os.getenv("KIBANA_SPACE")
kiburl = f"{KIBANA_URL}/app/discover#/doc/{KIBANA_SPACE}/"
ES_URL = os.getenv("ELASTICSEARCH_URL")
ES_USER = os.getenv("ELASTICSEARCH_USER")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD")
