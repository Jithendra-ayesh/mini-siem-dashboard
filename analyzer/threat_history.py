import json

THREAT_FILE = "logs/threat_history.json"

def load_threat_history():
    try:
        with open(THREAT_FILE, "r") as file:
            return json.load(file)
    except:
        return []