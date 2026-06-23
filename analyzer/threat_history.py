import json

THREAT_FILE = "logs/threat_history.json"

def load_threat_history():
    try:
        with open(THREAT_FILE, "r") as file:
            return json.load(file)
    except:
        return []
    
def mark_ip_blocked(ip):

    try:

        with open(THREAT_FILE, "r") as file:
            threats = json.load(file)

    except:
        return

    for threat in threats:

        if (
            threat["ip"] == ip and
            threat["status"] == "OPEN"
        ):

            threat["status"] = "BLOCKED"

    with open(THREAT_FILE, "w") as file:
        json.dump(threats, file, indent=4)