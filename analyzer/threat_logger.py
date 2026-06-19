import json
from datetime import datetime

THREAT_FILE = "logs/threat_history.json"


def log_threat(
        severity,
        threat_type,
        ip,
        username,
        reason,
        impact):

    try:

        with open(THREAT_FILE, "r") as file:
            threats = json.load(file)

    except:
        threats = []

    for threat in reversed(threats):
        if (
            threat["ip"] == ip and
            threat["threat_type"] == threat_type and
            threat["status"] == "OPEN"
        ):
            return

    threats.append({

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "severity": severity,
        "threat_type": threat_type,
        "ip": ip,
        "username": username,
        "reason": reason,
        "impact": impact,
        "status": "OPEN"
    })

    with open(THREAT_FILE, "w") as file:
        json.dump(threats, file, indent=4)