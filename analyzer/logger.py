import json
import os
from datetime import datetime


LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "security_logs.json"
)


def log_event(event_type, username, ip_address):

    event = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address
    }

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        logs = []

    logs.append(event)

    with open(LOG_FILE, "w") as file:
        json.dump(logs, file, indent=4)