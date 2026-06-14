import json
import os

LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "security_logs.json"
)


def analyze_logs():

    try:

        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        logs = []

    total_events = len(logs)

    successful_logins = sum(
        1 for log in logs
        if log["event_type"] == "LOGIN_SUCCESS"
    )

    failed_logins = sum(
        1 for log in logs
        if log["event_type"] == "LOGIN_FAILED"
    )

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins
    }