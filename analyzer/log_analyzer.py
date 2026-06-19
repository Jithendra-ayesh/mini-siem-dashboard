import json
import os
from collections import Counter
from datetime import datetime

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
        "failed_logins": failed_logins,
        "recent_events": logs[::-1][:50]
    }

def analyze_top_ips():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    ip_counter = Counter()

    for log in logs:
        ip_counter[log["ip_address"]] += 1

    return ip_counter.most_common(5)

def analyze_top_usernames():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    username_counter = Counter()

    for log in logs:

        username_counter[
            log["username"]
        ] += 1

    return username_counter.most_common(5)

def analyze_daily_activity():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return {}

    daily_counter = Counter()

    for log in logs:

        date = log["timestamp"].split(" ")[0]

        daily_counter[date] += 1

    return dict(daily_counter)

def analyze_hourly_activity():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return {}

    hourly_counter = Counter()

    for log in logs:

        timestamp = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        hour = timestamp.strftime("%H:00")

        hourly_counter[hour] += 1

    return dict(hourly_counter)