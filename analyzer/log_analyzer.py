import json
import os
from collections import Counter
from datetime import datetime, timedelta
from analyzer.threat_history import load_threat_history

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

def analyze_top_ips(days=7):

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    ip_counter = Counter()

    if days != "all":

        cutoff = datetime.now() - timedelta(
            days=int(days)
        )

    for log in logs:

        timestamp = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        if days != "all" and timestamp < cutoff:
            continue

        ip_counter[log["ip_address"]] += 1

    return ip_counter.most_common(10)

def analyze_top_usernames(days=7):

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    username_counter = Counter()

    if days != "all":

        cutoff = datetime.now() - timedelta(
            days=int(days)
        )

    for log in logs:

        timestamp = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        if days != "all" and timestamp < cutoff:
            continue

        username_counter[log["username"]] += 1

    return username_counter.most_common(10)

def analyze_daily_activity(days=7):

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return {}

    daily_counter = Counter()

    if days != "all":

        cutoff = datetime.now() - timedelta(
            days=int(days)
        )

    for log in logs:

        timestamp = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        if days != "all" and timestamp < cutoff:
            continue

        date = timestamp.strftime("%Y-%m-%d")

        daily_counter[date] += 1

    return dict(daily_counter)

def analyze_hourly_activity(selected_day=None, days=7):

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)
    except:
        return {}

    hourly_counter = Counter()

    if selected_day is None:
        selected_day = datetime.now().strftime("%Y-%m-%d")

    if days != "all":
        cutoff = datetime.now() - timedelta(days=int(days))

    for log in logs:

        timestamp = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        if days != "all" and timestamp < cutoff:
            continue

        if timestamp.strftime("%Y-%m-%d") != selected_day:
            continue

        hour = timestamp.strftime("%H:00")

        hourly_counter[hour] += 1

    return dict(hourly_counter)

def analyze_threat_distribution():

    threats = load_threat_history()
    counts = {}

    for threat in threats:
        threat_type = threat["threat_type"]
        counts[threat_type] = (
            counts.get(threat_type, 0) + 1
        )

    return counts

def get_all_ips():

    try:
        with open("logs/security_logs.json", "r") as file:
            logs = json.load(file)

    except:
        return []

    counter = Counter()

    for log in logs:
        counter[log["ip_address"]] += 1

    return counter.most_common()


def get_all_usernames():

    try:
        with open("logs/security_logs.json", "r") as file:
            logs = json.load(file)

    except:
        return []

    counter = Counter()

    for log in logs:
        counter[log["username"]] += 1

    return counter.most_common()

def analyze_hourly_activity_by_day(selected_day):

    try:

        with open("logs/security_logs.json", "r") as file:
            logs = json.load(file)

    except:
        return {}

    hourly = {
        f"{hour:02d}": 0
        for hour in range(24)
    }

    for log in logs:

        date = log["timestamp"][:10]

        if date != selected_day:
            continue

        hour = log["timestamp"][11:13]

        hourly[hour] += 1

    return hourly