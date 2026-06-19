import json
import os
from datetime import datetime, timedelta
from analyzer.threat_logger import log_threat

LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "security_logs.json"
)

def is_recent(timestamp_str, minutes=5):

    log_time = datetime.strptime(
        timestamp_str,
        "%Y-%m-%d %H:%M:%S"
    )

    return log_time >= (
        datetime.now() - timedelta(minutes=minutes)
    )

def detect_credential_stuffing():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    alerts = []

    failed_attempts = {}

    for log in logs:

        if log["event_type"] != "LOGIN_FAILED":
            continue
        if not is_recent(log["timestamp"]):
            continue

        key = (
            log["ip_address"],
            log["username"]
        )

        failed_attempts[key] = (
            failed_attempts.get(key, 0) + 1
        )

    for (ip, username), count in failed_attempts.items():

        if count >= 5:

            alerts.append({
                "type": "Credential Stuffing",
                "ip": ip,
                "username": username,
                "attempts": count
            })

            log_threat(
                "HIGH",
                "Credential Stuffing",
                ip,
                username,
                f"{count} failed login attempts within 5 minutes",
                "Potential account compromise attempt"
            )

    return alerts

def detect_username_enumeration():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    ip_users = {}

    for log in logs:

        if log["event_type"] != "LOGIN_FAILED":
            continue
        if not is_recent(log["timestamp"]):
            continue

        ip = log["ip_address"]
        username = log["username"]

        if ip not in ip_users:
            ip_users[ip] = set()

        ip_users[ip].add(username)

    alerts = []

    for ip, usernames in ip_users.items():

        if len(usernames) >= 5:

            alerts.append({
                "type": "Username Enumeration",
                "ip": ip,
                "user_count": len(usernames)
            })

            log_threat(
                "MEDIUM",
                "Username Enumeration",
                ip,
                "MULTIPLE_USERS",
                f"{len(usernames)} usernames tested from same IP",
                "Account discovery activity detected"
            )

    return alerts