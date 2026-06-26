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

def detect_brute_force():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    failed_attempts = {}
    alerts = []

    for log in logs:

        if log["event_type"] != "LOGIN_FAILED":
            continue

        if not is_recent(log["timestamp"]):
            continue

        ip = log["ip_address"]

        failed_attempts[ip] = (
            failed_attempts.get(ip, 0) + 1
        )

    for ip, count in failed_attempts.items():

        if count >= 10:
            alerts.append({
                "type": "Brute Force",
                "ip": ip,
                "attempts": count
            })

            log_threat(
                "HIGH",
                "Brute Force Attack",

                ip,
                "MULTIPLE_USERS",
                f"{count} failed login attempts from same IP",
                "Password guessing attack detected"
            )
    return alerts

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

def detect_mixed_attack():

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except:
        return []

    ip_activity = {}
    alerts = []

    for log in logs:

        if log["event_type"] != "LOGIN_FAILED":
            continue

        if not is_recent(log["timestamp"]):
            continue

        ip = log["ip_address"]
        username = log["username"]

        if ip not in ip_activity:

            ip_activity[ip] = {
                "attempts": 0,
                "usernames": set()
            }

        ip_activity[ip]["attempts"] += 1
        ip_activity[ip]["usernames"].add(username)

    for ip, data in ip_activity.items():

        if (
            data["attempts"] >= 10 and
            len(data["usernames"]) >= 5
        ):

            alerts.append({
                "type": "Mixed Attack",
                "ip": ip,
                "attempts": data["attempts"],
                "usernames": len(
                    data["usernames"]
                )
            })

            log_threat(
                "HIGH",
                "Mixed Attack",
                ip,

                "MULTIPLE_USERS",
                f"{data['attempts']} failed attempts against {len(data['usernames'])} usernames",
                "Multiple attack techniques detected from same source"
            )
    return alerts