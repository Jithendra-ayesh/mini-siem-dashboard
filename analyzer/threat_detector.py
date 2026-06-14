import json
import os

LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "security_logs.json"
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

    return alerts