import json

BLOCK_FILE = "logs/blocked_ips.json"

def get_blocked_ips():

    try:
        with open(BLOCK_FILE, "r") as file:
            return json.load(file)

    except:
        return []

def is_ip_blocked(ip):

    blocked_ips = get_blocked_ips()

    for blocked in blocked_ips:

        if blocked["ip"] == ip:
            return True

    return False