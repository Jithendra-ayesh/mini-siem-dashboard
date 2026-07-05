import json
import os

USERS_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "users",
    "users.json"
)

def load_users():
    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except:
        return []

def authenticate(username, password):
    users = load_users()
    for user in users:
        if (
            user["username"] == username and
            user["password"] == password
        ):
            return user
    return None

def get_user(username):
    users = load_users()
    for user in users:
        if user["username"] == username:
            return user

    return None
