import requests

TARGET_URL = "http://127.0.0.1:5000/login"

for i in range(5):

    data = {
        "username": "admin",
        "password": f"wrong{i}"
    }

    requests.post(
        TARGET_URL,
        data=data
    )

    print(
        f"Attempt {i+1} sent"
    )