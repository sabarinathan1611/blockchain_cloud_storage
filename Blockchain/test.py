import requests
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
API_URL = "http://localhost:5000"
headers = {
    "Authorization": jwt.encode({"iss": "test_client"}, JWT_SECRET, algorithm="HS256")
}

# Disable SSL warnings for local testing
requests.packages.urllib3.disable_warnings()



def add_data(data_type, user_email, user_id, content):
    data = {
        "data": {
            "type": data_type,
            "email": user_email,
            "user_id": user_id,
            "content": content
        }
    }
    res = requests.post(f"{API_URL}/add_block", json=data, headers=headers, verify=False)
    print(f"Add {data_type} response:", res.json())



def list_data(endpoint, user_email, user_id):
    data = {"email": user_email, "user_id": user_id}
    res = requests.post(f"{API_URL}/{endpoint}", json=data, headers=headers, verify=False)
    print(f"{endpoint.replace('-', ' ').title()}:", res.json())



if __name__ == "__main__":
    user_email = "user@example.com"
    user_id = "12345"

    # Add password data
    add_data("password", user_email, user_id, "my_secure_password")

    # Add file data
    add_data("file", user_email, user_id, {"filename": "document.pdf", "filehash": "abcdef123456"})

    # List password data
    list_data("password-list", user_email, user_id)

    # List file data
    list_data("filedata-list", user_email, user_id)
