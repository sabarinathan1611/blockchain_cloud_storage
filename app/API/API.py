import base64
import requests
import os
import jwt
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

class APIManager:
    def __init__(self):
        self.jwt_secret = os.getenv("JWT_SECRET")
        self.api_url = os.getenv("API_URL")
        self.headers = {
            "Authorization": jwt.encode({"iss": "APIManager", "timestamp": datetime.utcnow().isoformat()}, self.jwt_secret, algorithm="HS256")
        }

    @staticmethod
    def encode_base64(data):
        if isinstance(data, bytes):
            return base64.b64encode(data).decode('utf-8')
        return data

    def add_password_data(self, data_type, user_id, user_email, encrypted_key, iv, ciphertext, private_key_path, public_key_path):
        payload = {
            "data": {
                "user_id": user_id,
                "user_email": user_email,
                "type": data_type,
                "encrypted_Key": encrypted_key,
                "iv": iv,
                "ciphertext": ciphertext,
                "private_key_path": private_key_path,
                "public_key_path": public_key_path,
            }
        }

        # Encoding bytes fields to base64
        for key, value in payload["data"].items():
            if isinstance(value, bytes):
                payload["data"][key] = base64.b64encode(value).decode('utf-8')

        res = requests.post(f"{self.api_url}/add_block", json=payload, headers=self.headers, verify=False)
        return f"Add {data_type} response:", res.json()

    def add_file_data(self, data_type, user_id, user_email, filename, filepath, private_key_path, public_key_path, mimetype, iv, encrypted_key):
        payload = {
            "data": {
                "data_type": data_type,
                "user_id": user_id,
                "user_email": user_email,
                "filename": filename,
                "filepath": filepath,
                "private_key_path": private_key_path,
                "public_key_path": public_key_path,
                "mimetype": mimetype,
                "iv": iv,
                "encrypted_key": encrypted_key,
            }
        }

        for key, value in payload["data"].items():
            if isinstance(value, bytes):
                payload["data"][key] = base64.b64encode(value).decode('utf-8')

        res = requests.post(f"{self.api_url}/add_block", json=payload, headers=self.headers, verify=False)
        return f"Add {data_type} response:", res.json()

    def list_data(self, endpoint, user_email, user_id):
        data = {"email": user_email, "user_id": user_id}
        res = requests.post(f"{self.api_url}/{endpoint}", json=data, headers=self.headers, verify=False)
        return res.json()
"""
### Explanation:
- All byte objects (`encrypted_key`, `iv`, `ciphertext`) are now base64 encoded.
- JWT now uses ISO timestamp for more secure token payload.
- You avoid `bytes` objects entirely in your JSON payload.

This will solve your `TypeError: Object of type bytes is not JSON serializable` issue.
"""