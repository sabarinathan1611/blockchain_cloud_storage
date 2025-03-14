from flask import Flask, jsonify, request
import requests
import random
import os
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()


# Fetch nodes from .env file and convert to a list
OTHER_SERVERS = os.getenv("OTHER_SERVERS", "").split(",")

# Remove empty entries (if .env is misconfigured)
NODES = [server.strip() for server in OTHER_SERVERS if server.strip()]

 

@app.route('/add_block', methods=['POST'])
def add_block():
    node = random.choice(NODES)
    try:
        res = requests.post(f"{node}/add_block", json=request.json)
        return jsonify(res.json()), res.status_code
    except requests.RequestException as e:
        return jsonify({"error": "Node unreachable or error", "details": str(e)}), 503

@app.route('/get_chain', methods=['GET'])
def get_chain():
    chains = []
    unique_hashes = set()

    for node in NODES:
        try:
            res = requests.get(f"{node}/get_chain").json()
            for block in res['chain']:
                if block['hash'] not in unique_hashes and block['index'] != 0:  # Filter Genesis Block
                    unique_hashes.add(block['hash'])
                    chains.append(block)
        except:
            continue

    chains.sort(key=lambda x: x['index'])
    return jsonify({"chain": chains}), 200


@app.route('/delete_block/<int:index>', methods=['DELETE'])
def delete_block(index):
    success = False
    for node in NODES:
        try:
            res = requests.delete(f"{node}/delete_block/{index}")
            if res.status_code == 200:
                success = True
        except:
            continue
    if success:
        return jsonify({"message": "Block marked as deleted."}), 200
    else:
        return jsonify({"error": "Block not found on any node."}), 404


@app.route('/password-list', methods=['POST'])
def password_list():
    """Returns list of blocks where type is 'password' for a specific user."""
    data = request.json
    user_email = data.get("email")
    user_id = data.get("user_id")

    if not user_email or not user_id:
        return jsonify({"error": "Missing email or user_id"}), 400

    chains = []
    unique_hashes = set()

    for node in NODES:
        try:
            res = requests.get(f"{node}/get_chain").json()
            for block in res['chain']:
                if (block['hash'] not in unique_hashes 
                    and block['index'] != 0  # Filter Genesis Block
                    and block['data'].get("type") == "password"
                    and block['data'].get("email") == user_email
                    and block['data'].get("user_id") == user_id):
                    
                    unique_hashes.add(block['hash'])
                    chains.append(block)
        except:
            continue

    chains.sort(key=lambda x: x['index'])
    return jsonify({"passwords": chains}), 200


@app.route('/filedata-list', methods=['POST'])
def filedata_list():
    """Returns list of blocks where type is 'file' for a specific user."""
    data = request.json
    user_email = data.get("email")
    user_id = data.get("user_id")

    if not user_email or not user_id:
        return jsonify({"error": "Missing email or user_id"}), 400

    chains = []
    unique_hashes = set()

    for node in NODES:
        try:
            res = requests.get(f"{node}/get_chain").json()
            for block in res['chain']:
                if (block['hash'] not in unique_hashes 
                    and block['index'] != 0  # Filter Genesis Block
                    and block['data'].get("type") == "file"
                    and block['data'].get("email") == user_email
                    and block['data'].get("user_id") == user_id):
                    
                    unique_hashes.add(block['hash'])
                    chains.append(block)
        except:
            continue

    chains.sort(key=lambda x: x['index'])
    return jsonify({"files": chains}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
