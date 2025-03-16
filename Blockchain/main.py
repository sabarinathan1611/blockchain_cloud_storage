from flask import Flask, jsonify, request
import requests
import random
import os
from pymongo import MongoClient
from dotenv import load_dotenv
import jwt

app = Flask(__name__)
load_dotenv()

JWT_SECRET = os.getenv('JWT_SECRET')
DB_URI = os.getenv('DB_URI')

client = MongoClient(DB_URI)
nodes_collection = client["general"].nodes

# Fetch nodes dynamically from MongoDB
def get_nodes():
    nodes = nodes_collection.find({})
    return [f"http://{node['host']}:{node['port']}" for node in nodes]

# Generate JWT Token
def get_token():
    return jwt.encode({"iss": "main.py"}, JWT_SECRET, algorithm='HS256')

headers = {"Authorization": get_token()}

# Check if nodes are active
def check_active_nodes():
    active_nodes = []
    for node in get_nodes():
        try:
            res = requests.get(f"{node}/get_chain", headers=headers, verify=False, timeout=3)
            if res.ok:
                active_nodes.append(node)
        except requests.RequestException as e:
            print(f"Failed to connect to {node}: {e}")
            continue
    return active_nodes

@app.route('/add_block', methods=['POST'])
def add_block():
    nodes = check_active_nodes()
    random.shuffle(nodes)
    for node in nodes:
        try:
            res = requests.post(f"{node}/add_block", json=request.json, headers=headers, verify=False)
            if res.ok:
                return jsonify(res.json()), res.status_code
        except requests.RequestException as e:
            print(f"Error contacting node {node}: {e}")
            continue
    return jsonify({"error": "All nodes unreachable"}), 503

@app.route('/get_chain', methods=['GET'])
def get_chain():
    chains, unique_hashes = [], set()
    for node in check_active_nodes():
        try:
            res = requests.get(f"{node}/get_chain", headers=headers, verify=False).json()
            for block in res['chain']:
                if block['hash'] not in unique_hashes and block['index'] != 0:
                    unique_hashes.add(block['hash'])
                    chains.append(block)
        except:
            continue
    chains.sort(key=lambda x: x['index'])
    return jsonify({"chain": chains}), 200

@app.route('/delete_block/<int:index>', methods=['DELETE'])
def delete_block(index):
    success = False
    for node in check_active_nodes():
        try:
            res = requests.delete(f"{node}/delete_block/{index}", headers=headers, verify=False)
            if res.status_code == 200:
                success = True
        except:
            continue
    return (jsonify({"message": "Block marked as deleted."}), 200) if success else (jsonify({"error": "Block not found"}), 404)

# User-specific data endpoints

def filter_chain(data_type, user_email, user_id):
    chains, unique_hashes = [], set()
    for node in check_active_nodes():
        try:
            res = requests.get(f"{node}/get_chain", headers=headers, verify=False).json()
            for block in res['chain']:
                
                block_data = block.get('data', {})
                print(block_data)
                
                if (
                    block['hash'] not in unique_hashes
                    and block['index'] != 0
                    and block_data.get("type") == data_type
                    and block_data.get("user_email") == user_email
                    and block_data.get("user_id") == user_id
                ):
                    unique_hashes.add(block['hash'])
                    chains.append(block)
        except Exception as e:
            print(f"Error fetching from node {node}: {e}")
            continue
    return sorted(chains, key=lambda x: x['index'])


@app.route('/password-list', methods=['POST'])
def password_list():
    user_email, user_id = request.json.get("email"), request.json.get("user_id")
    if not user_email or not user_id:
        return jsonify({"error": "Missing email or user_id"}), 400
    print("EMAIL:",user_email,"\n","ID",user_id)
    passwords = filter_chain("password", user_email, user_id)
    return jsonify({"passwords": passwords}), 200

@app.route('/filedata-list', methods=['POST'])
def filedata_list():
    user_email, user_id = request.json.get("email"), request.json.get("user_id")
    if not user_email or not user_id:
        return jsonify({"error": "Missing email or user_id"}), 400
    files = filter_chain("file", user_email, user_id)
    return jsonify({"files": files}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
