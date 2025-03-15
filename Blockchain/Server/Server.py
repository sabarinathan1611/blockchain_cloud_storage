from flask import Flask, jsonify, request
import hashlib, time, json, requests, sys, os
from pymongo import MongoClient
from dotenv import load_dotenv
import jwt
from functools import wraps

load_dotenv()
JWT_SECRET = os.getenv('JWT_SECRET')
DB_URI = os.getenv('DB_URI')
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5051

app = Flask(__name__)
client = MongoClient(DB_URI)
db = client[f"blockchain_{PORT}"]
blocks_collection = db.blocks
nodes_collection = client["general"].nodes

class Block:
    def __init__(self, index, timestamp, data, previous_hash, deleted=False):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.deleted = deleted
        self.hash = hashlib.sha256(f"{index}{timestamp}{json.dumps(data)}{previous_hash}{deleted}".encode()).hexdigest()

class Blockchain:
    def __init__(self):
        if blocks_collection.count_documents({}) == 0:
            genesis = Block(0, time.time(), {"msg": "Genesis"}, "0")
            blocks_collection.insert_one(genesis.__dict__)

    def add_block(self, data):
        latest_block = blocks_collection.find_one(sort=[("index", -1)])
        new_block = Block(latest_block['index']+1, time.time(), data, latest_block['hash'])
        blocks_collection.insert_one(new_block.__dict__)
        self.broadcast_block(new_block)
        return new_block

    def broadcast_block(self, block):
        headers = {'Authorization': jwt.encode({"iss": f"node_{PORT}"}, JWT_SECRET, algorithm='HS256')}
        nodes = nodes_collection.find({"port": {"$ne": PORT}})
        for node in nodes:
            url = f"http://{node['host']}:{node['port']}/receive_block"
            try:
                block_data = json.loads(json.dumps(block.__dict__, default=str))
                requests.post(url, json=block_data, headers=headers, timeout=3)
            except requests.RequestException as e:
                print(f"Failed to broadcast to {url}: {e}")

blockchain = Blockchain()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token: return jsonify({"error": "Missing token"}), 401
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated

headers = {'Authorization': jwt.encode({"iss": f"node_{PORT}"}, JWT_SECRET, algorithm='HS256')}
blockchain = Blockchain()

@app.route('/add_block', methods=['POST'])
@token_required
def add_block():
    data = request.json.get("data")
    if not data:
        return jsonify({"error": "Data required"}), 400
    block = blockchain.add_block(data)
    block_data = json.loads(json.dumps(block.__dict__, default=str))
    return jsonify(block_data), 201

@app.route('/receive_block', methods=['POST'])
@token_required
def receive_block():
    block = request.json
    if not block:
        return jsonify({"error": "Invalid data"}), 400
    if blocks_collection.find_one({"hash": block["hash"]}):
        return jsonify({"message": "Block already exists"}), 200
    blocks_collection.insert_one(block)
    return jsonify({"message": "Block added"}), 201

@app.route('/get_chain')
@token_required
def get_chain():
    blocks = list(blocks_collection.find({"deleted": False}, {"_id": 0}))
    return jsonify({"chain": blocks}), 200

blockchain = Blockchain()
headers = {'Authorization': jwt.encode({"iss": f"node_{PORT}"}, JWT_SECRET, algorithm='HS256')}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)