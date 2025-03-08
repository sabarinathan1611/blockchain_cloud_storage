from flask import Flask, jsonify, request
import hashlib
import time
import json
import requests
from pymongo import MongoClient
import sys

app = Flask(__name__)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5051

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client[f"blockchain_{PORT}"]
blocks_collection = db.blocks

class Block:
    def __init__(self, index, timestamp, data, previous_hash, deleted=False):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.deleted = deleted
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data_to_hash = f"{self.index}{self.timestamp}{json.dumps(self.data)}{self.previous_hash}{self.deleted}"
        return hashlib.sha256(data_to_hash.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        if blocks_collection.count_documents({}) == 0:
            genesis = Block(0, time.time(), {"message": "Genesis Block"}, "0")
            self.save_block(genesis)

    def get_all_blocks(self, include_deleted=False):
        query = {} if include_deleted else {"deleted": False}
        blocks = list(blocks_collection.find(query, {"_id": 0}).sort("index", 1))
        return blocks

    def add_block(self, data):
        blocks = self.get_all_blocks(include_deleted=True)
        latest_block = blocks[-1]

        new_block = Block(latest_block['index'] + 1, time.time(), data, latest_block['hash'])
        self.save_block(new_block)
        self.broadcast_new_block(new_block)

        return new_block

    def save_block(self, block):
        block_dict = {
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash,
            "deleted": block.deleted
        }
        blocks_collection.insert_one(block_dict)

    def is_chain_valid(self):
        blocks = self.get_all_blocks(include_deleted=True)
        for i in range(1, len(blocks)):
            if blocks[i]['previous_hash'] != blocks[i-1]['hash']:
                return False
            recalculated_hash = Block(
                blocks[i]['index'],
                blocks[i]['timestamp'],
                blocks[i]['data'],
                blocks[i]['previous_hash'],
                blocks[i]['deleted']
            ).calculate_hash()
            if blocks[i]['hash'] != recalculated_hash:
                return False
        return True

    def broadcast_new_block(self, block):
        OTHER_SERVERS = ["http://127.0.0.1:5051", "http://127.0.0.1:5052", "http://127.0.0.1:5053"]
        OTHER_SERVERS = [url for url in OTHER_SERVERS if not url.endswith(str(PORT))]

        for server in OTHER_SERVERS:
            try:
                requests.post(f"{server}/receive_block", json=block.__dict__)
            except:
                continue

blockchain = Blockchain()

@app.route('/receive_block', methods=['POST'])
def receive_block():
    block = request.json
    if block:
        existing_block = blocks_collection.find_one({"hash": block["hash"]})
        if existing_block:
            return jsonify({"message": "Block already exists."}), 200
        blocks_collection.insert_one(block)
        return jsonify({"message": "Block added from broadcast."}), 201
    return jsonify({"error": "Invalid data."}), 400

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.json.get("data")
    if not data:
        return jsonify({"error": "Data is required"}), 400

    new_block = blockchain.add_block(data)
    return jsonify({"message": "Block added", "block": {
        "index": new_block.index,
        "timestamp": new_block.timestamp,
        "data": new_block.data,
        "previous_hash": new_block.previous_hash,
        "hash": new_block.hash,
        "deleted": new_block.deleted
    }}), 201

@app.route('/get_chain', methods=['GET'])
def get_chain():
    blocks = blockchain.get_all_blocks()
    return jsonify({"chain": blocks}), 200

@app.route('/delete_block/<int:index>', methods=['DELETE'])
def delete_block(index):
    result = blocks_collection.update_one({"index": index}, {"$set": {"deleted": True}})
    if result.modified_count > 0:
        return jsonify({"message": "Block marked as deleted."}), 200
    return jsonify({"error": "Block not found."}), 404

@app.route('/sync_chain', methods=['GET'])
def sync_chain():
    OTHER_SERVERS = ["http://127.0.0.1:5051", "http://127.0.0.1:5052", "http://127.0.0.1:5053"]
    OTHER_SERVERS = [url for url in OTHER_SERVERS if not url.endswith(str(PORT))]

    longest_chain = []
    for server in OTHER_SERVERS:
        try:
            chain = requests.get(f"{server}/get_chain").json()['chain']
            if len(chain) > len(longest_chain):
                longest_chain = chain
        except:
            continue

    if longest_chain:
        blocks_collection.delete_many({})
        blocks_collection.insert_many(longest_chain)
        return jsonify({"message": "Blockchain synced."}), 200

    return jsonify({"message": "Already up to date."}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
