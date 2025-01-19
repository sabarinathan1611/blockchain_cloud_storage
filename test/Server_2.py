from flask import Flask, jsonify, request
import hashlib
import time
import json
from pymongo import MongoClient

# MongoDB Configuration
client = MongoClient("mongodb://localhost:27017/")  
db = client.blockchain_db2
blocks_collection = db.blocks

# Block Class
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data_to_hash = f"{self.index}{self.timestamp}{json.dumps(self.data)}{self.previous_hash}"
        return hashlib.sha256(data_to_hash.encode()).hexdigest()

# Blockchain Class
class Blockchain:
    def __init__(self):
        # Create Genesis Block if blockchain is empty
        if blocks_collection.count_documents({}) == 0:
            self.add_block({"message": "Genesis Block"})

    def get_all_blocks(self):
        blocks = list(blocks_collection.find().sort("index", 1))
        return [
            Block(block["index"], block["timestamp"], block["data"], block["previous_hash"])
            for block in blocks
        ]

    def add_block(self, data):
        blocks = self.get_all_blocks()
        latest_block = blocks[-1] if blocks else Block(0, time.time(), {"message": "Genesis Block"}, "0")

        new_block = Block(len(blocks), time.time(), data, latest_block.hash)

        # Save new block to MongoDB
        blocks_collection.insert_one({
            "index": new_block.index,
            "timestamp": new_block.timestamp,
            "data": new_block.data,
            "previous_hash": new_block.previous_hash,
            "hash": new_block.hash,
        })
        return new_block

    def is_chain_valid(self):
        blocks = self.get_all_blocks()
        for i in range(1, len(blocks)):
            current_block = blocks[i]
            previous_block = blocks[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

# Flask Application
app = Flask(__name__)
blockchain = Blockchain()

@app.route('/add_block', methods=['POST'])
def add_block():
    data = request.json.get("data")
    if not data:
        return jsonify({"message": "Data is required"}), 400

    new_block = blockchain.add_block(data)
    return jsonify({"message": "Block added", "block": vars(new_block)}), 201

@app.route('/get_chain', methods=['GET'])
def get_chain():
    chain_data = [
        {
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash,
        }
        for block in blockchain.get_all_blocks()
    ]
    return jsonify({"chain": chain_data}), 200

@app.route('/is_valid', methods=['GET'])
def is_valid():
    valid = blockchain.is_chain_valid()
    return jsonify({"message": "Blockchain is valid" if valid else "Blockchain is invalid"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5051)  # Change port for other nodes (e.g., 5051, 5052)
