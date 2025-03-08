from flask import Flask, jsonify, request
import requests
import random

app = Flask(__name__)

NODES = [
    "http://127.0.0.1:5051",
    "http://127.0.0.1:5052",
    "http://127.0.0.1:5053"
]

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
