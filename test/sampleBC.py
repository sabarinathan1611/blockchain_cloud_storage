from flask import Flask, jsonify, request
import requests
import bcrypt
import json

app = Flask(__name__)

# List of blockchain nodes
BLOCKCHAIN_NODES = [
    "http://127.0.0.1:5050",
    "http://127.0.0.1:5051",
    "http://127.0.0.1:5052"
]

def communicate_with_blockchain(endpoint, method="GET", data=None):
    successful_response = None
    for node in BLOCKCHAIN_NODES:
        try:
            if method == "POST":
                response = requests.post(f"{node}{endpoint}", json=data)
            else:
                response = requests.get(f"{node}{endpoint}")
            
            # Log the status of each request
            print(f"Node {node}: Status {response.status_code}")
            
            if response.status_code == 200 or response.status_code == 201:
                successful_response = response.json()
                break  # Return the first successful response
        except requests.exceptions.RequestException as e:
            print(f"Node {node} unreachable. Error: {e}")
    
    if not successful_response:
        print("All nodes unreachable or failed to process.")
        raise Exception("All blockchain nodes are unreachable")
    
    return successful_response


@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    # Get the blockchain to check if the user exists
    try:
        chain_data = communicate_with_blockchain('/get_chain')
    except Exception as e:
        return jsonify({"message": str(e)}), 500

    # Check if the user exists
    for block in chain_data['chain']:
        if block['index'] == 0:  # Skip Genesis Block
            continue
        
        # If `block['data']` is already a dictionary, use it directly
        block_data = block['data'] if isinstance(block['data'], dict) else json.loads(block['data'])

        if block_data.get("username") == username:
            return jsonify({"message": "User already exists"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Add the user to the blockchain
    try:
        new_block = communicate_with_blockchain('/add_block', method="POST", data={"data": json.dumps({"username": username, "password": hashed_password})})
    except Exception as e:
        return jsonify({"message": str(e)}), 500

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    # Get the blockchain to find the user
    try:
        chain_data = communicate_with_blockchain('/get_chain')
    except Exception as e:
        return jsonify({"message": str(e)}), 500

    # Check user credentials
    for block in chain_data['chain']:
        if block['index'] == 0:  # Skip Genesis Block
            continue
        
        # If `block['data']` is already a dictionary, use it directly
        block_data = block['data'] if isinstance(block['data'], dict) else json.loads(block['data'])
        
        if block_data.get("username") == username:
            # Verify password
            if bcrypt.checkpw(password.encode(), block_data["password"].encode()):
                return jsonify({"message": "Login successful"}), 200
            else:
                return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "User not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
