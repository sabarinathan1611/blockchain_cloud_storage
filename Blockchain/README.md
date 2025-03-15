# Blockchain Server Documentation

This document outlines the functionality and implementation details of the provided blockchain server using Flask, MongoDB, JWT authentication, and Python.

## Overview

The blockchain server:

- Initializes a blockchain with a genesis block.
- Adds new blocks containing data.
- Broadcasts newly added blocks to peer nodes.
- Receives and adds blocks from peer nodes.
- Provides an API to query the blockchain state.

## Dependencies

Ensure the following dependencies are installed:

```bash
pip install Flask pymongo python-dotenv PyJWT requests
```

## Environment Setup

Use a `.env` file to store environment variables securely:

```env
JWT_SECRET=your_jwt_secret
DB_URI=mongodb://localhost:27017/
```

## Server Initialization

Start the blockchain server by specifying a port:

```bash
python Server.py 5051
```

## API Endpoints

### 1. Add Block

**Endpoint:** `/add_block`

**Method:** POST

**Headers:**

- `Authorization`: JWT token

**Request Body:**

```json
{
  "data": "Your data here"
}
```

**Response:**

```json
{
  "index": 1,
  "timestamp": 1710483987.182628,
  "data": "Your data here",
  "previous_hash": "previous_hash_value",
  "deleted": false,
  "hash": "new_block_hash"
}
```

### 2. Receive Block

**Endpoint:** `/receive_block`

**Method:** POST

**Headers:**

- `Authorization`: JWT token

**Request Body:**

```json
{
  "index": 1,
  "timestamp": 1710483987.182628,
  "data": "Your data here",
  "previous_hash": "previous_hash_value",
  "deleted": false,
  "hash": "new_block_hash"
}
```

**Response:**

```json
{
  "message": "Block added"
}
```

### 3. Get Blockchain

**Endpoint:** `/get_chain`

**Method:** GET

**Headers:**

- `Authorization`: JWT token

**Response:**

```json
{
    "chain": [
        {
            "index": 0,
            "timestamp": 1710483987.182628,
            "data": {"msg": "Genesis"},
            "previous_hash": "0",
            "deleted": false,
            "hash": "genesis_block_hash"
        },
        ... additional blocks
    ]
}
```

## JWT Authentication

All endpoints require a JWT token in the `Authorization` header:

Generate JWT tokens using the same secret (`JWT_SECRET`) defined in the `.env` file:

```python
import jwt

token = jwt.encode({"iss": "node_5051"}, JWT_SECRET, algorithm='HS256')
```

## Node Broadcasting

The server automatically broadcasts newly added blocks to all peer nodes defined in the MongoDB `general.nodes` collection.

MongoDB Node Example:

```json
{
  "host": "localhost",
  "port": 5052
}
```

## Error Handling

The server gracefully handles:

- Missing or invalid JWT tokens.
- Duplicate blocks.
- Network errors when broadcasting blocks.

## Running the Server

To run the server:

```bash
python Server.py [port]
```

Example:

```bash
python Server.py 5051
```

Ensure multiple servers run on different ports for full node synchronization.

---

**Note:** This server implementation is ideal for development and testing purposes. Ensure proper security measures (SSL/TLS, secure token management, production-grade database settings) are implemented before deploying to a production environment.
