from flask import Flask, request, jsonify, make_response
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for JWT encoding and decoding
app.config['SECRET_KEY'] = 'your_secret_key'

# In-memory user storage for simplicity
users = {}


# Route 1: Register a new user (POST /register)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({"message": "User already exists!"}), 400

    hashed_password = generate_password_hash(password)
    users[username] = hashed_password
    return jsonify({"message": "User registered successfully!"}), 201


# Route 2: User login (POST /login) - Create JWT Token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if user exists
    if username not in users:
        return jsonify({"message": "User not found!"}), 404

    # Check password
    if not check_password_hash(users[username], password):
        return jsonify({"message": "Invalid password!"}), 401

    # Create JWT token
    token = jwt.encode({
        'sub': username,
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({"token": token})


# Route 3: Get JWT (GET /get-jwt)
@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    token = request.headers.get('Authorization')  # e.g. 'Bearer <token>'
    if not token:
        return jsonify({"message": "Token is missing!"}), 400

    try:
        token = token.split()[1]  # Get token from "Bearer <token>"
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({"message": "Token is valid", "payload": decoded_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401


# Route 4: Set JWT (POST /set-jwt)
@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"message": "Token is missing!"}), 400
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({"message": "Token is valid", "payload": decoded_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401


if __name__ == '__main__':
    app.run(debug=True)