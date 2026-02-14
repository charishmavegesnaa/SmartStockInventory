from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = "smartstock_secret_key"

client = MongoClient("mongodb://localhost:27017/")
db = client["smartstock"]
collection = db["users"]

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return jsonify({"message": "Token missing"}), 401

        try:
            data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )
            current_user = data
        except:
            return jsonify({"message": "Token invalid"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    username = data["username"]
    email = data["email"]
    password = data["password"]
    role = data["role"]
    contactNumber = data.get("contactNumber", "")
    shopAddress = data.get("shopAddress", "")
    gstin = data.get("gstin", "")
    city = data.get("city", "")
    state = data.get("state", "")
    pincode = data.get("pincode", "")

    if collection.find_one({"username": username}):
        return jsonify({"message": "Username already exists"}), 400

    if collection.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)

    collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_password,
        "role": role,
        "contactNumber": contactNumber,
        "shopAddress": shopAddress,
        "gstin": gstin,
        "city": city,
        "state": state,
        "pincode": pincode
    })

    return jsonify({"message": "Registration successful"}), 201

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    username = data["username"]
    password = data["password"]

    # Check if user exists by username or email
    user = collection.find_one({
        "$or": [
            {"username": username},
            {"email": username}
        ]
    })

    if not user:
        return jsonify({"message": "Account does not exist"}), 401

    if not check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid password"}), 401

    token = jwt.encode({
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token,
        "role": user["role"]
    })


@app.route("/admin/users", methods=["GET"])
@token_required
def get_users(current_user):

    if current_user["role"] != "admin":
        return jsonify({"message": "Admin access required"}), 403

    users = list(collection.find({}, {"_id": 0, "username": 1, "role": 1}))

    return jsonify({"users": users})


if __name__ == "__main__":
    app.run(debug=True)
