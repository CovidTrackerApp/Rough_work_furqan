from datetime import date
from flask import Flask, json, request, jsonify, make_response
from flask_restful import Resource, Api
from functools import wraps
import jwt
import bcrypt
import datetime
import os
# from flask_pymongo import PyMongo

# from security import authenticate, identity
from pymongo import MongoClient
from pymongo.read_preferences import Secondary

app = Flask(__name__)
api = Api(app)

app.config["SECRET_KEY"] = "thisi-sth(esecret_key"

# client = MongoClient("mongodb://db:27017")
# client = MongoClient('localhost', 27017)
client = MongoClient('mongodb://localhost:27017/')

# app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
# mongo = PyMongo(app)

db = client.Users
users = db["Users"]

# users.find({
#     "username": username
# })[0]["password"]


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token") # http://127.0.0.1:5000/route?token=sdasdasdaqwesadaw
        if not token:
            return jsonify({"message" : "Token is missing!"}), 403

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])

        except:
            return jsonify({"message" : "Token is invalid!"}), 403

        return f(*args, **kwargs)

    return decorated


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        contact = postedData["contact_num"]
        email = postedData["email"]
        age = postedData["age"]
        gender = postedData["gender"]

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # store username and password in the database
        users.insert({
            "username": username,
            "password": hashed_pw,
            "contact_num": contact,
            "email": email,
            "age": age,
            "gender": gender
        })

        if username and password:
            token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"])
            
            return jsonify({"Token": token.decode('UTF-8')}, 200)
        
        retJson = {
            "status" : 301,
            "msg" : "Please fill all the fields."
        }
        return jsonify(retJson)

class Login(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if username and password:
            token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"])
            
            return jsonify({"Token": token.decode('UTF-8')})

        return make_response("Could not verify!", 401, {"WWW-Authenticate" : 'Basic realm="Login Required"'}) 

@app.route("/protected")
@token_required
def protected():
    return jsonify({"message": "This is only available to people with valid token!"})

# class Protected(Resource):
#     @token_required
#     def get(self):
#         return jsonify({"message": "This is only available for valid tokens"})


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
# api.add_resource(Protected, '/protected')


app.run(port=5000, debug=True)




