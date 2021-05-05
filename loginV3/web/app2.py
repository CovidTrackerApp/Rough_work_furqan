from flask import Flask, request, jsonify, send_file
from flask_restful import Resource, Api
from functools import wraps
import jwt
import bcrypt
import datetime
from random import randint
from cryptography.fernet import Fernet
import hashlib

from multiprocessing import Process
import os
import csv
from werkzeug.utils import secure_filename

from flask_mail import Mail, Message
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)


app.config["SECRET_KEY"] = "t+isi-sth(esec4_OPof"

# mail thing here
app.config['MAIL_SERVER']='smtp.yandex.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'furqan4545@yandex.ru'
app.config['MAIL_PASSWORD'] = 'Yandex12345'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# mail end here

# uploading file
UPLOAD_FOLDER = '/usr/src/app/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

client = MongoClient("mongodb://db:27017")
mail = Mail(app)
# client = MongoClient('localhost', 27017)
# client = MongoClient('mongodb://localhost:27017/')

# app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
# mongo = PyMongo(app)

db = client.Users
users = db["Users"]  # making collections

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'csv', 'xlsx', 'docx'])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token") # http://127.0.0.1:5000/route?token=sdasdasdaqwesadaw
        if not token:
            return jsonify({"msg" : "Token is missing!", "status": 402})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])

        except:
            return jsonify({"msg" : "Token is invalid!", "status": 403})

        return f(*args, **kwargs)

    return decorated

def UserExist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else: 
        return True

def EmailExist(email_hashed):
    if users.find({"email_hashed": email_hashed}).count() == 0:
        return False
    else: 
        return True

def ContactExist(contact_hashed):
    if users.find({"contact_hashed": contact_hashed}).count() == 0:
        return False
    else: 
        return True

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False

# def verifyPwWithEmail(email, password):
#     if not EmailhashedExist(email):
#         return False

#     hashed_pw = users.find({
#         "email": email
#     })[0]["password"]

#     if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
#         return True
#     else:
#         return False

# modified
def verifyPwWithEmail(email, password):
    if not EmailExist(email):
        return False
    
    
    # hashed_email = users.find({
    #         "email": email
    #     })[0]["hashed_email"]

    hashed_pw = users.find({
        "email": email
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False


# def updateVerificationCode(email):
#     code = users.find({
#             "email": email
#         })[0]["verification_code"]

#     generated_code = randint(10000, 99999)
    
#     users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

#     return generated_code

# remember you don't need an email to send user the email of reseting password. All you need is just a reference ID
# which is actually the username.
def updateVerificationCode(username):
    code = users.find({
            "username": username
        })[0]["verification_code"]

    generated_code = randint(10000, 99999)
    
    users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

    return generated_code


# def GetCodeFromDb(email):
#     code = users.find({
#             "email": email
#         })[0]["verification_code"]
#     print("Code Here : ", code)
#     return code

def GetCodeFromDb(username):
    code = users.find({
            "username": username
        })[0]["verification_code"]
    print("Code Here : ", code)
    return code

# def setNewPassword(email, updated_password):
#     password = users.find({
#             "email": email
#         })[0]["password"]
    
#     users.update({"password" : password}, {"$set" : {"password": updated_password}})    

def setNewPassword(username, updated_password):
    password = users.find({
            "username": username
        })[0]["password"]
    
    users.update({"password" : password}, {"$set" : {"password": updated_password}})    

def TokenExist(username):
    existing_token = users.find({
                    "username": username
                })[0]["Token"]

    return existing_token


def generate_key_for_credentials(username):
    key = Fernet.generate_key()
    c_path = os.getcwd()+ "/credential_keys"
    if os.path.exists(c_path):
        with open(f'{c_path}/{username}.key', 'wb') as new_key_file:
            new_key_file.write(key)
        return key
    else:
        os.mkdir(c_path)
        with open(f'{c_path}/{username}.key', 'wb') as new_key_file:
            new_key_file.write(key)
        return key


# create a msg to encode
def encode_credentials(username, email, contact_num, age, gender):
    # Instantiate the object with your key.
    # (Refer to Encoding types above).
    key = generate_key_for_credentials(username)
    # username = username.encode()
    email = email.encode()
    contact_num = contact_num.encode()
    age = age.encode()
    gender = gender.encode()
    f = Fernet(key)
    # Pass your bytes type message into encrypt.
    # encrypted_username = f.encrypt(username)
    encrypted_email = f.encrypt(email)
    encrypted_number = f.encrypt(contact_num)
    encrypted_age = f.encrypt(age)
    encrypted_gender = f.encrypt(gender)
    
    print(encrypted_number)
    # return encrypted_username, encrypted_email, encrypted_number, encrypted_age, encrypted_gender
    return key, encrypted_email, encrypted_number, encrypted_age, encrypted_gender

def decode_email(username):
    c_path = os.getcwd()+ "/credential_keys"
    if os.path.exists(f"{c_path}/{username}.key"):
        print("file exist")
        
        with open(f'{c_path}/{username}.key', 'rb') as my_private_key:
            key = my_private_key.read()
            # Instantiate Fernet on the recip system.
        
        encrypted_email = users.find({
                "username": username
            })[0]["email_encrypted"]
        f = Fernet(key)
        # Decrypt the message.
        decrypted_email = f.decrypt(encrypted_email)
        # Decode the bytes back into a string.
        decrypted_email = decrypted_email.decode()
        # if email == decrypted_email:
        #     return 
        return decrypted_email
    return False
    
#     print(decrpted_email)


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        contact = postedData["contact_num"]
        email = postedData["email"]
        age = postedData["age"]
        gender = postedData["gender"]
        
        # email_hash = email.lower()
        email = email.lower()
        email_enc = email.encode("utf-8")
        contact_enc = contact.encode("utf-8")

        if username and password and email and contact:
            if UserExist(username):
                retJson = {
                    "status" : 301,
                    "msg" : "Username already exists"
                }
                return jsonify(retJson)

            email_hashed = hashlib.sha224(email_enc).hexdigest()
            
            if EmailExist(email_hashed):
                retJson = {
                        "status" : 302,
                        "msg" : "Email is already registered"
                    }
                return jsonify(retJson)
            
            contact_hashed = hashlib.sha224(contact_enc).hexdigest()
            if ContactExist(contact_hashed):
                retJson = {
                        "status" : 303,
                        "msg" : "Contact number is already registered"
                    }
                return jsonify(retJson)
                
            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
            
        # store username and password in the database
        # if username and password:
            token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            # token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=10)}, app.config["SECRET_KEY"])

            u_key, encrypted_email, encrypted_number, encrypted_age, encrypted_gender = encode_credentials(username, email, contact, age, gender)

            # utc_timestamp = datetime.datetime.utcnow()

            # users.create_index("date", expireAfterSeconds=20)
            users.insert({
                "username": username,
                "password": hashed_pw,
                "contact_num": encrypted_number,
                "contact_hashed" : contact_hashed,
                "email_hashed": email_hashed,
                "email_encrypted": encrypted_email,
                "age": encrypted_age,
                "gender": encrypted_gender,
                "Token" : token,
                # "date": utc_timestamp,
                "u_key" : u_key,
                "verification_code": 0,
                "OTP" : 0
            })
            retJson = {
                "Token": token.decode('UTF-8'),
                "status" : 200
            }

            return jsonify(retJson)
        
        retJson = {
            "status" : 303,
            "msg" : "Please fill all the fields."
        }
        return jsonify(retJson)

class Login(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        # email = postedData["email"]
        password = postedData["password"]
        
        if username and password:
            correct_pw = verifyPw(username, password)

            if not correct_pw:
                retJson = {
                    "status" : 301,
                    "msg" : "Invalid Password"
                    }
                return jsonify(retJson)
            
            Oldtoken = TokenExist(username)
            if not Oldtoken:

                new_token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
                users.update({"username" : username}, {"$set" : {"Token": new_token}})
                retJson = {
                    "status" : 302,
                    "msg" : "Old token doesn't exist anymore, here is the new one.",
                    "Token" : new_token.decode('UTF-8')
                }
                return jsonify(retJson)

            # token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, app.config["SECRET_KEY"])
            
            
            # users.update({"Token" : code}, {"$set" : {"Token": generated_code}})

            retJson = {
                # "Token" : token.decode('UTF-8'),
                "Token" : Oldtoken.decode('UTF-8'),
                "status" : 200
            }

            return jsonify(retJson)

        retJson = {
            "msg" : "Fields can not be empty. Login required!",
            "status" : 401
        }
        return jsonify(retJson)

class ForgetPass(Resource):
    def post(self):
        postedData = request.get_json()

        # email = postedData["email"]
        username = postedData["username"]
        new_password = postedData["newPassword"]
        confirm_password = postedData["confirmPassword"]
        code = postedData["code"]

        if username and new_password and confirm_password and code:

            if new_password != confirm_password:
                retJson = {
                    "msg": "Password doesn't match!",
                    "status" : 301 
                }
                return jsonify(retJson)

            db_code = GetCodeFromDb(username)

            if db_code != code:
                retJson = {
                    "msg": "The code didn't match!",
                    "status" : 302 
                }
                return jsonify(retJson)
            
            hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            setNewPassword(username, hashed_password)

            retJson = {
                "msg" : "Password updated successfully.",
                "status" : 200
            }
            return jsonify(retJson)

        retJson = {
            "message" : "Please fill all the fields",
            "status" : 303
        }
            
        return retJson


class SendVerificationCode(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        email = postedData["email"]

        email = email.lower()
        
        if email and username:
            
            if not UserExist(username):
                retJson = {
                    "status" : 301,
                    "msg" : "No such Username exists"
                }
                return jsonify(retJson)

            decoded_email = decode_email(username)
            # if not EmailExist(decoded_email, email):
            #     retJson = {
            #         "msg" : "No such registered email",
            #         "status" : 303
            #     }
            #     return jsonify(retJson)
            if decoded_email != email:
                retJson = {
                    "msg" : "No such registered email",
                    "status" : 303
                }
                return jsonify(retJson)

            code = updateVerificationCode(username)
            msg = Message('Covid Tracker: {}'.format(code), sender = 'furqan4545@yandex.ru', recipients = [email])
            msg.body = "Here is your verification code: {}".format(code)
            mail.send(msg)

            retJson = {
                "msg": "Email has been sent to the registered email",
                "status" : 200
            }            
            return jsonify(retJson)

        retJson = {
            "msg": "Email field can't be empty!",
            "status": 302
        }
        return jsonify(retJson)

class WriteCsvFile(Resource):
    def get(self):
        # mongo_docs = users.find()
        # cursor = list(mongo_docs)
        # # json_export = cursor.to_json()
        # if mongo_docs.count() == 0:
        #     return
        # with open('furqan.csv', 'w') as outfile:   
        #     fields = ['_id', "username",
        #         "password",
        #         "contact_num",
        #         "contact_hashed",
        #         "email_hashed",
        #         "email_encrypted",
        #         "age",
        #         "gender",
        #         "Token",
        #         "verification_code",
        #         "OTP"]
        #     write = csv.DictWriter(outfile, fieldnames=fields)
        #     write.writeheader()
        #     write.writerow({"username": cursor[0]["username"], "password" : cursor[0]["password"]})
        
        # retJson = {
            
        # }
        # return jsonify(cursor[0]["username"])
        # return jsonify()
        c_path = os.getcwd()+ "/credential_keys"
        with open(f'{c_path}/furqaan.key', 'rb') as my_private_key:
            key = my_private_key.read()
            print("key is here : ", key)

        retJson = {
            "msg" : str(key),
            "status": 200
        }

        return jsonify(retJson)

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file-upload', methods=['POST'])
def upload_file():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'message' : 'No file part in the request', 'file': request.files, "path": os.getcwd()})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'message' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		resp = jsonify({'message' : 'File successfully uploaded'})
		resp.status_code = 201
		return resp
	else:
		resp = jsonify({'message' : 'Allowed file types are txt, pdf, csv, docx, xlsx'})
		resp.status_code = 400
		return resp

class DownloadSensorCSV(Resource):
    def post(self):
        postedData = request.get_json()
        filename = postedData["filename"]
        file_path = os.getcwd()+"/uploads/"+filename
        # file_path = os.getcwd()+"/uploads/"+"ali.xlsx"
        # return send_file(file_path, as_attachment=True, attachment_filename="Random.xlsx")
        return send_file(file_path, as_attachment=True)


def background_remove(path):
    task = Process(target=rm(path))
    task.start()

def rm(path):
    os.remove(path)

class WriteMongoFile(Resource):
    def get(self):
        mongo_docs = users.find()
        cursor = list(mongo_docs)
        # # json_export = cursor.to_json()
        if mongo_docs.count() == 0:
            return
        with open('furqan.csv', 'w') as outfile:   
            fields = ['_id', "username",
                "password",
                "contact_num",
                "contact_hashed",
                "email_hashed",
                "email_encrypted",
                "age",
                "gender",
                "Token",
                "verification_code",
                "OTP"]
            write = csv.DictWriter(outfile, fieldnames=fields)
            write.writeheader()
            for i in range(len(cursor)):
                write.writerow({
                    "username": cursor[i]["username"], "password" : cursor[i]["password"].decode("utf-8"),
                    "contact_num" : cursor[i]["contact_num"].decode("utf-8"), "email_encrypted" : cursor[i]["email_encrypted"].decode("utf-8"),
                    "age" : cursor[i]["age"].decode("utf-8"), "gender" : cursor[i]["gender"].decode("utf-8")
                    })
            
        file_path = os.getcwd()+"/furqan.csv"
        # return jsonify(cursor[0]["email_encrypted"].decode("utf-8"))
        return send_file(file_path, as_attachment=True, attachment_filename="furqan.csv")
        


@app.route("/protected")
@token_required
def protected():
    return jsonify({"msg": "This is only available to people with valid token!"})


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(SendVerificationCode, '/sendcode')
api.add_resource(ForgetPass, '/resetpass')
api.add_resource(WriteCsvFile, '/writecsv')
api.add_resource(WriteMongoFile, '/writemongo')
api.add_resource(DownloadSensorCSV, '/downloadsensor')


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)




