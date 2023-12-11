from flask import Flask, jsonify, request, g
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import jwt
import base64
import sqlite3
import os
import uuid
import secrets
import argon2
import time
#wow thats a lot of imports

#Owen Glasscock
#og0112


app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"

AES_KEY = os.environ.get('NOT_MY_KEY')

#Check if AES_KEY is provided
if AES_KEY is None:
    raise ValueError("Environment variable NOT_MY_KEY not found!")

def derive_aes_key():
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = base64.urlsafe_b64encode(kdf.derive(AES_KEY.encode()))
    return aes_key

#Encrypt data using AES
def encrypt_data(data):
    fernet = Fernet(derive_aes_key())
    if isinstance(data, str):
        data = data.encode()
    encrypted_data = fernet.encrypt(data)
    return encrypted_data

#Decrypt data using AES
def decrypt_data(data):
    fernet = Fernet(derive_aes_key())
    decrypted_data = fernet.decrypt(data).decode()
    return decrypted_data

#Create database and its tables (unless they are already there)
def create_db():
    connection = sqlite3.connect(DB_FILE)

    connection.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
    connection.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    ''')
    
    connection.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    connection.commit()
    connection.close()
    
create_db()

def save_private_key_to_db(key, exp):
    connection = sqlite3.connect(DB_FILE)
    
    encrypted_key = encrypt_data(key)

    connection.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (encrypted_key, exp))

    connection.commit()
    connection.close()

#Obtains keys from the database
def read_private_keys_from_db():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute('''
        SELECT key, exp FROM keys WHERE exp > ?
    ''', (int(datetime.utcnow().timestamp()),))

    rows = cursor.fetchall()
    keys = [{'key': row[0], 'exp': row[1]} for row in rows]

    cursor.close()
    connection.close()
    return keys

#Create private, expired, and public keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

#PEM encoded private, expired, and public keys
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_key_bytes = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#Extract private keu from PEM encoded key
def extract_private_key_from_key(key_bytes):
    private_key = load_pem_private_key(key_bytes, password=None)
    return private_key

numbersz = private_key.private_numbers()

kid = "normal"
expkid = "expired"

stringtime1 = datetime.utcnow() + timedelta(hours=1)
stringtime2 = datetime.utcnow() - timedelta(hours=1)
expiryNorm = int(stringtime1.timestamp())
expiryExp =  int(stringtime2.timestamp())

#Save private keys to the DB
save_private_key_to_db(private_key_bytes, expiryNorm)
save_private_key_to_db(expired_key_bytes, expiryExp)

#Converts integer into base64
def int_to_base64(number):
    byte_representation = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big', signed=False)
    base64url_encoded = base64.urlsafe_b64encode(byte_representation).decode('utf-8').rstrip('=')
    return base64url_encoded

#GET handler
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method == 'GET':
        jwks = {
            "keys": [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": int_to_base64(numbersz.public_numbers.n), "e": int_to_base64(numbersz.public_numbers.e)}]
        }
        return jsonify(jwks)
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

#POST (/register) handler  
@app.route('/register', methods=['POST'])
def register_user():
    if request.method == 'POST':
        req_data = request.get_json()
        
        if req_data is None:
            return jsonify({'message': 'Invalid JSON format'}), 400
        
        username = req_data.get('username')
        email = req_data.get('email')

        #Generate a secure password for the user using UUIDv4
        generated_password = str(uuid.uuid4())

        #Hash the password using Argon2
        argon2_hasher = argon2.PasswordHasher()
        hashed_password = argon2_hasher.hash(generated_password)

        connection = sqlite3.connect(DB_FILE)
        cursor = connection.cursor()

        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
            ''', (username, hashed_password, email))

            connection.commit()
            return jsonify({'password': generated_password}), 201
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Username or Email already exists'}), 400
        finally:
            cursor.close()
            connection.close()
            
        

    else:
        return jsonify({'message': 'Method Not Allowed'}), 405
    
    
RATE_LIMIT = 10 
rate_limit_window = timedelta(seconds=1)
rate_limit_requests = []

#Fuction to set the rate limit
def rate_limit(func):
    def wrapper(*args, **kwargs):
        current_time = time.time()
        while rate_limit_requests and rate_limit_requests[0] < current_time - 1:
            rate_limit_requests.pop(0)

        if len(rate_limit_requests) >= RATE_LIMIT:
            return jsonify({'message': 'Too Many Requests'}), 429

        rate_limit_requests.append(current_time)
        return func(*args, **kwargs)

    return wrapper  

#Function to log authentication requests
def log_auth_request(ip_address, user_id):
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()

    cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id)
        VALUES (?, ?)
    ''', (ip_address, user_id))

    connection.commit()
    cursor.close()
    connection.close()

#POST (/auth) handler
@app.route('/auth', methods=['POST'])
@rate_limit
def authenticate():
    if request.method == 'POST':
        expired = request.args.get('expired')
        ip_address = request.remote_addr  #Get request IP address

        #Retrieve user ID from database based on username (this might need adjustment based on your DB schema)
        username = request.json.get('username')  #Assuming username is sent in the request JSON
        connection = sqlite3.connect(DB_FILE)
        cursor = connection.cursor()

        cursor.execute('''
            SELECT id FROM users WHERE username = ?
        ''', (username,))

        user_row = cursor.fetchone()
        if user_row:
            user_id = user_row[0]
        else:
            return jsonify({'message': 'User not found'}), 404
        
        cursor.close()
        connection.close()
        
        #Log authentication request
        log_auth_request(ip_address, user_id)
       
        keys = read_private_keys_from_db()
        valid_key_info = keys[0]  #Use a valid key by default
        expired_key_info = keys[1]  #Retrieve the expired key from the database
        
        for key_info in keys:
            if key_info['exp'] > int(datetime.utcnow().timestamp()):
                if key_info['key'] == private_key_bytes:
                    valid_key_info = key_info
                elif key_info['key'] == expired_key_bytes:
                    expired_key_info = key_info
        
        headers = {"kid": kid}
        payload = {"user": "username", "exp": int(stringtime1.timestamp())}
        key_info = None
        
        if expired == 'true':
            headers["kid"] = expkid
            payload["exp"] = int(stringtime2.timestamp())
            key_info = expired_key_info  #Use the expired key
            private_key_to_use = expired_key_bytes
        else:
            key_info = valid_key_info  #Use the valid key
            private_key_to_use = private_key_bytes
            
        if not key_info:
            return jsonify({'message': 'No valid key found'}), 500

        token = jwt.encode(payload, private_key_to_use, algorithm='RS256', headers=headers)
        return token
    
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405


if __name__ == '__main__':
    app.run(port=8080)