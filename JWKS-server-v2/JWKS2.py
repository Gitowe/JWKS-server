from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64
import sqlite3
import os


app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"

def create_db():
    connection = sqlite3.connect(DB_FILE)

    connection.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')

    connection.commit()
    connection.close()
    
create_db()

def save_private_key_to_db(key, exp):
    connection = sqlite3.connect(DB_FILE)

    connection.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (key, exp))

    connection.commit()
    connection.close()

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

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

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

# Save private keys to the DB
save_private_key_to_db(private_key_bytes, expiryNorm)
save_private_key_to_db(expired_key_bytes, expiryExp)

def int_to_base64(number):
    byte_representation = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big', signed=False)
    base64url_encoded = base64.urlsafe_b64encode(byte_representation).decode('utf-8').rstrip('=')
    return base64url_encoded

# GET handler
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method == 'GET':
        jwks = {
            "keys": [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": int_to_base64(numbersz.public_numbers.n), "e": int_to_base64(numbersz.public_numbers.e)}]
        }
        return jsonify(jwks)
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

# POST (/auth) handler
@app.route('/auth', methods=['POST'])
def authenticate():
    if request.method == 'POST':
        expired = request.args.get('expired')
       
        keys = read_private_keys_from_db()
        valid_key_info = keys[0]  # Use a valid key by default
        expired_key_info = keys[1]  # Retrieve the expired key from the database
        
        headers = {"kid": kid}
        payload = {"user": "username", "exp": int(stringtime1.timestamp())}
        key_info = valid_key_info
        
        if expired == 'true':
            headers["kid"] = expkid
            payload["exp"] = stringtime2
            key_info = expired_key_info  # Use the expired key

        token = jwt.encode(payload, private_key_bytes, algorithm='RS256', headers=headers)
        return token
    
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405


if __name__ == '__main__':
    app.run(port=8080)