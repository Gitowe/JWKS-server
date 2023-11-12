from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64

app = Flask(__name__)


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
    
numbers = private_key.private_numbers()

kid = "normal"
expkid = "expired"

expiry = datetime.utcnow() + timedelta(hours=1)

def int_to_base64(number):
    byte_representation = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big', signed=False)
    base64url_encoded = base64.urlsafe_b64encode(byte_representation).decode('utf-8').rstrip('=')

    return base64url_encoded


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method == 'GET':
        jwks = {
            "keys": [
                {
                    "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": int_to_base64(numbers.public_numbers.n), "e": int_to_base64(numbers.public_numbers.e)
                }
            ]
        }
        return jsonify(jwks)
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

@app.route('/auth', methods=['POST'])
def authenticate():
    if request.method == 'POST':
        expired = request.args.get('expired')
        
        headers={"kid": kid}
        payload = {"user": "username","exp": expiry}
        if expired == 'true':
            headers["kid"] = expkid
            payload["exp"] = datetime.utcnow() - timedelta(hours=1)
        
        token = jwt.encode(payload, private_key_bytes, algorithm='RS256', headers=headers)
        return token
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

if __name__ == '__main__':
    app.run(port=8080)
