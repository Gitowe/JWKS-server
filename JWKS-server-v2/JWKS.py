from flask import Flask, jsonify, request
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

app = Flask(__name__)

# Generate RSA key pair and associate kid and expiry timestamp
def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    kid = str(datetime.utcnow().timestamp())
    expiry = datetime.utcnow() + timedelta(days=1)

    return {
        "kid": kid,
        "exp": expiry,
        "public_key": public_key_bytes.decode('utf-8')
    }

keys = [generate_key()]

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method == 'GET':
        now = datetime.utcnow()
        filtered_keys = [key for key in keys if now < key["exp"]]
        jwks = {
            "keys": [{"kid": key["kid"], "kty": "RSA", "alg": "RS256", "use": "sig", "n": key["public_key"]} for key in filtered_keys]
        }
        return jsonify(jwks)
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

@app.route('/auth', methods=['POST'])
def authenticate():
    if request.method == 'POST':
        expired = request.args.get('expired')
        key = keys[-1]  # Use the latest key (could be expired)
        expiry = key["exp"]
        private_key_for_signing = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        expired_key_for_signing = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        token = jwt.encode({'exp': expiry, 'kid': key['kid']}, private_key_for_signing, algorithm='RS256')
        return token
    else:
        return jsonify({'message': 'Method Not Allowed'}), 405

if __name__ == '__main__':
    app.run(port=8080)