# app.py
from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
from jwks_manager import JWKSManager

app = Flask(__name__)
jwks_manager = JWKSManager()

# Generate two keys, one that expires and one that's current
jwks_manager.generate_key("current_key", expires_in=3600)  # 1 hour expiry
jwks_manager.generate_key("expired_key", expires_in=-3600)  # Already expired

@app.route('/jwks', methods=['GET'])
def jwks():
    # Serve only non-expired public keys in JWKS format
    keys = jwks_manager.get_jwks()
    return jsonify({"keys": keys})

@app.route('/auth', methods=['POST'])
def auth():
    # Check for the "expired" query parameter
    use_expired = request.args.get('expired', 'false').lower() == 'true'
    if use_expired:
        kid = "expired_key"
        private_key = jwks_manager.get_expired_private_key(kid)
    else:
        kid = "current_key"
        private_key = jwks_manager.get_private_key(kid)

    if private_key:
        # Create a JWT token
        payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=10)
        }
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
        return jsonify({"token": token})

    return jsonify({"error": "Key not found or expired"}), 400

if __name__ == '__main__':
    app.run(port=8080)
