from flask import Flask, request, jsonify
from flask_cors import CORS

from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import cryptography.hazmat.primitives.serialization as serialization
import struct

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

TIMESTAMP_BASE = int(datetime(1999, 11, 15, 12, 0, 0).timestamp())

#FAKE_TIMESTAMP_BYTES = struct.pack('>d', TIMESTAMP_BASE)
FAKE_TIMESTAMP_BYTES = TIMESTAMP_BASE.to_bytes(8, byteorder='big')

doc_hashes = set()

# Generate a new ECDSA key pair
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
public_key = private_key.public_key()

@app.route('/submit-hash', methods=['OPTIONS', 'POST'])
def sign():

    if request.data is None and request.method == 'OPTIONS':
        return jsonify({}), 200
    
    if request.data is None:
        return jsonify({'error': 'No data provided'}), 415

    print("Timestamp:", TIMESTAMP_BASE)

    print("To sign:", [ x for x in request.data])

    # Hash the provided data
    to_sign = request.data + FAKE_TIMESTAMP_BYTES
    
    # Sign the hash
    signature = private_key.sign(
        to_sign,
        ec.ECDSA(hashes.SHA256())
    )

    r, s = decode_dss_signature(signature)

    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')

    deconstructed_signature = r_bytes + s_bytes

    print("Signature sent:", [ x for x in deconstructed_signature])
    print("Signature length:", len(deconstructed_signature))

    return deconstructed_signature + FAKE_TIMESTAMP_BYTES, 200

@app.route('/public-key', methods=['OPTIONS', 'GET'])
def send_public_key():
    # Get the public key in PEM format
    public_key_raw = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    print("Public key sent:", [ x for x in public_key_raw])

    return public_key_raw, 200

if __name__ == '__main__':
    app.run(debug=True)
