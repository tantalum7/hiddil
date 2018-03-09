
# Library imports
from flask  import Flask, request
from flask.ext.classy import FlaskView
import sys
import jsonschema
import schema
import base64

# Project imports
from util_funcs import GoodJsonResponse, BadJsonResponse, GenerateRandomCharString
from block_store import BlockStore
from protocol import Protocol
import crypt
from exceptions import *


# Prepare server instance
server = Flask(__name__)
server.secret_key = GenerateRandomCharString(32)

# Prepare block store instance
blockstore = BlockStore({"path": "hiddil.db"})
protocol = Protocol()

class HiddilServer(FlaskView):


    @server.route("/hello")
    def hello():
        return "Hello World"

    @server.route("/block", methods=['GET'])
    def block_get():

        # Grab json and try to validate
        try:
            json = schema.validateJSON( request.get_json(), schema.BLOCK_GET )
            public_key = blockstore.auth.get_salted_public_key(json.pubkey_id)
            blockstore.auth.verify_signature(data=json.address.encode("utf-8"), signature_b64=json.signature, pubkey=public_key)

        # Catch json validation error, and return a bad response
        except jsonschema.ValidationError as e:
            return BadJsonResponse({'error': "JSON parse error : "+e.message})

        # Catch key not salted error, and return a bad response
        except KeyNotSaltedException:
            return BadJsonResponse({'error': "Key not salted"})

        # Catch signature verification failure, and return a bad response
        except SignatureVerifyFailException:
            return BadJsonResponse({'error': "Signature verification failed"})

        else:

            block = blockstore.get(pubkey_id=json.pubkey_id, address=json.address)

            if block:
                data = block.get('data')
            else:
                data = base64.b64encode("No data")

            return GoodJsonResponse({"status": "Good request", "data": data})

    @server.route("/block", methods=['PUT'])
    def block_put():

        # Grab JSON and try to validate
        try:
            json = schema.validateJSON(request.get_json(), schema.BLOCK_PUT)
            public_key = blockstore.auth.get_salted_public_key(json.pubkey_id)
            blockstore.auth.verify_signature(data_b64=json.data, signature_b64=json.signature, pubkey=public_key)

        # Catch json validation error, and return a bad response
        except jsonschema.ValidationError as e:
            return BadJsonResponse({'error': "JSON parse error : "+e.message})

        # Catch key not salted error, and return a bad response
        except KeyNotSaltedException:
            return BadJsonResponse({'error': "Key not salted"})

        # Catch signature verification failure, and return a bad response
        except SignatureVerifyFailException:
            return BadJsonResponse({'error': "Signature verification failed"})

        # No exceptions found
        else:

            # Create block
            address = blockstore.put(pubkey_id=json.pubkey_id, address=json.address, data=json.data, expiration=json.expiration)

            # Return a good response, with the block insertion address and data hash
            return GoodJsonResponse({"status": "Block insertion complete", "insertion_address": address,
                                     "data_hash": crypt.hash_bytes(crypt.b64_decode(json.data))})

    @server.route("/salt", methods=['GET'])
    def salt_get():

        # TODO: Implement whitelist, so we don't salt keys for all and sundry

        try:
            # Grab JSON and validate
            json = schema.validateJSON(request.get_json(), schema.SALT_GET)

        # Catch json validation error, and return a bad response
        except jsonschema.ValidationError as e:
            return BadJsonResponse({'error': "JSON parse error : "+e.message})

        # No exceptions found
        else:

            # Grab ascii public key from json, import into PublicKey object
            pubkey = crypt.PublicKey(json.pubkey)

            # Create salt for public key (encrypted)
            encrypt_salt = blockstore.auth.create_salt(pubkey)

            # Return a good response with the pubkey id and the encrypted salt
            return GoodJsonResponse({'pubkey_id': pubkey.key_id, 'encrypt_salt': encrypt_salt})

    @server.route("/upload", methods=["PUT"])
    def upload():

        # Try to validate json, grab salted public key and process upload chunk
        try:
            json = schema.validateJSON(request.get_json(), schema.UPLOAD)
            public_key = blockstore.auth.get_salted_public_key(json.pubkey_id)
            protocol.upload_chunk(public_key, json.chunk_data_b64)

        # Catch json validation error, and return a bad response
        except jsonschema.ValidationError as e:
            return BadJsonResponse({'error': "JSON parse error : " + e.message})

        # Catch key not salted error, and return a bad response
        except KeyNotSaltedException:
            return BadJsonResponse({'error': "Key not salted"})

        # No exceptions found
        else:
            return GoodJsonResponse({'message': 'Upload chunk successful'})

    @server.route("/download", methods=["GET"])
    def download():
        pass


if __name__ == "__main__":

    server.debug = True

    if "angela" in sys.argv:
        print("Angela server mode")
        server.run(host="45.58.35.135", port=80) # We're running on angela server, server has external IP on port 80
    else:
        server.run(host="localhost", port=4567)
