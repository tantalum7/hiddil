
# Library imports
from flask  import Flask, request, make_response
import sys
import schema
import json

# Project imports
from util_funcs import GenerateRandomCharString
from block import Block
from storage import Storage
from transfer import Transfer
from auth import Authentication
import crypt
from exceptions import *


# Prepare server instance
server = Flask(__name__)
server.secret_key = GenerateRandomCharString(32)

# Prepare block store instance
transfer = Transfer()
storage = Storage({"path": "hiddil_sqlite3.db"})
auth = Authentication()


@server.route("/hello")
def hello():
    return "Hello World"


@server.route("/block", methods=['GET'])
def block_get():

    # Grab req_json and try to validate
    try:
        req_json = schema.validate_json(request.get_json(), schema.BLOCK_GET)
        public_key = auth.get_salted_public_key(req_json["pubkey_id"])
        auth.verify_get_signature(block_num=req_json["block_num"], signature_b64=req_json["signature"], pubkey=public_key)

    # Catch json validation error, and return a bad response
    except schema.ValidationError as e:
        return _bad_response({'error': "JSON parse error : "+e.message})

    # Catch key not salted error, and return a bad response
    except KeyNotSaltedException:
        return _bad_response({'error': "Key not salted"})

    # Catch signature verification failure, and return a bad response
    except SignatureVerifyFailException:
        return _bad_response({'error': "Signature verification failed"})

    else:

        # Fetch block
        block = Block(block_number=req_json["block_num"], storage=storage, public_key=public_key)

        # If the data stored is small enough to fit in one packet, put it the reply
        if len(block) < transfer.MAX_CHUNK_SIZE:
            return _good_response({"status": "Good request", "chunked": False, "data": block.as_b64()})

        # Block data is too big for a single reply, start a transfer
        else:
            transfer.register_download(public_key=public_key, block=block)
            return _good_response({"status": "Good request", "chunked": True})


@server.route("/block", methods=['PUT'])
def block_put():

    # Grab JSON and try to validate
    try:
        req_json = schema.validate_json(request.get_json(), schema.BLOCK_PUT)
        public_key = auth.get_salted_public_key(req_json["pubkey_id"])
        data = crypt.b64_decode(req_json.get("data", None)) if "data" in req_json else b''
        auth.verify_put_signature(signature_b64=req_json["signature"], pubkey=public_key, block_num=req_json["block_num"],
                                  data=data)

    # Catch json validation error, and return a bad response
    except schema.ValidationError as e:
        return _bad_response({'error': "JSON parse error : "+e.message})

    # Catch key not salted error, and return a bad response
    except KeyNotSaltedException:
        return _bad_response({'error': "Key not salted"})

    # Catch signature verification failure, and return a bad response
    except SignatureVerifyFailException:
        return _bad_response({'error': "Signature verification failed"})

    # No exceptions found
    else:

        # Create block, and prepare transfer
        block = Block(block_number=req_json["block_num"], storage=storage, public_key=public_key)

        # If chunked flag is false, data is in the put request.
        if not req_json["chunked"]:

            # If data size is larger than max chunk, return a bad response
            if req_json["size"] > transfer.MAX_CHUNK_SIZE:
                return _bad_response({"error": "Data size ({}) too large for a single put request".format(req_json["size"])})

            # Data size is smaller than max, insert into block and return a good response
            else:
                block.from_b64(req_json["data"])
                return _good_response({"status": "Data stored in block {}".format(req_json["block_num"]),
                                       "data_hash": crypt.hash_bytes(data)})

        # If chunked flag is true, data will requires an upload registered
        else:
            transfer.register_upload(public_key, block, req_json["size"])
            return _good_response({"status": "Upload request accepted", "max_chunk_size": transfer.MAX_CHUNK_SIZE})


@server.route("/salt", methods=['GET'])
def salt_get():

    # TODO: Implement whitelist, so we don't salt keys for all and sundry

    try:
        # Grab JSON and validate
        req_json = schema.validate_json(request.get_json(), schema.SALT_GET)

    # Catch json validation error, and return a bad response
    except schema.ValidationError as e:
        return _bad_response({'error': "JSON parse error : "+e.message})

    # No exceptions found
    else:

        # Grab ascii public key from json, import into PublicKey object
        pubkey = crypt.PublicKey(req_json["pubkey"])

        # Create salt for public key (encrypted)
        encrypt_salt = auth.create_salt(pubkey)

        # Return a good response with the pubkey id and the encrypted salt
        return _good_response({'pubkey_id': pubkey.key_id, 'encrypt_salt': encrypt_salt})


@server.route("/upload", methods=["PUT"])
def upload():

    # Try to validate json, grab salted public key and process upload chunk
    try:
        req_json = schema.validate_json(request.get_json(), schema.UPLOAD)
        public_key = auth.get_salted_public_key(req_json["pubkey_id"])
        upload_done = transfer.upload_chunk(public_key, req_json["data_chunk_b64"], req_json["rolling_hash"])

    # Catch json validation error, and return a bad response
    except schema.ValidationError as e:
        return _bad_response({'error': "JSON parse error : " + e.message})

    # Catch key not salted error, and return a bad response
    except KeyNotSaltedException:
        return _bad_response({'error': "Key not salted"})

    # Catch rolling hash exception, delete the transfer request and return a bad response
    except RollingHashException:
        # transfer.active_transfers[req_json["pubkey_id"]] # Could be abused, we aren't proving key
        return _bad_response({'error': "Rolling hash failure"})

    # No exceptions found
    else:
        if upload_done:
            return _good_response({'status': 'Upload complete'})

        else:
            return _good_response({'status': "Chunk uploaded successful, upload still in progress"})


@server.route("/download", methods=["GET"])
def download():
    pass


def _bad_response(data, status_code=401):
    response = make_response(json.dumps(data), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response


def _good_response(data, status_code=200):
    response = make_response(json.dumps(data), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response





if __name__ == "__main__":

    server.debug = True

    if "angela" in sys.argv:
        print("Angela server mode")
        server.run(host="45.58.35.135", port=80) # We're running on angela server, server has external IP on port 80
    else:
        server.run(host="localhost", port=4567)
