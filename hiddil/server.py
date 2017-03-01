#!/usr/bin/env python

from flask  import Flask, render_template, request, session, g, jsonify
from util_funcs     import GenerateRandomCharString
from block_store    import BlockStore
from auth           import KeyNotSaltedException, SignatureVerifyFailException
import sys
import jsonschema
import schema
import base64

# Prepare server instance
server = Flask(__name__)
server.secret_key = GenerateRandomCharString(32)

# Prepare block store instance
# if "angela" in sys.argv:
try:
    blockstore = BlockStore( ip_port_tuple=("mongodb", 27017) ) # We're running on angela server, DB is local not remote
except Exception as e:
    raise e
# else:
    # blockstore = BlockStore( ip_port_tuple=("45.58.35.135", 27027) )

@server.route("/hello")
def hello():
    return "Hello World"


@server.route("/block", methods=['GET'])
def block_get():

    # Grab json and try to validate
    try:
        json = schema.validateJSON( request.get_json(), schema.BLOCK_GET )

        blockstore.auth.verifySignature(data=json.address, signature_b64=json.signature, pubkey_id=json.pubkey_id)

    # Catch json validation error, and return a bad response
    except jsonschema.ValidationError as e:
        return jsonify({'error':"JSON parse error : "+e.message}), 400

    # Catch key not salted error, and return a bad response
    except KeyNotSaltedException:
        return jsonify({'error':"Key not salted"}), 400

    # Catch signature verification failure, and return a bad response
    except SignatureVerifyFailException:
        return jsonify({'error':"Signature verification failed"}), 400

    # Catch any other exceptions and re-raise them
    except:
        raise

    else:

        block = blockstore.Get(pubkey_id=json.pubkey_id, address=json.address)

        if block:
            data = block.get('data')
        else:
            data = base64.b64encode("No data")

        return jsonify({"status" : "Good request", "data" : data }, )

    #return jsonify({'block':BLOCKS[blockid]})


@server.route("/block", methods=['PUT'])
def block_put():

    try:
        # Grab JSON and validate
        json = schema.validateJSON( request.get_json(), schema.BLOCK_PUT )

        # Validate signature
        blockstore.auth.verifySignature(data_b64=json.data, signature_b64=json.signature, pubkey_id=json.pubkey_id)

    # Catch json validation error, and return a bad response
    except jsonschema.ValidationError as e:
        return jsonify({'error':"JSON parse error : "+e.message}), 400

    # Catch key not salted error, and return a bad response
    except KeyNotSaltedException:
        return jsonify({'error':"Key not salted"}), 400

    # Catch signature verification failure, and return a bad response
    except SignatureVerifyFailException:
        return jsonify({'error':"Signature verification failed"}), 400

    # Catch any other exceptions and re-raise them
    except:
        raise

    # No exceptions found
    else:

        # Create block
        addr = blockstore.Put(pubkey_id=json.pubkey_id, data=json.data, expiration=json.expiration)

        return jsonify({"status" : "Block insertion complete", "insertion_address" : addr})


@server.route("/salt", methods=['GET'])
def salt_get():

    try:
        # Grab JSON and validate
        json = schema.validateJSON( request.get_json(), schema.SALT_GET )

    # Catch json validation error, and return a bad response
    except jsonschema.ValidationError as e:
        return jsonify({'error':"JSON parse error : "+e.message}), 400

      # Catch any other exceptions and re-raise them
    except:
        raise

    # No exceptions found
    else:

        # Create salt for public key, fetch public key ID and encrypted salt
        pubkey_id, encrypt_salt = blockstore.auth.createSalt( json.pubkey.encode("utf-8") )

        # Return a good response with the pubkey id and the encrypted salt
        return jsonify({'pubkey_id' : pubkey_id, 'encrypt_salt' : encrypt_salt})




if __name__ == "__main__":

    server.debug = True
    server.use_reloader = True
    # if "angela" in sys.argv:
    #     print("Angela server mode")
    #     server.run(host="45.58.35.135", port=80) # We're running on angela server, server has external IP on port 80
    # else:
    server.run(host="0.0.0.0", port=5000)
