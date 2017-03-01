#!/usr/bin/env python
# Library imports
from Cryptodome.PublicKey   import RSA
from Cryptodome.Cipher      import PKCS1_OAEP
from Cryptodome.Signature   import PKCS1_v1_5
from Cryptodome.Hash        import SHA
import requests         as req
import base64

class Client(object):

    def __init__(self, server_url="http://127.0.0.1:5000/", key_file="test_key"):

        # Initialise class vars
        self.server_url = server_url
        self.key_file   = key_file
        self.pubkey_id  = None
        self.salt       = None

        # Load private key
        self.loadPrivateKey(self.key_file)

        # Request salt before starting put/get requests and to prove server connection
        self.requestSalt()

    def loadPrivateKey(self, file):

        # Open key file, and parse into key object
        with open(file, 'r') as key_file:
            self.key = RSA.importKey( key_file.read() )

    def requestSalt(self):

        # Issue JSON request
        response = req.get( self.server_url+"salt", json={"pubkey" : str(self.key.exportKey("OpenSSH"))} )

        # Pull JSON from request response
        json = response.json()

        # Check if response was good (HTTP 200)
        if response:

            # Pull public key ID from json
            self.pubkey_id = json.get('pubkey_id')

            # Pull encrypted salt from json and decrypt it
            self.salt = self.Decrypt( json.get('encrypt_salt') )

            print(self.salt)

    def Encrypt(self, data):

        # Create cipher object
        cipher = PKCS1_OAEP.new(self.key)

        # Encrypt the data, and apply base64 encoding and return
        return base64.b64encode( cipher.encrypt(data) )

    def Decrypt(self, data):

        # Create cipher object
        cipher = PKCS1_OAEP.new(self.key)

        # Remove base64 encoding, decrypt data and return
        return cipher.decrypt( base64.b64decode(data) )

    def Hash(self, data):
        return SHA.new(data)

    def Sign(self, data):

        # Get hash of data and the
        data_hash = self.Hash(data + self.salt)

        # Prepare signing object
        signer = PKCS1_v1_5.new(self.key)

        # Sign the hash, apply b64 encoding and return
        return base64.b64encode( signer.sign(data_hash) )

    def getBlock(self, address):

        # Create signature of address
        sig = self.Sign(address)

        # Prepare json dict
        get_json = { "pubkey_id"    : self.pubkey_id,
                     "address"      : address,
                     "signature"    : sig }

        # Issue get request
        response = req.get(self.server_url+"block", json=get_json)

        # Pull json from request
        json = response.json()

        if response:

            print (base64.b64decode( json.get("data") ))


    def putBlock(self, data, expiration=2592000):

        # Create signature of put data
        sig = self.Sign(data)

        # Apply b64 encoding to data
        data_b64 = base64.b64encode(data)

        # Prepare json dict
        put_json = { "pubkey_id"    : self.pubkey_id,
                     "data"         : data_b64,
                     "signature"    : sig,
                     "expiration"   : expiration }

        # Issue put block request
        response = req.put(self.server_url+"block", json=put_json)

        # Pull json from request
        json = response.json()

        if response:

            return json.get("insertion_address")


if __name__ == "__main__":





    cli = Client()

    b1_addr = cli.putBlock("Secret messsage1")
    b2_addr = cli.putBlock("Secret messsage2")

    cli.getBlock(b1_addr)

    print("done")


