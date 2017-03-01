#!/usr/bin/env python
# Library imports
import requests

# Project imports
import crypt
from exceptions import *


class Client(object):

    MAX_BLOCK_CHUNK = 700

    def __init__(self, server_url: str="http://127.0.0.1:4567/", key_file: str="test_key"):
        """
        Main client class, provides API to access remote hiddil storage and handle keys
        :param server_url: url of remote hiddil server (defaults to local test server)
        :param key_file: PEM encoded private key to access hiddil storage with TODO: Add support for passworded keys
        """
        # Initialise class vars
        self.server_url = server_url
        self.pubkey_id = None
        self.salt = None
        self.private_key = None

        # Load private key
        self.load_private_key(key_file)

        # Request salt before starting put/get requests and to prove server connection
        self.request_salt()

    def load_private_key(self, key_path: str):
        """
        Loads a private key from path provided
        :param key_path: File path string to the key
        """
        # Open key file, and parse into key object
        with open(key_path, 'r') as key_file:
            self.private_key = crypt.PrivateKey(key_file.read())

    def request_salt(self):
        """
        Requests salt from the hiddil server to use in all future transactions, stores it in class
        """
        # Issue JSON request
        response = requests.get(self.server_url + "salt", json={"pubkey": self.private_key.export_public_str()})

        # Pull JSON from request response
        json = response.json()

        # Check if response was good (HTTP 200)
        if response:

            # Pull public key ID from json
            self.pubkey_id = json.get('pubkey_id')

            # Pull encrypted salt from json and decrypt it
            self.salt = crypt.decrypt(json.get('encrypt_salt'), self.private_key)

    def get_block(self, block_num: int) -> bytes:
        """
        Gets block store at address provided. Returns none if block doesn't exist or is empty
        :param block_num: Block number to retrieve
        :return: bytes or None
        """

        # Create signature of address
        sig = crypt.sign_list([bytes([block_num]), self.salt], private_key=self.private_key)

        # Prepare json dict
        get_json = {"pubkey_id": self.pubkey_id,
                    "block_num": block_num,
                    "signature": sig}

        # Issue get request
        response = requests.get(self.server_url + "block", json=get_json)

        # Pull json from request
        json = response.json()

        if json.get("chunked"):
            pass


        if not response:
            return response.json().get("error")

        # Return the data
        return crypt.b64_decode(json.get("data"))

    def put_block(self, data: bytes, block_num: int, expiration: int=2592000):
        """
        Puts a block into hiddil storage. If an address is provided, it overwrites the existing contents silently.
        :param data: Data bytes to store
        :param block_num: Block number to store data to
        :param expiration: Seconds until data expires and is irretrievable
        :raises PutDataHashException if remote hash doesn't equal local (data corruption)
        """

        if len(data) < self.MAX_BLOCK_CHUNK:
            self._single_put(data, block_num, expiration)
        else:
            self._chunked_put(data, block_num, expiration)


    def _single_put(self, data: bytes, block_num: int, expiration: int):

        # Create signature of put data
        sig = crypt.sign_list([bytes([block_num]), data, self.salt], self.private_key)

        # Apply b64 encoding to data
        data_b64 = crypt.b64_encode(data)

        # Prepare json dict
        put_json = {
            "pubkey_id": self.pubkey_id,
            "data": data_b64,
            "block_num": block_num,
            "signature": sig,
            "expiration": expiration,
            "sequence": 0,
            "size": len(data),
            "chunked": False
        }

        # Issue put block request
        response = requests.put(self.server_url+"block", json=put_json)

        # Pull json from request
        json = response.json()

        # Raise exception if local and remote data hash don't match
        if crypt.hash_bytes(data) != json.get("data_hash"):
            raise PutDataHashException

    def _chunked_put(self, data: bytes, block_num: int, expiration: int):

        # Create signature of put data
        sig = crypt.sign_list([bytes([block_num]), self.salt], self.private_key)

        # Prepare json dict
        put_json = {
            "pubkey_id": self.pubkey_id,
            "block_num": block_num,
            "signature": sig,
            "expiration": expiration,
            "sequence": 0,
            "size": len(data),
            "chunked": True
        }

        # Issue put block request
        response = requests.put(self.server_url + "block", json=put_json)

        # Prepare loop iter vars
        bytes_done = 0
        total_bytes = len(data)
        max_chunk_size = response.json().get("max_chunk_size")

        # Iterate until we've sent the required number of bytes
        while bytes_done != total_bytes:

            # Slice the next chunk of data to upload, and increment bytes done counter
            chunk_data = data[bytes_done: bytes_done + max_chunk_size]
            bytes_done += len(chunk_data)

            # Prepare the upload json request
            upload_json = {
                "pubkey_id": self.pubkey_id,
                "data_chunk_b64": crypt.b64_encode(chunk_data),
                "rolling_hash": crypt.hash_bytes(data[:bytes_done])
            }

            # Sent the upload request
            response = requests.put(self.server_url + "upload", json=upload_json)


        if response.json().get("status") != "Upload complete":
            raise Exception


if __name__ == "__main__":

    cli = Client()

    b1_num = 10
    b1_data = "short, secret message".encode("utf-8")

    b2_num = 20
    b2_data = "another message".encode("utf-8")

    b3_num = 30
    b3_data = bytes(b'a'*10000)

    cli.put_block(b1_data, b1_num)
    assert cli.get_block(b1_num) == b1_data

    cli.put_block(b2_data, b2_num)
    assert cli.get_block(b2_num) == b2_data

    cli.put_block(b3_data, b3_num)

    print("done")


