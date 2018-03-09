
# Library imports
import requests

# Project imports
import crypt
from exceptions import *


class Client(object):

    def __init__(self, server_url: str="http://127.0.0.1:4567/", key_file: str="test_key"):
        """
        Main client class, provides API to access remote hiddile storage and handle keys
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

    def get_block(self, address: str) -> bytes:
        """
        Gets block store at address provided. Returns none if block doesn't exist or is empty
        :param address: Globally unique address string
        :return: bytes or None
        """

        # Create signature of address
        sig = crypt.sign_salted(data=address.encode("utf-8"), salt=self.salt, private_key=self.private_key)

        # Prepare json dict
        get_json = {"pubkey_id": self.pubkey_id,
                    "address": address,
                    "signature": sig}

        # Issue get request
        response = requests.get(self.server_url + "block", json=get_json)

        # Pull json from request
        json = response.json()

        # Return the data
        return crypt.b64_decode(json.get("data"))

    def put_block(self, data: bytes, address: str, expiration: int=2592000):
        """
        Puts a block into hiddil storage. If an address is provided, it overwrites the existing contents silently.
        :param data: Data bytes to store
        :param address: Address to store data to
        :param expiration: Seconds until data expires and is irretrievable
        :raises PutDataHashException if remote hash doesn't equal local (data corruption)
        :return: Returns the address the data was inserted to
        """

        # Create signature of put data
        sig = crypt.sign_salted(data, self.salt, self.private_key)

        # Apply b64 encoding to data
        data_b64 = crypt.b64_encode(data)

        # Prepare json dict
        put_json = {
            "pubkey_id": self.pubkey_id,
            "data": data_b64,
            "address" : address,
            "signature": sig,
            "expiration": expiration,
            "sequence": 0,
        }

        # Issue put block request
        response = requests.put(self.server_url+"block", json=put_json)

        # Pull json from request
        json = response.json()

        # Raise exception if local and remote data hash don't match
        if crypt.hash_bytes(data) != json.get("data_hash"):
            raise PutDataHashException

        # Return the insertion address
        return json.get("insertion_address")


if __name__ == "__main__":

    cli = Client()

    b1_addr = cli.put_block("Secret messsage1".encode("utf-8"), "1f39c940213211e891fed89ef3043ca9")
    b2_addr = cli.put_block("Secret messsage2".encode("utf-8"), "2f39c940213211e891fed89ef3043ca9")

    print(cli.get_block(b1_addr))

    print("done")


