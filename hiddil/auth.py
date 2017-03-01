
# Library imports
import uuid
import time
from Crypto.PublicKey   import RSA
from Crypto.Cipher      import PKCS1_OAEP
from Crypto.Signature   import PKCS1_v1_5
from Crypto             import Signature
from Crypto.Hash        import SHA
import base64

# Project imports
import settings


class KeyNotSaltedException(Exception):
    pass
class SignatureVerifyFailException(Exception):
    pass


def randomHexString():
    return uuid.uuid1().hex

class Authentication(object):

    class _SaltItem(object):
        def __init__(self, public_key, salt=None):
            self.public_key = public_key
            self.salt       = salt
            self.expiration = time.time() + settings.TRUST_EXPIRE_TIME

    def __init__(self):

        # Initialise class vars
        self._salted_items = {}

    def verifySignature(self, signature_b64, pubkey_id, data_b64=None, data=None):

        # Perform garbage collection
        self._garbage_collection()

        # If key is not salted, throw exception
        if not self.isSalted(pubkey_id):
            raise KeyNotSaltedException()

        # Remove b64 encoding from their signature
        signature = base64.b64decode(signature_b64)

        # If data_b64 arg was passed, remove b64 encoding from it
        if data_b64:
            data = base64.b64decode(data_b64)

        # Grab key and salt
        key  = self._get_key_object(pubkey_id)
        salt = self._get_salt(pubkey_id)

        # Prepare hash of data
        data_hash = self._hash_data(data=data, salt=salt)

        # Create new signature scheme object with key
        scheme = PKCS1_v1_5.new(key)


        # Verify the signature
        result = scheme.verify(data_hash, signature)

        # If the verify fails, revoke the key salt and raise exception
        if result is False:
            self.revokeSalt(pubkey_id)
            raise SignatureVerifyFailException

    def createSalt(self, public_key):

        # Perform garbage collection
        self._garbage_collection()

        # Grab the id for this public key
        pubkey_id = self.publicKeyID(public_key)

        # Create salt string
        salt = randomHexString()

        print(")Salt: {}".format(salt))

        # Create a saltItem for this key, and store in dict
        self._salted_items[pubkey_id] = self._SaltItem(public_key=public_key, salt=salt)

        # Encrypt the salt
        encrypt_salt = self.Encrypt(pubkey_id=pubkey_id, data=salt)

        # Return a tuple of the public key id, and the encrypted salt
        return (pubkey_id, encrypt_salt)

    def Encrypt(self, data, pubkey_id):

        # If key is not salted, throw exception
        if not self.isSalted(pubkey_id):
            raise KeyNotSaltedException()

        # Grab key
        key = self._get_key_object(pubkey_id)

        # Create cipher object
        cipher = PKCS1_OAEP.new(key)

        # Encrypt the data, and apply base64 encoding and return
        return base64.b64encode( cipher.encrypt(data) )

    def Hash(self, data):
        return SHA.new(data)

    def publicKeyID(self, public_key):
        return SHA.new(public_key).hexdigest()

    def isSalted(self, pubkey_id):
        return pubkey_id in self._salted_items

    def revokeSalt(self, pubkey_id):
        if pubkey_id in self._salted_items:
            del self._salted_items[pubkey_id]

    def _get_key_object(self, pubkey_id):
        return RSA.importKey(self._get_public_key(pubkey_id))

    def _get_public_key(self, pubkey_id):
        return self._salted_items[pubkey_id].public_key

    def _get_salt(self, pubkey_id):
        return self._salted_items[pubkey_id].salt

    def _hash_data(self, data, salt):
        return SHA.new(data + salt)

    def _garbage_collection(self):

        # Create a copy of the list to iterate
        keys = self._salted_items.keys()

        # Iterate through all pending challenges
        for key in keys:

            # If challenge has expired, delete it
            if key in self._salted_items:
                if self._salted_items[key].expiration < time.time():
                    del self._salted_items[key]
