
# Library imports
import time

# Project imports
import hiddil.settings as settings
import hiddil.crypt as crypt
from hiddil.exceptions import *


class Authentication(object):

    class _SaltedKey(object):
        def __init__(self, public_key: crypt.PublicKey, salt: bytes):
            self.public_key = public_key
            self.salt = salt
            self.expiration = time.time() + settings.TRUST_EXPIRE_TIME

    def __init__(self):

        # Initialise class vars
        self._salted_items = {}

    def verify_signature(self, signature_b64: str, pubkey: crypt.PublicKey, data_b64: str=None, data: bytes=None):
        """
        Verify the signature of the data passed, and make sure its signed using an valid salt
        :param signature_b64: Data signature, encoded as a base64 string
        :param pubkey: Public key to verify with
        :param data_b64: Signed data, as a base64 string (use this arg or data for raw bytes)
        :param data: Signed data, as raw bytes
        :raises SignatureVerifyFailException: When signature verification fails
        :raises KeyNotSaltedException: When pubkey does not have a valid salt registered
        """
        # Perform garbage collection
        self._garbage_collection()

        # Get the key's salt
        salt = self._get_salt(pubkey)

        # If data_b64 arg was passed, remove b64 encoding from it
        if data_b64:
            data = crypt.b64_decode(data_b64)

        # Verify the signature, and check if it fails revoke the salt and raise and exception
        if not crypt.verify_list_signature([data, salt], signature_b64=signature_b64, public_key=pubkey):
            self.revoke_salt(pubkey)
            raise SignatureVerifyFailException

    def verify_put_signature(self, signature_b64: str, pubkey: crypt.PublicKey, block_num: int, data: bytes):
        self.verify_signature(signature_b64=signature_b64, pubkey=pubkey, data=bytes([block_num])+data)

    def verify_get_signature(self, signature_b64: str, pubkey: crypt.PublicKey, block_num: int):
        self.verify_signature(signature_b64=signature_b64, pubkey=pubkey, data=bytes([block_num]))

    def create_salt(self, public_key: crypt.PublicKey) -> str:
        """
        Creates a salt for the given public key, and registers it within the Authentication class.
        The salt is returned encrypted to the public key given
        :param public_key: Public key to link the salt to
        :return: Base64 encoded, encrypted salt
        """
        # Perform garbage collection
        self._garbage_collection()

        # Create new salt, and store it in the dict (indexed by pubkey id)
        salt_item = self._new_salt(public_key)
        self._salted_items[public_key.key_id] = salt_item

        # Encrypt the salt, and return it
        return crypt.encrypt(salt_item.salt, public_key)

    def is_salted(self, public_key: crypt.PublicKey) -> bool:
        """
        Returns true if the public key passed has a valid salt registered
        :param public_key: Public key to check is salted
        :return: True if salted, otherwise False
        """
        return public_key.key_id in self._salted_items

    def revoke_salt(self, public_key: crypt.PublicKey):
        """
        Revokes salt from the register for the given public key. If there isn't a valid salt, it does nothing
        :param public_key:
        """
        if public_key.key_id in self._salted_items:
            del self._salted_items[public_key.key_id]

    def get_salted_public_key(self, pubkey_id: str) -> crypt.PublicKey:
        """
        Grabs the public key for the id passed, if its salted. Raises KeyNotSaltedException if not salted.
        :param pubkey_id: ID of the public to fetch
        :return: PublicKey instance
        :raises: KeyNotSaltedException
        """
        try:
            return self._salted_items[pubkey_id].public_key
        except KeyError:
            raise KeyNotSaltedException

    def _get_salt(self, public_key: crypt.PublicKey):
        try:
            return self._salted_items[public_key.key_id].salt
        except KeyError:
            raise KeyNotSaltedException

    def _new_salt(self, public_key: crypt.PublicKey):
        return self._SaltedKey(public_key=public_key, salt=crypt.new_uuid().encode("utf-8"))

    def _garbage_collection(self):

        # Create a copy of the list to iterate
        keys = self._salted_items.keys()

        # Iterate through all pending challenges
        for key in keys:

            # If challenge has expired, delete it
            if key in self._salted_items:
                if self._salted_items[key].expiration < time.time():
                    del self._salted_items[key]






