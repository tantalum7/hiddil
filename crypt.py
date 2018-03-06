
# Library imports
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import uuid
import base64

# Project imports
from exceptions import *


class _RSA_Key:

    def __init__(self, key_ascii, passphrase=None):
        self._rsa = RSA.importKey(key_ascii, passphrase)
        self._id = hash_bytes(self._rsa.publickey().exportKey("DER"))[0:31]

    @property
    def key_id(self) -> str:
        """
        Returns the key ID, the first 32 hex chars of a 256bit hash of the public key.
        Used as shorthand for indexing a public key only, never for anything cryptographic
        :return: key ID string
        """
        return self._id

    def PKCS1_OAEP(self) -> PKCS1_OAEP:
        """
        Returns a new PKCS1_OAEP protocol instance, loaded with this key
        :return: New PKCS1_OAEP instance
        """
        return PKCS1_OAEP.new(self._rsa)

    def PKCS1_v1_5(self) -> PKCS1_v1_5:
        """
        Returns a new PKCS1_V1_5 protocol instance, loaded with this key
        :return: New PKCS1_V1_5 instance
        """
        return PKCS1_v1_5.new(self._rsa)


class PublicKey(_RSA_Key):

    def __init__(self, key_ascii: str):
        """
        Container class for RSA Public key
        :param key_ascii: Public key ascii string (PEM format)
        """
        super(PublicKey, self).__init__(key_ascii)

    def export_public_str(self) -> str:
        """
        Exports the public key as an ascii PEM string
        :return: Public key PEM ascii string
        """
        return self._rsa.exportKey("PEM").decode("utf-8")

    def export_public_bytes(self) -> bytes:
        """
        Exports the public key as bytes
        :return: Public key bytes
        """
        return self._rsa.exportKey("DER")


class PrivateKey(_RSA_Key):

    def __init__(self, key_ascii, passphrase=None):
        """
        Container class for RSA private key
        :param key_ascii: ascii format string of key to import
        :param passphrase: Password to unlock key with (None if not required)
        :raises: KeyImportException
        """
        super(PrivateKey, self).__init__(key_ascii, passphrase)
        if not self._rsa.has_private():
            raise KeyImportException("This is not a valid private key")

    def export_public_str(self) -> str:
        """
        Exports the RSA key as an ascii PEM string
        :return: RSA PEM ascii string
        """
        return self._rsa.publickey().exportKey("PEM").decode("utf-8")

    def export_public_bytes(self) -> bytes:
        """
        Exports the RSA key as bytes
        :return: RSA key bytes
        """
        return self._rsa.publickey().exportKey("DER")


def encrypt_str(plain_string: str, public_key: PublicKey, encoding: str ="utf-8") -> str:
    """
    Wrapped for Crypt.encrypt(), but it encodes the string ino bytes first
    :param plain_string: string to encrypt
    :param public_key: Public key to encrypt with
    :param encoding: Encoding to apply to input string (defaults to utf-8)
    :return: encrypted bytes, encoded as base64 string
    """
    return encrypt(plain_bytes=plain_string.encode(encoding), public_key=public_key)


def encrypt(plain_bytes: bytes, public_key: PublicKey) -> str:
    """
    Encrypt using PKCS1_OAEP protocol (using RSA).
    Encrypted bytes are encoded as a base64 string for portability
    :param plain_bytes: Data to encrypt
    :param public_key: Public key to encrypt with
    :return: encrypted bytes, encoded as base64 string
    """
    # Encrypt the data, and apply base64 encoding and return
    return b64_encode(public_key.PKCS1_OAEP().encrypt(plain_bytes))


def decrypt_str(crypt_string: str, private_key: PrivateKey, encoding: str = "utf-8") -> str:
    """
    Wrapper for decrypt, that returns a decoded string instead of raw bytes
    :param crypt_string: Data to decrypt, encoded as base64 string
    :param private_key: Private key to decrypt with
    :param encoding: String encoding to apply decode bytes with (defaults to utf-8)
    :return:
    """
    return decrypt(crypt_string=crypt_string, private_key=private_key).decode(encoding)


def decrypt(crypt_string: str, private_key: PrivateKey) -> bytes:
    """
    Decrypt using the PKCS1_OAEP protocol (using RSA)
    Assumes bytes are encoded as a base64 string
    :param crypt_string: Data to decrypt, encoded as base64 string
    :param private_key: Private RSA key to decrypt with
    :return: decrypted bytes
    """
    # Remove base64 encoding, decrypt data and return
    return private_key.PKCS1_OAEP().decrypt(b64_decode(crypt_string))


def hash_str(string: str, encoding: str="utf-8") -> str:
    """
    Wrapper for hash_bytes, which takes a string input and encodes it to bytes first
    :param string: Data string to hash
    :param encoding: Encoding to unpack string to bytes with (defaults to utf-8)
    :return: Hash hex digest string
    """
    return hash_bytes(data=string.encode(encoding))


def hash_bytes(data: bytes) -> str:
    """
    Generates SHA256 hash of input data, and returns it as a hex string
    :param data: Data bytes to hash
    :return: Hash hex digest string
    """
    return SHA.new(data).hexdigest()

def sign_salted(data: bytes, salt: bytes, private_key: PrivateKey) -> str:
    """
    Wrapper for sign, that appends a salt before signing.
    :param data: Data to sign
    :param salt: Salt to add to data
    :param private_key: Private RSA key to sign with
    :return:
    """
    return sign(data=data + salt, private_key=private_key)


def sign(data: bytes, private_key: PrivateKey) -> str:
    """
    Signs data bytes passed using PKCS1_V1_5 protocol, and returns as a base64 string.
    Uses crypt.hash_bytes to hash the data before signing
    :param data: Bytes to sign (the hash of)
    :param private_key: Private RSA key to sign with
    :return: Signature as base64 string
    """
    # Get hash of data and the
    data_hash = SHA.new()
    data_hash.update(data)

    # Sign the hash, apply b64 encoding and return
    return b64_encode(private_key.PKCS1_v1_5().sign(data_hash))


def verify_signature(signed_data: bytes, signature_b64: str, public_key: PublicKey) -> bool:
    """
    Verifies a signature using PKCS1_V1_5 protocol.
    Assumes the incoming signature is a base64 encoded string
    :param signed_data: Signed data to verify with
    :param signature_b64: Signature to verify, as a base64 string
    :param public_key: Public key to verify against
    :return: True if verify passes, otherwise false
    """
    # Create a local hash of the signed data
    data_hash = SHA.new()
    data_hash.update(signed_data)

    # Verify the signature, and return the response
    return public_key.PKCS1_v1_5().verify(data_hash, b64_decode(signature_b64))


def verify_salted_signature(signed_data: bytes, salt: bytes, signature_b64: str, public_key: PublicKey) -> bool:
    """
    Wrapper for verify_signature, that includes a salt
    :param signed_data: Signed data to verify with
    :param salt: Bytes to salt the data with before verifying
    :param signature_b64: Signature to verify, encoded with base64
    :param public_key: Public key to verify signature against
    :return: True if signature verifies, otherwise False
    """
    return verify_signature(signed_data=signed_data+salt, signature_b64=signature_b64, public_key=public_key)


def new_uuid() -> str:
    """
    Generates a new uuid, as a hex string
    :return: uuid hex string
    """
    return uuid.uuid1().hex


def b64_encode(bytes_in: bytes) -> str:
    """
    Applies base64 encoding to raw bytes, for safe operation in text-only mediums
    :param bytes_in:
    :return:
    """
    return "_B64_"+base64.b64encode(bytes_in).decode("utf-8")


def b64_decode(str_in: str) -> bytes:
    """
    Decocdes base64 encoding string, and returns raw bytes
    :param str_in: Base64 string to decode
    :return: Decoded raw bytes
    """
    return base64.b64decode(str_in[5:])
