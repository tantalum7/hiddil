
# Project imports
from hiddil.crypt import PublicKey, b64_encode, b64_decode
from storage import Storage
from storage.uid import UID
from hiddil.exceptions import *


class Block:

    BLOCK_NUM_MAX = 999999999999999
    BLOCK_NUM_MIN = 1

    def __init__(self, block_number: int, storage: Storage, public_key: PublicKey):
        """
        Wrapper block object for storing data bytes in storage class, and managing expiration etc
        :param block_number: Block number to access
        :param storage: Reference to the storage instance the block is stored in
        :param public_key: Public key the block is stored with
        """

        # If block if block number is out of bounds, raise an exception
        if self.BLOCK_NUM_MIN > block_number > self.BLOCK_NUM_MAX:
            raise BlockNumOutofBounds("value:{}, max:{}, min{}".format(block_number, self.BLOCK_NUM_MAX,
                                                                       self.BLOCK_NUM_MIN))

        # Store args in class vars
        self._storage = storage
        self._pubkey = public_key
        self._uid = UID(public_key.key_id)
        self._block_number = block_number
        self._key = str(self.block_number)

    @property
    def public_key(self) -> PublicKey:
        return self._pubkey

    @property
    def block_number(self) -> int:
        return self._block_number

    @property
    def data(self) -> bytes:
        return self._storage.get(self._uid, self._key)

    @data.setter
    def data(self, new_data: bytes):
        self._storage.put(self._uid, self._key, new_data)

    def as_b64(self) -> str:
        return b64_encode(self.data)

    def from_b64(self, b64_data: str):
        self.data = b64_decode(b64_data)

    def erase(self):
        self._storage.delete(self._uid, self._key)

    def _key(self) -> str:
        return str(self.block_number)

    def __iter__(self):
        raise NotImplemented

    def __len__(self):
        return len(self._storage.get(self._uid, self._key))
