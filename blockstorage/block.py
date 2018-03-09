
# Library imports

# Project imports
from blockstorage import BadBlockParametersException
from crypt import PublicKey
from storage import Storage
from storage.uid import UID


class Block:

    def __init__(self, storage: Storage, public_key: PublicKey):
        """
        This is a dict like storage class that maps arbitrary key strings with value strings.
        The values aren't stored in the class, the object is a wrapper for accessing through a Storage object
        :param storage:
        :param uid:
        """
        self._storage = storage
        self._pubkey = public_key
        self._uid = UID(public_key.export_public_str())

    @property
    def public_key(self) -> PublicKey:
        return self._pubkey

    def __getitem__(self, key: str) -> bytes:
        return self._storage.get(self._uid, str(key))

    def __setitem__(self, key: str, value: bytes):
        self._storage.put(self._uid, key, str(value))

    def __delitem__(self, key: str):
        self._storage.delete(self._uid, key)

    def __iter__(self):
        raise NotImplemented

    def __len__(self):
        return self._storage.count(self._uid)

    def values(self) -> [str]:
        return self._storage.get_dict(self._uid).values()

    def keys(self) -> [str]:
        return self._storage.get_dict(self._uid).keys()

    def items(self) -> [(str, str)]:
        return self._storage.get_dict(self._uid).items()


class EncryptedDocument(Document):

    def __init__(self, storage: Storage, uid: str, doc_key: DocumentKey):
        """
        Encrypted variant of Document. Inserts an encrypt/decrypt stage in set/get
        :param storage:
        :param uid:
        :param doc_key:
        """
        super(EncryptedDocument, self).__init__(storage=storage, uid=uid)
        self._doc_key = doc_key

    def __getitem__(self, key: str) -> str:
        return self._doc_key.decrypt(self._storage.get(self._uid, str(key)))

    def __setitem__(self, key: str, value: str):
        self._storage.put(self._uid, key, self._doc_key.encrypt(str(value)))