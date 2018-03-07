
# Project imports
from storage.sqlite3_bindings import Sqlite3Backend
from storage.uid import UID


# Exceptions
class InvalidKeyException(Exception): pass
class InvalidUIDException(Exception): pass
class InvalidDataException(Exception): pass


# Set the default backend
StorageBackend = Sqlite3Backend


class Database:

    MAX_KEY_LENGTH = 32
    MAX_DATA_LENGTH = 65536

    def __init__(self, settings: dict):
        """
        Thin wrapper class around the specific implementation of GenericBackend used
        :param settings:
        """
        self._backend = StorageBackend(settings=settings)

    def open(self):
        self._backend.open()

    def close(self, options=None):
        self._backend.close(options=options)

    def get(self, uid: UID, key: str):
        self._validate(key=key, uid=uid)
        return self._backend.get(uid=uid, key=key)

    def get_dict(self, uid: UID):
        self._validate(uid=uid)
        return self._backend.get_document(uid=uid)

    def put(self, uid: UID, key, data):
        self._validate(uid=uid, key=key, data=data)
        self._backend.put(uid=uid, key=key, data=data)

    def delete(self, uid: UID, key):
        self._validate(uid=uid, key=key)
        self._backend.delete(uid=uid, key=key)

    def delete_document(self, uid):
        self._validate(uid=uid)
        self._backend.delete_document(uid=uid)

    def sync(self, options=None):
        self._backend.sync(options=options)

    def count(self, uid: UID):
        self._validate(uid=uid)
        return self._backend.count(uid=uid)

    @staticmethod
    def generate_uid():
        return UID.new()

    def _validate(self, key: str=None, uid: UID=None, data: bytes=None):
        # Validate key
        if key is not None:
            if not isinstance(key, str) or len(key) == 0 or len(key) > self.MAX_KEY_LENGTH:
                raise InvalidKeyException

        # Validate uid
        if uid is not None:
            if not isinstance(uid, UID):
                raise InvalidUIDException

        # Validate data
        if data is not None:
            if not isinstance(data, bytes) or len(data) < self.MAX_DATA_LENGTH:
                raise InvalidDataException
