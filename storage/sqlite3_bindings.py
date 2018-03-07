
# Library imports
import sqlite3

# Project imports
from storage.uid import UID


class Sqlite3Backend:

    MAX_KEY_LENGTH = 32

    class _Connection:

        def __init__(self, db_path: str):
            self._conn = sqlite3.connect(db_path)
            self._conn.isolation_level = "EXCLUSIVE"
            self._conn.execute("BEGIN EXCLUSIVE")

        def __enter__(self):
            return self._conn.cursor()

        def __exit__(self, *args, **kwargs):
            self._conn.commit()
            self._conn.close()

    def __init__(self, settings: dict):
        """
        SQLite3 storage backend
        :param settings:
        """
        self.settings = settings

    def open(self):
        """
        Open function not used
        """
        pass

    def close(self, options: dict):
        """
        Close function not used
        """
        pass

    def create(self):
        """
        Creates a new database file at the path specified in settings dict.
        """
        with self._get_cursor() as cursor:
            cursor.execute("""CREATE TABLE hiddil (uid VARCHAR(32), dkey VARCHAR(32), data BLOB, 
                              PRIMARY KEY (uid, dkey));""")

    def get(self, uid: UID, key: str) -> bytes:
        """
        Fetches the bytes stored under the key for this UID.
        :param uid: UID instance to access
        :param key: Key string to lookup
        :return: bytes stored or None if key doesn't exist or data is empty
        """
        with self._get_cursor() as cursor:
            result = cursor.execute("SELECT data FROM hiddil WHERE uid=? AND dkey=?;", (str(uid),key)).fetchone()
            if result:
                return result[0]
            else:
                return None

    def get_document(self, uid) -> dict:
        """
        Retrieves every key: value pair associated with the UID provided
        :param uid: ID instance to retrieve document for
        :return: Dict of key: value pairs
        """
        with self._get_cursor() as cursor:
            result = cursor.execute("SELECT dkey, data FROM hiddil WHERE uid=?;", (str(uid),)).fetchall()
            if result:
                return dict(result)
            else:
                None

    def put(self, uid: UID, key: str, data: bytes):
        """
        Stores data bytes against the key provided, for the document at the UID provided.
        This operation replaces existing contents silently (upsert)
        :param uid: UID instance for the document to operate on
        :param key: Key string to store the data against
        :param data: Data bytes to store
        """

        with self._get_cursor() as cursor:
            cursor.execute("REPLACE INTO hiddil (uid, dkey, data) VALUES(?, ?, ?)", (str(uid), str(key), data,))

    def delete(self, uid, key):
        """
        Delete data store against the key for the document with the UID provided.
        This operation will fail silently if there is no entry to delete
        :param uid: UID instance for the document to operate on
        :param key: Key string tfor the entry to remove
        """
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM hiddil WHERE uid=? AND dkey=?;", (str(uid), key))

    def delete_document(self, uid):
        """
        Delete the entire document with the UID provided
        :param uid:
        :return:
        """
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM hiddil WHERE uid=?;", (str(uid),))

    def sync(self, options: dict):
        """
        Sync not used
        """
        # TODO: Add backup file option? Operate on tempfile db, and duplicate to real file on sync?
        pass

    def count(self, uid: UID) -> int:
        """
        Returns the number of keys associated to a UID
        :param uid: UID to count keys for
        :return: number of keys (int)
        """
        with self._get_cursor() as cursor:
            return len(cursor.execute("SELECT uid FROM hiddil WHERE uid=?;", (str(uid),)).fetchall())

    def _get_cursor(self):
        return self._Connection(self.settings["path"])


def test_sqlite3_backend():
    import os

    backend = Sqlite3Backend({"path": "test.db"})

    u1 = UID("01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    # Test create
    backend.create()

    # Test put() and get()
    backend.put(u1, "first", "first_entry".encode("utf-8"))
    assert backend.get(u1, "first") == b'first_entry'
    backend.put(u1, "second", "second_entry".encode("utf-8"))
    assert backend.get(u1, "second") == b'second_entry'

    # Test count()
    assert backend.count(u1) == 2

    # Test delete()
    backend.delete(u1, "first")
    assert backend.get(u1, "first") is None

    # Test get_document()
    assert backend.get_document(u1) == {"second": b'second_entry'}

    # Test delete_document()
    backend.delete_document(u1)
    assert backend.get_document(u1) is None

    # Clean up test file afterwards
    os.remove("test.db")


if __name__ == "__main__":

    test_sqlite3_backend()
    print("done")
