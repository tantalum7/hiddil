
# Library imports
import uuid


class UID:

    def __init__(self, uid: str):
        """
        Simple container object for uid string. Replacing generic string uid in case we need to tie the format
        down to something more specific.
        :param uid:
        """
        self._uid = uid

    def __str__(self):
        return str(self._uid)

    def __repr__(self):
        return "UID({0})".format(self.__str__())

    @staticmethod
    def new():
        return UID(uuid.uuid4().hex)

