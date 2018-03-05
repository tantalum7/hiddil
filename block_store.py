
from auth import Authentication, randomHexString
from database import Database


class BadBlockParametersException(Exception):
    pass


class BlockStore(object):

    def __init__(self, ip_port_tuple):

        # Prepare main modules
        self.auth       = Authentication()
        self.db         = Database(ip_port_tuple)

    def Put(self, pubkey_id, data, expiration, address=None):

        # If no address is passed, create a new one
        address = randomHexString() if address is None else address

        # Prepare document
        doc = { '_id'           : address,
                'pubkey_id'     : pubkey_id,
                'data'          : data,
                'expiration'    : expiration
              }

        # Insert
        return self.db.insert_one(doc).inserted_ids[0]

    def Get(self, pubkey_id, address):

        # Search for block
        block = self.db.find_one( {'_id':address} )

        # If searching pubkey doesn't match block pubkey, set the block to None
        if pubkey_id != block.get('pubkey_id'):
            block = None

        # Return the block
        return block



class Block(object):

    def __init__(self, pubkey, data, signature, expiration, address=None):

        # Copy class vars
        self.address    = str(address)
        self.data   = str(data)
        self.expiration = int(expiration)

        # Check for bad address, and raise exception as required
        int(address)
        if len(self.address) != 32:
            raise BadBlockParametersException("Invalid address hex string")

        # Check for invalid data size, and raise exception as required
        if len(self.data) > 11000:
            raise BadBlockParametersException("Data string too long, greater than 11K")

        # Check for invalid expiration length, and raise exception as required
        if self.expiration > (60 * 60 * 24 * 365 * 1000):
            raise BadBlockParametersException("Invalid expiration, greater than 1000 years")

        # If no address is passed, create a random address (assumed unique)
        if self.address is None:
            self.address = randomHexString()