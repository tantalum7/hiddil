
# Library imports
import time

# Project imports
from crypt import PublicKey
import crypt
import settings
from block import Block
from exceptions import RollingHashException, UploadOverflowException


class Transfer:

    MAX_CHUNK_SIZE = 700 # Allows for b64 encoding, and stays within 1.5K MTU

    class _Transfer:

        DOWNLOAD = "download"
        UPLOAD = "upload"

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block):
            # Store args in class
            self.public_key = public_key
            self.block = block
            self.operation = None
            self.expire_time = time.time() + settings.TRANSFER_EXPIRE_TIME
            self.num_bytes_total = num_bytes
            self.num_bytes_done = 0
            self.rolling_hash = None
            self.data = bytes()

        @property
        def expired(self) -> bool:
            return time.time() > self.expire_time

    class _Upload(_Transfer):

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block):
            super(Transfer._Upload, self).__init__(public_key=public_key, num_bytes=num_bytes, block=block)
            self.operation = self.UPLOAD
            if self.block.data is None:
                self.block.data = b''

        def upload_chunk(self, data_chunk: bytes, rolling_hash: str) -> bool:

            # If rolling hash provided doesn't match a locally generated one, raise an exception
            if crypt.hash_bytes(self.data + data_chunk) != rolling_hash:
                raise RollingHashException

            # If we have received too many data bytes, raise an exception
            if self.num_bytes_done + len(data_chunk) > self.num_bytes_total:
                raise UploadOverflowException

            # No errors, append this data chunk
            self.data += data_chunk

            # Increment num bytes done by the chunk size
            self.num_bytes_done += len(data_chunk)

            # If that's all the data uploaded, copy to the block and expire this transfer object, and return true
            if self.num_bytes_done == self.num_bytes_total:
                self.block.data = self.data
                self.expire_time = 0
                return True

            # Upload still not complete, return false
            else:
                return False

    class _Download(_Transfer):

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block):
            super(Transfer._Download, self).__init__(public_key=public_key, num_bytes=num_bytes, block=block)
            self.operation = self.DOWNLOAD

        def download_chunk(self) -> bytes:

            # Set chunk size to max chunk size or less (for the last bytes)
            num_bytes_left = self.num_bytes_total - self.num_bytes_done
            chunk_size = num_bytes_left if num_bytes_left < Transfer.MAX_CHUNK_SIZE else Transfer.MAX_CHUNK_SIZE

            # Slice the chunk data, and increment bytes done counter
            chunk_data = self.block.data[self.num_bytes_done:self.num_bytes_done+chunk_size]
            self.num_bytes_done += chunk_size

            # If that's all the data downloaded, expire this transfer object
            if self.num_bytes_done == self.num_bytes_total:
                self.expire_time = 0

            # Return the chunk data
            return chunk_data

    def __init__(self):
        self.active_transfers = {}

    def register_download(self, public_key: PublicKey, block: Block):
        self.active_transfers[public_key.key_id] = self._Download(public_key=public_key, num_bytes=len(block), block=block)

    def register_upload(self, public_key: PublicKey, block: Block, num_bytes: int):
        self.active_transfers[public_key.key_id] = self._Upload(public_key=public_key, num_bytes=num_bytes, block=block)

    def upload_chunk(self, public_key: PublicKey, chunk_data_b64: str, rolling_hash: str) -> bool:

        return self.active_transfers[public_key.key_id].upload_chunk(crypt.b64_decode(chunk_data_b64), rolling_hash)

    def _garbage_collection(self):

        expired_list = []
        for pubkey_id, transfer in self.active_transfers.items():
            if transfer.expired:
                expired_list.append(pubkey_id)

        for pubkey_id in expired_list:
            self.active_transfers.pop(pubkey_id, None)

