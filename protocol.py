
# Library imports
import time

# Project imports
from crypt import PublicKey
import crypt
import settings
from blockstorage.block import Block
from exceptions import RollingHashException, UploadOverflowException


class Protocol:

    MAX_CHUNK_SIZE = 700 # Allows for b64 encoding, and stays within 1.5K MTU

    class _Transfer:

        DOWNLOAD = "download"
        UPLOAD = "upload"

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block, block_key: str):
            # Store args in class
            self.public_key = public_key
            self.block = block
            self.operation = None
            self.expire_time = time.time() + settings.TRANSFER_EXPIRE_TIME
            self.num_bytes_total = num_bytes
            self.num_bytes_done = 0
            self.block_key = block_key
            self.rolling_hash = None
            self.data = bytes()

        @property
        def expired(self) -> bool:
            return time.time() > self.expire_time

    class _Upload(_Transfer):

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block, block_key: str):
            super(Protocol._Upload, self).__init__(public_key=public_key, num_bytes=num_bytes,
                                                   block=block, block_key=block_key)
            self.operation = self.UPLOAD

        def upload_chunk(self, data_chunk: bytes, rolling_hash: str):
            # If rolling hash provided doesn't match a locally generated one, raise an exception
            if crypt.hash_bytes(self.block[self.block_key] + data_chunk) != rolling_hash:
                raise RollingHashException

            # If we have received too many data bytes, raise an exception
            if self.num_bytes_done + len() > self.num_bytes_total:
                raise UploadOverflowException

            # No errors, append this data chunk
            self.data += data_chunk

            # If that's all the data uploaded, copy to the block and expire this transfer object
            if self.num_bytes_done == self.num_bytes_total:
                self.block[self.block_key] = self.data
                self.expire_time = 0

    class _Download(_Transfer):

        def __init__(self, public_key: PublicKey, num_bytes: int, block: Block, block_key: str):
            super(Protocol._Download, self).__init__(public_key=public_key, num_bytes=num_bytes,
                                                     block=block, block_key=block_key)
            self.operation = self.DOWNLOAD

        def download_chunk(self) -> bytes:

            # Set chunk size to max chunk size or less (for the last bytes)
            num_bytes_left = self.num_bytes_total - self.num_bytes_done
            chunk_size = num_bytes_left if num_bytes_left < Protocol.MAX_CHUNK_SIZE else Protocol.MAX_CHUNK_SIZE

            # Slice the chunk data, and increment bytes done counter
            chunk_data = self.data[self.num_bytes_done:self.num_bytes_done+chunk_size]
            self.num_bytes_done += chunk_size

            # If that's all the data downloaded, expire this transfer object
            if self.num_bytes_done == self.num_bytes_total:
                self.expire_time = 0

            # Return the chunk data
            return chunk_data

    def __init__(self):
        self._transfers = {}

    def register_download(self, public_key: PublicKey, block: Block, block_key: str, num_bytes: int):
        self._transfers[public_key.key_id] = self._Download(public_key=public_key, num_bytes=num_bytes,
                                                            block=block, block_key=block_key)

    def register_upload(self, public_key: PublicKey, block: Block, block_key: str, num_bytes: int):
        self._transfers[public_key.key_id] = self._Upload(public_key=public_key, num_bytes=num_bytes,
                                                          block=block, block_key=block_key)

    def upload_chunk(self, public_key: PublicKey, chunk_data_b64: str, rolling_hash: str):

        self._transfers[public_key.key_id].upload_chunk(crypt.b64_decode(chunk_data_b64), rolling_hash)

    def _garbage_collection(self):

        expired_list = []
        for pubkey_id, transfer in self._transfers.items():
            if transfer.expired:
                expired_list.append(pubkey_id)

        for pubkey_id in expired_list:
            self._transfers.pop(pubkey_id, None)

