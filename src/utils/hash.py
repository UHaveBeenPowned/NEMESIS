from enum import Enum
import hashlib

from utils.logger import log_error

class SHAType(Enum):
    SHA_1   = 1,
    SHA_256 = 2,
    SHA_512 = 3,

class Hasher: 
    def __init__(self, sha_type: SHAType, file_path: str = None):
        self._sha_type = sha_type;
        self._file_path = file_path;

    def set_sha_type(self, sha_type: SHAType):
        self._sha_type = sha_type;

    def set_file_path(self, file_path: SHAType):
        self._file_path = file_path;

    def digest(self):
        if not self._file_path:
            log_error(f"[ERROR] No file path");
            return;

        try:
            hasher = self.__create_hasher();

            with open(self._file_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    hasher.update(block);
            return hasher.hexdigest();
        except Exception as e:
            log_error(f"Error calculating hash of {self._file_path}: {e}");

    def __create_hasher(self):
        hasher = None;
        match self._sha_type:
            case SHAType.SHA_1:   hasher = hashlib.sha1();
            case SHAType.SHA_256: hasher = hashlib.sha256();
            case SHAType.SHA_512: hasher = hashlib.sha512();

        return hasher;