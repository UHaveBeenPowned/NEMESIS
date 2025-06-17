import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from pathlib import Path

from utils.logger import log_info, log_error

class Decryptor:
#public
    def __init__(self):
        log_info(f'[INFO] Setting up "Decryptor"');
        self._key_b64:   str   = None;
        self._plain_key: bytes = None;
        self._extension: str   = ".fun";
#public
    def search_and_destroy(self, path: str = "C:\\"):
        if self._key_b64 or self._plain_key:
            key: bytes = self.__decode_base64(self._key_b64) if self._key_b64 else self._plain_key;
            for root, dirs, _ in os.walk(path, topdown=True):
                for dir in dirs:
                    for file in dir:
                        try:
                            file_path: Path = Path(root) / dir / file;
                            if file_path.suffix ==  self._extension:
                                self.__decrypt_file(str(file_path), key);
                        except Exception as e:
                            log_error(f"[ERROR] Error while processing: {e}");
        else:
            log_info(f'[INFO] No key setted, setting down "Decryptor"');

#private
    def __decrypt_file(self, file_path: str, key: bytes):
        log_info(f"\n[INFO] Removing encryption in {file_path}");

        try:
            with open(file_path, "rb") as f:
                encrypted_data: bytes = f.read();
            
            cipher = AES.new(key, AES.MODE_ECB);
            clean_data = unpad(cipher.decrypt(encrypted_data), AES.block_size);
            
            clean_path = file_path.with_suffix("");
            with open(clean_path, "wb") as f:
                f.write(clean_data);
            
            os.remove(file_path);
            log_info(f"[SUCCESS] {file_path} recovered.");
        except Exception as e:
            log_error(f"[ERROR] Error while removing encryption: {e}");

    def __decode_base64(self, data: str):
        try:
            return base64.b64decode(data);
        except Exception as e:
            log_error(f"[ERROR] Error while decoding key: {e}");