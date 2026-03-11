import os
from cryptography.fernet import Fernet
from typing import Tuple

class AESCipher:
    def __init__(self, key: bytes = None):
        """
        Initialize the cipher. If no key is provided, one is generated.
        The backend should optimally persist and provide this key.
        """
        if not key:
            key = Fernet.generate_key()
        self.key = key
        self.fernet = Fernet(self.key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts data in memory."""
        return self.fernet.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypts data in memory."""
        return self.fernet.decrypt(encrypted_data)
        
    def get_key(self) -> bytes:
        return self.key
