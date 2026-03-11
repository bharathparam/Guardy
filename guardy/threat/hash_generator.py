import hashlib

class HashGenerator:
    @staticmethod
    def generate_sha256(file_bytes: bytes) -> str:
        """
        Generates a SHA-256 hash for the given file bytes.
        """
        sha256_hash = hashlib.sha256()
        sha256_hash.update(file_bytes)
        return sha256_hash.hexdigest()
