from typing import Optional

# Common magic bytes sequences for some file types
MAGIC_SIGNATURES = {
    "image/jpeg": [b"\xFF\xD8\xFF"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "application/pdf": [b"%PDF-"],
    "application/zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "image/gif": [b"GIF87a", b"GIF89a"],
}

class SignatureVerifier:
    @staticmethod
    def verify(file_bytes: bytes, expected_mime: str) -> bool:
        """
        Verify if the file_bytes match the expected magic bytes for the given mime type.
        Returns True if matched, False if mismatch, or True if we don't track signatures for that mime.
        """
        if not expected_mime or expected_mime not in MAGIC_SIGNATURES:
            # If we don't have a signature for it, we can't definitively verify it's anomalous via this check
            return True

        signatures = MAGIC_SIGNATURES[expected_mime]
        for sig in signatures:
            if file_bytes.startswith(sig):
                return True
                
        return False
