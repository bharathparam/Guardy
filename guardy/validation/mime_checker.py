import magic

class MimeChecker:
    @staticmethod
    def get_mime_type(file_bytes: bytes) -> str:
        """Uses python-magic to robustly detect the true MIME type from file bytes."""
        try:
            return magic.from_buffer(file_bytes, mime=True)
        except Exception:
            return "application/octet-stream"
