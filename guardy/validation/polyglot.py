import re
from typing import List

class PolyglotDetector:
    """
    Layer 3: Embedded Content Detection
    Scans the raw binary for signatures of nested file types or malicious scripts
    that do not belong inside the reported MIME type.
    """
    
    # Common polyglot signatures
    SUSPICIOUS_PATTERNS = {
        "PHP Script": rb"<\?php",
        "System Execution": rb"(eval\(|system\(|exec\()",
        "HTML/JS Script": rb"(<html|<script|javascript:)",
        "Embedded ZIP Archive": rb"PK\x03\x04",
        "Embedded Windows Executable (MZ)": rb"MZ",
        "Embedded PDF": rb"%PDF-"
    }

    @staticmethod
    def detect(file_bytes: bytes, mime_type: str) -> List[str]:
        """
        Scans binary content for suspicious script/html/binary patterns.
        Returns a list of detected anomalies.
        """
        anomalies = []
        
        # Determine what signatures are "expected" based on the mime type so we don't false positive
        expected_patterns = []
        if mime_type in ["application/zip", "application/x-zip-compressed", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]:
            expected_patterns.append("Embedded ZIP Archive")
        if mime_type == "application/pdf":
            expected_patterns.append("Embedded PDF")
        if mime_type == "text/html":
            expected_patterns.append("HTML/JS Script")
            
        # Count how many distinct file formats seem to be embedded
        format_hits = 0

        for name, pattern in PolyglotDetector.SUSPICIOUS_PATTERNS.items():
            if name in expected_patterns:
                continue
                
            # For MZ (Windows PE), we only consider it highly suspicious if it's found but we are not an EXE.
            # Usually MZ is at the very beginning of a file, but in a polyglot it might be offset.
            # To reduce false positives on 'MZ' (it's just two ascii characters), we could restrict the search
            # slightly, but for this demonstration we'll scan the whole payload.
            if name == "Embedded Windows Executable (MZ)":
                # Check if MZ appears followed by standard PE structure indicators (heuristically)
                # Or just report it if it's found at the exact start (which is a standard EXE, but MIME was wrong) 
                # or randomly inside (which could be a false positive or an embedded dropper).
                if file_bytes.startswith(b"MZ") and mime_type not in ["application/x-msdownload", "application/x-executable"]:
                     anomalies.append(f"Embedded Content Anomaly: File claims to be '{mime_type}' but starts with Windows Executable (MZ) signature.")
                     format_hits += 1
            else:
                if re.search(pattern, file_bytes, re.IGNORECASE):
                    anomalies.append(f"Embedded Content Anomaly: Found unexpected {name} signature inside '{mime_type}'.")
                    format_hits += 1
                    
        if format_hits >= 2:
            anomalies.append("Severe Embedded Content Anomaly: Multiple conflicting magic signatures detected. High probability of a Polyglot payload.")
            
        return anomalies
