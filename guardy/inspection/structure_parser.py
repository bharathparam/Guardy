import struct
from typing import List

class StructureParser:
    """
    Layer 2: Parses the internal structure/tree of specific high-risk file types 
    (like JPEG and PDF) to ensure they are properly formed and not just 
    carrying a faked header signature.
    """

    @staticmethod
    def parse(file_bytes: bytes, mime_type: str) -> List[str]:
        anomalies = []
        
        if mime_type in ["image/jpeg", "image/jpg"]:
            anomalies.extend(StructureParser._parse_jpeg(file_bytes))
        elif mime_type == "application/pdf":
            anomalies.extend(StructureParser._parse_pdf(file_bytes))
            
        return anomalies

    @staticmethod
    def _parse_jpeg(data: bytes) -> List[str]:
        anomalies = []
        if len(data) < 2 or data[0:2] != b'\xff\xd8':
            anomalies.append("Structure Anomaly: Invalid JPEG Start of Image (SOI) marker.")
            return anomalies
        
        # Look for expected APP0/APP1 or DQT markers near the start
        has_app_marker = False
        # Read the first chunk of headers
        i = 2
        while i < len(data) and i < 1024:
            if data[i] == 0xff:
                marker = data[i+1]
                if marker in [0xe0, 0xe1]: # APP0 or APP1
                    has_app_marker = True
                    break
            i += 1
            
        if not has_app_marker:
            anomalies.append("Structure Anomaly: JPEG lacks expected APP segment headers.")
            
        # Check for ZIP structures embedded inside the JPEG (Layer 3 overlap)
        if b'PK\x03\x04' in data[10:]:
            anomalies.append("Structure Anomaly: ZIP archive signature detected inside JPEG binary stream.")
            
        return anomalies

    @staticmethod
    def _parse_pdf(data: bytes) -> List[str]:
        anomalies = []
        
        if not data.startswith(b'%PDF-'):
            anomalies.append("Structure Anomaly: Missing PDF header sequence.")
            
        # Check for EOF marker closing the structural tree
        if b'%%EOF' not in data[-1024:]:
            anomalies.append("Structure Anomaly: Missing %%EOF marker, indicating malformed or appended payload.")
            
        # Check for suspicious embedded Javascript execution tags
        suspicious_tags = [b'/JS', b'/JavaScript', b'/OpenAction', b'/Launch']
        for tag in suspicious_tags:
            if tag in data:
                # PDF can legitimately have JS, but it increases risk significantly
                anomalies.append(f"Structure Anomaly: Extracted active content script tag: {tag.decode('utf-8', 'ignore')}")
                
        return anomalies
