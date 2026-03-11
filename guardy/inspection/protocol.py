from typing import Dict, Any, List

class ProtocolInspector:
    """
    Layer 1: Inspects the raw metadata surrounding the file upload. 
    Looks for tampering, missing lengths, or suspicious multipart boundaries 
    before the bytes are deeply parsed.
    """
    
    @staticmethod
    def inspect(file_metadata: Dict[str, Any], raw_bytes_length: int) -> List[str]:
        anomalies = []
        
        # 1. Content-Length mismatch
        reported_size = file_metadata.get("size", -1)
        if reported_size > 0 and reported_size != raw_bytes_length:
            anomalies.append(f"Protocol Anomaly: Reported content length ({reported_size}) does not match actual bytes received ({raw_bytes_length}).")
            
        # 2. Suspicious Headers (If the backend forwards them)
        headers = file_metadata.get("headers", {})
        suspicious_headers = ["x-forwarded-host", "via", "x-hacker"]
        for header in headers.keys():
            if header.lower() in suspicious_headers:
                anomalies.append(f"Protocol Anomaly: Suspicious HTTP header detected '{header}'.")
        
        # 3. Double Extensions disguised in Content-Disposition filename
        filename = file_metadata.get("filename", "")
        if filename.count('.') > 1:
            # Check if it ends in common executable disguised as safe
            lower_name = filename.lower()
            if lower_name.endswith(('.jpg.exe', '.png.sh', '.pdf.vbs', '.doc.scr')):
                anomalies.append(f"Protocol Anomaly: Suspicious double-extension detected in filename '{filename}'.")
                
        return anomalies
