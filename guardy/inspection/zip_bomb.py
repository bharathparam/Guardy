import io
import zipfile
import tarfile
from typing import List

class ZipBombDetector:
    """
    Layer 4: Zip Bomb & Archive Compression Analyzer.
    Reads zip/tar files strictly in memory (without extracting to disk)
    to calculate compression ratios and nested depths.
    """
    
    # 100x compression is highly suspicious for standard documents/images
    MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024 # Reject if expands to > 500MB
    MAX_NESTED_ARCHIVES = 3
    
    @staticmethod
    def scan_archive(file_bytes: bytes, mime_type: str, max_compression_ratio: float = 100.0) -> List[str]:
        anomalies = []
        is_zip = mime_type in ["application/zip", "application/x-zip-compressed"]
        is_tar = mime_type in ["application/x-tar", "application/gzip"]
        
        if not (is_zip or is_tar):
            return anomalies
            
        stream = io.BytesIO(file_bytes)
        compressed_size = len(file_bytes)
        
        if compressed_size == 0:
            return anomalies
            
        try:
            if is_zip and zipfile.is_zipfile(stream):
                anomalies.extend(ZipBombDetector._analyze_zip(stream, compressed_size, max_compression_ratio))
            elif is_tar:
                # Need to reset stream for tar
                stream.seek(0)
                try:
                    with tarfile.open(fileobj=stream, mode='r:*') as tar:
                        anomalies.extend(ZipBombDetector._analyze_tar(tar, compressed_size, max_compression_ratio))
                except tarfile.TarError:
                    pass # Not a valid tar or corrupted
        except Exception as e:
            anomalies.append(f"Archive Anomaly: Malformed or unparseable archive structure ({str(e)}).")

        return anomalies

    @staticmethod
    def _analyze_zip(stream: io.BytesIO, compressed_size: int) -> List[str]:
        anomalies = []
        total_uncompressed = 0
        nested_count = 0
        
        try:
            with zipfile.ZipFile(stream) as zf:
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    
                    if info.filename.lower().endswith(('.zip', '.tar', '.gz')):
                        nested_count += 1
                        
                ratio = float(total_uncompressed) / float(compressed_size)
                
                if ratio > ZipBombDetector.MAX_COMPRESSION_RATIO:
                    anomalies.append(f"Archive Anomaly: Extreme compression ratio ({ratio:.1f}x) detected. Possible Zip Bomb.")
                    
                if total_uncompressed > ZipBombDetector.MAX_UNCOMPRESSED_SIZE:
                    anomalies.append(f"Archive Anomaly: Uncompressed size exceeds safe threshold ({total_uncompressed / 1024 / 1024:.1f}MB).")
                    
                if nested_count > ZipBombDetector.MAX_NESTED_ARCHIVES:
                    anomalies.append(f"Archive Anomaly: Excessive nested archives ({nested_count}) detected.")
                    
        except zipfile.BadZipFile:
            anomalies.append("Archive Anomaly: Corrupted Zip Header.")
            
        return anomalies

    @staticmethod
    def _analyze_tar(tar: tarfile.TarFile, compressed_size: int) -> List[str]:
        anomalies = []
        total_uncompressed = 0
        nested_count = 0
        
        for member in tar.getmembers():
            if member.isfile():
                total_uncompressed += member.size
                if member.name.lower().endswith(('.zip', '.tar', '.gz')):
                    nested_count += 1
                    
        ratio = float(total_uncompressed) / float(compressed_size)
        
        if ratio > ZipBombDetector.MAX_COMPRESSION_RATIO:
            anomalies.append(f"Archive Anomaly: Extreme compression ratio ({ratio:.1f}x) detected. Possible Tar Bomb.")
            
        if total_uncompressed > ZipBombDetector.MAX_UNCOMPRESSED_SIZE:
             anomalies.append(f"Archive Anomaly: Uncompressed size exceeds safe threshold ({total_uncompressed / 1024 / 1024:.1f}MB).")
             
        if nested_count > ZipBombDetector.MAX_NESTED_ARCHIVES:
             anomalies.append(f"Archive Anomaly: Excessive nested archives ({nested_count}) detected.")
             
        return anomalies
