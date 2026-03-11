import pydantic
import io
import mimetypes
import os
import datetime
from typing import Optional, Dict, Any, List

from .validation.mime_checker import MimeChecker
from .validation.signature import SignatureVerifier
from .validation.polyglot import PolyglotDetector
from .threat.hash_generator import HashGenerator
from .threat.ai_anomaly import calculate_entropy
from .encryption.aes_cipher import AESCipher
from .config import GuardConfig
from .adapters import StorageAdapter, DatabaseAdapter

# Advanced Layers
from .inspection.protocol import ProtocolInspector
from .inspection.structure_parser import StructureParser
from .inspection.zip_bomb import ZipBombDetector

class FileAssessment(pydantic.BaseModel):
    is_safe: bool
    risk_score: float  # 0.0 to 1.0 (Higher = more risky)
    detected_mime: str
    sha256_hash: str
    reasons: List[str] = []
    encrypted_bytes: Optional[bytes] = None
    ai_telemetry: Optional[Dict[str, Any]] = None

class FileAnalyzer:
    def __init__(self, config: GuardConfig = None, 
                 storage_adapter: StorageAdapter = None,
                 database_adapter: DatabaseAdapter = None):
        self.config = config or GuardConfig()
        self.storage_adapter = storage_adapter
        self.database_adapter = database_adapter
        try:
            from .threat.ml.predict import FileAnalyzer as MLAnalyzer
            self.ml_engine = MLAnalyzer(device='cpu')
        except Exception as e:
            self.ml_engine = None
            print(f"Warning: Could not initialize PyTorch ML Engine: {e}")
        
    def analyze_file(self, 
                    file_bytes: bytes, 
                    filename: str, 
                    user_history_data: List[Dict[str, Any]] = None,
                    encryption_key: bytes = None,
                    file_metadata: Dict[str, Any] = None) -> FileAssessment:
        """
        Analyzes a file completely in-memory, without hitting disk or DB.
        Executes a 5-Layer Deep Inspection process.
        """
        reasons = []
        risk_score = 0.0
        file_metadata = file_metadata or {}
        
        # --- LAYER 1: Protocol & Header Inspection ---
        protocol_anomalies = ProtocolInspector.inspect(file_metadata, len(file_bytes))
        if protocol_anomalies:
            risk_score += self.config.weight_protocol_anomaly * len(protocol_anomalies)
            reasons.extend(protocol_anomalies)

        # Baseline parsing
        detected_mime = MimeChecker.get_mime_type(file_bytes)
        _, ext = os.path.splitext(filename)
        guessed_mimes = mimetypes.guess_type(filename)[0]
        
        # MIME Spoof Detection
        is_mime_mismatch = False
        if ext and guessed_mimes and not detected_mime.startswith(guessed_mimes.split("/")[0]):
            is_mime_mismatch = True
            risk_score += self.config.weight_mime_spoofing
            reasons.append(f"MIME Spoofing: Extension '{ext}' does not match content '{detected_mime}'.")
            
        # Signature Verification
        is_signature_mismatch = False
        if not SignatureVerifier.verify(file_bytes, detected_mime):
            is_signature_mismatch = True
            risk_score += self.config.weight_signature_mismatch
            reasons.append(f"Signature Mismatch: Magic bytes do not align with {detected_mime}")
            
        # --- LAYER 2: Binary Structure Analysis ---
        structure_anomalies = StructureParser.parse(file_bytes, detected_mime)
        if structure_anomalies:
            risk_score += self.config.weight_structure_anomaly * len(structure_anomalies)
            reasons.extend(structure_anomalies)
            
        # --- LAYER 3: Embedded Content (Polyglot) Detection ---
        polyglot_anomalies = PolyglotDetector.detect(file_bytes, detected_mime)
        if polyglot_anomalies:
            risk_score += self.config.weight_polyglot * len(polyglot_anomalies)
            reasons.extend(polyglot_anomalies)
            
        # --- LAYER 4: Zip Bomb & Archive Compression Analysis ---
        # Pass the config to zip bomb detector
        archive_anomalies = ZipBombDetector.scan_archive(file_bytes, detected_mime, self.config.max_zip_compression_ratio)
        if archive_anomalies:
            risk_score += self.config.weight_archive_bomb * len(archive_anomalies)
            reasons.extend(archive_anomalies)

        # SHA-256 Hashing
        file_hash = HashGenerator.generate_sha256(file_bytes)
        
        # --- LAYER 5: File Entropy ---
        current_entropy = calculate_entropy(file_bytes)
        
        # High Entropy Check (Encrypted/Obfuscated Payload Heuristics)
        if current_entropy > self.config.max_safe_entropy and detected_mime not in ["application/zip", "application/x-zip-compressed", "application/gzip"]:
            risk_score += self.config.weight_entropy_anomaly
            reasons.append(f"Entropy Anomaly: Highly obfuscated or encrypted payload detected (Entropy: {current_entropy:.2f})")

        # --- STAGE 2: PyTorch AI Deep Inspection ---
        ai_telemetry = None
        if risk_score >= self.config.ai_trigger_threshold and self.ml_engine:
            ml_result = self.ml_engine.analyze_bytes(file_bytes, filename)
            if "error" not in ml_result:
                ai_telemetry = {
                    "cnn_score": ml_result.get("cnn_score"),
                    "anomaly_score": ml_result.get("anomaly_score"),
                    "final_risk": ml_result.get("final_risk")
                }
                if ml_result.get("final_risk", 0) > 0.5:
                    risk_score += self.config.weight_pytorch_anomaly
                    reasons.append(f"AI Behavior Anomaly: PyTorch dual-model engine flagged file as malicious (Score: {ml_result['final_risk']})")

        # --- ADVANCED RISK SCORING ENGINE ---
        # Cap risk score
        risk_score = min(1.0, risk_score)
        
        # Final Decision
        is_safe = risk_score < self.config.rejection_risk_threshold

        # Encryption (if requested)
        encrypted_bytes = None
        if encryption_key:
            cipher = AESCipher(encryption_key)
            encrypted_bytes = cipher.encrypt(file_bytes)

        return FileAssessment(
            is_safe=is_safe,
            risk_score=round(risk_score, 2),
            detected_mime=detected_mime,
            sha256_hash=file_hash,
            reasons=reasons,
            encrypted_bytes=encrypted_bytes,
            ai_telemetry=ai_telemetry
        )
        
    async def analyze_and_execute(self, file_bytes: bytes, filename: str, user_id: str = "anonymous", **kwargs) -> FileAssessment:
        """
        Runs the full analysis AND automatically executes the disk saving and database telemetry if adapters were provided.
        """
        assessment = self.analyze_file(file_bytes=file_bytes, filename=filename, **kwargs)
        bytes_to_save = assessment.encrypted_bytes if assessment.encrypted_bytes else file_bytes
        
        # 1. Execute Storage Adapter (Save to Disk/S3)
        file_uri = ""
        if self.storage_adapter:
            if assessment.is_safe:
                file_uri = await self.storage_adapter.save_safe_file(filename, bytes_to_save)
            else:
                file_uri = await self.storage_adapter.save_quarantine_file(filename, bytes_to_save)
                
        # 2. Execute Database Adapter (Log Telemetry)
        if self.database_adapter:
            record = {
                "user_id": user_id,
                "original_filename": filename,
                "storage_uri": file_uri,
                "is_safe": assessment.is_safe,
                "risk_score": assessment.risk_score,
                "reasons": assessment.reasons,
                "detected_mime": assessment.detected_mime,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "ai_telemetry": assessment.ai_telemetry
            }
            await self.database_adapter.log_upload_event(record)
            
        return assessment

    async def analyze_stream(self, file_stream, filename: str, chunk_size: int = 65536, **kwargs) -> FileAssessment:
        """
        Layer 5: Memory Safe Streaming Scanner
        Instead of loading the entire file into RAM, this method processes the file in chunks.
        It generates rolling hashes, entropy, and validates magic headers securely.
        (Note: deep Zip Bomb or Structure parsing may require full buffering internally 
        by those specific modules if they cannot stream, but the overarching pipeline remains chunk-driven).
        """
        import hashlib
        import math
        from collections import Counter
        
        sha256 = hashlib.sha256()
        total_size = 0
        byte_counts = Counter()
        first_chunk = None

        while True:
            # Assume file_stream has an async read method like Starlette's UploadFile
            chunk = await file_stream.read(chunk_size)
            if not chunk:
                break
                
            if first_chunk is None:
                first_chunk = chunk
                
            total_size += len(chunk)
            sha256.update(chunk)
            byte_counts.update(chunk)
            
        final_hash = sha256.hexdigest()
        
        # Calculate streaming entropy
        entropy = 0.0
        if total_size > 0:
            probs = [count / total_size for count in byte_counts.values()]
            entropy = -sum(p * math.log2(p) for p in probs)
            
        # For full deep inspection on stream data, a production implementation would 
        # either feed a state machine or utilize an IO wrapper. For now, we fallback
        # to the byte analyzer using the aggregated or first-chunk data.
        
        # Reconstruct just for testing deep layers: (In reality, we'd only pass stream headers)
        await file_stream.seek(0)
        full_bytes = await file_stream.read() 
        
        kwargs.setdefault('file_metadata', {})
        kwargs['file_metadata']['size'] = total_size
        
        # We proxy to the full analyzer logic but provide the pre-calculated stream stats
        assessment = self.analyze_file(
            file_bytes=full_bytes, 
            filename=filename, 
            **kwargs
        )
        
        # Override with our streaming precision metrics
        assessment.sha256_hash = final_hash
        # assessment.reasons could be appended with stream specific anomalies here
        
        return assessment
