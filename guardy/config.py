from pydantic import BaseModel, Field

class GuardConfig(BaseModel):
    """
    Configuration model for the Secure File Guard library.
    Allows backend developers to customize the internal risk thresholds and weights 
    for the 5-layer Deep Inspection engine.
    """
    
    # --- Deep Inspection Thresholds ---
    max_safe_entropy: float = Field(default=7.8, description="Files with entropy higher than this are flagged as obfuscated/encrypted anomalies.")
    max_zip_compression_ratio: float = Field(default=100.0, description="Maximum allowed expansion ratio for archives to prevent Zip Bombs.")
    max_ai_anomaly_score: float = Field(default=0.6, description="Behavioral uploads scoring higher than this are penalized.")
    
    # --- Advanced Risk Scoring Weights ---
    # The final risk score (0.0 - 1.0) is calculated by summing these penalties when an anomaly is detected.
    weight_protocol_anomaly: float = Field(default=0.15, description="Penalty added per protocol/header anomaly.")
    weight_mime_spoofing: float = Field(default=0.3, description="Penalty added if the file extension does not match the MIME type.")
    weight_signature_mismatch: float = Field(default=0.3, description="Penalty added if the file magic bytes do not match the MIME type.")
    weight_structure_anomaly: float = Field(default=0.35, description="Penalty added per internal tree structure anomaly (e.g. malformed JPEG APP0).")
    weight_polyglot: float = Field(default=0.4, description="Penalty added per unauthorized embedded file format detected.")
    weight_archive_bomb: float = Field(default=0.5, description="Penalty added per zip-bomb indicator triggered.")
    weight_behavioral_anomaly: float = Field(default=0.2, description="Penalty added if the AI model flags the upload pattern.")
    weight_entropy_anomaly: float = Field(default=0.2, description="Penalty added if the file byte entropy exceeds max_safe_entropy.")
    weight_pytorch_anomaly: float = Field(default=0.4, description="Penalty added if the 2nd Stage PyTorch CNN flags the file as Malicious.")
    
    # --- Final Decision Threshold ---
    rejection_risk_threshold: float = Field(default=0.5, description="If the final calculated risk score is greater than or equal to this value, is_safe is False.")
    ai_trigger_threshold: float = Field(default=0.1, description="If the Stage 1 Rule-based score >= this threshold, the Stage 2 PyTorch AI models are invoked.")
