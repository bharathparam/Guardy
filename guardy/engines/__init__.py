from guardy.validation.mime_checker import MimeChecker
from guardy.validation.signature import SignatureVerifier
from guardy.validation.polyglot import PolyglotDetector
from guardy.inspection.protocol import ProtocolInspector
from guardy.inspection.structure_parser import StructureParser
from guardy.inspection.zip_bomb import ZipBombDetector
from guardy.threat.ai_anomaly import calculate_entropy
from guardy.threat.ml.predict import FileAnalyzer as PrivateMLAnalyzer
from guardy.config import GuardConfig

class MLAnalyzer(PrivateMLAnalyzer):
    """
    Public Developer API: The 2-Stage PyTorch & Isolation Forest execution wrapper.
    Used for explicitly scoring byte arrays using trained AI weights.
    """
    pass

# We expose the internal functions straight to the developer namespace for ease of use
__all__ = [
    "MimeChecker",
    "SignatureVerifier",
    "PolyglotDetector",
    "ProtocolInspector",
    "StructureParser",
    "ZipBombDetector",
    "calculate_entropy",
    "MLAnalyzer",
    "GuardConfig"
]
