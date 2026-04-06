"""
Forensic Security Scanner for Historical Blockchain Data
========================================================

أداة فحص أمني جنائي لبيانات البلوكشين التاريخية (2009-2014)

المميزات الرئيسية:
- اكتشاف تكرار Nonce في التوقيعات الرقمية (ECDSA)
- فحص محافظ الجمل النصية الضعيفة (Brain Wallets)
- تحليل السكريبت واكتشاف الثغرات
- التحليل الجنائي للعناوين (Address Clustering)
- تتبع مسار الأموال

Usage:
    from forensic_scanner import ForensicScanner
    
    scanner = ForensicScanner()
    scanner.initialize()
    results = scanner.scan_signatures(0, 336000)
"""

__version__ = "1.0.0"
__author__ = "Forensic Security Team"
__license__ = "MIT"

from .main import ForensicScanner
from .modules.signature_analyzer import SignatureAnalyzer
from .modules.brainwallet_scanner import BrainWalletScanner
from .modules.script_analyzer import ScriptAnalyzer
from .modules.forensic_analyzer import ForensicAnalyzer
from .core.bitcoin_rpc import BitcoinRPCClient
from .database.models import DatabaseManager

__all__ = [
    'ForensicScanner',
    'SignatureAnalyzer',
    'BrainWalletScanner',
    'ScriptAnalyzer',
    'ForensicAnalyzer',
    'BitcoinRPCClient',
    'DatabaseManager',
]
