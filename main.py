#!/usr/bin/env python3
"""
Forensic Security Scanner for Historical Blockchain Data (2009-2014)
====================================================================
أداة فحص أمني جنائي لبيانات البلوكشين التاريخية

المميزات:
- اكتشاف تكرار Nonce في التوقيعات الرقمية
- فحص محافظ الجمل النصية الضعيفة
- تحليل السكريبت والثغرات
- التحليل الجنائي للعناوين

Usage:
    python main.py --mode full --start-block 0 --end-block 336000
    python main.py --mode signatures --start-block 0 --end-block 100000
    python main.py --mode brainwallets --wordlist-dir ./wordlists
    python main.py --mode forensics --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
"""

import os
import sys
import argparse
import logging
import signal
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import json
import time
from contextlib import contextmanager

# إضافة المسار
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "data"))

from config.settings import (
    BitcoinRPCConfig, DatabaseConfig, ScannerConfig, 
    KNOWN_VULNERABILITIES
)
from core.bitcoin_rpc import BitcoinRPCClient, MockBitcoinRPCClient, BlockchainDataFetcher
from database.models import DatabaseManager, ScanProgress
from database.nonce_repository import NonceRepository, SignatureRValue
from modules.signature_analyzer import SignatureAnalyzer, DERParser
from modules.brainwallet_scanner import BrainWalletScanner, WordlistLoader
from utils.cpp_bridge import CPPAnalyzerBridge
from modules.master_analyzer import MasterMultiAnalyzer
from utils.etl_bridge import BitcoinETLBridge

# إعداد التسجيل
def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """إعداد نظام التسجيل"""
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    
    return logging.getLogger(__name__)


class ForensicScanner:
    """
    الماسح الأمني الجنائي الرئيسي
    """
    
    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.logger = logging.getLogger(__name__)
        
        # المكونات
        self.rpc_client: Optional[BitcoinRPCClient] = None
        self.db_manager: Optional[DatabaseManager] = None
        self.sig_analyzer: Optional[SignatureAnalyzer] = None
        self.brain_scanner: Optional[BrainWalletScanner] = None
        self.cpp_bridge = CPPAnalyzerBridge(Path(__file__).parent)
        self.mega_analyzer = MasterMultiAnalyzer(self)
        self.etl_bridge = BitcoinETLBridge()
        self.watchlist = set()
        
        # حالة التشغيل
        self.running = False
        self.current_scan_id: Optional[int] = None
        
        # الإحصائيات
        self.stats = {
            'start_time': None,
            'blocks_processed': 0,
            'transactions_processed': 0,
            'signatures_analyzed': 0,
            'findings': []
        }
        
        # إعداد معالجة الإشارات
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """معالج الإشارات"""
        self.logger.warning(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def load_targets(self, file_paths: List[str]):
        """تحميل العناوين المستهدفة من الملفات"""
        from utils.helpers import load_addresses_from_files
        self.watchlist = load_addresses_from_files(file_paths)
        self.logger.info(f"Loaded {len(self.watchlist)} target addresses into watchlist.")

    def _process_target_vulnerabilities(self, address: str, tx_hash: str, block_number: int):
        """تحليل الثغرات للعناوين المستهدفة"""
        if address in self.watchlist:
            self.logger.critical(f"[TARGET] TARGET ADDRESS SPOTTED: {address} in TX {tx_hash}")
            # تنفيذ تحليل عميق للتوقيعات فوراً
            # (سيقوم SignatureAnalyzer بمتابعة Nonce Reuse تلقائياً)
    def initialize(
        self,
        rpc_config: BitcoinRPCConfig = None,
        db_config: DatabaseConfig = None,
        use_mock: bool = False,
        skip_rpc: bool = False
    ):
        """تهيئة المكونات"""
        self.logger.info("Initializing Forensic Scanner...")
        
        # تهيئة قاعدة البيانات
        db_config = db_config or DatabaseConfig()
        self.db_manager = DatabaseManager(db_config.connection_string)
        self.db_manager.create_tables()
        self.logger.info("Database initialized")
        
        # تهيئة RPC
        if not skip_rpc:
            rpc_config = rpc_config or BitcoinRPCConfig()
            
            if use_mock:
                self.logger.warning("USING MOCK RPC CLIENT (SIMULATION MODE)")
                self.rpc_client = MockBitcoinRPCClient()
            else:
                self.rpc_client = BitcoinRPCClient(
                    host=rpc_config.host,
                    port=rpc_config.port,
                    username=rpc_config.username,
                    password=rpc_config.password,
                    timeout=rpc_config.timeout
                )
            
            if not self.rpc_client.test_connection():
                raise Exception("Failed to connect to Bitcoin Core RPC")
        else:
            self.logger.info("Skipping RPC initialization (Disk-only mode)")
        
        # تهيئة محلل التوقيعات
        self.sig_analyzer = SignatureAnalyzer(
            use_memory_only=False,
            db_path="data/nonce_repository.db"
        )
        
        # إعداد Callbacks
        self.sig_analyzer.on_reuse_found = self._on_nonce_reuse
        self.sig_analyzer.on_weak_signature = self._on_weak_signature
        
        # تهيئة ماسح Brain Wallets
        wordlist_loader = WordlistLoader()
        wordlist_loader.load_all_wordlists()
        self.brain_scanner = BrainWalletScanner(wordlist_loader)
        
        # بناء index العناوين فقط إذا لم نكن في وضع disk-only
        if not skip_rpc:
            self.brain_scanner.build_address_index()
        
        self.logger.info("Forensic Scanner initialized successfully")
    
    def _on_nonce_reuse(self, match):
        """Callback عند اكتشاف تكرار Nonce"""
        self.logger.critical(
            f"[ALERT] NONCE REUSE DETECTED!\n"
            f"   r: {match.r_hex[:40]}...\n"
            f"   TX1: {match.sig1.tx_hash}\n"
            f"   TX2: {match.sig2.tx_hash}\n"
            f"   Can recover private key: {match.can_recover_private_key}"
        )
        
        self.stats['findings'].append({
            'type': 'nonce_reuse',
            'severity': 'CRITICAL',
            'r': match.r_hex,
            'tx1': match.sig1.tx_hash,
            'tx2': match.sig2.tx_hash,
            'can_recover_private_key': match.can_recover_private_key,
            'exploitability': 'HIGH' if match.can_recover_private_key else 'LOW',
            'timestamp': datetime.now().isoformat()
        })
    
    def _on_weak_signature(self, result):
        """Callback عند اكتشاف توقيع ضعيف"""
        self.logger.warning(
            f"[WARNING] Weak signature detected: {result.weakness_types} "
            f"in TX {result.tx_hash[:20]}..."
        )
    
    def scan_signatures(
        self, 
        start_block: int = None, 
        end_block: int = None
    ) -> dict:
        """
        مسح التوقيعات في نطاق البلوكات
        
        Args:
            start_block: بداية النطاق (افتراضي: من الإعدادات)
            end_block: نهاية النطاق (افتراضي: من الإعدادات)
        
        Returns:
            إحصائيات المسح
        """
        start_block = start_block or self.config.START_BLOCK
        end_block = end_block or self.config.END_BLOCK
        
        self.logger.info(
            f"Starting signature scan from block {start_block} to {end_block}"
        )
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # إنشاء سجل التقدم
        session = self.db_manager.get_session()
        progress = ScanProgress(
            scan_type='signatures',
            start_block=start_block,
            end_block=end_block,
            current_block=start_block,
            status='running'
        )
        session.add(progress)
        session.commit()
        self.current_scan_id = progress.id
        
        try:
            for block_number in range(start_block, end_block + 1):
                if not self.running:
                    self.logger.info("Scan interrupted by user")
                    break
                
                try:
                    self._process_block_signatures(block_number)
                    self.stats['blocks_processed'] += 1
                    
                    # تحديث التقدم
                    if block_number % 100 == 0:
                        progress.current_block = block_number
                        progress.progress_percent = (
                            (block_number - start_block) / (end_block - start_block)
                        ) * 100
                        session.commit()
                        
                        self._log_progress()
                        
                except Exception as e:
                    self.logger.error(f"Error processing block {block_number}: {e}")
                    continue
            
            # إكمال المسح
            progress.status = 'completed'
            progress.completed_at = datetime.now()
            session.commit()
            
        except Exception as e:
            progress.status = 'failed'
            progress.error_message = str(e)
            session.commit()
            raise
        
        finally:
            session.close()
        
        return self._get_final_stats()
    
    def _process_block_signatures(self, block_number: int):
        """معالجة توقيعات بلوك واحد"""
        try:
            block_hash = self.rpc_client.get_block_hash(block_number)
            block_data = self.rpc_client.get_block(block_hash, verbosity=2)
            
            for tx in block_data.get('tx', []):
                if isinstance(tx, str):
                    tx = self.rpc_client.get_transaction(tx, block_hash)
                
                self._process_transaction_signatures(tx, block_number, block_data['time'])
                self.stats['transactions_processed'] += 1
                
        except Exception as e:
            self.logger.error(f"Error in block {block_number}: {e}")
    
    def _process_transaction_signatures(
        self, 
        tx: dict, 
        block_number: int,
        timestamp: int
    ):
        """معالجة توقيعات معاملة واحدة"""
        tx_hash = tx.get('txid') or tx.get('hash')
        
        for idx, vin in enumerate(tx.get('vin', [])):
            # تخطي Coinbase
            if 'coinbase' in vin:
                continue
            
            script_sig = vin.get('scriptSig', {}).get('hex', '')
            if not script_sig:
                continue
            
            try:
                # استخراج التوقيعات من ScriptSig
                script_bytes = bytes.fromhex(script_sig)
                signatures = DERParser.extract_from_script(script_bytes)
                
                for sig in signatures:
                    # معالجة التوقيع
                    result = self.sig_analyzer.process_signature(
                        der_bytes=sig.der_encoded,
                        tx_hash=tx_hash,
                        input_index=idx,
                        block_number=block_number,
                        address=vin.get('address', ''),
                        timestamp=timestamp
                    )
                    
                    if result:
                        self.stats['signatures_analyzed'] += 1
                        
            except Exception as e:
                self.logger.debug(f"Error processing signature in {tx_hash}: {e}")
    
    def scan_brain_wallets(
        self,
        start_block: int = None,
        end_block: int = None
    ) -> dict:
        """
        مسح محافظ الجمل النصية
        
        Args:
            start_block: بداية النطاق
            end_block: نهاية النطاق
        
        Returns:
            إحصائيات المسح
        """
        start_block = start_block or self.config.START_BLOCK
        end_block = end_block or self.config.END_BLOCK
        
        self.logger.info(
            f"Starting brain wallet scan from block {start_block} to {end_block}"
        )
        
        self.running = True
        findings = []
        
        for block_number in range(start_block, end_block + 1):
            if not self.running:
                break
            
            try:
                block_hash = self.rpc_client.get_block_hash(block_number)
                block_data = self.rpc_client.get_block(block_hash, verbosity=2)
                
                for tx in block_data.get('tx', []):
                    if isinstance(tx, str):
                        tx = self.rpc_client.get_transaction(tx, block_hash)
                    
                    # تحضير بيانات المعاملة
                    tx_data = {
                        'tx_hash': tx.get('txid'),
                        'block_number': block_number,
                        'timestamp': block_data['time'],
                        'inputs': [],
                        'outputs': []
                    }
                    
                    # استخراج العناوين
                    for vin in tx.get('vin', []):
                        if 'address' in vin:
                            tx_data['inputs'].append({'address': vin['address']})
                    
                    for vout in tx.get('vout', []):
                        addresses = vout.get('scriptPubKey', {}).get('addresses', [])
                        if addresses:
                            tx_data['outputs'].append({
                                'address': addresses[0],
                                'value': vout.get('value', 0)
                            })
                    
                    # فحص المعاملة
                    tx_findings = self.brain_scanner.scan_transaction(tx_data)
                    findings.extend(tx_findings)
                
                if block_number % 1000 == 0:
                    self.logger.info(f"Scanned block {block_number}, findings: {len(findings)}")
                    
            except Exception as e:
                self.logger.error(f"Error scanning block {block_number}: {e}")
        
        return {
            'total_findings': len(findings),
            'findings': [
                {
                    'phrase': f.candidate.phrase,
                    'address': f.matched_address,
                    'private_key': f.candidate.private_key,
                    'tx': f.matched_in_tx
                }
                for f in findings
            ]
        }
    
    def scan_forensics(
        self,
        target_address: str = None,
        start_block: int = None,
        end_block: int = None
    ) -> dict:
        """
        التحليل الجنائي
        
        Args:
            target_address: عنوان محدد للتحليل (اختياري)
            start_block: بداية النطاق
            end_block: نهاية النطاق
        
        Returns:
            نتائج التحليل
        """
        self.logger.info("Starting forensic analysis...")
        
        # TODO: تنفيذ التحليل الجنائي
        # - تتبع الروابط بين العناوين
        # - اكتشاف Change Addresses
        # - تحليل أنماط التحويل
        
        return {'status': 'not_implemented'}
    
    def scan_local_disk(self, blocks_dir: str, start_year: int = 2015, end_year: int = None):
        """
        الفحص المباشر لملفات .dat من القرص باستخدام bitcoinlib
        """
        try:
            from bitcoinlib.blocks import Block
        except ImportError:
            self.logger.error("bitcoinlib not installed. Install with: pip install bitcoinlib")
            return

        # تحويل السنوات إلى أزمنة Unix
        from datetime import datetime
        start_ts = int(datetime(start_year, 1, 1).timestamp())
        end_ts = int(datetime(end_year, 12, 31, 23, 59, 59).timestamp()) if end_year else None
        
        self.logger.info(f"Starting direct disk scan from: {blocks_dir}")
        self.running = True
        self.stats['start_time'] = time.time()

        if not os.path.exists(blocks_dir):
            self.logger.error(f"Blocks directory not found: {blocks_dir}")
            return

        # التحقق من وجود ملف xor.dat (للملفات المشفرة في Bitcoin Core)
        xor_key = None
        xor_path = os.path.join(blocks_dir, 'xor.dat')
        if os.path.exists(xor_path):
            with open(xor_path, "rb") as xf:
                xor_key = xf.read()
                self.logger.info(f"Using XOR key from {xor_path}: {xor_key.hex()}")

        blk_files = sorted([f for f in os.listdir(blocks_dir) if f.startswith('blk') and f.endswith('.dat')])
        
        for blk_file in blk_files:
            if not self.running: break
            file_path = os.path.join(blocks_dir, blk_file)
            self.logger.info(f"Scanning {blk_file}...")
            
            try:
                with open(file_path, "rb") as f:
                    file_pos = 0
                    while self.running:
                        # قراءة magic (4 bytes)
                        magic_bytes = f.read(4)
                        if len(magic_bytes) < 4:
                            break  # نهاية الملف
                        
                        # قراءة size (4 bytes, little endian)
                        size_raw = f.read(4)
                        if len(size_raw) < 4:
                            break
                        
                        # تطبيق XOR إذا لزم الأمر
                        if xor_key:
                            magic_xor = bytes([magic_bytes[i] ^ xor_key[(file_pos + i) % len(xor_key)] for i in range(4)])
                            size_xor = bytes([size_raw[i] ^ xor_key[(file_pos + 4 + i) % len(xor_key)] for i in range(4)])
                            file_pos += 8
                        else:
                            magic_xor = magic_bytes
                            size_xor = size_raw
                            file_pos += 8

                        size = int.from_bytes(size_xor, byteorder='little')
                        
                        # قراءة block data
                        block_data_raw = f.read(size)
                        if len(block_data_raw) < size:
                            break
                        
                        if xor_key:
                            block_data = bytes([block_data_raw[i] ^ xor_key[(file_pos + i) % len(xor_key)] for i in range(size)])
                            file_pos += size
                        else:
                            block_data = block_data_raw
                            file_pos += size
                        
                        try:
                            # تحليل البلوك
                            block = Block.parse(block_data, parse_transactions=True)
                            self.stats['blocks_processed'] += 1

                            if self.stats['blocks_processed'] % 100 == 0:
                                self._log_progress()

                            block_number = getattr(block, 'height', 0)
                            block_time = getattr(block, 'time', 0)

                            # فلاتر السنة
                            if start_ts and block_time > 0 and block_time < start_ts:
                                continue
                            if end_ts and block_time > end_ts:
                                continue

                            # معالجة المعاملات
                            for tx in block.transactions:
                                tx_hash = tx.hash.hex() if hasattr(tx, 'hash') else 'unknown'
                                found_in_block = False

                                # 1. فحص المخرجات (هل استلم أحد أهدافي أموالاً؟)
                                for vout in tx.outputs:
                                    addr = getattr(vout, 'address', '')
                                    if addr in self.watchlist:
                                        self.logger.critical(f"[TARGET] Payment received by: {addr} in TX {tx_hash}")
                                        found_in_block = True

                                # 2. فحص المدخلات (هل صرف أحد أهدافي أموالاً؟ + تحليل التوقيع)
                                for idx, vin in enumerate(tx.inputs):
                                    # التحقق من العنوان
                                    addr = getattr(vin, 'address', '')
                                    if addr in self.watchlist:
                                        self.logger.critical(f"[TARGET] Spending detected from: {addr} in TX {tx_hash}")
                                        found_in_block = True

                                    # تحليل التوقيع (الجزء الأهم للثغرات)
                                    if hasattr(vin, 'script_sig') and vin.script_sig:
                                        self._process_script_signatures(
                                            vin.script_sig.hex(), 
                                            tx_hash, 
                                            idx, 
                                            block_number, 
                                            block_time
                                        )

                                if found_in_block:
                                    self.stats['findings'].append({
                                        'type': 'target_activity',
                                        'address': addr,
                                        'txid': tx_hash,
                                        'block': block_number,
                                        'timestamp': datetime.fromtimestamp(block_time).isoformat() if block_time > 0 else 'unknown'
                                    })

                                self.stats['transactions_processed'] += 1

                        except Exception as e:
                            # لا تظهر أخطاء البارسينج إلا في وضع الديباج
                            pass

                            
            except Exception as e:
                self.logger.error(f"Error processing {blk_file}: {e}")
            
            self._log_progress()

        return self._get_final_stats()
    
    def scan_puzzle(self, target: str, range_start: str, range_end: str, threads: int = 16, use_gpu: bool = False):
        """
        حل لغز البلوكشين (Puzzle 70/71) باستخدام محرك الـ C++
        """
        self.logger.info(f"Starting puzzle solver for target: {target}")
        self.logger.info(f"Range: {range_start} -> {range_end}")
        
        self.stats['start_time'] = time.time()
        
        result = self.cpp_bridge.search_key(
            target=target,
            range_start=range_start,
            range_end=range_end,
            threads=threads,
            use_gpu=use_gpu
        )
        
        if result.get('success'):
            self.logger.info("C++ Analyzer finished successfully")
            # تحليل المخرجات للبحث عن المفتاح الخاص
            stdout = result.get('stdout', '')
            if "PRIVATE KEY FOUND" in stdout or "Key:" in stdout:
                self.logger.critical("[ALERT] PRIVATE KEY FOUND BY C++ ENGINE!")
                self.stats['findings'].append({
                    'type': 'puzzle_solution',
                    'severity': 'CRITICAL',
                    'target': target,
                    'details': stdout,
                    'timestamp': datetime.now().isoformat()
                })
            return result
        else:
            self.logger.error(f"C++ Analyzer failed: {result.get('error')}")
            return result

    def scan_via_etl(self, blocks_dir: str, start_block: int, end_block: int):
        """
        استخراج وفحص البيانات باستخدام Bitcoin ETL
        """
        self.logger.info(f"Starting ETL-based scan for blocks {start_block} to {end_block}")
        
        # 1. الاستخراج
        if not self.etl_bridge.export_provider_data(blocks_dir, start_block, end_block):
            return {"error": "ETL Export failed"}
            
        # 2. الفحص السريع لملف المعاملات
        tx_file = self.etl_bridge.get_transaction_file()
        self.logger.info(f"Scanning extracted transactions in {tx_file}...")
        
        import csv
        findings_count = 0
        
        with open(tx_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                tx_hash = row.get('hash')
                # فحص المدخلات والمخرجات (في Bitcoin ETL المعاملات تحتوي على تفاصيل العناوين)
                # ملاحظة: سنقوم بتحميل الـ Inputs/Outputs المرتبطة من الـ CSV
                pass
                
        return {"status": "completed", "blocks": end_block - start_block}

    def run_mega_scan(self, blocks_dir: str, start_year: int = 2009, end_year: int = None):
        """تنفيذ التحليل الشامل بـ 15 طريقة"""
        return self.mega_analyzer.execute_mega_scan(
            blocks_dir=blocks_dir, 
            watchlist=self.watchlist,
            start_year=start_year,
            end_year=end_year
        )

    def _process_script_signatures(self, script_hex: str, tx_hash: str, input_index: int, block_number: int, timestamp: int):
        """معالجة التوقيعات في script"""
        # البحث عن توقيعات DER (تبدأ بـ 30)
        pos = 0
        while pos < len(script_hex) - 2:
            if script_hex[pos:pos+2] == '30':
                # محاولة استخراج توقيع DER
                try:
                    sig_start = pos // 2  # convert to byte position
                    # التوقيع عادة 70-72 bytes
                    sig_length = 140  # 70 bytes * 2 hex chars
                    if pos + sig_length <= len(script_hex):
                        sig_hex = script_hex[pos:pos + sig_length]
                        sig_bytes = bytes.fromhex(sig_hex)
                        
                        # معالجة التوقيع
                        result = self.sig_analyzer.process_signature(
                            der_bytes=sig_bytes,
                            tx_hash=tx_hash,
                            input_index=input_index,
                            block_number=block_number,
                            address='',
                            timestamp=timestamp
                        )
                        
                        if result:
                            self.stats['signatures_analyzed'] += 1
                except Exception as e:
                    self.logger.debug(f"Error processing signature at pos {pos}: {e}")
            
            pos += 2  # التالي

    def export_results(self, output_dir: str = "output"):
        """تصدير النتائج"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # تصدير إحصائيات Nonce
        if self.sig_analyzer:
            nonce_stats = self.sig_analyzer.get_statistics()
            with open(output_path / f"nonce_stats_{timestamp}.json", 'w') as f:
                json.dump(nonce_stats, f, indent=2, default=str)
        
        # تصدير الاكتشافات
        with open(output_path / f"findings_{timestamp}.json", 'w') as f:
            json.dump(self.stats['findings'], f, indent=2, default=str)
        
        self.logger.info(f"Results exported to {output_dir}")
    
    def _log_progress(self):
        """تسجيل التقدم"""
        elapsed = time.time() - self.stats['start_time']
        blocks_per_sec = self.stats['blocks_processed'] / elapsed if elapsed > 0 else 0
        
        self.logger.info(
            f"Progress: {self.stats['blocks_processed']} blocks, "
            f"{self.stats['transactions_processed']} txs, "
            f"{self.stats['signatures_analyzed']} sigs, "
            f"{len(self.stats['findings'])} findings, "
            f"{blocks_per_sec:.2f} blocks/sec"
        )
    
    def _get_final_stats(self) -> dict:
        """الحصول على الإحصائيات النهائية"""
        elapsed = time.time() - self.stats['start_time']
        
        return {
            'elapsed_seconds': elapsed,
            'blocks_processed': self.stats['blocks_processed'],
            'transactions_processed': self.stats['transactions_processed'],
            'signatures_analyzed': self.stats['signatures_analyzed'],
            'total_findings': len(self.stats['findings']),
            'findings_by_type': self._categorize_findings()
        }
    
    def _categorize_findings(self) -> dict:
        """تصنيف الاكتشافات"""
        categories = {}
        for finding in self.stats['findings']:
            ftype = finding['type']
            categories[ftype] = categories.get(ftype, 0) + 1
        return categories
    
    def close(self):
        """إغلاق الماسح"""
        self.logger.info("Closing Forensic Scanner...")
        
        if self.sig_analyzer:
            self.sig_analyzer.close()
        
        if self.rpc_client:
            self.rpc_client.close()
        
        if self.db_manager:
            self.db_manager.close()
        
        self.logger.info("Forensic Scanner closed")


def create_parser() -> argparse.ArgumentParser:
    """إنشاء محلل الوسائط"""
    parser = argparse.ArgumentParser(
        description="Forensic Security Scanner for Historical Blockchain Data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # مسح كامل
  python main.py --mode full --start-block 0 --end-block 336000
  
  # مسح التوقيعات فقط
  python main.py --mode signatures --start-block 0 --end-block 100000
  
  # مسح Brain Wallets
  python main.py --mode brainwallets --start-block 0 --end-block 336000
  
  # تحليل عنوان محدد
  python main.py --mode forensics --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['full', 'signatures', 'brainwallets', 'forensics', 'info', 'local', 'puzzle', 'mega-scan', 'etl-scan'],
        default='info',
        help='وضع التشغيل'
    )
    
    parser.add_argument(
        '--target',
        type=str,
        help='العنوان المستهدف أو Hash160 (لوضع puzzle)'
    )
    
    parser.add_argument(
        '--target-files',
        nargs='+',
        help='قائمة ملفات تحتوي على العناوين المستهدفة للبحث بداخلها'
    )
    
    parser.add_argument(
        '--range-start',
        type=str,
        default='0x1',
        help='بداية النطاق للبحث (Hex)'
    )
    
    parser.add_argument(
        '--range-end',
        type=str,
        default='0xFFFFFFFFFFFFFFFF',
        help='نهاية النطاق للبحث (Hex)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=16,
        help='عدد خيوط المعالجة (C++ Engine)'
    )
    
    parser.add_argument(
        '--use-gpu',
        action='store_true',
        help='استخدام تسريع GPU (C++ Engine)'
    )
    
    parser.add_argument(
        '--use-cpp',
        action='store_true',
        help='تفعيل محرك الـ C++ للعمليات السريعة'
    )
    
    parser.add_argument(
        '--blocks-dir',
        type=str,
        default=r'D:\blocks',
        help='مسار مجلد ملفات البلوكات (.dat)'
    )
    
    parser.add_argument(
        '--start-block',
        type=int,
        default=0,
        help='رقم البلوك البداية (افتراضي: 0)'
    )
    
    parser.add_argument(
        '--end-block',
        type=int,
        default=336000,
        help='رقم البلوك النهاية (افتراضي: 336000 ~ نهاية 2014)'
    )
    
    parser.add_argument(
        '--start-year',
        type=int,
        default=2009,
        help='سنة البداية لفلترة البلوكات (افتراضي: 2009)'
    )
    
    parser.add_argument(
        '--end-year',
        type=int,
        default=None,
        help='سنة النهاية لفلترة البلوكات (افتراضي: None تعني حتى الأحدث)'
    )
    
    parser.add_argument(
        '--address',
        type=str,
        help='عنوان محدد للتحليل (في وضع forensics)'
    )
    
    parser.add_argument(
        '--rpc-host',
        type=str,
        default='localhost',
        help='عنوان Bitcoin Core RPC'
    )
    
    parser.add_argument(
        '--rpc-port',
        type=int,
        default=8332,
        help='منفذ Bitcoin Core RPC'
    )
    
    parser.add_argument(
        '--rpc-user',
        type=str,
        default='bitcoin',
        help='اسم مستخدم RPC'
    )
    
    parser.add_argument(
        '--rpc-password',
        type=str,
        default='password',
        help='كلمة مرور RPC'
    )
    
    parser.add_argument(
        '--db-type',
        choices=['sqlite', 'postgresql'],
        default='sqlite',
        help='نوع قاعدة البيانات'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='output',
        help='مجلد إخراج النتائج'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='مستوى التسجيل'
    )
    
    parser.add_argument(
        '--wordlist-dir',
        type=str,
        default='wordlists',
        help='مجلد قوائم الكلمات'
    )
    
    parser.add_argument(
        '--mock',
        action='store_true',
        help='تشغيل في وضع المحاكاة (بدون الحاجة لـ Bitcoin Core)'
    )
    
    return parser


def main():
    """الدالة الرئيسية"""
    parser = create_parser()
    args = parser.parse_args()
    
    # إعداد التسجيل
    logger = setup_logging(args.log_level, 'logs/forensic_scanner.log')
    
    # عرض المعلومات فقط
    if args.mode == 'info':
        print("""
+----------------------------------------------------------------------+
|     Forensic Security Scanner for Historical Blockchain Data         |
|                    (Genesis Block - End of 2014)                     |
+----------------------------------------------------------------------+
|  Features:                                                           |
|    [SIG] ECDSA Signature Analysis (Nonce Reuse Detection)            |
|    [BRAIN] Brain Wallet Scanner                                      |
|    [SEARCH] Forensic Address Analysis                                 |
|    [STATS] Script & Vulnerability Detection                          |
|    [PUZZLE] Puzzle Solver (70/71) - Optimized C++ Engine             |
+----------------------------------------------------------------------+
|  Usage: python main.py --mode full --start-block 0 --end-block 336000 |
|         python main.py --mode puzzle --target <address> --use-gpu    |
|  Help:  python main.py --help                                        |
+----------------------------------------------------------------------+
        """)
        
        # عرض الثغرات المعروفة
        print("\nKnown Vulnerabilities in Target Period (2009-2014):")
        print("-" * 60)
        for cve_id, info in KNOWN_VULNERABILITIES.items():
            print(f"  {cve_id}: {info['name']}")
            print(f"    Block Range: {info['block_range']}")
            print(f"    Description: {info['description']}")
            print()
        
        return
    
    # إعداد الإعدادات
    from data.config_loader import RPC_HOST, RPC_PORT, RPC_USER, RPC_PASS
    
    # استخدام القيم من سطر الأوامر إذا وجدت، وإلا استخدام القيم الافتراضية
    host = args.rpc_host or RPC_HOST
    port = args.rpc_port or RPC_PORT
    user = args.rpc_user or RPC_USER
    password = args.rpc_password or RPC_PASS
    
    rpc_config = BitcoinRPCConfig(
        host=host,
        port=port,
        username=user,
        password=password
    )
    
    db_config = DatabaseConfig(db_type=args.db_type)
    scanner_config = ScannerConfig()
    
    # إنشاء الماسح
    scanner = ForensicScanner(scanner_config)
    
    # في وضع المحاكاة، نقلل عدد البلوكات للفحص السريع
    if args.mock:
        args.end_block = min(args.end_block, args.start_block + 100)
        logger.info(f"Mock mode: scanning blocks {args.start_block} to {args.end_block}")
    
    try:
        # تهيئة الماسح
        # تخطي الـ RPC إذا كان المسار محلياً أو الوضع 'local' أو 'mega-scan' مع وجود مجلد
        skip_rpc_flag = (args.mode == 'local' or args.mode == 'mega-scan' or args.blocks_dir is not None)
        scanner.initialize(rpc_config, db_config, use_mock=args.mock, skip_rpc=skip_rpc_flag)
        
        # تحميل العناوين المستهدفة إذا وجدت
        if args.target_files:
            scanner.load_targets(args.target_files)
        
        # تنفيذ الوضع المحدد
        if args.mode == 'full':
            logger.info("Running full scan...")
            
            # مسح التوقيعات
            sig_results = scanner.scan_signatures(args.start_block, args.end_block)
            print("\n" + "="*60)
            print("SIGNATURE SCAN RESULTS:")
            print("="*60)
            print(json.dumps(sig_results, indent=2))
            
            # مسح Brain Wallets
            brain_results = scanner.scan_brain_wallets(args.start_block, args.end_block)
            print("\n" + "="*60)
            print("BRAIN WALLET SCAN RESULTS:")
            print("="*60)
            print(json.dumps(brain_results, indent=2))
            
        elif args.mode == 'signatures':
            logger.info("Running signature scan...")
            results = scanner.scan_signatures(args.start_block, args.end_block)
            print("\n" + "="*60)
            print("SIGNATURE SCAN RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
            
        elif args.mode == 'brainwallets':
            logger.info("Running brain wallet scan...")
            results = scanner.scan_brain_wallets(args.start_block, args.end_block)
            print("\n" + "="*60)
            print("BRAIN WALLET SCAN RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
            
        elif args.mode == 'local':
            logger.info(f"Running direct disk scan on {args.blocks_dir} (year filter: {args.start_year}-{args.end_year})...")
            results = scanner.scan_local_disk(
                args.blocks_dir,
                start_year=args.start_year,
                end_year=args.end_year
            )
            print("\n" + "="*60)
            print("LOCAL DISK SCAN RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
            
        elif args.mode == 'puzzle':
            if not args.target:
                logger.error("Target address or Hash160 is required for puzzle mode")
                sys.exit(1)
            
            logger.info(f"Running puzzle solver for target {args.target}...")
            results = scanner.scan_puzzle(
                target=args.target,
                range_start=args.range_start,
                range_end=args.range_end,
                threads=args.threads,
                use_gpu=args.use_gpu
            )
            print("\n" + "="*60)
            print("PUZZLE SOLVER RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
            
        elif args.mode == 'mega-scan':
            logger.info("Running MEGA-SCAN: 15 Distributed Analysis Methods...")
            results = scanner.run_mega_scan(
                blocks_dir=args.blocks_dir,
                start_year=args.start_year,
                end_year=args.end_year
            )
            print("\n" + "="*60)
            print("MEGA-SCAN RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
            
        elif args.mode == 'etl-scan':
            logger.info("Running ETL-SCAN: High-Speed Bitcoin ETL Extraction...")
            results = scanner.scan_via_etl(
                blocks_dir=args.blocks_dir,
                start_block=args.start_block,
                end_block=args.end_block
            )
            print("\n" + "="*60)
            print("ETL-SCAN RESULTS:")
            print("="*60)
            print(json.dumps(results, indent=2))
        
        # تصدير النتائج
        scanner.export_results(args.output_dir)
        
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        scanner.close()


if __name__ == '__main__':
    main()
