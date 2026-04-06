# Forensic Security Scanner for Historical Blockchain Data

## أداة فحص أمني جنائي لبيانات البلوكشين التاريخية (2009-2014)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Bitcoin-Core-green.svg" alt="Bitcoin Core">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License">
</p>

---

## 📋 نظرة عامة

هذه الأداة المتخصصة تقوم بفحص بيانات البلوكشين التاريخية (من Genesis Block حتى نهاية عام 2014) للكشف عن الثغرات الأمنية والضعف في التوقيعات الرقمية ومحافظ الجمل النصية.

### ⚠️ الثغرات المستهدفة

| الثغرة | الوصف | الفترة |
|--------|-------|--------|
| **Nonce Reuse** | تكرار قيمة k في توقيعات ECDSA | 2009-2014 |
| **CVE-2010-5137** | ثغرة overflow (184 مليار بيتكوين) | < 74600 |
| **CVE-2010-5141** | ثغرة OP_LSHIFT crash | < 74600 |
| **CVE-2012-1909** | Transaction Malleability | < 180000 |
| **CVE-2013-4165** | ضعف OpenSSL RNG | 250000-280000 |
| **CVE-2013-3220** | خلل Android RNG | 240000-260000 |
| **Brain Wallets** | محافظ الجمل النصية الضعيفة | 2009-2014 |

---

## 🚀 التثبيت

### المتطلبات الأساسية

- Python 3.8 أو أحدث
- Bitcoin Core (مع تمكين RPC)
- PostgreSQL أو SQLite (اختياري)

### خطوات التثبيت

```bash
# استنساخ المستودع
git clone https://github.com/yourusername/forensic-scanner.git
cd forensic-scanner

# إنشاء بيئة افتراضية
python -m venv venv
source venv/bin/activate  # Linux/Mac
# أو: venv\Scripts\activate  # Windows

# تثبيت المتطلبات
pip install -r requirements.txt

# إعداد قاعدة البيانات
mkdir -p data wordlists logs output
```

### إعداد Bitcoin Core

تأكد من إضافة الإعدادات التالية إلى `bitcoin.conf`:

```conf
server=1
rpcuser=bitcoin
rpcpassword=your_secure_password
rpcallowip=127.0.0.1
rpcport=8332
txindex=1
```

---

## 💻 الاستخدام

### الوضع التفاعلي (عرض المعلومات)

```bash
python main.py --mode info
```

### مسح كامل

```bash
python main.py --mode full \
    --start-block 0 \
    --end-block 336000 \
    --rpc-user bitcoin \
    --rpc-password your_password
```

### مسح التوقيعات فقط

```bash
python main.py --mode signatures \
    --start-block 0 \
    --end-block 100000
```

### مسح Brain Wallets

```bash
python main.py --mode brainwallets \
    --start-block 0 \
    --end-block 336000 \
    --wordlist-dir ./wordlists
```

### التحليل الجنائي لعنوان محدد

```bash
python main.py --mode forensics \
    --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
    --start-block 0 \
    --end-block 336000
```

---

## 🏗️ هيكل المشروع

```
forensic_scanner/
├── config/
│   └── settings.py              # الإعدادات والتهيئة
├── core/
│   ├── __init__.py
│   └── bitcoin_rpc.py           # الاتصال بـ Bitcoin Core RPC
├── database/
│   ├── __init__.py
│   ├── models.py                # نماذج قاعدة البيانات (SQLAlchemy)
│   └── nonce_repository.py      # مستودع Nonce المتخصص
├── modules/
│   ├── __init__.py
│   ├── signature_analyzer.py    # محلل التوقيعات (الأهم)
│   ├── brainwallet_scanner.py   # ماسح Brain Wallets
│   ├── script_analyzer.py       # محلل السكريبت
│   └── forensic_analyzer.py     # التحليل الجنائي
├── wordlists/                   # قوائم الكلمات
│   ├── common_passwords.txt
│   ├── quotes.txt
│   ├── religious_phrases.txt
│   └── ...
├── data/                        # قاعدة البيانات
├── logs/                        # سجلات التشغيل
├── output/                      # نتائج المسح
├── main.py                      # الملف الرئيسي
├── requirements.txt             # المتطلبات
└── README.md                    # هذا الملف
```

---

## 🔐 موديول التوقيعات الرقمية (Signature Analyzer)

### نظرة عامة

هذا الموديول هو الأهم في الأداة، حيث يقوم بـ:

1. **استخراج قيم r و s** من التوقيعات DER
2. **اكتشاف تكرار Nonce (k)** عبر مقارنة قيم r
3. **استخراج المفاتيح الخاصة** من التوقيعات المكررة
4. **اكتشاف Nonce الضعيف** (قيم صغيرة)

### كيفية عمل اكتشاف تكرار Nonce

```python
from forensic_scanner.modules.signature_analyzer import SignatureAnalyzer

# إنشاء المحلل
analyzer = SignatureAnalyzer()

# معالجة توقيع
result = analyzer.process_signature(
    der_bytes=signature_der,
    tx_hash=tx_hash,
    input_index=0,
    block_number=100000,
    address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
)

# التحقق من الضعف
if result and result.is_weak:
    print(f"Weak signature found: {result.weakness_types}")
    print(f"Severity: {result.severity}")
```

### استخراج المفتاح الخاص من تكرار Nonce

عندما يتم استخدام نفس قيمة k في توقيعين مختلفين:

```
k = (z1 - z2) / (s1 - s2) mod n
d = (s1 * k - z1) / r mod n
```

حيث:
- `z1, z2`: hash الرسالتين
- `s1, s2`: قيم s في التوقيعين
- `r`: قيمة r المشتركة
- `n`: order المنحنى
- `d`: المفتاح الخاص

### تخزين قيم r بكفاءة

يستخدم المستودع عدة تقنيات للأداء العالي:

```python
from database.nonce_repository import NonceRepository

repo = NonceRepository(db_path="data/nonce_repository.db")

# إدراج توقيع
sig = SignatureRValue(
    r_hex="abcd1234...",
    tx_hash="tx_hash...",
    input_index=0,
    block_number=100000,
    address="1A1z...",
    s_hex="efgh5678..."
)

# اكتشاف التكرار تلقائياً
match = repo.insert_signature(sig, check_reuse=True)

if match:
    print(f"Nonce reuse detected! r={match.r_hex}")
```

### تقنيات التحسين

1. **Bloom Filter**: للكشف السريع عن الاحتمالية
2. **Hash Table في الذاكرة**: للوصول السريع O(1)
3. **فهارس قاعدة البيانات**: للبحث السريع
4. **Batch Inserts**: للإدراج الفعال

---

## 🧠 موديول Brain Wallets

### نظرة عامة

يقوم بفحص العناوين المشتقة من عبارات نصية ضعيفة:

```python
from forensic_scanner.modules.brainwallet_scanner import BrainWalletScanner, WordlistLoader

# تحميل قوائم الكلمات
loader = WordlistLoader()
loader.load_all_wordlists()

# إنشاء الماسح
scanner = BrainWalletScanner(loader)
scanner.build_address_index()

# فحص معاملة
findings = scanner.scan_transaction(tx_data)

for finding in findings:
    print(f"Brain wallet found!")
    print(f"Phrase: {finding.candidate.phrase}")
    print(f"Address: {finding.matched_address}")
    print(f"Private Key: {finding.candidate.private_key}")
```

### أنواع العبارات المدعومة

- **كلمات مرور شائعة**: password, 123456, qwerty, ...
- **اقتباسات مشهورة**: "To be or not to be", ...
- **عبارات دينية**: "In the beginning God created..."
- **اقتباسات من الأفلام**: "May the force be with you", ...
- **اقتباسات تاريخية**: "I have a dream", ...

---

## 🔍 موديول التحليل الجنائي

### تجميع العناوين (Address Clustering)

```python
from forensic_scanner.modules.forensic_analyzer import ForensicAnalyzer

analyzer = ForensicAnalyzer()

# تحليل معاملة
analyzer.analyze_transaction(tx_data)

# الحصول على مجموعة عنوان
cluster = analyzer.get_cluster_for_address("1A1z...")

if cluster:
    print(f"Cluster size: {len(cluster.addresses)}")
    print(f"Wallet type: {cluster.wallet_type}")
```

### تتبع الأموال

```python
# تتبع للأمام
paths = analyzer.trace_funds(
    tx_hash="tx_hash...",
    direction='forward',
    max_depth=5
)

# تتبع للخلف
sources = analyzer.trace_funds(
    tx_hash="tx_hash...",
    direction='backward',
    max_depth=5
)
```

---

## 📊 قاعدة البيانات

### النماذج الرئيسية

| الجدول | الوصف |
|--------|-------|
| `blocks` | معلومات البلوكات |
| `transactions` | معلومات المعاملات |
| `signatures` | التوقيعات مع قيم r و s |
| `nonce_reuse_incidents` | حوادث تكرار Nonce |
| `brainwallet_candidates` | مرشحو Brain Wallets |
| `address_clusters` | مجموعات العناوين |
| `vulnerability_findings` | الاكتشافات الأمنية |

### الفهارس المحسنة

```sql
-- فهرس رئيسي للبحث عن تكرار r
CREATE INDEX idx_sig_r_block ON signatures(r, block_number);

-- فهرس للبحث عن العناوين
CREATE INDEX idx_sig_r_address ON signatures(r, address);
```

---

## 📈 الإحصائيات والنتائج

### أمثلة على الاكتشافات

```json
{
  "nonce_reuse_incidents": [
    {
      "r_value": "abcd1234...",
      "sig1_tx_hash": "tx1_hash...",
      "sig2_tx_hash": "tx2_hash...",
      "address_1": "1A1z...",
      "address_2": "1B2y...",
      "severity": "CRITICAL",
      "private_key_recovered": true
    }
  ],
  "brain_wallet_findings": [
    {
      "phrase": "password123",
      "address": "1C3z...",
      "private_key": "5Hue...",
      "total_received": 100000000
    }
  ],
  "weak_signatures": [
    {
      "tx_hash": "tx_hash...",
      "weakness_type": "small_nonce",
      "r_value": "00000001...",
      "severity": "HIGH"
    }
  ]
}
```

---

## ⚙️ الإعدادات المتقدمة

### ملف `.env`

```bash
# Bitcoin RPC
BITCOIN_RPC_HOST=localhost
BITCOIN_RPC_PORT=8332
BITCOIN_RPC_USER=bitcoin
BITCOIN_RPC_PASSWORD=your_secure_password

# Database
DB_TYPE=sqlite
SQLITE_PATH=data/forensic_scanner.db

# أو PostgreSQL
# DB_TYPE=postgresql
# PG_HOST=localhost
# PG_PORT=5432
# PG_DATABASE=forensic_scanner
# PG_USER=scanner
# PG_PASSWORD=scanner

# Scanner Settings
SCAN_BATCH_SIZE=1000
MAX_WORKERS=4
LOG_LEVEL=INFO
```

---

## 🔧 استكشاف الأخطاء

### مشكلة: فشل الاتصال بـ Bitcoin Core

**الحل**: تأكد من:
1. تشغيل Bitcoin Core
2. تمكين RPC في الإعدادات
3. صحة بيانات الاعتماد

### مشكلة: بطء في المسح

**الحلول**:
1. زيادة `BATCH_SIZE`
2. استخدام PostgreSQL بدلاً من SQLite
3. زيادة ذاكرة الكاش
4. استخدام SSD للتخزين

### مشكلة: نفاد الذاكرة

**الحل**: استخدم وضع الذاكرة المحدودة:

```python
analyzer = SignatureAnalyzer(use_memory_only=False)
```

---

## 📚 المراجع

### الثغرات الأمنية

- [CVE-2010-5137](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-5137) - Value Overflow
- [CVE-2010-5141](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-5141) - OP_LSHIFT Crash
- [CVE-2012-1909](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1909) - Transaction Malleability
- [CVE-2013-4165](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4165) - OpenSSL Weak RNG
- [CVE-2013-3220](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3220) - Android RNG Bug

### موارد تعليمية

- [ECDSA Nonce Reuse Attack](https://blog.trailofbits.com/2020/06/11/ecdsa-nonce-reuse-attack/)
- [Bitcoin Wiki - Weaknesses](https://en.bitcoin.it/wiki/Weaknesses)
- [Blockchain Forensics](https://www.futurelearn.com/info/courses/forensic-blockchain-analysis/0/steps/1)

---

## 📜 الترخيص

هذا المشروع مرخص بموجب MIT License - انظر ملف [LICENSE](LICENSE) للتفاصيل.

---

## 🤝 المساهمة

نرحب بالمساهمات! يرجى:

1. عمل Fork للمستودع
2. إنشاء فرع للميزة (`git checkout -b feature/amazing-feature`)
3. Commit التغييرات (`git commit -m 'Add amazing feature'`)
4. Push للفرع (`git push origin feature/amazing-feature`)
5. فتح Pull Request

---

## ⚠️ إخلاء المسؤولية

هذه الأداة مخصصة للأغراض التعليمية والبحثية فقط. استخدامها لسرقة الأموال أو اختراق المحافظ غير قانوني وأخلاقي. يتحمل المستخدم المسؤولية الكاملة عن استخدام هذه الأداة.

---

## 📧 التواصل

للأسئلة والاقتراحات:

- Email: forensic-scanner@example.com
- GitHub Issues: [github.com/yourusername/forensic-scanner/issues](https://github.com/yourusername/forensic-scanner/issues)

---

<p align="center">
  <strong>صُنع بـ ❤️ للمجتمع الأمني</strong>
</p>
