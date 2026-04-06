import sqlite3
import os

def format_table(headers, rows):
    """دالة بسيطة لتنسيق الجداول بدون مكتبات خارجية"""
    if not rows:
        return "No data found."
    
    # حساب عرض الأعمدة
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))
            
    # إنشاء الخط الفاصل
    separator = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    
    # إنشاء الصفوف
    lines = [separator]
    
    # الهيدر
    header_line = "|" + "|".join([f" {headers[i]:<{col_widths[i]}} " for i in range(len(headers))]) + "|"
    lines.append(header_line)
    lines.append(separator)
    
    # البيانات
    for row in rows:
        row_line = "|" + "|".join([f" {str(row[i]):<{col_widths[i]}} " for i in range(len(row))]) + "|"
        lines.append(row_line)
    
    lines.append(separator)
    return "\n".join(lines)

def analyze_db(db_path="data/nonce_repository.db"):
    if not os.path.exists(db_path):
        print(f"[!] Error: Database not found at {db_path}")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\n" + "="*60)
        print(f"[STATS] Database Analysis (Lightweight Mode): {db_path}")
        print("="*60)

        # 1. إحصائيات عامة
        cursor.execute("SELECT COUNT(*) FROM signatures")
        total_sigs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT r) FROM signatures")
        unique_r = cursor.fetchone()[0]

        print(f"[OK] Total Signatures: {total_sigs:,}")
        print(f"[OK] Unique R-Values:  {unique_r:,}")
        print(f"[OK] Reused R-Values:  {(total_sigs - unique_r):,}")

        # 2. أكثر العناوين تكراراً
        print("\n[TOP] Top 10 Active Addresses:")
        cursor.execute("""
            SELECT address, COUNT(*) as sig_count 
            FROM signatures 
            GROUP BY address 
            ORDER BY sig_count DESC 
            LIMIT 10
        """)
        rows = cursor.fetchall()
        print(format_table(["Address", "Signature Count"], rows))

        # 3. عرض حالات تكرار Nonce (إن وجدت)
        print("\n[ALERT] Detected Nonce Reuse Incidents:")
        reuse_query = """
            SELECT s1.r, s1.tx_hash, s2.tx_hash, s1.address
            FROM signatures s1
            JOIN signatures s2 ON s1.r = s2.r AND s1.tx_hash != s2.tx_hash
            GROUP BY s1.r
            LIMIT 10
        """
        cursor.execute(reuse_query)
        reuse_rows = cursor.fetchall()

        if reuse_rows:
            print(format_table(["R-Value (Hex)", "TX 1 Hash", "TX 2 Hash", "Address"], reuse_rows))
            print(f"\n[!!!] Found potential private key recovery opportunities!")
        else:
            print("No reuse detected yet. Keep scanning!")

        # 4. توزيع البلوكات
        cursor.execute("SELECT MIN(block_number), MAX(block_number) FROM signatures")
        start_b, end_b = cursor.fetchone()
        print(f"\n[DATE] Scan Coverage: Block {start_b} to {end_b}")

        conn.close()
    except Exception as e:
        print(f"[!] Database Error: {e}")

if __name__ == "__main__":
    analyze_db()
