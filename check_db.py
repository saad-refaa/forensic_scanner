import sqlite3
import os

def analyze():
    db_path = "data/nonce_repository.db"
    if not os.path.exists(db_path):
        print(f"File not found: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # إحصائيات سريعة
    cur.execute("SELECT COUNT(*) FROM signatures")
    total = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(DISTINCT r) FROM signatures")
    unique = cur.fetchone()[0]
    
    print("-" * 40)
    print(f"Total Signatures: {total}")
    print(f"Unique R values:  {unique}")
    print(f"Duplicates found: {total - unique}")
    print("-" * 40)
    
    # عرض التكرارات إن وجدت
    if total - unique > 0:
        print("\n[!] Potential Reuse Detected:")
        cur.execute("SELECT r, COUNT(*) as c FROM signatures GROUP BY r HAVING c > 1 LIMIT 5")
        for row in cur.fetchall():
            print(f"R: {row[0][:30]}... (Found {row[1]} times)")
    else:
        print("\nNo duplicates found in the database yet.")
        
    conn.close()

if __name__ == "__main__":
    analyze()
