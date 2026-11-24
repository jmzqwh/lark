import base64, struct
from Crypto.Cipher import AES

BASE = r'C:\Users\Administrator\Documents\Trae-CN\temp_20261120_03\_work\data3\data\data\com.ss.android.lark\files'

kv = open(BASE + r'\kPreference', 'rb').read().decode('ascii')
iv_b64, kb_b64 = kv.split(':')
iv_file = base64.b64decode(iv_b64)       # 16B
keyblob = base64.b64decode(kb_b64)       # 32B
print('iv(16B)=', iv_file.hex())
print('kb(32B)=', keyblob.hex())

lp = open(BASE + r'\lkSuitPreference', 'rb').read()
print('lp size', len(lp))

KNOWN = [
    b'rust', b'userId', b'tenant_brand', b'set_rust_env',
    b'f3234c2b', b'7239619144853684225', b'env_type',
    b'slardar-bd', b'8060950', b'crashCount', b'loggedIn',
]

KEYS = {
    'keyblob_full_AES256':      keyblob,
    'keyblob_first16_AES128':   keyblob[:16],
    'keyblob_last16_AES128':    keyblob[16:],
    'keyblob_mix_xor_a':        bytes(a^b for a,b in zip(keyblob[:16], keyblob[16:])),
    'keyblob_xor_iv':           bytes(a^b for a,b in zip(keyblob[:16], iv_file)),
    'file_iv_AES128':           iv_file,
}

print('\n=== Full CBC brute ===')
found = 0
for kname, key in KEYS.items():
    for hdr in range(0, 25):
        for iv_off in range(hdr, min(hdr+16, len(lp))):
            ct_off = iv_off + 16
            if ct_off >= len(lp): continue
            iv = lp[iv_off:iv_off+16]
            ct = lp[ct_off: ct_off + ((len(lp)-ct_off)//16*16)]
            if len(ct) < 16: continue
            try:
                c = AES.new(key, AES.MODE_CBC, iv)
                pt = c.decrypt(ct)
            except: continue
            score = sum(1 for k in KNOWN if k in pt)
            if score >= 2:
                found += 1
                print('HIT key=%s hdr=%d iv_off=%d score=%d' % (kname, hdr, iv_off, score))
                try: print('  ascii:', pt.decode('utf-8','replace')[:300])
                except: pass

print('\n=== Also try IV=keyblob/AES-Derived ===')
for kname, key in KEYS.items():
    for hdr in range(0, 25):
        ct = lp[hdr:]
        ct = ct[:len(ct)//16*16]
        if len(ct) < 16: continue
        for iv_name, iv in [('zero', b'\x00'*16), ('iv_file', iv_file), ('first16', keyblob[:16]),
                            ('last16', keyblob[16:]), ('full_key_aes_cbc_of_zero', None)]:
            if iv_name == 'full_key_aes_cbc_of_zero':
                try:
                    iv = AES.new(key, AES.MODE_ECB).decrypt(b'\x00'*16)
                except: continue
            try:
                c = AES.new(key, AES.MODE_CBC, iv)
                pt = c.decrypt(ct)
            except: continue
            score = sum(1 for k in KNOWN if k in pt)
            if score >= 2:
                found += 1
                print('HIT key=%s hdr=%d iv=%s score=%d' % (kname, hdr, iv_name, score))
                try: print('  ascii:', pt.decode('utf-8','replace')[:300])
                except: pass

print('\n=== Try 32B CBC (key+IV concatenated from 32B regions) ===')
# 有些实现用一个 32B/48B blob 同时当 key+iv
for blob_off in range(0, len(lp)-32):
    blob = lp[blob_off:blob_off+32]
    key = blob[:16]; iv = blob[16:]
    for hdr in range(0, blob_off):
        ct = lp[hdr:blob_off] + lp[blob_off+32:]
        ct = ct[:len(ct)//16*16]
        if len(ct) < 16: continue
        try:
            c = AES.new(key, AES.MODE_CBC, iv)
            pt = c.decrypt(ct)
        except: continue
        score = sum(1 for k in KNOWN if k in pt)
        if score >= 2:
            found += 1
            print('HIT blob_off=%d hdr=%d score=%d' % (blob_off, hdr, score))
            try: print('  ascii:', pt.decode('utf-8','replace')[:300])
            except: pass

print('\n=== ECB with various keys ===')
for kname, key in KEYS.items():
    for hdr in range(0, 25):
        ct = lp[hdr:]
        ct = ct[:len(ct)//16*16]
        if len(ct) < 16: continue
        try:
            c = AES.new(key, AES.MODE_ECB)
            pt = c.decrypt(ct)
        except: continue
        score = sum(1 for k in KNOWN if k in pt)
        if score >= 2:
            found += 1
            print('HIT ECB key=%s hdr=%d score=%d' % (kname, hdr, score))
            try: print('  ascii:', pt.decode('utf-8','replace')[:300])
            except: pass

print('\n=== XOR-scan:已知明文块1反推 IV ===')
# 已知 pt1='{"env_type":1,"set_rust_env":false,' (block0) -> 48B 取前16B
pt_candidates = [
    b'{"env_type":1,"', b'{"rust":"f3234c2b', b'"rust":"f3234c2b',
    b'slardar-bd.feis', b'"set_rust_env":fa', b'"tenant_brand":"f',
    b'"userId":"72396191', b'{"crashCount":3,"dat',
]
for pt1 in pt_candidates:
    pt1 = pt1[:16].ljust(16, b'\x00')
    for hdr in range(0, 25):
        ct = lp[hdr:]
        if len(ct) < 16: continue
        block0 = ct[:16]
        iv_recover = bytes(a^b for a,b in zip(block0, pt1))
        # 用 recoverd IV 解后续块，看是否命中关键字
        for kname, key in KEYS.items():
            try:
                c = AES.new(key, AES.MODE_CBC, iv_recover)
                pt = c.decrypt(ct[:len(ct)//16*16])
            except: continue
            score = sum(1 for k in KNOWN if k in pt)
            if score >= 2:
                found += 1
                print('HIT XOR key=%s hdr=%d iv_recover=%s score=%d pt_cand=%s' %
                      (kname, hdr, iv_recover.hex(), score, pt1[:8]))
                try: print('  ascii:', pt.decode('utf-8','replace')[:300])
                except: pass

print('\nTOTAL FOUND', found)
