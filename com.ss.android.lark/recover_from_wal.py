import struct, hashlib, sqlite3, os
from Crypto.Cipher import AES

BASE = r'C:\Users\Administrator\Documents\Trae-CN\temp_20261120_03\_work\data3\data\data\com.ss.android.lark\databases\sdk_storage\a72ae447cbebc68c8c9dbe99c71532a4'
OUT = r'C:\Users\Administrator\Documents\Trae-CN\temp_20261120_03\_work\im_recovered.db'
HEXK = '96C245D73A29C7651C9A76E0C4D11DD941558C7EC596C80E352A903F883B903A'
MAGIC = b'SQLite format 3\x00'
PSZ = 4096

wal = open(BASE + r'\im.db-wal', 'rb').read()
main = open(BASE + r'\im.db', 'rb').read()
salt = main[:16]
key = hashlib.pbkdf2_hmac('sha512', ('x"' + HEXK + '"').encode(), salt, 4000, 32)

# 取每页最新帧；主库只有 1 页，以 WAL 为准
pages = {1: main}
off = 32
while off + 24 + PSZ <= len(wal):
    pgno = struct.unpack('>I', wal[off:off+4])[0]
    pages[pgno] = wal[off+24:off+24+PSZ]
    off += 24 + PSZ

def dec(pgno, page):
    st = 16 if pgno == 1 else 0
    ct = page[st:PSZ-16]
    iv = page[PSZ-16:PSZ]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    tail = page[PSZ-16:PSZ]            # 保留区(IV 所在 16 字节)，保持页长 4096
    return (MAGIC + pt + tail) if pgno == 1 else pt + tail

buf = bytearray()
for pgno in range(1, max(pages) + 1):
    if pgno not in pages:
        print('缺页', pgno)
        buf += b'\x00' * PSZ
        continue
    buf += dec(pgno, pages[pgno])

open(OUT, 'wb').write(bytes(buf))
print('written', OUT, len(buf))
print('header:', buf[:16])
print('page_size', struct.unpack('>H', buf[16:18])[0], 'reserved', buf[20], 'pages', struct.unpack('>I', buf[28:32])[0])

con = sqlite3.connect(OUT)
print('integrity:', con.execute('PRAGMA integrity_check').fetchall())
tabs = con.execute("select name from sqlite_master where type='table' order by name").fetchall()
print('tables:', len(tabs))
print([t[0] for t in tabs][:60])
for name in [t[0] for t in tabs]:
    try:
        n = con.execute('select count(*) from "%s"' % name).fetchone()[0]
    except Exception as e:
        n = 'ERR:%s' % e
    if isinstance(n, int) and n > 0:
        print('  %-40s %d' % (name, n))
con.close()
