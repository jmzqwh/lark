#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线还原飞书 SP 中 key="rust" 的值（app_secret 前 32 位来源）。

数据来源（两者缺一不可）：
  1) files/mmkv/lark                      -> MMKV 存储的密文条目
  2) files/kPreference                    -> AES 密钥 + HMAC 密钥（base64:base64）

存储格式（对应 com.ss.android.lark.storage.kv.mmkv.legacy.d / hi7.a$b / seccache.impl.AesCbcUtils）：
  MMKV 的 key   = base64( SHA-256(逻辑key) )            (gb7.d.i)
  MMKV 的 value = "<base64 iv>:<base64 hmac>:<base64 ct>"  (AesCbcUtils$a.toString)
  kPreference   = "<base64 aesKey16>:<base64 hmacKey32>"   (hi7.a$b.toString)
  加密算法      = AES/CBC/PKCS5Padding，HMAC = HmacSHA256(iv || ct)

用法：
  python decrypt_rust_key.py [mmkv文件] [kPreference文件]
不带参数时使用下面的默认路径。
"""

import base64
import hashlib
import hmac
import os
import sys

from Crypto.Cipher import AES

LOGICAL_KEY = "rust"
EXPECTED = "f3234c2b-6ab4-4fc4-8b50-7a0cb6ae4949"

DEFAULT_MMKV = r"_work\data3\data\data\com.ss.android.lark\files\mmkv\lark"
DEFAULT_KPREF = r"_work\data3\data\data\com.ss.android.lark\files\kPreference"


def b64d(s: str) -> bytes:
    """容错的 base64 解码：自动补 padding。"""
    return base64.b64decode(s + "=" * (-len(s) % 4))


def read_varint(buf: bytes, pos: int):
    """MMKV 的 protobuf-style varint，返回 (值, 新位置)。"""
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def load_keypair(path: str):
    """读取 kPreference -> (aes_key16, hmac_key32)"""
    raw = open(path, "rb").read().decode("ascii").strip()
    parts = raw.split(":")
    if len(parts) != 2:
        raise ValueError("kPreference 格式非法，应为 base64:base64")
    aes_key, hmac_key = b64d(parts[0]), b64d(parts[1])
    if len(aes_key) != 16 or len(hmac_key) != 32:
        raise ValueError("kPreference 长度非法: aes=%d hmac=%d" % (len(aes_key), len(hmac_key)))
    return aes_key, hmac_key


def find_entry(mmkv: bytes, logical_key: str):
    """
    在 MMKV 文件里定位逻辑 key 对应的条目。
    MMKV 用 base64(SHA-256(key)) 作为真实 key，其后跟两层长度前缀：
      外层 varint = 整个 MMBuffer 的长度
      内层 varint = 字符串本身的长度（MMKV 会跳过可变长度类型的前缀）
    """
    real_key = base64.b64encode(hashlib.sha256(logical_key.encode()).digest())
    idx = mmkv.find(real_key)
    if idx < 0:
        raise LookupError("MMKV 中找不到 key: %r" % logical_key)

    pos = idx + len(real_key)
    outer_len, pos = read_varint(mmkv, pos)
    inner_len, pos = read_varint(mmkv, pos)
    value = mmkv[pos:pos + inner_len].decode("ascii")
    return real_key.decode(), outer_len, inner_len, value


def main():
    mmkv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MMKV
    kp_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_KPREF

    for p in (mmkv_path, kp_path):
        if not os.path.exists(p):
            sys.exit("文件不存在: %s" % p)

    print("=" * 68)
    print("飞书 SP 值离线解密（key = %r）" % LOGICAL_KEY)
    print("=" * 68)

    # ---- 1. 密钥（kPreference） ----
    aes_key, hmac_key = load_keypair(kp_path)
    print("[1] kPreference -> AES 密钥 / HMAC 密钥")
    print("    AES-128 key : %s" % aes_key.hex())
    print("    HMAC key    : %s" % hmac_key.hex())

    # ---- 2. 密文（MMKV） ----
    mmkv = open(mmkv_path, "rb").read()
    real_key, outer_len, inner_len, value = find_entry(mmkv, LOGICAL_KEY)
    print("\n[2] MMKV 条目")
    print("    真实 key    : %s" % real_key)
    print("    条目偏移    : %d (外层varint=%d, 内层varint=%d)" % (mmkv.find(real_key.encode()), outer_len, inner_len))
    print("    值字符串    : %s" % value)

    parts = value.split(":")
    if len(parts) == 3:
        iv_b64, mac_b64, ct_b64 = parts
        stored_mac = b64d(mac_b64)
    elif len(parts) == 2:                      # 兼容旧格式（无 HMAC）
        iv_b64, ct_b64 = parts
        stored_mac = None
    else:
        raise ValueError("值格式非法: %r" % value)

    iv, ct = b64d(iv_b64), b64d(ct_b64)
    print("\n[3] 拆解")
    print("    IV          : %s (%dB)" % (iv.hex(), len(iv)))
    print("    密文        : %s (%dB)" % (ct.hex(), len(ct)))
    print("    HMAC        : %s" % (stored_mac.hex() if stored_mac else "<旧格式，无>"))

    # ---- 4. 校验 HMAC ----
    if stored_mac is not None:
        calc = hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()
        ok = hmac.compare_digest(calc, stored_mac)
        print("\n[4] HMAC-SHA256(iv||ct) 校验: %s" % ("PASS" if ok else "FAIL"))
        if not ok:
            sys.exit("HMAC 不匹配：密钥或文件不是同一份")

    # ---- 5. AES-CBC 解密 ----
    plain = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        sys.exit("PKCS5 padding 非法，解密失败")
    text = plain[:-pad].decode("utf-8")

    print("\n[5] AES/CBC/PKCS5Padding 解密")
    print("    原始字节    : %r" % plain)
    print("    去 padding  : %r" % text)

    # ---- 6. 结论 ----
    print("\n[6] 结果")
    print("    " + text)
    print("    断言        : %s" % ("PASS" if text == EXPECTED else "FAIL (期望 %s)" % EXPECTED))
    return 0 if text == EXPECTED else 1


if __name__ == "__main__":
    sys.exit(main())
