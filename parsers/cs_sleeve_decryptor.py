#!/usr/bin/env python3
"""
Cobalt Strike Sleeve 解密器 + Beacon 配置解析器
================================================
从 cobaltstrike.auth 提取 SleeveKey, 解密 sleeve/ 模板,
解析 Beacon DLL 中的 Settings TLV 配置块。

基于 CS 4.9.1 逆向分析:
- SleeveSecurity.java: AES-128-CBC + HMAC-SHA256
- Settings.java: 6144-byte TLV patch block
- Authorization.java: RSA + auth file parsing

用法:
    python3 cs_sleeve_decryptor.py --auth cobaltstrike.auth --pubkey authkey.pub --sleeve-dir sleeve/ --output decrypted/
    python3 cs_sleeve_decryptor.py --parse-beacon decrypted/beacon.dll
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:
    try:
        from Cryptodome.Cipher import AES, PKCS1_v1_5
        from Cryptodome.PublicKey import RSA
    except ImportError:
        print("[!] 需要 pycryptodome: pip3 install pycryptodome")
        sys.exit(1)


# ─── 常量 ───────────────────────────────────────────────────
SLEEVE_IV = b"abcdefghijklmnop"              # 硬编码 IV (SleeveSecurity.java:57)
AUTH_MAGIC_40 = 0xCAFED023                    # 4.0+ auth header (-889274157)
AUTH_MAGIC_PRE40 = 0xCAFED00B                 # pre-4.0 header (-889274181)
AUTHKEY_MD5 = "8bb4df00c120881a1945a43e2bb2379e"  # authkey.pub 校验和
SETTINGS_PATCH_SIZE = 6144                    # Settings.java:16
SETTINGS_MAX = 128                            # Settings.java:17
TYPE_NONE = 0
TYPE_SHORT = 1
TYPE_INT = 2
TYPE_PTR = 3

# 已知 Setting ID → 名称映射 (从 Beacon 源码和公开资料汇编)
SETTING_NAMES = {
    1: "SETTING_PROTOCOL",          # 0=HTTP, 1=HTTPS, 8=DNS, ...
    2: "SETTING_PORT",
    3: "SETTING_SLEEPTIME",
    4: "SETTING_MAXGET",
    5: "SETTING_JITTER",
    7: "SETTING_PUBKEY",            # RSA public key (256 bytes)
    8: "SETTING_DOMAINS",           # C2 server domains
    9: "SETTING_USERAGENT",
    10: "SETTING_SUBMITURI",        # POST URI
    11: "SETTING_C2_RECOVER",
    12: "SETTING_C2_REQUEST",
    13: "SETTING_C2_POSTREQ",
    14: "SETTING_SPAWNTO_X86",
    15: "SETTING_SPAWNTO_X64",
    19: "SETTING_CRYPTO_SCHEME",
    26: "SETTING_WATERMARK",        # License watermark
    27: "SETTING_CLEANUP",
    28: "SETTING_CFG_CAUTION",
    29: "SETTING_PIPENAME",
    30: "SETTING_DNS_IDLE",
    31: "SETTING_DNS_SLEEP",
    32: "SETTING_SSH_HOST",
    33: "SETTING_SSH_PORT",
    34: "SETTING_SSH_USERNAME",
    35: "SETTING_SSH_PASSWORD",
    36: "SETTING_SSH_KEY",
    37: "SETTING_C2_HOST_HEADER",
    38: "SETTING_HTTP_NO_COOKIES",
    39: "SETTING_PROXY_CONFIG",
    40: "SETTING_PROXY_USER",
    41: "SETTING_PROXY_PASSWORD",
    42: "SETTING_PROXY_BEHAVIOR",
    43: "SETTING_INJECT_OPTIONS",
    44: "SETTING_KILLDATE_YEAR",
    45: "SETTING_KILLDATE_MONTH",
    46: "SETTING_KILLDATE_DAY",
    47: "SETTING_GARGLE_NOOK",
    48: "SETTING_GARGLE_SECTIONS",
    49: "SETTING_PROCINJ_PERMS_I",
    50: "SETTING_PROCINJ_PERMS",
    51: "SETTING_PROCINJ_MINALLOC",
    52: "SETTING_PROCINJ_TRANSFORM_X86",
    53: "SETTING_PROCINJ_TRANSFORM_X64",
    54: "SETTING_PROCINJ_ALLOWED",
    55: "SETTING_BINDHOST",
    56: "SETTING_HTTP_HEADER_ORDER",
    57: "SETTING_DATA_STORE",
    58: "SETTING_BEACON_GATE",       # BeaconGate syscall config (4.10+)
    59: "SETTING_TCP_FRAME_HEADER",
    60: "SETTING_SMB_FRAME_HEADER",
    70: "SETTING_HOST_HEADER",
}


# ─── Sleeve 解密 ────────────────────────────────────────────
class SleeveDecryptor:
    """复现 SleeveSecurity.java 的解密逻辑"""

    def __init__(self, sleeve_key: bytes):
        # registerKey(): SHA-256(key) → AES[0:16] + HMAC[16:32]
        key_hash = hashlib.sha256(sleeve_key).digest()
        self.aes_key = key_hash[:16]
        self.hmac_key = key_hash[16:]
        print(f"[+] AES Key:  {self.aes_key.hex()}")
        print(f"[+] HMAC Key: {self.hmac_key.hex()}")

    def decrypt(self, data: bytes) -> bytes:
        """
        decrypt() 逻辑:
        1. 分离 ciphertext (data[:-16]) 和 HMAC (data[-16:])
        2. 验证 HMAC-SHA256(ciphertext)[:16] == stored HMAC
        3. AES-CBC 解密
        4. 跳过 4B random + 读 4B length + 提取 payload
        """
        if len(data) < 32:
            raise ValueError(f"数据太短: {len(data)} bytes")

        ciphertext = data[:-16]
        stored_hmac = data[-16:]

        # HMAC 验证
        computed_hmac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("HMAC 验证失败 — 密钥错误或数据损坏")

        # AES-CBC 解密
        cipher = AES.new(self.aes_key, AES.MODE_CBC, SLEEVE_IV)
        plaintext = cipher.decrypt(ciphertext)

        # 解析: [4B random][4B length][payload][0x41 padding]
        if len(plaintext) < 8:
            raise ValueError("解密后数据太短")
        _random = struct.unpack(">I", plaintext[:4])[0]
        payload_len = struct.unpack(">I", plaintext[4:8])[0]

        if payload_len < 0 or payload_len > len(data):
            raise ValueError(f"无效的 payload 长度: {payload_len}")

        return plaintext[8:8 + payload_len]


# ─── Auth 文件解析 ───────────────────────────────────────────
def extract_sleeve_key(auth_path: str, pubkey_path: str) -> tuple:
    """
    从 cobaltstrike.auth 提取 SleeveKey
    Authorization.java 逻辑:
    1. 读取 512 字节 auth 文件
    2. RSA 解密前 256 字节 (使用 authkey.pub)
    3. 解析: [magic:4][key_len:1][key:N][skip_len:1][skip:M][version:1][valid_to:4][watermark:4]
    """
    auth_data = open(auth_path, "rb").read()
    if len(auth_data) != 512:
        raise ValueError(f"Auth 文件大小错误: {len(auth_data)} bytes (期望 512)")

    pubkey_data = open(pubkey_path, "rb").read()
    pubkey_md5 = hashlib.md5(pubkey_data).hexdigest()
    print(f"[*] authkey.pub MD5: {pubkey_md5}")
    if pubkey_md5 != AUTHKEY_MD5:
        print(f"[!] 警告: MD5 不匹配 (期望 {AUTHKEY_MD5})")

    # RSA 解密 (AuthCrypto.java: RSA/ECB/PKCS1Padding, decrypt with public key)
    # Java Cipher.init(DECRYPT_MODE, publicKey) does raw RSA: m = c^e mod n
    # Then strips PKCS1 v1.5 signature padding: 00 01 FF...FF 00 [data]
    rsa_key = RSA.import_key(pubkey_data)
    from Crypto.Util.number import bytes_to_long, long_to_bytes

    block1 = auth_data[:256]
    block_int = bytes_to_long(block1)
    decrypted_int = pow(block_int, rsa_key.e, rsa_key.n)
    decrypted_raw = long_to_bytes(decrypted_int)

    # 补齐到 key size (可能丢失前导零)
    key_size = (rsa_key.size_in_bits() + 7) // 8
    if len(decrypted_raw) < key_size:
        decrypted_raw = b'\x00' * (key_size - len(decrypted_raw)) + decrypted_raw

    print(f"[*] RSA 解密原始数据 (前 16 bytes): {decrypted_raw[:16].hex()}")

    # PKCS1 v1.5 signature padding: 00 01 FF FF ... FF 00 [data]
    # 或 encryption padding: 00 02 [random non-zero] 00 [data]
    if decrypted_raw[0:2] == b'\x00\x01':
        # 签名 padding: 跳过 FF 填充直到 00
        pad_end = 2
        while pad_end < len(decrypted_raw) and decrypted_raw[pad_end] == 0xFF:
            pad_end += 1
        if pad_end < len(decrypted_raw) and decrypted_raw[pad_end] == 0x00:
            pad_end += 1  # 跳过终止 0x00
        print(f"[*] PKCS1 v1.5 签名 padding, 数据起始: offset {pad_end}")
    elif decrypted_raw[0:2] == b'\x00\x02':
        # 加密 padding: 跳过随机非零字节直到 00
        try:
            pad_end = decrypted_raw.index(b'\x00', 2) + 1
        except ValueError:
            pad_end = 0
        print(f"[*] PKCS1 v1.5 加密 padding, 数据起始: offset {pad_end}")
    else:
        print(f"[!] 非标准 padding: {decrypted_raw[:4].hex()}")
        # 尝试直接扫描 magic bytes
        magic_pos = decrypted_raw.find(b'\xca\xfe\xd0\x23')
        if magic_pos != -1:
            pad_end = magic_pos
            print(f"[*] 找到 CAFED023 magic 在 offset {pad_end}")
        else:
            # 也可能第一个字节被截断 (long_to_bytes 移除了前导 0x00)
            pad_end = 0

    payload = decrypted_raw[pad_end:]

    # AuthCrypto.decrypt(): 检查 magic header
    # DataParser 读取: [magic:4][key_len:2][key_data:N]
    if len(payload) < 6:
        raise ValueError("RSA 解密 payload 太短")

    magic = struct.unpack(">I", payload[:4])[0]
    magic_signed = struct.unpack(">i", payload[:4])[0]

    print(f"[*] Auth Magic: 0x{magic:08X} ({magic_signed})")

    if magic_signed == -889274181:  # 0xCAFED00B
        raise ValueError("pre-4.0 auth 文件, 不支持")
    if magic_signed != -889274157:  # 0xCAFED023
        raise ValueError(f"无效的 auth magic: 0x{magic:08X}")

    # AuthCrypto.decrypt(): readShort + readBytes
    key_len = struct.unpack(">H", payload[4:6])[0]
    auth_payload = payload[6:6 + key_len]
    print(f"[+] Auth payload 长度: {key_len} bytes")

    # Authorization.java 解析 auth_payload:
    # [sleeve_key_len:1][sleeve_key:N][skip_len:1][skip:M][version:1][valid_to:4][watermark:4]
    offset = 0
    sleeve_key_len = auth_payload[offset]
    offset += 1
    sleeve_key = auth_payload[offset:offset + sleeve_key_len]
    offset += sleeve_key_len

    skip_len = auth_payload[offset]
    offset += 1
    offset += skip_len  # consume skip bytes

    version_byte = auth_payload[offset]
    offset += 1

    valid_to = struct.unpack(">I", auth_payload[offset:offset + 4])[0]
    offset += 4

    watermark = struct.unpack(">I", auth_payload[offset:offset + 4])[0]
    offset += 4

    print(f"[+] SleeveKey 长度: {sleeve_key_len} bytes")
    print(f"[+] SleeveKey: {sleeve_key.hex()}")
    print(f"[+] Version byte: {version_byte} ('{chr(version_byte)}')")
    if valid_to == 29999999:
        print(f"[+] Valid to: perpetual (forever)")
    else:
        print(f"[+] Valid to: 20{valid_to}")
    print(f"[+] Watermark: {watermark}")

    return sleeve_key, watermark, valid_to


# ─── Settings TLV 解析 ──────────────────────────────────────
def find_settings_block(data: bytes) -> int:
    """
    在 Beacon DLL 中查找 Settings 配置块
    Settings 是 6144 字节的 TLV 块, 嵌入在 PE 的 .data 或 .rdata 段
    搜索策略: 找到有效的 TLV 起始序列
    """
    # Settings TLV 格式: [id:2][type:2][len:2][value:N]
    # 第一个 entry 通常是 SETTING_PROTOCOL (id=1, type=1, len=2)
    # 字节: 00 01 00 01 00 02 XX XX
    pattern = b'\x00\x01\x00\x01\x00\x02'

    offset = 0
    while True:
        pos = data.find(pattern, offset)
        if pos == -1:
            return -1

        # 验证: 后续的 entries 也应该是有效的 TLV
        if validate_tlv_sequence(data[pos:pos + 256]):
            return pos
        offset = pos + 1

    return -1


def validate_tlv_sequence(data: bytes) -> bool:
    """验证一段数据是否是有效的 TLV 序列"""
    offset = 0
    valid_count = 0

    while offset + 4 <= len(data):
        entry_id = struct.unpack(">H", data[offset:offset + 2])[0]
        entry_type = struct.unpack(">H", data[offset + 2:offset + 4])[0]

        if entry_id == 0:  # TYPE_NONE terminator
            return valid_count >= 3

        if entry_id > SETTINGS_MAX:
            return False
        if entry_type not in (TYPE_SHORT, TYPE_INT, TYPE_PTR):
            return False

        if offset + 6 > len(data):
            return False

        entry_len = struct.unpack(">H", data[offset + 4:offset + 6])[0]

        if entry_type == TYPE_SHORT and entry_len != 2:
            return False
        if entry_type == TYPE_INT and entry_len != 4:
            return False

        offset += 6 + entry_len
        valid_count += 1

    return valid_count >= 3


def parse_settings(data: bytes, offset: int) -> list:
    """解析 Settings TLV 块"""
    settings = []
    pos = offset

    while pos + 6 <= len(data):
        entry_id = struct.unpack(">H", data[pos:pos + 2])[0]
        entry_type = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        entry_len = struct.unpack(">H", data[pos + 4:pos + 6])[0]

        if entry_id == 0:  # terminator
            break

        value_data = data[pos + 6:pos + 6 + entry_len]

        if entry_type == TYPE_SHORT:
            value = struct.unpack(">H", value_data)[0]
        elif entry_type == TYPE_INT:
            value = struct.unpack(">I", value_data)[0]
        elif entry_type == TYPE_PTR:
            value = value_data
        else:
            value = value_data

        name = SETTING_NAMES.get(entry_id, f"UNKNOWN_{entry_id}")
        settings.append({
            "id": entry_id,
            "name": name,
            "type": entry_type,
            "type_name": ["NONE", "SHORT", "INT", "PTR"][entry_type],
            "length": entry_len,
            "value": value,
        })

        pos += 6 + entry_len

    return settings


def parse_beacon_config(filepath: str):
    """解析 Beacon DLL 的 Settings 配置"""
    data = open(filepath, "rb").read()
    print(f"\n{'='*60}")
    print(f"Beacon 配置解析: {filepath}")
    print(f"文件大小: {len(data):,} bytes")
    print(f"{'='*60}")

    # 检查 PE header
    if data[:2] == b'MZ':
        print("[+] 格式: PE (MZ header)")
    elif data[:4] == b'\x7fELF':
        print("[+] 格式: ELF")
    else:
        print(f"[*] 格式: 未知 ({data[:4].hex()})")

    # 搜索 Settings 块
    settings_offset = find_settings_block(data)
    if settings_offset == -1:
        print("[-] 未找到 Settings 配置块")
        print("[*] 提示: Beacon DLL 可能仍被加密, 需要先用 sleeve 解密")
        return

    print(f"[+] Settings 块偏移: 0x{settings_offset:X}")
    settings = parse_settings(data, settings_offset)

    print(f"[+] 解析到 {len(settings)} 个配置项:\n")

    for s in settings:
        if isinstance(s["value"], bytes):
            # 对于字节数据, 显示可打印字符串或 hex 摘要
            try:
                text = s["value"].rstrip(b'\x00').decode('utf-8', errors='replace')
                if all(32 <= ord(c) < 127 or c == '\x00' for c in text[:50]):
                    display = f'"{text[:80]}"'
                else:
                    display = f"[{len(s['value'])}B] {s['value'][:32].hex()}..."
            except Exception:
                display = f"[{len(s['value'])}B] {s['value'][:32].hex()}..."
        else:
            display = str(s["value"])
            # 特殊格式化
            if s["id"] == 1:  # PROTOCOL
                proto_map = {0: "HTTP", 1: "HTTPS", 2: "TCP Bind", 4: "TCP Reverse",
                             8: "DNS", 16: "SMB", 32: "ExtC2"}
                display += f" ({proto_map.get(s['value'], 'Unknown')})"
            elif s["id"] == 26:  # WATERMARK
                display = f"{s['value']} (0x{s['value']:08X})"

        print(f"  [{s['id']:3d}] {s['name']:<35s} {s['type_name']:<5s} = {display}")

    return settings


# ─── 字符串标记搜索 ─────────────────────────────────────────
MARKERS = {
    b"TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ": "String Table Marker (4096B block)",
    b"GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd": "Guardrails Patch Marker (2048B block)",
    b"ZZZZZZZXXXXWYYYY": "PostEx Loader Marker",
}


def scan_markers(filepath: str):
    """扫描 Beacon DLL 中的已知标记"""
    data = open(filepath, "rb").read()
    print(f"\n[*] 扫描标记: {filepath}")

    for marker, desc in MARKERS.items():
        offset = data.find(marker)
        if offset != -1:
            print(f"  [+] {desc}")
            print(f"      偏移: 0x{offset:X}")
            print(f"      Hex: {marker[:16].hex()}...")
        else:
            print(f"  [-] {desc} — 未找到")


# ─── 主程序 ─────────────────────────────────────────────────
def cmd_decrypt_sleeve(args):
    """解密 sleeve 模板"""
    # 提取 SleeveKey
    sleeve_key, watermark, valid_to = extract_sleeve_key(args.auth, args.pubkey)

    # 初始化解密器
    decryptor = SleeveDecryptor(sleeve_key)

    # 解密 sleeve 目录
    sleeve_dir = Path(args.sleeve_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(sleeve_dir.iterdir())
    success = 0
    failed = 0

    for f in files:
        if not f.is_file():
            continue
        try:
            encrypted = f.read_bytes()
            decrypted = decryptor.decrypt(encrypted)
            out_path = output_dir / f.name
            out_path.write_bytes(decrypted)
            size_ratio = len(encrypted) / len(decrypted) if len(decrypted) > 0 else 0
            print(f"  [+] {f.name:<40s} {len(encrypted):>8,}B → {len(decrypted):>8,}B")
            success += 1
        except Exception as e:
            print(f"  [-] {f.name:<40s} 失败: {e}")
            failed += 1

    print(f"\n[*] 完成: {success} 成功, {failed} 失败, 输出: {output_dir}")


def cmd_parse_beacon(args):
    """解析 Beacon 配置"""
    parse_beacon_config(args.file)
    if args.markers:
        scan_markers(args.file)


def cmd_extract_key(args):
    """仅提取 SleeveKey"""
    sleeve_key, watermark, valid_to = extract_sleeve_key(args.auth, args.pubkey)
    if args.output:
        Path(args.output).write_bytes(sleeve_key)
        print(f"[+] SleeveKey 已保存到: {args.output}")


def main():
    parser = argparse.ArgumentParser(
        description="Cobalt Strike Sleeve 解密器 + Beacon 配置解析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 提取 SleeveKey
  %(prog)s extract-key --auth cobaltstrike.auth --pubkey authkey.pub

  # 解密所有 sleeve 模板
  %(prog)s decrypt --auth cobaltstrike.auth --pubkey authkey.pub --sleeve-dir sleeve/ -o decrypted/

  # 解析 Beacon 配置 (解密后的 DLL)
  %(prog)s parse --file decrypted/beacon.dll --markers
        """)

    subparsers = parser.add_subparsers(dest="command")

    # extract-key
    p_key = subparsers.add_parser("extract-key", help="从 auth 文件提取 SleeveKey")
    p_key.add_argument("--auth", required=True, help="cobaltstrike.auth 路径")
    p_key.add_argument("--pubkey", required=True, help="authkey.pub 路径")
    p_key.add_argument("-o", "--output", help="保存 SleeveKey 到文件")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="解密 sleeve 模板")
    p_dec.add_argument("--auth", required=True, help="cobaltstrike.auth 路径")
    p_dec.add_argument("--pubkey", required=True, help="authkey.pub 路径")
    p_dec.add_argument("--sleeve-dir", required=True, help="sleeve/ 目录路径")
    p_dec.add_argument("-o", "--output", default="decrypted", help="输出目录 (默认: decrypted/)")

    # parse
    p_parse = subparsers.add_parser("parse", help="解析 Beacon DLL 配置")
    p_parse.add_argument("--file", required=True, help="Beacon DLL 路径")
    p_parse.add_argument("--markers", action="store_true", help="同时扫描已知标记")

    args = parser.parse_args()
    if args.command == "extract-key":
        cmd_extract_key(args)
    elif args.command == "decrypt":
        cmd_decrypt_sleeve(args)
    elif args.command == "parse":
        cmd_parse_beacon(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
