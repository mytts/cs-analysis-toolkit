#!/usr/bin/env python3
"""生成一个模拟的 Beacon 配置块用于测试解析平台"""
import struct

def make_setting(sid, stype, value):
    """Create a TLV setting entry"""
    if stype == 1:  # SHORT
        data = struct.pack(">H", value)
    elif stype == 2:  # INT
        data = struct.pack(">I", value)
    elif stype == 3:  # PTR
        data = value if isinstance(value, bytes) else value.encode()
    else:
        data = b''
    return struct.pack(">HHH", sid, stype, len(data)) + data

def main():
    # Build a realistic settings TLV block
    settings = b''
    settings += make_setting(1, 1, 0)             # PROTOCOL = HTTP
    settings += make_setting(2, 1, 443)            # PORT = 443
    settings += make_setting(3, 2, 60000)          # SLEEP = 60s
    settings += make_setting(5, 1, 25)             # JITTER = 25%
    settings += make_setting(8, 3, b'cdn.example.com,www.evil.net,c2.malware.io\x00')
    settings += make_setting(9, 3, b'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\x00')
    settings += make_setting(10, 3, b'/submit.php?id=\x00')
    settings += make_setting(14, 3, b'%windir%\\syswow64\\rundll32.exe\x00')
    settings += make_setting(15, 3, b'%windir%\\sysnative\\rundll32.exe\x00')
    settings += make_setting(19, 1, 0)             # CRYPTO = 0
    settings += make_setting(26, 2, 1670873463)    # WATERMARK
    settings += make_setting(29, 3, b'\\\\.\\pipe\\MSSE-1234-server\x00')
    settings += make_setting(3, 2, 60000)          # duplicate for realism
    settings += make_setting(37, 3, b'cdn.example.com\x00')
    settings += make_setting(43, 2, 0x00000004)    # INJECT_OPTIONS
    settings += make_setting(44, 1, 2027)          # KILLDATE_YEAR
    settings += make_setting(45, 1, 12)            # KILLDATE_MONTH
    settings += make_setting(46, 1, 31)            # KILLDATE_DAY
    settings += make_setting(49, 1, 4)             # PROCINJ_PERMS_I = RW
    settings += make_setting(50, 1, 32)            # PROCINJ_PERMS = RX
    settings += make_setting(7, 3, b'\x30' * 256)  # Fake RSA pubkey (256B)

    # Pad to 6144 bytes (4.9.1 patch size)
    settings = settings.ljust(6144, b'\x00')

    # XOR encode with 0x2E
    encoded = bytes(b ^ 0x2E for b in settings)

    # Build a minimal PE-like file with the config block
    # MZ header
    pe = bytearray(b'MZ' + b'\x00' * 58)
    pe[0x3C:0x40] = struct.pack("<I", 64)  # e_lfanew
    # PE signature + COFF header (DLL, x64)
    pe += b'PE\x00\x00'
    pe += struct.pack("<H", 0x8664)  # Machine = AMD64
    pe += b'\x00' * 16
    pe += struct.pack("<H", 0x2022)  # Characteristics (DLL)
    # Pad to a nice offset
    pe = pe.ljust(0x1000, b'\x00')
    # Insert the XOR-encoded config block
    config_offset = len(pe)
    pe += encoded
    # Add some padding after
    pe += b'\x00' * 0x1000

    out = "test_beacon_sim.bin"
    with open(out, "wb") as f:
        f.write(pe)
    print(f"[+] Generated {out} ({len(pe)} bytes)")
    print(f"    Config block at offset 0x{config_offset:X}")
    print(f"    XOR key: 0x2E")
    print(f"    Settings: {len(settings)} bytes")

if __name__ == "__main__":
    main()
