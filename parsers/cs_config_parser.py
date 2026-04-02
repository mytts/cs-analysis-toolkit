#!/usr/bin/env python3
"""
Cobalt Strike Beacon 配置解析器
================================
从 Beacon 样本 (DLL/shellcode/内存 dump) 中提取 C2 配置。

原理 (来自 BeaconPayload.java 逆向):
1. 搜索标记 "AAAABBBBCCCCDDDDEEEEFFFF" (24 bytes)
2. 标记位置的数据就是 Settings TLV 块 (4096 或 6144 bytes)
3. XOR 0x2E 解码
4. 解析 TLV 格式: [ID:2][Type:2][Len:2][Value:N]

用法:
    python3 cs_config_parser.py beacon.dll
    python3 cs_config_parser.py memory_dump.bin --format json
    python3 cs_config_parser.py beacon.bin --xor-scan
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

# ─── 常量 ───────────────────────────────────────────────────
CONFIG_MARKER = b"AAAABBBBCCCCDDDDEEEEFFFF"   # 24 bytes (BeaconPayload.java:424)
XOR_KEY_DEFAULT = 0x2E                         # beacon_obfuscate() XOR key
XOR_KEY_ALT = 0x69                             # 替代 XOR key
PATCH_SIZE_461 = 4096                          # Settings.java (4.6.1)
PATCH_SIZE_491 = 6144                          # Settings.java (4.9.1)
MAX_SETTINGS = 128

TYPE_NONE = 0
TYPE_SHORT = 1
TYPE_INT = 2
TYPE_PTR = 3

# Setting ID → 名称 + 描述
SETTINGS = {
    1:  ("SETTING_PROTOCOL",        "C2 协议类型"),
    2:  ("SETTING_PORT",            "C2 端口"),
    3:  ("SETTING_SLEEPTIME",       "Sleep 间隔 (ms)"),
    4:  ("SETTING_MAXGET",          "最大 GET 大小"),
    5:  ("SETTING_JITTER",          "Jitter 百分比"),
    7:  ("SETTING_PUBKEY",          "RSA 公钥 (256B)"),
    8:  ("SETTING_DOMAINS",         "C2 域名列表"),
    9:  ("SETTING_USERAGENT",       "User-Agent"),
    10: ("SETTING_SUBMITURI",       "POST 提交 URI"),
    11: ("SETTING_C2_RECOVER",      "C2 恢复策略"),
    12: ("SETTING_C2_REQUEST",      "C2 GET 请求变换"),
    13: ("SETTING_C2_POSTREQ",      "C2 POST 请求变换"),
    14: ("SETTING_SPAWNTO_X86",     "x86 注入目标进程"),
    15: ("SETTING_SPAWNTO_X64",     "x64 注入目标进程"),
    19: ("SETTING_CRYPTO_SCHEME",   "加密方案"),
    26: ("SETTING_WATERMARK",       "许可证水印 ID"),
    27: ("SETTING_CLEANUP",         "自清理标志"),
    28: ("SETTING_CFG_CAUTION",     "谨慎模式"),
    29: ("SETTING_PIPENAME",        "SMB 管道名"),
    30: ("SETTING_DNS_IDLE",        "DNS 空闲 IP"),
    31: ("SETTING_DNS_SLEEP",       "DNS Sleep (ms)"),
    32: ("SETTING_SSH_HOST",        "SSH 主机"),
    33: ("SETTING_SSH_PORT",        "SSH 端口"),
    34: ("SETTING_SSH_USERNAME",    "SSH 用户名"),
    35: ("SETTING_SSH_PASSWORD",    "SSH 密码"),
    36: ("SETTING_SSH_KEY",         "SSH 私钥"),
    37: ("SETTING_C2_HOST_HEADER",  "Host header"),
    38: ("SETTING_HTTP_NO_COOKIES", "禁用 Cookie"),
    39: ("SETTING_PROXY_CONFIG",    "代理配置"),
    40: ("SETTING_PROXY_USER",      "代理用户名"),
    41: ("SETTING_PROXY_PASSWORD",  "代理密码"),
    42: ("SETTING_PROXY_BEHAVIOR",  "代理行为"),
    43: ("SETTING_INJECT_OPTIONS",  "注入选项"),
    44: ("SETTING_KILLDATE_YEAR",   "Kill Date 年"),
    45: ("SETTING_KILLDATE_MONTH",  "Kill Date 月"),
    46: ("SETTING_KILLDATE_DAY",    "Kill Date 日"),
    47: ("SETTING_GARGLE_NOOK",     "Gargle 参数"),
    48: ("SETTING_GARGLE_SECTIONS", "Gargle 节数"),
    49: ("SETTING_PROCINJ_PERMS_I", "注入初始权限"),
    50: ("SETTING_PROCINJ_PERMS",   "注入最终权限"),
    51: ("SETTING_PROCINJ_MINALLOC","注入最小分配"),
    52: ("SETTING_PROCINJ_TRANSFORM_X86", "注入变换 x86"),
    53: ("SETTING_PROCINJ_TRANSFORM_X64", "注入变换 x64"),
    54: ("SETTING_PROCINJ_ALLOWED", "允许的注入方法"),
    55: ("SETTING_BINDHOST",        "绑定主机"),
    56: ("SETTING_HTTP_HEADER_ORDER","HTTP Header 顺序"),
    57: ("SETTING_DATA_STORE",      "数据存储大小"),
    58: ("SETTING_BEACON_GATE",     "BeaconGate 配置 (4.10+)"),
    59: ("SETTING_TCP_FRAME_HEADER","TCP 帧头"),
    60: ("SETTING_SMB_FRAME_HEADER","SMB 帧头"),
    70: ("SETTING_HOST_HEADER",     "Host header (alt)"),
}

PROTOCOL_NAMES = {
    0: "HTTP", 1: "HTTPS", 2: "TCP Bind", 4: "TCP Reverse",
    8: "DNS", 16: "SMB", 32: "ExtC2",
}


# ─── XOR 解码 ───────────────────────────────────────────────
def xor_decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ─── 搜索配置块 ─────────────────────────────────────────────
def find_config_blocks(data: bytes) -> list:
    """在二进制数据中搜索所有可能的配置块"""
    results = []

    # 方法 1: 搜索明文标记 (模板/未混淆)
    offset = 0
    while True:
        pos = data.find(CONFIG_MARKER, offset)
        if pos == -1:
            break
        results.append(("marker_plain", pos, 0x00))
        offset = pos + 1

    # 方法 2: 搜索 XOR 0x2E 编码的标记
    xor_marker = xor_decode(CONFIG_MARKER, XOR_KEY_DEFAULT)
    offset = 0
    while True:
        pos = data.find(xor_marker, offset)
        if pos == -1:
            break
        results.append(("marker_xor2e", pos, XOR_KEY_DEFAULT))
        offset = pos + 1

    # 方法 3: 搜索 XOR 0x69 编码的标记
    xor_marker_alt = xor_decode(CONFIG_MARKER, XOR_KEY_ALT)
    offset = 0
    while True:
        pos = data.find(xor_marker_alt, offset)
        if pos == -1:
            break
        results.append(("marker_xor69", pos, XOR_KEY_ALT))
        offset = pos + 1

    # 方法 4: XOR 暴力扫描 (尝试所有单字节 key)
    # 仅在未找到标记时使用
    if not results:
        for key in range(1, 256):
            xm = xor_decode(CONFIG_MARKER, key)
            pos = data.find(xm)
            if pos != -1:
                results.append((f"marker_xor{key:02x}", pos, key))

    # 方法 5: 直接 TLV 模式匹配 (无标记, 如内存 dump)
    if not results:
        # 搜索 PROTOCOL(1) SHORT(1) LEN(2) 开头
        for key in [0x00, XOR_KEY_DEFAULT, XOR_KEY_ALT]:
            pattern = xor_decode(b'\x00\x01\x00\x01\x00\x02', key)
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                # 验证后续 TLV
                test_data = xor_decode(data[pos:pos+256], key) if key else data[pos:pos+256]
                if validate_tlv(test_data):
                    results.append((f"tlv_direct_{key:02x}", pos, key))
                offset = pos + 1

    return results


def validate_tlv(data: bytes) -> bool:
    """验证一段数据是否是有效的 TLV 序列"""
    offset = 0
    count = 0
    while offset + 6 <= len(data) and count < 20:
        sid = struct.unpack(">H", data[offset:offset+2])[0]
        stype = struct.unpack(">H", data[offset+2:offset+4])[0]
        slen = struct.unpack(">H", data[offset+4:offset+6])[0]

        if sid == 0:
            return count >= 3
        if sid > MAX_SETTINGS or stype not in (TYPE_SHORT, TYPE_INT, TYPE_PTR):
            return False
        if stype == TYPE_SHORT and slen != 2:
            return False
        if stype == TYPE_INT and slen != 4:
            return False
        if slen > 8192:
            return False

        offset += 6 + slen
        count += 1
    return count >= 3


# ─── TLV 解析 ───────────────────────────────────────────────
def parse_config(data: bytes, offset: int, xor_key: int, method: str) -> dict:
    """解析配置块, 返回结构化结果"""

    # 确定块大小: 标记方法使用完整块, TLV 直接方法估算
    if "marker" in method:
        # 标记后直接就是配置数据 (标记本身会被替换)
        config_start = offset
    else:
        config_start = offset

    # 尝试两种块大小
    for patch_size in [PATCH_SIZE_491, PATCH_SIZE_461]:
        if config_start + patch_size > len(data):
            continue

        block = data[config_start:config_start + patch_size]
        if xor_key:
            block = xor_decode(block, xor_key)

        settings = []
        pos = 0
        while pos + 6 <= len(block):
            sid = struct.unpack(">H", block[pos:pos+2])[0]
            stype = struct.unpack(">H", block[pos+2:pos+4])[0]
            slen = struct.unpack(">H", block[pos+4:pos+6])[0]

            if sid == 0:
                break
            if sid > MAX_SETTINGS or stype not in (TYPE_SHORT, TYPE_INT, TYPE_PTR):
                break
            if pos + 6 + slen > len(block):
                break

            raw_value = block[pos+6:pos+6+slen]

            # 解析值
            if stype == TYPE_SHORT:
                value = struct.unpack(">H", raw_value)[0]
            elif stype == TYPE_INT:
                value = struct.unpack(">I", raw_value)[0]
            elif stype == TYPE_PTR:
                value = raw_value
            else:
                value = raw_value

            name, desc = SETTINGS.get(sid, (f"UNKNOWN_{sid}", "未知"))

            settings.append({
                "id": sid,
                "name": name,
                "description": desc,
                "type": stype,
                "type_name": ["NONE", "SHORT", "INT", "PTR"][stype],
                "length": slen,
                "value": value,
                "raw": raw_value,
            })

            pos += 6 + slen

        if len(settings) >= 3:
            return {
                "method": method,
                "offset": offset,
                "xor_key": xor_key,
                "patch_size": patch_size,
                "version": "4.9.1+" if patch_size == 6144 else "4.6.x",
                "settings_count": len(settings),
                "settings": settings,
            }

    return None


# ─── 输出格式化 ─────────────────────────────────────────────
def format_value(setting: dict) -> str:
    """格式化 Setting 值为可读字符串"""
    sid = setting["id"]
    value = setting["value"]

    if isinstance(value, bytes):
        # 尝试解码为字符串
        try:
            text = value.rstrip(b'\x00').decode('utf-8', errors='strict')
            if text and all(32 <= ord(c) < 127 for c in text):
                return f'"{text}"'
        except (UnicodeDecodeError, ValueError):
            pass

        if len(value) <= 32:
            return value.hex()
        return f"[{len(value)}B] {value[:24].hex()}..."

    # 特殊格式化
    if sid == 1:
        proto = PROTOCOL_NAMES.get(value, f"Unknown({value})")
        return f"{value} ({proto})"
    elif sid == 3:
        return f"{value} ms ({value/1000:.0f}s)"
    elif sid == 5:
        return f"{value}%"
    elif sid == 26:
        return f"{value} (0x{value:08X})"
    elif sid in (44, 45, 46):
        return str(value)
    elif sid == 49 or sid == 50:
        perms = {4: "PAGE_READWRITE", 32: "PAGE_EXECUTE_READ", 64: "PAGE_EXECUTE_READWRITE"}
        return f"{value} ({perms.get(value, hex(value))})"

    return str(value)


def print_config(config: dict, verbose: bool = False):
    """打印配置到终端"""
    print(f"\n{'='*70}")
    print(f"Cobalt Strike Beacon 配置")
    print(f"{'='*70}")
    print(f"  检测方法:  {config['method']}")
    print(f"  偏移:      0x{config['offset']:X}")
    print(f"  XOR Key:   0x{config['xor_key']:02X}" if config['xor_key'] else "  XOR Key:   无 (明文)")
    print(f"  块大小:    {config['patch_size']} bytes")
    print(f"  推测版本:  {config['version']}")
    print(f"  配置项数:  {config['settings_count']}")
    print(f"{'='*70}\n")

    # 按功能分组显示
    groups = {
        "C2 通信": [1, 2, 3, 4, 5, 8, 9, 10, 37, 38, 70],
        "加密/密钥": [7, 19, 26],
        "注入配置": [14, 15, 43, 49, 50, 51, 52, 53, 54],
        "Kill Date": [44, 45, 46],
        "DNS": [30, 31],
        "SMB/TCP": [29, 59, 60],
        "SSH": [32, 33, 34, 35, 36],
        "代理": [39, 40, 41, 42],
        "高级": [11, 12, 13, 27, 28, 47, 48, 55, 56, 57, 58],
    }

    # 建立 ID→setting 映射
    by_id = {s["id"]: s for s in config["settings"]}
    shown = set()

    for group_name, ids in groups.items():
        group_settings = [by_id[sid] for sid in ids if sid in by_id]
        if not group_settings:
            continue

        print(f"  ── {group_name} ──")
        for s in group_settings:
            display = format_value(s)
            print(f"  [{s['id']:3d}] {s['name']:<35s} = {display}")
            shown.add(s["id"])
        print()

    # 显示未分组的
    ungrouped = [s for s in config["settings"] if s["id"] not in shown]
    if ungrouped:
        print(f"  ── 其他 ──")
        for s in ungrouped:
            display = format_value(s)
            print(f"  [{s['id']:3d}] {s['name']:<35s} = {display}")
        print()

    # 提取关键 IOC
    print(f"{'='*70}")
    print("关键 IOC 提取:")
    print(f"{'='*70}")

    if 1 in by_id:
        print(f"  协议:      {PROTOCOL_NAMES.get(by_id[1]['value'], 'Unknown')}")
    if 2 in by_id:
        print(f"  端口:      {by_id[2]['value']}")
    if 8 in by_id:
        domains = format_value(by_id[8])
        print(f"  C2 域名:   {domains}")
    if 9 in by_id:
        print(f"  UA:        {format_value(by_id[9])}")
    if 10 in by_id:
        print(f"  POST URI:  {format_value(by_id[10])}")
    if 26 in by_id:
        print(f"  水印 ID:   {by_id[26]['value']}")
    if 7 in by_id and isinstance(by_id[7]["value"], bytes):
        pubkey_hash = hashlib.sha256(by_id[7]["value"]).hexdigest()[:16]
        print(f"  公钥 SHA:  {pubkey_hash}...")
    if 14 in by_id:
        print(f"  SpawnTo86: {format_value(by_id[14])}")
    if 15 in by_id:
        print(f"  SpawnTo64: {format_value(by_id[15])}")
    if 29 in by_id:
        print(f"  Pipe:      {format_value(by_id[29])}")

    print()


def export_json(config: dict) -> dict:
    """导出为 JSON 兼容格式"""
    result = {
        "method": config["method"],
        "offset": config["offset"],
        "xor_key": config["xor_key"],
        "patch_size": config["patch_size"],
        "version": config["version"],
        "settings": {},
    }
    for s in config["settings"]:
        key = s["name"]
        if isinstance(s["value"], bytes):
            try:
                text = s["value"].rstrip(b'\x00').decode('utf-8', errors='strict')
                if all(32 <= ord(c) < 127 for c in text):
                    result["settings"][key] = text
                else:
                    result["settings"][key] = s["value"].hex()
            except (UnicodeDecodeError, ValueError):
                result["settings"][key] = s["value"].hex()
        else:
            result["settings"][key] = s["value"]
    return result


# ─── 标记扫描 ───────────────────────────────────────────────
KNOWN_MARKERS = {
    b"TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ": ("String Table", 4096),
    b"AAAABBBBCCCCDDDDEEEEFFFF": ("Settings Config", "4096/6144"),
    b"GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd": ("Guardrails", 2048),
    b"ZZZZZZZXXXXWYYYY": ("PostEx Loader", 16),
    b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR": ("Screenshot Config", 72),
}


def scan_all_markers(data: bytes):
    """扫描所有已知 CS 标记"""
    print(f"\n{'='*70}")
    print("CS 标记扫描")
    print(f"{'='*70}")

    found = False
    for marker, (name, size) in KNOWN_MARKERS.items():
        pos = data.find(marker)
        if pos != -1:
            print(f"  [+] {name:<20s} @ 0x{pos:08X}  (块大小: {size})")
            found = True

        # 也搜索 XOR 编码版本
        for key in [XOR_KEY_DEFAULT, XOR_KEY_ALT]:
            xm = xor_decode(marker, key)
            pos = data.find(xm)
            if pos != -1:
                print(f"  [+] {name:<20s} @ 0x{pos:08X}  (XOR 0x{key:02X}, 块大小: {size})")
                found = True

    if not found:
        print("  [-] 未找到任何已知标记")
    print()


# ─── 主程序 ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Cobalt Strike Beacon 配置解析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s beacon.dll                    # 解析 Beacon DLL
  %(prog)s beacon.bin --format json      # JSON 输出
  %(prog)s memory.dmp --xor-scan         # 扫描内存 dump
  %(prog)s beacon.dll --scan-markers     # 扫描所有 CS 标记
  %(prog)s beacon.dll -o report.json     # 保存报告
        """)

    parser.add_argument("file", help="Beacon 样本路径")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="输出格式")
    parser.add_argument("--xor-scan", action="store_true", help="暴力扫描所有 XOR key")
    parser.add_argument("--scan-markers", action="store_true", help="扫描所有 CS 标记")
    parser.add_argument("-o", "--output", help="保存报告到文件")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    args = parser.parse_args()

    data = open(args.file, "rb").read()
    print(f"[*] 文件: {args.file}")
    print(f"[*] 大小: {len(data):,} bytes")
    print(f"[*] MD5:  {hashlib.md5(data).hexdigest()}")

    # PE 检测
    if data[:2] == b'MZ':
        print("[*] 格式: PE (MZ header)")
    elif data[:4] == b'\x7fELF':
        print("[*] 格式: ELF")
    else:
        print(f"[*] 格式: Raw ({data[:4].hex()})")

    if args.scan_markers:
        scan_all_markers(data)

    # 搜索配置块
    blocks = find_config_blocks(data)

    if not blocks:
        print("\n[-] 未找到配置块")
        print("[*] 提示:")
        print("    - 模板文件不含配置 (Settings 在生成时注入)")
        print("    - 尝试 --xor-scan 暴力搜索")
        print("    - 尝试 --scan-markers 查看已知标记")
        return

    configs = []
    for method, offset, xor_key in blocks:
        config = parse_config(data, offset, xor_key, method)
        if config:
            configs.append(config)

    if not configs:
        print("\n[-] 找到标记但无法解析配置")
        print(f"[*] 找到 {len(blocks)} 个候选位置:")
        for method, offset, xor_key in blocks:
            print(f"    {method} @ 0x{offset:X} (XOR: 0x{xor_key:02X})")
        return

    # 输出
    if args.format == "json":
        result = [export_json(c) for c in configs]
        output = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(output)
            print(f"\n[+] JSON 报告已保存到: {args.output}")
        else:
            print(output)
    else:
        for config in configs:
            print_config(config, args.verbose)

    print(f"[+] 共解析 {len(configs)} 个配置块")


if __name__ == "__main__":
    main()
