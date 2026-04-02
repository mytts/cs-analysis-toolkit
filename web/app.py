#!/usr/bin/env python3
"""
Cobalt Strike Beacon Config 在线解析平台
=========================================
Flask Web 应用 — 上传 Beacon 样本 → 解析配置 → 可视化 IOC

启动:
    python3 app.py
    # 浏览器打开 http://127.0.0.1:5000
"""

import hashlib
import json
import os
import struct
import sys
import tempfile
import time
from pathlib import Path

from flask import Flask, render_template_string, request, jsonify

# ─── 常量 ───────────────────────────────────────────────────
CONFIG_MARKER = b"AAAABBBBCCCCDDDDEEEEFFFF"
XOR_KEY_DEFAULT = 0x2E
XOR_KEY_ALT = 0x69
PATCH_SIZE_461 = 4096
PATCH_SIZE_491 = 6144
MAX_SETTINGS = 128
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB

TYPE_NONE = 0
TYPE_SHORT = 1
TYPE_INT = 2
TYPE_PTR = 3

SETTINGS = {
    1:  ("SETTING_PROTOCOL",        "C2 协议类型", "c2"),
    2:  ("SETTING_PORT",            "C2 端口", "c2"),
    3:  ("SETTING_SLEEPTIME",       "Sleep 间隔 (ms)", "c2"),
    4:  ("SETTING_MAXGET",          "最大 GET 大小", "c2"),
    5:  ("SETTING_JITTER",          "Jitter 百分比", "c2"),
    7:  ("SETTING_PUBKEY",          "RSA 公钥 (256B)", "crypto"),
    8:  ("SETTING_DOMAINS",         "C2 域名列表", "c2"),
    9:  ("SETTING_USERAGENT",       "User-Agent", "c2"),
    10: ("SETTING_SUBMITURI",       "POST 提交 URI", "c2"),
    11: ("SETTING_C2_RECOVER",      "C2 恢复策略", "advanced"),
    12: ("SETTING_C2_REQUEST",      "C2 GET 请求变换", "advanced"),
    13: ("SETTING_C2_POSTREQ",      "C2 POST 请求变换", "advanced"),
    14: ("SETTING_SPAWNTO_X86",     "x86 注入目标进程", "inject"),
    15: ("SETTING_SPAWNTO_X64",     "x64 注入目标进程", "inject"),
    19: ("SETTING_CRYPTO_SCHEME",   "加密方案", "crypto"),
    26: ("SETTING_WATERMARK",       "许可证水印 ID", "meta"),
    27: ("SETTING_CLEANUP",         "自清理标志", "advanced"),
    28: ("SETTING_CFG_CAUTION",     "谨慎模式", "advanced"),
    29: ("SETTING_PIPENAME",        "SMB 管道名", "smb"),
    30: ("SETTING_DNS_IDLE",        "DNS 空闲 IP", "dns"),
    31: ("SETTING_DNS_SLEEP",       "DNS Sleep (ms)", "dns"),
    32: ("SETTING_SSH_HOST",        "SSH 主机", "ssh"),
    33: ("SETTING_SSH_PORT",        "SSH 端口", "ssh"),
    34: ("SETTING_SSH_USERNAME",    "SSH 用户名", "ssh"),
    35: ("SETTING_SSH_PASSWORD",    "SSH 密码", "ssh"),
    36: ("SETTING_SSH_KEY",         "SSH 私钥", "ssh"),
    37: ("SETTING_C2_HOST_HEADER",  "Host header", "c2"),
    38: ("SETTING_HTTP_NO_COOKIES", "禁用 Cookie", "c2"),
    39: ("SETTING_PROXY_CONFIG",    "代理配置", "proxy"),
    40: ("SETTING_PROXY_USER",      "代理用户名", "proxy"),
    41: ("SETTING_PROXY_PASSWORD",  "代理密码", "proxy"),
    42: ("SETTING_PROXY_BEHAVIOR",  "代理行为", "proxy"),
    43: ("SETTING_INJECT_OPTIONS",  "注入选项", "inject"),
    44: ("SETTING_KILLDATE_YEAR",   "Kill Date 年", "meta"),
    45: ("SETTING_KILLDATE_MONTH",  "Kill Date 月", "meta"),
    46: ("SETTING_KILLDATE_DAY",    "Kill Date 日", "meta"),
    47: ("SETTING_GARGLE_NOOK",     "Gargle 参数", "advanced"),
    48: ("SETTING_GARGLE_SECTIONS", "Gargle 节数", "advanced"),
    49: ("SETTING_PROCINJ_PERMS_I", "注入初始权限", "inject"),
    50: ("SETTING_PROCINJ_PERMS",   "注入最终权限", "inject"),
    51: ("SETTING_PROCINJ_MINALLOC","注入最小分配", "inject"),
    52: ("SETTING_PROCINJ_TRANSFORM_X86", "注入变换 x86", "inject"),
    53: ("SETTING_PROCINJ_TRANSFORM_X64", "注入变换 x64", "inject"),
    54: ("SETTING_PROCINJ_ALLOWED", "允许的注入方法", "inject"),
    55: ("SETTING_BINDHOST",        "绑定主机", "advanced"),
    56: ("SETTING_HTTP_HEADER_ORDER","HTTP Header 顺序", "c2"),
    57: ("SETTING_DATA_STORE",      "数据存储大小", "advanced"),
    58: ("SETTING_BEACON_GATE",     "BeaconGate 配置 (4.10+)", "advanced"),
    59: ("SETTING_TCP_FRAME_HEADER","TCP 帧头", "smb"),
    60: ("SETTING_SMB_FRAME_HEADER","SMB 帧头", "smb"),
    70: ("SETTING_HOST_HEADER",     "Host header (alt)", "c2"),
}

PROTOCOL_NAMES = {
    0: "HTTP", 1: "HTTPS", 2: "TCP Bind", 4: "TCP Reverse",
    8: "DNS", 16: "SMB", 32: "ExtC2",
}

KNOWN_MARKERS = {
    "AAAABBBBCCCCDDDDEEEEFFFF": ("Settings Config", "4096/6144"),
    "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ": ("String Table", "4096"),
    "GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd": ("Guardrails", "2048"),
    "ZZZZZZZXXXXWYYYY": ("PostEx Loader", "—"),
}


# ─── 解析引擎 ──────────────────────────────────────────────
def xor_decode(data, key):
    return bytes(b ^ key for b in data)


def validate_tlv(data):
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


def find_config_blocks(data):
    results = []
    # Method 1-3: Marker search
    for label, key in [("marker_plain", 0x00), ("marker_xor2e", XOR_KEY_DEFAULT), ("marker_xor69", XOR_KEY_ALT)]:
        marker = xor_decode(CONFIG_MARKER, key) if key else CONFIG_MARKER
        offset = 0
        while True:
            pos = data.find(marker, offset)
            if pos == -1:
                break
            results.append((label, pos, key))
            offset = pos + 1

    # Method 4: Brute force XOR
    if not results:
        for key in range(1, 256):
            if key in (XOR_KEY_DEFAULT, XOR_KEY_ALT):
                continue
            xm = xor_decode(CONFIG_MARKER, key)
            pos = data.find(xm)
            if pos != -1:
                results.append((f"marker_xor{key:02x}", pos, key))

    # Method 5: Direct TLV pattern
    if not results:
        for key in [0x00, XOR_KEY_DEFAULT, XOR_KEY_ALT]:
            pattern = xor_decode(b'\x00\x01\x00\x01\x00\x02', key)
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                test_data = xor_decode(data[pos:pos+256], key) if key else data[pos:pos+256]
                if validate_tlv(test_data):
                    results.append((f"tlv_direct_{key:02x}", pos, key))
                offset = pos + 1
    return results


def parse_config(data, offset, xor_key, method):
    for patch_size in [PATCH_SIZE_491, PATCH_SIZE_461]:
        if offset + patch_size > len(data):
            continue
        block = data[offset:offset + patch_size]
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

            if stype == TYPE_SHORT:
                value = struct.unpack(">H", raw_value)[0]
            elif stype == TYPE_INT:
                value = struct.unpack(">I", raw_value)[0]
            else:
                value = raw_value

            meta = SETTINGS.get(sid, (f"UNKNOWN_{sid}", "未知", "other"))
            name, desc, group = meta[0], meta[1], meta[2] if len(meta) > 2 else "other"
            settings.append({
                "id": sid, "name": name, "description": desc, "group": group,
                "type": stype, "type_name": ["NONE", "SHORT", "INT", "PTR"][stype],
                "length": slen, "value": value, "raw": raw_value,
            })
            pos += 6 + slen

        if len(settings) >= 3:
            return {
                "method": method, "offset": offset, "xor_key": xor_key,
                "patch_size": patch_size,
                "version": "4.9.1+" if patch_size == 6144 else "4.6.x",
                "settings_count": len(settings), "settings": settings,
            }
    return None


def format_value(s):
    sid, value = s["id"], s["value"]
    if isinstance(value, bytes):
        try:
            text = value.rstrip(b'\x00').decode('utf-8', errors='strict')
            if text and all(32 <= ord(c) < 127 for c in text):
                return text
        except:
            pass
        if len(value) <= 32:
            return value.hex()
        return f"[{len(value)}B] {value[:24].hex()}..."
    if sid == 1:
        return f"{PROTOCOL_NAMES.get(value, f'Unknown({value})')}"
    if sid == 3:
        return f"{value} ms ({value/1000:.0f}s)"
    if sid == 5:
        return f"{value}%"
    if sid == 26:
        return f"{value} (0x{value:08X})"
    if sid in (49, 50):
        perms = {4: "PAGE_READWRITE", 32: "PAGE_EXECUTE_READ", 64: "PAGE_EXECUTE_READWRITE"}
        return f"{perms.get(value, hex(value))}"
    return str(value)


def scan_markers(data):
    found = []
    for marker_str, (name, size) in KNOWN_MARKERS.items():
        marker = marker_str.encode()
        for key_name, key in [("plain", 0x00), ("XOR 0x2E", XOR_KEY_DEFAULT), ("XOR 0x69", XOR_KEY_ALT)]:
            m = xor_decode(marker, key) if key else marker
            pos = data.find(m)
            if pos != -1:
                found.append({"name": name, "offset": f"0x{pos:08X}", "encoding": key_name, "block_size": size})
    return found


def extract_iocs(config):
    """Extract key IOCs from parsed config"""
    iocs = []
    by_id = {s["id"]: s for s in config["settings"]}

    if 1 in by_id:
        proto = PROTOCOL_NAMES.get(by_id[1]["value"], "Unknown")
        iocs.append({"type": "Protocol", "value": proto, "severity": "info", "icon": "globe"})
    if 2 in by_id:
        iocs.append({"type": "Port", "value": str(by_id[2]["value"]), "severity": "info", "icon": "hash"})
    if 8 in by_id:
        domains = format_value(by_id[8])
        for d in domains.split(","):
            d = d.strip()
            if d:
                iocs.append({"type": "C2 Domain", "value": d, "severity": "critical", "icon": "server"})
    if 9 in by_id:
        iocs.append({"type": "User-Agent", "value": format_value(by_id[9]), "severity": "high", "icon": "monitor"})
    if 10 in by_id:
        iocs.append({"type": "POST URI", "value": format_value(by_id[10]), "severity": "high", "icon": "upload"})
    if 26 in by_id:
        iocs.append({"type": "Watermark", "value": str(by_id[26]["value"]), "severity": "high", "icon": "fingerprint"})
    if 7 in by_id and isinstance(by_id[7]["value"], bytes):
        h = hashlib.sha256(by_id[7]["value"]).hexdigest()[:32]
        iocs.append({"type": "PubKey SHA256", "value": h, "severity": "high", "icon": "key"})
    if 14 in by_id:
        iocs.append({"type": "SpawnTo x86", "value": format_value(by_id[14]), "severity": "medium", "icon": "cpu"})
    if 15 in by_id:
        iocs.append({"type": "SpawnTo x64", "value": format_value(by_id[15]), "severity": "medium", "icon": "cpu"})
    if 29 in by_id:
        iocs.append({"type": "Named Pipe", "value": format_value(by_id[29]), "severity": "high", "icon": "git-branch"})
    if 3 in by_id:
        iocs.append({"type": "Sleep", "value": format_value(by_id[3]), "severity": "info", "icon": "clock"})
    if 5 in by_id:
        iocs.append({"type": "Jitter", "value": format_value(by_id[5]), "severity": "info", "icon": "activity"})

    # Kill date
    y = by_id.get(44, {}).get("value", 0)
    m = by_id.get(45, {}).get("value", 0)
    d = by_id.get(46, {}).get("value", 0)
    if y:
        iocs.append({"type": "Kill Date", "value": f"{y}-{m:02d}-{d:02d}", "severity": "medium", "icon": "calendar"})

    return iocs


def analyze_file(data, filename):
    """Full analysis pipeline → JSON result"""
    result = {
        "filename": filename,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "Unknown",
        "markers": [],
        "configs": [],
        "iocs": [],
        "errors": [],
    }

    # Detect format
    if data[:2] == b'MZ':
        result["format"] = "PE (MZ)"
        # Try to get PE info
        try:
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            if data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                machine = struct.unpack("<H", data[e_lfanew+4:e_lfanew+6])[0]
                result["arch"] = "x64" if machine == 0x8664 else "x86" if machine == 0x14c else f"0x{machine:X}"
                chars = struct.unpack("<H", data[e_lfanew+22:e_lfanew+24])[0]
                result["pe_type"] = "DLL" if chars & 0x2000 else "EXE"
                result["format"] = f"PE ({result['pe_type']}, {result['arch']})"
        except:
            pass
    elif data[:4] == b'\x7fELF':
        result["format"] = "ELF"
    elif data[:2] == b'\xfc\xe8' or data[:3] == b'\xe8\x00\x00':
        result["format"] = "Shellcode (x86)"
    elif data[:2] == b'\xfc\x48':
        result["format"] = "Shellcode (x64)"
    else:
        result["format"] = f"Raw/Memory Dump"

    # Scan markers
    result["markers"] = scan_markers(data)

    # Find and parse configs
    blocks = find_config_blocks(data)
    for method, offset, xor_key in blocks:
        config = parse_config(data, offset, xor_key, method)
        if config:
            # Serialize for JSON
            serialized_settings = []
            for s in config["settings"]:
                entry = {
                    "id": s["id"],
                    "name": s["name"],
                    "description": s["description"],
                    "group": s["group"],
                    "type_name": s["type_name"],
                    "length": s["length"],
                    "display_value": format_value(s),
                }
                if isinstance(s["value"], bytes):
                    entry["raw_hex"] = s["value"].hex() if len(s["value"]) <= 512 else s["value"][:64].hex() + "..."
                else:
                    entry["raw_value"] = s["value"]
                serialized_settings.append(entry)

            config_out = {
                "method": config["method"],
                "offset": f"0x{config['offset']:X}",
                "xor_key": f"0x{config['xor_key']:02X}" if config["xor_key"] else "None",
                "patch_size": config["patch_size"],
                "version": config["version"],
                "settings_count": config["settings_count"],
                "settings": serialized_settings,
            }
            result["configs"].append(config_out)

            # Extract IOCs from first valid config
            if not result["iocs"]:
                result["iocs"] = extract_iocs(config)

    if not blocks:
        result["errors"].append("未找到配置标记 — 可能是未注入配置的模板文件")
    elif not result["configs"]:
        result["errors"].append(f"找到 {len(blocks)} 个标记位置但无法解析 TLV 配置")

    return result


# ─── Flask App ──────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CS Beacon Config Analyzer</title>
<style>
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128; --border: #30363d;
  --text: #c9d1d9; --text2: #8b949e; --text3: #484f58;
  --blue: #58a6ff; --green: #3fb950; --red: #f85149;
  --orange: #d29922; --purple: #bc8cff; --pink: #f778ba;
  --radius: 8px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', 'Segoe UI', sans-serif;
       background: var(--bg); color: var(--text); min-height: 100vh; }

/* Header */
header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 16px 24px;
         display: flex; align-items: center; gap: 16px; }
header h1 { font-size: 18px; font-weight: 600; }
header h1 span { color: var(--red); }
header .badge { font-size: 11px; padding: 2px 8px; border-radius: 10px;
                background: var(--blue)22; color: var(--blue); border: 1px solid var(--blue)44; }

/* Main layout */
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }

/* Upload zone */
.upload-zone {
  border: 2px dashed var(--border); border-radius: 12px;
  padding: 48px 24px; text-align: center; cursor: pointer;
  transition: all 0.3s; background: var(--bg2);
  margin-bottom: 24px;
}
.upload-zone:hover, .upload-zone.dragover {
  border-color: var(--blue); background: var(--blue)08;
}
.upload-zone .icon { font-size: 48px; margin-bottom: 12px; opacity: 0.5; }
.upload-zone .hint { color: var(--text2); font-size: 14px; margin-top: 8px; }
.upload-zone .formats { color: var(--text3); font-size: 12px; margin-top: 4px; }
.upload-zone input[type=file] { display: none; }

/* Processing */
.processing { text-align: center; padding: 40px; display: none; }
.spinner { width: 40px; height: 40px; border: 3px solid var(--border); border-top-color: var(--blue);
           border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Results */
#results { display: none; }

/* File info card */
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
        margin-bottom: 16px; overflow: hidden; }
.card-header { padding: 12px 16px; border-bottom: 1px solid var(--border);
               display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 14px; }
.card-header .count { font-size: 11px; padding: 1px 6px; border-radius: 8px;
                      background: var(--text3)33; color: var(--text2); }
.card-body { padding: 16px; }

/* File meta */
.file-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
.meta-item { background: var(--bg3); border-radius: 6px; padding: 10px 14px; }
.meta-item .label { font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }
.meta-item .value { font-size: 14px; margin-top: 2px; font-family: 'SF Mono', monospace; word-break: break-all; }

/* IOC cards */
.ioc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
.ioc-card { background: var(--bg3); border-radius: 6px; padding: 12px; border-left: 3px solid;
            display: flex; align-items: flex-start; gap: 10px; }
.ioc-card.critical { border-left-color: var(--red); }
.ioc-card.high { border-left-color: var(--orange); }
.ioc-card.medium { border-left-color: var(--purple); }
.ioc-card.info { border-left-color: var(--text3); }
.ioc-icon { font-size: 18px; opacity: 0.6; flex-shrink: 0; }
.ioc-content { flex: 1; min-width: 0; }
.ioc-type { font-size: 11px; color: var(--text3); text-transform: uppercase; }
.ioc-value { font-size: 13px; font-family: 'SF Mono', monospace; word-break: break-all; margin-top: 2px; }
.ioc-card.critical .ioc-value { color: var(--red); }
.ioc-card.high .ioc-value { color: var(--orange); }

/* Settings table */
.settings-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.settings-table th { text-align: left; padding: 8px 12px; border-bottom: 2px solid var(--border);
                     color: var(--text2); font-size: 11px; text-transform: uppercase; }
.settings-table td { padding: 8px 12px; border-bottom: 1px solid var(--border)88; vertical-align: top; }
.settings-table tr:hover { background: var(--bg3); }
.settings-table .sid { color: var(--text3); font-family: monospace; }
.settings-table .sname { color: var(--blue); }
.settings-table .sval { font-family: 'SF Mono', monospace; word-break: break-all; }
.settings-table .sdesc { color: var(--text3); font-size: 12px; }

/* Group badges */
.group-badge { font-size: 10px; padding: 1px 6px; border-radius: 8px; white-space: nowrap; }
.group-c2 { background: var(--blue)22; color: var(--blue); }
.group-crypto { background: var(--orange)22; color: var(--orange); }
.group-inject { background: var(--red)22; color: var(--red); }
.group-dns { background: var(--purple)22; color: var(--purple); }
.group-smb { background: var(--green)22; color: var(--green); }
.group-ssh { background: var(--pink)22; color: var(--pink); }
.group-proxy { background: #d2a8ff22; color: #d2a8ff; }
.group-meta { background: var(--text3)22; color: var(--text2); }
.group-advanced { background: var(--bg); color: var(--text3); }
.group-other { background: var(--bg); color: var(--text3); }

/* Markers table */
.markers-list { display: flex; flex-wrap: wrap; gap: 8px; }
.marker-tag { font-size: 12px; padding: 4px 10px; border-radius: 6px;
              background: var(--bg3); border: 1px solid var(--border); font-family: monospace; }
.marker-name { color: var(--green); }
.marker-offset { color: var(--text3); }

/* Filter bar */
.filter-bar { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
.filter-btn { font-size: 11px; padding: 4px 10px; border-radius: 12px; cursor: pointer;
              background: var(--bg3); border: 1px solid var(--border); color: var(--text2);
              transition: all 0.2s; }
.filter-btn:hover, .filter-btn.active { border-color: var(--blue); color: var(--blue); background: var(--blue)11; }

/* Config meta bar */
.config-meta { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px;
               padding: 10px 14px; background: var(--bg3); border-radius: 6px; font-size: 13px; }
.config-meta span { color: var(--text3); }
.config-meta strong { color: var(--text); }

/* Errors */
.error-box { background: var(--red)11; border: 1px solid var(--red)44; border-radius: 6px;
             padding: 12px 16px; color: var(--red); font-size: 13px; margin-bottom: 16px; }

/* JSON export */
.export-bar { display: flex; gap: 8px; margin-bottom: 16px; }
.btn { padding: 8px 16px; border-radius: 6px; border: 1px solid var(--border);
       background: var(--bg2); color: var(--text); cursor: pointer; font-size: 13px; transition: all 0.2s; }
.btn:hover { border-color: var(--blue); color: var(--blue); }
.btn-primary { background: var(--blue)22; border-color: var(--blue)44; color: var(--blue); }
.btn-primary:hover { background: var(--blue)33; }

/* Responsive */
@media (max-width: 768px) {
  .container { padding: 12px; }
  .file-meta { grid-template-columns: 1fr; }
  .ioc-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<header>
  <h1><span>&#9670;</span> CS Beacon Config Analyzer</h1>
  <span class="badge">v1.0 | CS 4.x</span>
</header>

<div class="container">
  <!-- Upload -->
  <div class="upload-zone" id="upload-zone">
    <div class="icon">&#128270;</div>
    <div style="font-size:16px; font-weight:600;">拖放 Beacon 样本到这里</div>
    <div class="hint">或者点击选择文件</div>
    <div class="formats">支持: DLL / EXE / Shellcode / 内存 Dump &nbsp;|&nbsp; 最大 50 MB</div>
    <input type="file" id="file-input" accept=".dll,.exe,.bin,.raw,.dmp,.dump,.o,.dat,.beacon">
  </div>

  <!-- Processing -->
  <div class="processing" id="processing">
    <div class="spinner"></div>
    <div>正在分析...</div>
  </div>

  <!-- Results -->
  <div id="results">
    <!-- Export bar -->
    <div class="export-bar">
      <button class="btn btn-primary" onclick="exportJSON()">&#128190; 导出 JSON</button>
      <button class="btn" onclick="copyIOCs()">&#128203; 复制 IOC</button>
      <button class="btn" onclick="resetUpload()">&#10226; 重新上传</button>
    </div>

    <!-- Errors -->
    <div id="error-container"></div>

    <!-- File info -->
    <div class="card" id="file-card">
      <div class="card-header">&#128196; 文件信息</div>
      <div class="card-body"><div class="file-meta" id="file-meta"></div></div>
    </div>

    <!-- Markers -->
    <div class="card" id="markers-card" style="display:none">
      <div class="card-header">&#127993; 标记扫描 <span class="count" id="markers-count"></span></div>
      <div class="card-body"><div class="markers-list" id="markers-list"></div></div>
    </div>

    <!-- IOCs -->
    <div class="card" id="iocs-card" style="display:none">
      <div class="card-header">&#128680; IOC 提取 <span class="count" id="iocs-count"></span></div>
      <div class="card-body"><div class="ioc-grid" id="iocs-grid"></div></div>
    </div>

    <!-- Config details -->
    <div id="configs-container"></div>
  </div>
</div>

<script>
const ICON_MAP = {
  globe: '&#127760;', hash: '#', server: '&#128430;', monitor: '&#128187;',
  upload: '&#8679;', fingerprint: '&#128273;', key: '&#128272;',
  cpu: '&#9881;', 'git-branch': '&#9547;', clock: '&#9200;',
  activity: '&#12336;', calendar: '&#128197;'
};

let currentResult = null;

// Upload zone
const zone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');

zone.addEventListener('click', () => fileInput.click());
zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
zone.addEventListener('drop', e => {
  e.preventDefault(); zone.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', e => { if (e.target.files.length) handleFile(e.target.files[0]); });

function handleFile(file) {
  if (file.size > 50 * 1024 * 1024) { alert('文件过大 (>50MB)'); return; }
  zone.style.display = 'none';
  document.getElementById('processing').style.display = 'block';
  document.getElementById('results').style.display = 'none';

  const formData = new FormData();
  formData.append('file', file);

  fetch('/analyze', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      currentResult = data;
      renderResults(data);
      document.getElementById('processing').style.display = 'none';
      document.getElementById('results').style.display = 'block';
    })
    .catch(err => {
      alert('分析失败: ' + err);
      resetUpload();
    });
}

function renderResults(data) {
  // Errors
  const errC = document.getElementById('error-container');
  errC.innerHTML = '';
  if (data.errors && data.errors.length) {
    data.errors.forEach(e => {
      errC.innerHTML += `<div class="error-box">&#9888; ${e}</div>`;
    });
  }

  // File meta
  const meta = document.getElementById('file-meta');
  meta.innerHTML = `
    <div class="meta-item"><div class="label">文件名</div><div class="value">${data.filename}</div></div>
    <div class="meta-item"><div class="label">格式</div><div class="value">${data.format}</div></div>
    <div class="meta-item"><div class="label">大小</div><div class="value">${(data.size).toLocaleString()} bytes</div></div>
    <div class="meta-item"><div class="label">MD5</div><div class="value">${data.md5}</div></div>
    <div class="meta-item"><div class="label">SHA-256</div><div class="value" style="font-size:11px">${data.sha256}</div></div>
    ${data.arch ? `<div class="meta-item"><div class="label">架构</div><div class="value">${data.arch}</div></div>` : ''}
  `;

  // Markers
  const markersCard = document.getElementById('markers-card');
  if (data.markers && data.markers.length) {
    markersCard.style.display = '';
    document.getElementById('markers-count').textContent = data.markers.length;
    const ml = document.getElementById('markers-list');
    ml.innerHTML = data.markers.map(m =>
      `<div class="marker-tag"><span class="marker-name">${m.name}</span> @ <span class="marker-offset">${m.offset}</span> (${m.encoding}, ${m.block_size}B)</div>`
    ).join('');
  } else {
    markersCard.style.display = 'none';
  }

  // IOCs
  const iocsCard = document.getElementById('iocs-card');
  if (data.iocs && data.iocs.length) {
    iocsCard.style.display = '';
    document.getElementById('iocs-count').textContent = data.iocs.length;
    const ig = document.getElementById('iocs-grid');
    ig.innerHTML = data.iocs.map(ioc => `
      <div class="ioc-card ${ioc.severity}">
        <div class="ioc-icon">${ICON_MAP[ioc.icon] || '&#8226;'}</div>
        <div class="ioc-content">
          <div class="ioc-type">${ioc.type}</div>
          <div class="ioc-value">${escapeHtml(ioc.value)}</div>
        </div>
      </div>
    `).join('');
  } else {
    iocsCard.style.display = 'none';
  }

  // Configs
  const cc = document.getElementById('configs-container');
  cc.innerHTML = '';
  if (data.configs) {
    data.configs.forEach((config, idx) => {
      const groups = {};
      config.settings.forEach(s => {
        const g = s.group || 'other';
        if (!groups[g]) groups[g] = [];
        groups[g].push(s);
      });

      const groupOrder = ['c2', 'crypto', 'inject', 'dns', 'smb', 'ssh', 'proxy', 'meta', 'advanced', 'other'];
      const groupLabels = {
        c2: 'C2 通信', crypto: '加密/密钥', inject: '注入配置', dns: 'DNS',
        smb: 'SMB/TCP', ssh: 'SSH', proxy: '代理', meta: '元数据', advanced: '高级', other: '其他'
      };

      let tableHTML = '';
      groupOrder.forEach(g => {
        if (!groups[g]) return;
        tableHTML += `<tr><td colspan="5" style="padding:12px 12px 4px;font-weight:600;color:var(--text2);font-size:12px;border:none;">${groupLabels[g] || g}</td></tr>`;
        groups[g].forEach(s => {
          tableHTML += `<tr>
            <td class="sid">${s.id}</td>
            <td><span class="group-badge group-${s.group}">${s.group}</span></td>
            <td class="sname">${s.name}</td>
            <td class="sval">${escapeHtml(s.display_value)}</td>
            <td class="sdesc">${s.description}</td>
          </tr>`;
        });
      });

      cc.innerHTML += `
        <div class="card">
          <div class="card-header">&#9881; 配置块 #${idx+1} <span class="count">${config.settings_count} 项</span></div>
          <div class="card-body">
            <div class="config-meta">
              <div><span>版本:</span> <strong>${config.version}</strong></div>
              <div><span>检测:</span> <strong>${config.method}</strong></div>
              <div><span>偏移:</span> <strong>${config.offset}</strong></div>
              <div><span>XOR:</span> <strong>${config.xor_key}</strong></div>
              <div><span>块大小:</span> <strong>${config.patch_size}B</strong></div>
            </div>
            <div class="filter-bar" id="filter-bar-${idx}">
              <button class="filter-btn active" onclick="filterGroup(${idx},'all',this)">全部</button>
              ${groupOrder.filter(g => groups[g]).map(g =>
                `<button class="filter-btn" onclick="filterGroup(${idx},'${g}',this)">${groupLabels[g]}</button>`
              ).join('')}
            </div>
            <table class="settings-table" id="settings-table-${idx}">
              <thead><tr><th>ID</th><th>分组</th><th>名称</th><th>值</th><th>说明</th></tr></thead>
              <tbody>${tableHTML}</tbody>
            </table>
          </div>
        </div>
      `;
    });
  }
}

function filterGroup(idx, group, btn) {
  const bar = document.getElementById(`filter-bar-${idx}`);
  bar.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const table = document.getElementById(`settings-table-${idx}`);
  table.querySelectorAll('tbody tr').forEach(tr => {
    if (group === 'all') { tr.style.display = ''; return; }
    const badge = tr.querySelector('.group-badge');
    if (badge) {
      tr.style.display = badge.textContent === group ? '' : 'none';
    } else {
      // Group header row - show if any child matches
      tr.style.display = '';
    }
  });
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function exportJSON() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (currentResult.filename || 'beacon') + '_config.json';
  a.click();
}

function copyIOCs() {
  if (!currentResult || !currentResult.iocs) return;
  const text = currentResult.iocs.map(i => `${i.type}: ${i.value}`).join('\n');
  navigator.clipboard.writeText(text).then(() => alert('IOC 已复制到剪贴板'));
}

function resetUpload() {
  document.getElementById('results').style.display = 'none';
  document.getElementById('processing').style.display = 'none';
  document.getElementById('upload-zone').style.display = '';
  document.getElementById('file-input').value = '';
  currentResult = null;
}
</script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    data = f.read()
    result = analyze_file(data, f.filename)
    return jsonify(result)


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════╗
    ║  CS Beacon Config Analyzer - Web Platform        ║
    ║  http://127.0.0.1:5000                           ║
    ║                                                  ║
    ║  上传 Beacon DLL/Shellcode/内存 dump             ║
    ║  自动解析 C2 配置 + 提取 IOC                     ║
    ╚══════════════════════════════════════════════════╝
    """)
    app.run(host='127.0.0.1', port=5000, debug=False)
