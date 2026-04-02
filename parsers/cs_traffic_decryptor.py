#!/usr/bin/env python3
"""
Cobalt Strike C2 Traffic Decryptor

Decrypts Cobalt Strike Beacon C2 traffic given:
  - A PCAP file + RSA private key (beacon_keys)
  - Raw captured HTTP request/response data + session key

Requires: pycryptodome (pip install pycryptodome)

Usage:
  Mode 1 - Raw session decryption:
    python3 cs_traffic_decryptor.py --session-key <hex> --data <hex_or_file> --direction [task|callback]

  Mode 2 - Metadata decryption (RSA):
    python3 cs_traffic_decryptor.py --private-key beacon_keys.pem --metadata <base64_or_hex>

  Mode 3 - PCAP parsing (full pipeline):
    python3 cs_traffic_decryptor.py --pcap traffic.pcap --private-key beacon_keys.pem

  Self-test:
    python3 cs_traffic_decryptor.py --self-test
"""

import argparse
import hashlib
import hmac as hmac_mod
import io
import os
import struct
import sys
import base64
import binascii
import json
from collections import OrderedDict

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES, PKCS1_v1_5
        from Cryptodome.PublicKey import RSA
        from Cryptodome.Signature import pkcs1_15
        from Cryptodome.Hash import SHA256
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CS_AES_IV = b"abcdefghijklmnop"  # 16-byte fixed IV used by Cobalt Strike

COMMAND_IDS = {
    1: "SLEEP",
    2: "SHELL",
    3: "DIE/EXIT",
    4: "CD",
    5: "UNKNOWN_5",
    9: "DOWNLOAD_START",
    10: "DOWNLOAD_DATA",
    11: "DOWNLOAD_WRITE",
    27: "GETUID",
    33: "LS",
    39: "PWD",
    40: "MKDIR",
    44: "UPLOAD_START",
    53: "TIMESTOMP",
    55: "RUN",
    56: "INJECT_X86",
    57: "INJECT_X64",
    59: "SPAWN_X86",
    60: "SPAWN_X64",
    68: "SHELL_POWERSHELL",
    69: "INLINE_EXECUTE_BOF",
    78: "UPLOAD_CONTINUE",
    100: "BOF_EXECUTE",
}

CALLBACK_TYPES = {
    0: "OUTPUT",
    1: "KEYSTROKES",
    2: "METADATA",
    3: "SCREENSHOT_DATA",
    13: "DEAD",
    15: "OUTPUT_JOBS",
    17: "OUTPUT_HASHES",
    22: "SOCKS_DIE",
    23: "OUTPUT_DOWNLOADS",
    25: "OUTPUT_CHECKIN",
    28: "PART_START",
    29: "PART_DATA",
    30: "SCREENSHOT",
    32: "OUTPUT_KEYSTROKES",
}

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_keys(session_key: bytes):
    """
    Derive AES key and HMAC key from a 16-byte session key.
    SHA-256(session_key) -> first 16 bytes = AES key, next 16 bytes = HMAC key.
    """
    digest = hashlib.sha256(session_key).digest()
    aes_key = digest[:16]
    hmac_key = digest[16:32]
    return aes_key, hmac_key


# ---------------------------------------------------------------------------
# AES-CBC encrypt / decrypt with HMAC
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """
    Encrypt data using CS AES-128-CBC + HMAC-SHA256 scheme.
    Pads with PKCS7, encrypts, appends 16-byte HMAC.
    """
    if not HAS_CRYPTO:
        raise RuntimeError("pycryptodome is required for AES operations")

    # PKCS7 pad to 16-byte boundary
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=CS_AES_IV)
    ciphertext = cipher.encrypt(padded)

    # HMAC-SHA256 truncated to 16 bytes
    mac = hmac_mod.new(hmac_key, ciphertext, hashlib.sha256).digest()[:16]
    return ciphertext + mac


def aes_decrypt(data: bytes, aes_key: bytes, hmac_key: bytes, verify_hmac: bool = True) -> bytes:
    """
    Decrypt data using CS AES-128-CBC + HMAC-SHA256 scheme.
    Last 16 bytes are HMAC, remainder is ciphertext.
    """
    if not HAS_CRYPTO:
        raise RuntimeError("pycryptodome is required for AES operations")

    if len(data) < 32:
        raise ValueError(f"Data too short for AES+HMAC: {len(data)} bytes (need >= 32)")

    ciphertext = data[:-16]
    received_mac = data[-16:]

    if verify_hmac:
        computed_mac = hmac_mod.new(hmac_key, ciphertext, hashlib.sha256).digest()[:16]
        if not hmac_mod.compare_digest(received_mac, computed_mac):
            raise ValueError("HMAC verification failed - wrong session key or corrupted data")

    if len(ciphertext) % 16 != 0:
        raise ValueError(f"Ciphertext length {len(ciphertext)} not a multiple of 16")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=CS_AES_IV)
    plaintext = cipher.decrypt(ciphertext)

    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        # Possibly not padded or corrupt; return as-is
        return plaintext
    # Verify padding bytes
    if plaintext[-pad_len:] != bytes([pad_len] * pad_len):
        return plaintext
    return plaintext[:-pad_len]


# ---------------------------------------------------------------------------
# Metadata parsing (RSA-decrypted blob)
# ---------------------------------------------------------------------------

def parse_metadata(raw: bytes) -> dict:
    """
    Parse the decrypted metadata blob from the beacon's first checkin.

    Expected layout (variable, reverse-engineered):
      [4B ???/magic] [16B session_key] [2B charset?] [2B charset?]
      [4B beacon_id] [4B pid] [2B port] [1B flags]
      [2B OS major] [2B OS minor] [4B build] [4B unk] [4B unk]
      [variable: internal_ip as 4 bytes or encoded]
      [null-terminated strings: computer\\tuser\\tprocess]

    Because real-world layouts vary by CS version, we do best-effort parsing.
    """
    result = OrderedDict()

    if len(raw) < 32:
        result["raw_hex"] = raw.hex()
        result["error"] = "Metadata too short for full parse"
        return result

    offset = 0

    # First 4 bytes: could be key size or magic
    magic = struct.unpack(">I", raw[offset:offset + 4])[0]
    result["raw_key_field"] = f"0x{magic:08x}"
    offset += 4

    # Next 16 bytes: session key
    session_key = raw[offset:offset + 16]
    result["session_key"] = session_key.hex()
    offset += 16

    # Charset / locale info (4 bytes)
    if offset + 4 <= len(raw):
        charset1 = struct.unpack(">H", raw[offset:offset + 2])[0]
        charset2 = struct.unpack(">H", raw[offset + 2:offset + 4])[0]
        result["ansi_cp"] = charset1
        result["oem_cp"] = charset2
        offset += 4

    # Beacon ID
    if offset + 4 <= len(raw):
        beacon_id = struct.unpack(">I", raw[offset:offset + 4])[0]
        result["beacon_id"] = f"0x{beacon_id:08x} ({beacon_id})"
        offset += 4

    # PID
    if offset + 4 <= len(raw):
        pid = struct.unpack(">I", raw[offset:offset + 4])[0]
        result["pid"] = pid
        offset += 4

    # Port
    if offset + 2 <= len(raw):
        port = struct.unpack(">H", raw[offset:offset + 2])[0]
        result["port"] = port
        offset += 2

    # Flags
    if offset + 1 <= len(raw):
        flags = raw[offset]
        result["flags"] = f"0x{flags:02x}"
        flag_desc = []
        if flags & 0x01:
            flag_desc.append("x64")
        if flags & 0x02:
            flag_desc.append("admin")
        if flags & 0x04:
            flag_desc.append("SYSTEM")
        if flag_desc:
            result["flags_desc"] = ", ".join(flag_desc)
        offset += 1

    # OS version info
    if offset + 4 <= len(raw):
        os_major = struct.unpack(">H", raw[offset:offset + 2])[0]
        os_minor = struct.unpack(">H", raw[offset + 2:offset + 4])[0]
        result["os_version"] = f"{os_major}.{os_minor}"
        offset += 4

    if offset + 4 <= len(raw):
        build = struct.unpack(">I", raw[offset:offset + 4])[0]
        result["os_build"] = build
        offset += 4

    # After os_build: [4B ptr/unk] [4B internal_ip] [info_string\x00]
    # The info string is "computer\tuser\tprocess" null-terminated.
    # Primary approach: use fixed layout (skip 4B, read 4B IP, then string).
    # Fallback: scan for the 2-tab string pattern.
    remaining = raw[offset:]
    str_data = None

    # --- Try fixed layout first (most common CS versions) ---
    if len(remaining) >= 8:
        ip_bytes_fixed = remaining[4:8]
        candidate_start = 8
        null_idx = remaining.find(b"\x00", candidate_start)
        if null_idx > candidate_start:
            try:
                decoded = remaining[candidate_start:null_idx].decode("utf-8", errors="strict")
                if decoded.count("\t") == 2:
                    parts = decoded.split("\t")
                    if all(len(p) > 0 for p in parts):
                        str_data = decoded
                        result["internal_ip"] = (
                            f"{ip_bytes_fixed[0]}.{ip_bytes_fixed[1]}."
                            f"{ip_bytes_fixed[2]}.{ip_bytes_fixed[3]}"
                        )
            except (UnicodeDecodeError, ValueError):
                pass

    # --- Fallback: scan for 2-tab null-terminated string ---
    if str_data is None:
        for i in range(len(remaining)):
            null_idx = remaining.find(b"\x00", i)
            if null_idx <= i:
                continue
            candidate = remaining[i:null_idx]
            if candidate.count(b"\t") == 2:
                try:
                    decoded = candidate.decode("utf-8", errors="strict")
                    parts = decoded.split("\t")
                    if all(len(p) > 0 for p in parts):
                        str_data = decoded
                        if i >= 4:
                            ib = remaining[i - 4:i]
                            result["internal_ip"] = (
                                f"{ib[0]}.{ib[1]}.{ib[2]}.{ib[3]}"
                            )
                        break
                except (UnicodeDecodeError, ValueError):
                    continue

    if str_data:
        result["info_string"] = str_data
        parts = str_data.split("\t")
        if len(parts) >= 1:
            result["computer"] = parts[0]
        if len(parts) >= 2:
            result["user"] = parts[1]
        if len(parts) >= 3:
            result["process"] = parts[2]

    result["raw_hex"] = raw.hex()
    return result


# ---------------------------------------------------------------------------
# Task decryption (server -> beacon)
# ---------------------------------------------------------------------------

def parse_tasks(plaintext: bytes) -> list:
    """
    Parse decrypted task data (server -> beacon).
    Frame after AES decryption: [4B counter/timestamp][payload]
    Payload: [4B total_len][4B cmd_id][cmd_data]... (multiple commands, big-endian)
    """
    results = []

    if len(plaintext) < 4:
        return [{"error": "Task data too short", "raw_hex": plaintext.hex()}]

    counter = struct.unpack(">I", plaintext[:4])[0]
    payload = plaintext[4:]

    offset = 0
    cmd_index = 0
    while offset < len(payload):
        if offset + 8 > len(payload):
            if offset < len(payload):
                results.append({
                    "index": cmd_index,
                    "error": "Truncated command header",
                    "remaining_hex": payload[offset:].hex(),
                })
            break

        total_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        cmd_id = struct.unpack(">I", payload[offset + 4:offset + 8])[0]
        cmd_name = COMMAND_IDS.get(cmd_id, f"UNKNOWN_{cmd_id}")

        # cmd_data starts after the 8 byte header, length is total_len - 4 (cmd_id is part of total_len)
        # Actually in CS, total_len includes the cmd_id (4 bytes) and the data
        data_len = total_len - 4 if total_len >= 4 else 0
        cmd_data = payload[offset + 8:offset + 8 + data_len] if data_len > 0 else b""

        entry = OrderedDict()
        entry["index"] = cmd_index
        entry["counter"] = counter
        entry["cmd_id"] = cmd_id
        entry["cmd_name"] = cmd_name
        entry["data_len"] = len(cmd_data)

        # Attempt to interpret known commands
        _interpret_task_command(entry, cmd_id, cmd_data)

        results.append(entry)
        cmd_index += 1

        # Advance: 4 (total_len field) + total_len (cmd_id + data)
        offset += 4 + total_len

    return results


def _interpret_task_command(entry: dict, cmd_id: int, data: bytes):
    """Try to extract human-readable info from known command types."""
    if cmd_id == 1:  # SLEEP
        if len(data) >= 4:
            sleep_ms = struct.unpack(">I", data[:4])[0]
            entry["sleep_ms"] = sleep_ms
            entry["sleep_seconds"] = sleep_ms / 1000.0
            if len(data) >= 8:
                jitter = struct.unpack(">I", data[4:8])[0]
                entry["jitter_pct"] = jitter
    elif cmd_id == 2:  # SHELL
        try:
            entry["shell_command"] = data.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            entry["data_hex"] = data.hex()
    elif cmd_id == 4:  # CD
        try:
            entry["path"] = data.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            entry["data_hex"] = data.hex()
    elif cmd_id == 68:  # SHELL_POWERSHELL
        try:
            entry["powershell_command"] = data.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            entry["data_hex"] = data.hex()
    elif cmd_id == 55:  # RUN
        try:
            entry["run_command"] = data.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            entry["data_hex"] = data.hex()
    elif cmd_id == 40:  # MKDIR
        try:
            entry["directory"] = data.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            entry["data_hex"] = data.hex()
    elif cmd_id in (44, 78):  # UPLOAD_START, UPLOAD_CONTINUE
        entry["data_hex"] = data[:64].hex()
        if len(data) > 64:
            entry["data_hex"] += f"... ({len(data)} bytes total)"
    else:
        if data:
            try:
                text = data.decode("utf-8", errors="strict")
                if text.isprintable() or "\n" in text or "\t" in text:
                    entry["data_text"] = text.rstrip("\x00")
                else:
                    raise ValueError
            except (UnicodeDecodeError, ValueError):
                preview = data[:128].hex()
                entry["data_hex"] = preview
                if len(data) > 128:
                    entry["data_hex"] += f"... ({len(data)} bytes total)"


# ---------------------------------------------------------------------------
# Callback parsing (beacon -> server)
# ---------------------------------------------------------------------------

def parse_callbacks(plaintext: bytes) -> list:
    """
    Parse decrypted callback data (beacon -> server).
    Frame: [4B counter][4B callback_size][4B callback_type][callback_data]...
    """
    results = []

    if len(plaintext) < 4:
        return [{"error": "Callback data too short", "raw_hex": plaintext.hex()}]

    counter = struct.unpack(">I", plaintext[:4])[0]
    payload = plaintext[4:]

    offset = 0
    cb_index = 0
    while offset < len(payload):
        if offset + 8 > len(payload):
            if offset < len(payload):
                results.append({
                    "index": cb_index,
                    "error": "Truncated callback header",
                    "remaining_hex": payload[offset:].hex(),
                })
            break

        cb_size = struct.unpack(">I", payload[offset:offset + 4])[0]
        cb_type = struct.unpack(">I", payload[offset + 4:offset + 8])[0]
        cb_name = CALLBACK_TYPES.get(cb_type, f"UNKNOWN_{cb_type}")

        data_len = cb_size - 4 if cb_size >= 4 else 0
        cb_data = payload[offset + 8:offset + 8 + data_len] if data_len > 0 else b""

        entry = OrderedDict()
        entry["index"] = cb_index
        entry["counter"] = counter
        entry["callback_type"] = cb_type
        entry["callback_name"] = cb_name
        entry["data_len"] = len(cb_data)

        # Interpret
        if cb_type in (0, 15, 17, 25):  # Text output types
            try:
                entry["output"] = cb_data.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                entry["data_hex"] = cb_data[:256].hex()
        elif cb_type in (3, 30):  # SCREENSHOT
            entry["data_hex"] = cb_data[:64].hex()
            entry["note"] = f"Screenshot data, {len(cb_data)} bytes"
        elif cb_type == 32:  # OUTPUT_KEYSTROKES
            try:
                entry["keystrokes"] = cb_data.decode("utf-8", errors="replace")
            except Exception:
                entry["data_hex"] = cb_data[:256].hex()
        elif cb_type == 13:  # DEAD
            entry["note"] = "Beacon reported exit"
        else:
            if cb_data:
                try:
                    text = cb_data.decode("utf-8", errors="strict")
                    if text.isprintable() or "\n" in text:
                        entry["data_text"] = text.rstrip("\x00")
                    else:
                        raise ValueError
                except (UnicodeDecodeError, ValueError):
                    preview = cb_data[:256].hex()
                    entry["data_hex"] = preview
                    if len(cb_data) > 256:
                        entry["data_hex"] += f"... ({len(cb_data)} bytes total)"

        results.append(entry)
        cb_index += 1
        offset += 4 + cb_size

    return results


# ---------------------------------------------------------------------------
# RSA metadata decryption
# ---------------------------------------------------------------------------

def decrypt_metadata_rsa(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt RSA-encrypted metadata blob using PKCS1 v1.5."""
    if not HAS_CRYPTO:
        raise RuntimeError("pycryptodome is required for RSA decryption")

    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_v1_5.new(key)
    # Use a sentinel to detect decryption failure
    sentinel = b"\x00" * 32
    plaintext = cipher.decrypt(encrypted_data, sentinel)
    if plaintext == sentinel:
        raise ValueError("RSA decryption failed - wrong private key or corrupted data")
    return plaintext


# ---------------------------------------------------------------------------
# Minimal PCAP parser (no scapy dependency)
# ---------------------------------------------------------------------------

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6


class PcapReader:
    """Minimal PCAP file reader supporting Ethernet + IPv4 + TCP."""

    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.offset = 0
        self.big_endian = False
        self._read_global_header()

    def _unpack(self, fmt, size):
        prefix = ">" if self.big_endian else "<"
        val = struct.unpack(prefix + fmt, self.data[self.offset:self.offset + size])
        self.offset += size
        return val

    def _read_global_header(self):
        if len(self.data) < 24:
            raise ValueError("File too small for PCAP header")
        magic = struct.unpack("<I", self.data[:4])[0]
        if magic == PCAP_MAGIC_LE:
            self.big_endian = False
        elif magic == PCAP_MAGIC_BE:
            self.big_endian = True
        else:
            raise ValueError(f"Not a PCAP file (magic: 0x{magic:08x})")

        self.offset = 0
        magic, = self._unpack("I", 4)
        ver_major, ver_minor = self._unpack("HH", 4)
        thiszone, sigfigs = self._unpack("iI", 8)
        self.snaplen, = self._unpack("I", 4)
        self.linktype, = self._unpack("I", 4)

        if self.linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"Unsupported link type: {self.linktype} (only Ethernet supported)")

    def packets(self):
        """Yield (timestamp, raw_packet_bytes) for each packet."""
        while self.offset + 16 <= len(self.data):
            ts_sec, ts_usec, incl_len, orig_len = self._unpack("IIII", 16)
            if self.offset + incl_len > len(self.data):
                break
            pkt = self.data[self.offset:self.offset + incl_len]
            self.offset += incl_len
            yield (ts_sec + ts_usec / 1_000_000, pkt)


def parse_ethernet(pkt: bytes):
    """Parse Ethernet frame, return (ethertype, payload)."""
    if len(pkt) < 14:
        return None, None
    ethertype = struct.unpack("!H", pkt[12:14])[0]
    return ethertype, pkt[14:]


def parse_ipv4(data: bytes):
    """Parse IPv4 header, return (proto, src_ip, dst_ip, payload)."""
    if len(data) < 20:
        return None, None, None, None
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None, None, None, None
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
    dst_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
    payload = data[ihl:total_len] if total_len <= len(data) else data[ihl:]
    return proto, src_ip, dst_ip, payload


def parse_tcp(data: bytes):
    """Parse TCP header, return (src_port, dst_port, seq, flags, payload)."""
    if len(data) < 20:
        return None, None, None, None, None
    src_port, dst_port = struct.unpack("!HH", data[:4])
    seq = struct.unpack("!I", data[4:8])[0]
    data_offset = ((data[12] >> 4) & 0x0F) * 4
    flags = data[13]
    if data_offset < 20 or data_offset > len(data):
        return src_port, dst_port, seq, flags, b""
    return src_port, dst_port, seq, flags, data[data_offset:]


class HTTPStreamReassembler:
    """
    Minimal HTTP stream reassembler.
    Collects TCP payloads per (src, dst, sport, dport) flow,
    then extracts HTTP requests/responses.
    """

    def __init__(self):
        # flow_key -> list of (seq, data)
        self.flows = {}

    def add_segment(self, src_ip, dst_ip, src_port, dst_port, seq, data, timestamp):
        if not data:
            return
        key = (src_ip, dst_ip, src_port, dst_port)
        if key not in self.flows:
            self.flows[key] = []
        self.flows[key].append((seq, data, timestamp))

    def extract_http(self):
        """
        Yield dicts with HTTP info: method, path, headers, body, direction, timestamp.
        """
        for flow_key, segments in self.flows.items():
            src_ip, dst_ip, src_port, dst_port = flow_key
            # Sort by sequence number
            segments.sort(key=lambda x: x[0])
            # Concatenate payloads (simple, no gap handling)
            stream = b"".join(seg[1] for seg in segments)
            first_ts = segments[0][2] if segments else 0

            if not stream:
                continue

            # Try to find HTTP requests/responses in the stream
            offset = 0
            while offset < len(stream):
                remaining = stream[offset:]

                # Check for HTTP request
                if remaining[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
                    parsed = self._parse_http_message(remaining, "request", flow_key, first_ts)
                    if parsed:
                        yield parsed
                        offset += parsed.get("_consumed", len(remaining))
                        continue

                # Check for HTTP response
                if remaining[:5] == b"HTTP/":
                    parsed = self._parse_http_message(remaining, "response", flow_key, first_ts)
                    if parsed:
                        yield parsed
                        offset += parsed.get("_consumed", len(remaining))
                        continue

                # No HTTP found at this offset, skip forward
                break

    def _parse_http_message(self, data: bytes, msg_type: str, flow_key, timestamp):
        """Parse a single HTTP request or response from raw bytes."""
        header_end = data.find(b"\r\n\r\n")
        if header_end < 0:
            return None

        header_section = data[:header_end].decode("utf-8", errors="replace")
        lines = header_section.split("\r\n")
        first_line = lines[0]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        body_start = header_end + 4
        content_length = int(headers.get("content-length", 0))
        body = data[body_start:body_start + content_length] if content_length > 0 else b""

        consumed = body_start + len(body)

        result = {
            "type": msg_type,
            "first_line": first_line,
            "headers": headers,
            "body": body,
            "flow": flow_key,
            "timestamp": timestamp,
            "_consumed": consumed,
        }

        if msg_type == "request":
            parts = first_line.split(" ")
            if len(parts) >= 2:
                result["method"] = parts[0]
                result["path"] = parts[1]

        return result


# ---------------------------------------------------------------------------
# PCAP-based full decryption pipeline
# ---------------------------------------------------------------------------

def process_pcap(pcap_path: str, private_key_pem: bytes, http_port: int = 80):
    """
    Full pipeline: parse PCAP -> extract HTTP -> decrypt metadata -> derive keys -> decrypt traffic.
    """
    print(f"[*] Reading PCAP: {pcap_path}")
    reader = PcapReader(pcap_path)

    reassembler = HTTPStreamReassembler()
    pkt_count = 0

    for timestamp, pkt in reader.packets():
        pkt_count += 1
        ethertype, eth_payload = parse_ethernet(pkt)
        if ethertype != ETHERTYPE_IPV4 or eth_payload is None:
            continue
        proto, src_ip, dst_ip, ip_payload = parse_ipv4(eth_payload)
        if proto != IPPROTO_TCP or ip_payload is None:
            continue
        src_port, dst_port, seq, flags, tcp_payload = parse_tcp(ip_payload)
        if tcp_payload is None:
            continue
        reassembler.add_segment(src_ip, dst_ip, src_port, dst_port, seq, tcp_payload, timestamp)

    print(f"[*] Parsed {pkt_count} packets, {len(reassembler.flows)} TCP flows")

    http_messages = list(reassembler.extract_http())
    print(f"[*] Found {len(http_messages)} HTTP messages")

    # Step 1: Find metadata in Cookie headers (GET requests)
    session_key = None
    aes_key = None
    hmac_key = None
    beacon_metadata = None

    for msg in http_messages:
        if msg["type"] == "request" and msg.get("method") == "GET":
            cookie = msg["headers"].get("cookie", "")
            if not cookie:
                continue
            # Try to extract and decrypt the metadata from cookie value
            # Cookie format varies; common patterns: __session_id=<base64>, PHPSESSID=<base64>, etc.
            for part in cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    _, value = part.split("=", 1)
                    value = value.strip()
                else:
                    value = part.strip()

                if len(value) < 20:
                    continue

                try:
                    encrypted_blob = base64.b64decode(value)
                except Exception:
                    continue

                if len(encrypted_blob) < 128:
                    continue

                try:
                    decrypted = decrypt_metadata_rsa(encrypted_blob, private_key_pem)
                    metadata = parse_metadata(decrypted)
                    if "session_key" in metadata:
                        session_key = bytes.fromhex(metadata["session_key"])
                        aes_key, hmac_key = derive_keys(session_key)
                        beacon_metadata = metadata
                        print(f"[+] Decrypted metadata from cookie!")
                        print(f"    Session key: {session_key.hex()}")
                        for k, v in metadata.items():
                            if k not in ("raw_hex", "session_key"):
                                print(f"    {k}: {v}")
                        break
                except Exception:
                    continue

            if session_key:
                break

    if not session_key:
        print("[-] Could not find/decrypt beacon metadata in any cookie")
        print("    Trying POST bodies as metadata...")
        # Some configs send metadata via POST body
        for msg in http_messages:
            if msg["type"] == "request" and msg.get("method") == "POST" and msg["body"]:
                try:
                    # Try base64 decode first
                    try:
                        encrypted_blob = base64.b64decode(msg["body"])
                    except Exception:
                        encrypted_blob = msg["body"]

                    if len(encrypted_blob) >= 128:
                        decrypted = decrypt_metadata_rsa(encrypted_blob, private_key_pem)
                        metadata = parse_metadata(decrypted)
                        if "session_key" in metadata:
                            session_key = bytes.fromhex(metadata["session_key"])
                            aes_key, hmac_key = derive_keys(session_key)
                            beacon_metadata = metadata
                            print(f"[+] Decrypted metadata from POST body!")
                            print(f"    Session key: {session_key.hex()}")
                            for k, v in metadata.items():
                                if k not in ("raw_hex", "session_key"):
                                    print(f"    {k}: {v}")
                            break
                except Exception:
                    continue

    if not session_key:
        print("[-] Failed to extract session key from PCAP")
        return

    # Step 2: Decrypt task data (server -> beacon responses) and callback data (beacon -> server POST bodies)
    print(f"\n{'='*60}")
    print("DECRYPTED TRAFFIC")
    print(f"{'='*60}")

    for msg in http_messages:
        # Tasks: HTTP responses (server -> beacon)
        if msg["type"] == "response" and msg["body"] and len(msg["body"]) >= 32:
            try:
                plaintext = aes_decrypt(msg["body"], aes_key, hmac_key)
                tasks = parse_tasks(plaintext)
                print(f"\n[TASK] Server -> Beacon (timestamp: {msg['timestamp']:.3f})")
                for task in tasks:
                    print(f"  {json.dumps(task, indent=4)}")
            except Exception as e:
                pass  # Not all responses are encrypted task data

        # Callbacks: HTTP POST bodies (beacon -> server), skip the metadata POST
        if (msg["type"] == "request" and msg.get("method") == "POST"
                and msg["body"] and len(msg["body"]) >= 32):
            body = msg["body"]
            # Skip if this was the metadata blob
            try:
                test = decrypt_metadata_rsa(body, private_key_pem)
                if "session_key" in parse_metadata(test).get("session_key", ""):
                    continue
            except Exception:
                pass

            try:
                plaintext = aes_decrypt(body, aes_key, hmac_key)
                callbacks = parse_callbacks(plaintext)
                print(f"\n[CALLBACK] Beacon -> Server (timestamp: {msg['timestamp']:.3f})")
                for cb in callbacks:
                    print(f"  {json.dumps(cb, indent=4)}")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test():
    """Generate synthetic CS traffic, encrypt it, then decrypt and verify."""
    if not HAS_CRYPTO:
        print("FAIL: pycryptodome is required for self-test")
        return False

    print("=" * 60)
    print("COBALT STRIKE TRAFFIC DECRYPTOR - SELF TEST")
    print("=" * 60)
    passed = 0
    failed = 0

    # --- Test 1: Key derivation ---
    print("\n[Test 1] Key derivation")
    session_key = os.urandom(16)
    aes_key, hmac_key = derive_keys(session_key)
    assert len(aes_key) == 16, "AES key must be 16 bytes"
    assert len(hmac_key) == 16, "HMAC key must be 16 bytes"
    # Verify deterministic
    aes_key2, hmac_key2 = derive_keys(session_key)
    assert aes_key == aes_key2 and hmac_key == hmac_key2
    print(f"  Session key:  {session_key.hex()}")
    print(f"  AES key:      {aes_key.hex()}")
    print(f"  HMAC key:     {hmac_key.hex()}")
    print("  PASS")
    passed += 1

    # --- Test 2: AES encrypt/decrypt round-trip ---
    print("\n[Test 2] AES-CBC encrypt/decrypt round-trip")
    test_data = b"Hello, this is a test of the Cobalt Strike decryptor!"
    encrypted = aes_encrypt(test_data, aes_key, hmac_key)
    decrypted = aes_decrypt(encrypted, aes_key, hmac_key)
    assert decrypted == test_data, f"Round-trip failed: {decrypted!r} != {test_data!r}"
    print(f"  Plaintext:    {test_data!r}")
    print(f"  Encrypted:    {encrypted.hex()[:64]}...")
    print(f"  Decrypted:    {decrypted!r}")
    print("  PASS")
    passed += 1

    # --- Test 3: HMAC verification ---
    print("\n[Test 3] HMAC verification (tampered data)")
    tampered = bytearray(encrypted)
    tampered[0] ^= 0xFF  # Flip a bit in ciphertext
    try:
        aes_decrypt(bytes(tampered), aes_key, hmac_key)
        print("  FAIL: Should have raised ValueError")
        failed += 1
    except ValueError as e:
        print(f"  Correctly rejected: {e}")
        print("  PASS")
        passed += 1

    # --- Test 4: Task encryption/decryption ---
    print("\n[Test 4] Task command encryption/decryption")
    # Build a task frame: [4B counter][4B total_len][4B cmd_id][data]...
    counter = 1
    # Command: SHELL "whoami"
    shell_data = b"whoami\x00"
    cmd_frame = struct.pack(">I", len(shell_data) + 4)  # total_len = data + cmd_id
    cmd_frame += struct.pack(">I", 2)  # SHELL
    cmd_frame += shell_data
    # Command: SLEEP 60000ms, 10% jitter
    sleep_data = struct.pack(">II", 60000, 10)
    cmd_frame += struct.pack(">I", len(sleep_data) + 4)
    cmd_frame += struct.pack(">I", 1)  # SLEEP
    cmd_frame += sleep_data

    task_plain = struct.pack(">I", counter) + cmd_frame
    task_encrypted = aes_encrypt(task_plain, aes_key, hmac_key)
    task_decrypted = aes_decrypt(task_encrypted, aes_key, hmac_key)
    tasks = parse_tasks(task_decrypted)

    print(f"  Commands found: {len(tasks)}")
    for t in tasks:
        print(f"    {json.dumps(t)}")

    assert len(tasks) == 2, f"Expected 2 commands, got {len(tasks)}"
    assert tasks[0]["cmd_name"] == "SHELL"
    assert "whoami" in tasks[0].get("shell_command", "")
    assert tasks[1]["cmd_name"] == "SLEEP"
    assert tasks[1].get("sleep_ms") == 60000
    print("  PASS")
    passed += 1

    # --- Test 5: Callback encryption/decryption ---
    print("\n[Test 5] Callback encryption/decryption")
    counter = 2
    # Callback: OUTPUT "NT AUTHORITY\\SYSTEM"
    output_data = b"NT AUTHORITY\\SYSTEM\x00"
    cb_frame = struct.pack(">I", len(output_data) + 4)  # cb_size = data + type
    cb_frame += struct.pack(">I", 0)  # OUTPUT
    cb_frame += output_data

    cb_plain = struct.pack(">I", counter) + cb_frame
    cb_encrypted = aes_encrypt(cb_plain, aes_key, hmac_key)
    cb_decrypted = aes_decrypt(cb_encrypted, aes_key, hmac_key)
    callbacks = parse_callbacks(cb_decrypted)

    print(f"  Callbacks found: {len(callbacks)}")
    for cb in callbacks:
        print(f"    {json.dumps(cb)}")

    assert len(callbacks) == 1
    assert callbacks[0]["callback_name"] == "OUTPUT"
    assert "SYSTEM" in callbacks[0].get("output", "")
    print("  PASS")
    passed += 1

    # --- Test 6: RSA metadata round-trip ---
    print("\n[Test 6] RSA metadata encryption/decryption")
    from Crypto.PublicKey import RSA as RSA_mod

    print("  Generating RSA-2048 keypair (this may take a moment)...")
    key = RSA_mod.generate(2048)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()

    # Build metadata blob
    meta_session_key = os.urandom(16)
    beacon_id = 0xDEADBEEF
    pid = 4567
    port = 443
    flags = 0x03  # x64 + admin
    os_major = 10
    os_minor = 0
    build = 19041
    internal_ip = bytes([192, 168, 1, 100])

    meta_blob = b""
    meta_blob += struct.pack(">I", 48)  # magic / key size hint
    meta_blob += meta_session_key
    meta_blob += struct.pack(">HH", 1252, 437)  # charset
    meta_blob += struct.pack(">I", beacon_id)
    meta_blob += struct.pack(">I", pid)
    meta_blob += struct.pack(">H", port)
    meta_blob += bytes([flags])
    meta_blob += struct.pack(">HH", os_major, os_minor)
    meta_blob += struct.pack(">I", build)
    meta_blob += b"\x00" * 4  # padding
    meta_blob += internal_ip
    meta_blob += b"WORKSTATION\tAdministrator\tbeacon.exe\x00"

    # RSA encrypt
    pub_key = RSA_mod.import_key(public_pem)
    cipher_rsa = PKCS1_v1_5.new(pub_key)
    encrypted_meta = cipher_rsa.encrypt(meta_blob)
    b64_meta = base64.b64encode(encrypted_meta).decode()

    # Decrypt
    decrypted_meta = decrypt_metadata_rsa(encrypted_meta, private_pem)
    assert decrypted_meta == meta_blob, "RSA round-trip failed"

    parsed = parse_metadata(decrypted_meta)
    print(f"  Session key:  {parsed.get('session_key', 'N/A')}")
    print(f"  Beacon ID:    {parsed.get('beacon_id', 'N/A')}")
    print(f"  PID:          {parsed.get('pid', 'N/A')}")
    print(f"  Computer:     {parsed.get('computer', 'N/A')}")
    print(f"  User:         {parsed.get('user', 'N/A')}")
    print(f"  Process:      {parsed.get('process', 'N/A')}")
    print(f"  Internal IP:  {parsed.get('internal_ip', 'N/A')}")
    print(f"  OS Version:   {parsed.get('os_version', 'N/A')}")
    print(f"  Flags:        {parsed.get('flags', 'N/A')} ({parsed.get('flags_desc', 'N/A')})")

    assert parsed["session_key"] == meta_session_key.hex()
    parsed_str = json.dumps(parsed)
    assert "WORKSTATION" in parsed_str, f"Computer not found: {parsed}"
    assert "Administrator" in parsed_str, f"User not found: {parsed}"
    assert parsed.get("pid") == pid, f"PID mismatch"
    print("  PASS")
    passed += 1

    # --- Test 7: Full pipeline (metadata -> key derivation -> encrypt -> decrypt) ---
    print("\n[Test 7] Full pipeline: metadata -> derive keys -> encrypt tasks -> decrypt")
    derived_aes, derived_hmac = derive_keys(meta_session_key)

    # Build multi-command task
    commands = [
        (1, struct.pack(">II", 30000, 25)),    # SLEEP 30s, 25% jitter
        (2, b"ipconfig /all\x00"),              # SHELL
        (27, b""),                                # GETUID
        (4, b"C:\\Users\\Administrator\x00"),     # CD
        (68, b"Get-Process | Select-Object -First 10\x00"),  # POWERSHELL
    ]

    cmd_payload = b""
    for cmd_id, data in commands:
        total_len = len(data) + 4
        cmd_payload += struct.pack(">I", total_len)
        cmd_payload += struct.pack(">I", cmd_id)
        cmd_payload += data

    task_frame = struct.pack(">I", 42) + cmd_payload  # counter = 42
    encrypted_task = aes_encrypt(task_frame, derived_aes, derived_hmac)
    decrypted_task = aes_decrypt(encrypted_task, derived_aes, derived_hmac)
    parsed_tasks = parse_tasks(decrypted_task)

    print(f"  Encrypted {len(commands)} commands ({len(encrypted_task)} bytes)")
    print(f"  Decrypted {len(parsed_tasks)} commands:")
    for t in parsed_tasks:
        print(f"    [{t['cmd_name']}] {json.dumps({k: v for k, v in t.items() if k not in ('index', 'counter', 'cmd_id', 'cmd_name', 'data_len')})}")

    assert len(parsed_tasks) == len(commands)
    assert parsed_tasks[0]["cmd_name"] == "SLEEP"
    assert parsed_tasks[1]["cmd_name"] == "SHELL"
    assert parsed_tasks[2]["cmd_name"] == "GETUID"
    assert parsed_tasks[3]["cmd_name"] == "CD"
    assert parsed_tasks[4]["cmd_name"] == "SHELL_POWERSHELL"
    print("  PASS")
    passed += 1

    # --- Test 8: Edge cases ---
    print("\n[Test 8] Edge cases")

    # Empty command data
    empty_task = struct.pack(">I", 1) + struct.pack(">II", 4, 3)  # DIE with no data
    enc = aes_encrypt(empty_task, aes_key, hmac_key)
    dec = aes_decrypt(enc, aes_key, hmac_key)
    result = parse_tasks(dec)
    assert len(result) == 1
    assert result[0]["cmd_name"] == "DIE/EXIT"
    print("  Empty command data: PASS")

    # Large data
    large_data = os.urandom(4096)
    enc_large = aes_encrypt(large_data, aes_key, hmac_key)
    dec_large = aes_decrypt(enc_large, aes_key, hmac_key)
    assert dec_large == large_data
    print("  Large data (4096 bytes): PASS")

    # Wrong key detection
    wrong_key = os.urandom(16)
    wrong_aes, wrong_hmac = derive_keys(wrong_key)
    try:
        aes_decrypt(enc_large, wrong_aes, wrong_hmac)
        print("  Wrong key detection: FAIL (should have raised)")
        failed += 1
    except ValueError:
        print("  Wrong key detection: PASS")
        passed += 1

    passed += 1  # For the sub-tests above

    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*60}")
    return failed == 0


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def read_input_data(value: str) -> bytes:
    """
    Read input data from a hex string, base64 string, or file path.
    """
    # Check if it's a file path
    if os.path.isfile(value):
        with open(value, "rb") as f:
            return f.read()

    # Try hex decode
    clean = value.replace(" ", "").replace("\n", "").replace("0x", "")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        pass

    # Try base64
    try:
        return base64.b64decode(value)
    except Exception:
        pass

    raise ValueError(f"Cannot parse input as hex, base64, or file path: {value[:50]}...")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cobalt Strike C2 Traffic Decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt task data with known session key
  %(prog)s --session-key aabbccdd... --data encrypted.bin --direction task

  # Decrypt callback data
  %(prog)s --session-key aabbccdd... --data deadbeef... --direction callback

  # Decrypt RSA metadata from base64 cookie value
  %(prog)s --private-key beacon_keys.pem --metadata <base64>

  # Full PCAP analysis
  %(prog)s --pcap capture.pcap --private-key beacon_keys.pem

  # Run self-test
  %(prog)s --self-test
        """,
    )

    parser.add_argument("--self-test", action="store_true",
                        help="Run self-test with synthetic data")

    # Mode 1: Session key decryption
    parser.add_argument("--session-key", metavar="HEX",
                        help="16-byte session key in hex")
    parser.add_argument("--data", metavar="HEX_OR_FILE",
                        help="Encrypted data (hex string or file path)")
    parser.add_argument("--direction", choices=["task", "callback"],
                        help="Traffic direction: task (server->beacon) or callback (beacon->server)")
    parser.add_argument("--no-hmac-verify", action="store_true",
                        help="Skip HMAC verification (useful for partial/corrupted data)")

    # Mode 2: Metadata decryption
    parser.add_argument("--metadata", metavar="BASE64_OR_HEX",
                        help="RSA-encrypted metadata blob (base64 or hex)")

    # Mode 3: PCAP
    parser.add_argument("--pcap", metavar="FILE",
                        help="PCAP file to analyze")
    parser.add_argument("--private-key", metavar="PEM_FILE",
                        help="RSA private key file (PEM format)")

    # Output options
    parser.add_argument("--raw", action="store_true",
                        help="Output raw decrypted bytes as hex (no parsing)")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output as JSON")

    args = parser.parse_args()

    if not HAS_CRYPTO:
        print("ERROR: pycryptodome is required. Install with: pip install pycryptodome")
        sys.exit(1)

    # Self-test mode
    if args.self_test:
        success = self_test()
        sys.exit(0 if success else 1)

    # Mode 3: PCAP
    if args.pcap:
        if not args.private_key:
            parser.error("--private-key is required with --pcap")
        with open(args.private_key, "rb") as f:
            private_pem = f.read()
        process_pcap(args.pcap, private_pem)
        return

    # Mode 2: Metadata decryption
    if args.metadata:
        if not args.private_key:
            parser.error("--private-key is required with --metadata")
        with open(args.private_key, "rb") as f:
            private_pem = f.read()
        encrypted = read_input_data(args.metadata)
        decrypted = decrypt_metadata_rsa(encrypted, private_pem)

        if args.raw:
            print(decrypted.hex())
        else:
            metadata = parse_metadata(decrypted)
            if args.json_output:
                print(json.dumps(metadata, indent=2))
            else:
                print("Decrypted Beacon Metadata:")
                print("-" * 40)
                for k, v in metadata.items():
                    print(f"  {k:20s}: {v}")

            # Also print derived keys for convenience
            if "session_key" in metadata:
                sk = bytes.fromhex(metadata["session_key"])
                aes_k, hmac_k = derive_keys(sk)
                print(f"\nDerived keys:")
                print(f"  AES key:   {aes_k.hex()}")
                print(f"  HMAC key:  {hmac_k.hex()}")
        return

    # Mode 1: Session key decryption
    if args.session_key:
        if not args.data:
            parser.error("--data is required with --session-key")
        if not args.direction:
            parser.error("--direction is required with --session-key")

        session_key = bytes.fromhex(args.session_key.replace(" ", ""))
        if len(session_key) != 16:
            print(f"ERROR: Session key must be 16 bytes, got {len(session_key)}")
            sys.exit(1)

        aes_key, hmac_key = derive_keys(session_key)
        encrypted = read_input_data(args.data)

        print(f"[*] Session key: {session_key.hex()}")
        print(f"[*] AES key:     {aes_key.hex()}")
        print(f"[*] HMAC key:    {hmac_key.hex()}")
        print(f"[*] Data length: {len(encrypted)} bytes")
        print(f"[*] Direction:   {args.direction}")
        print()

        try:
            plaintext = aes_decrypt(encrypted, aes_key, hmac_key,
                                    verify_hmac=not args.no_hmac_verify)
        except ValueError as e:
            print(f"ERROR: {e}")
            if not args.no_hmac_verify:
                print("Hint: try --no-hmac-verify if the data might be truncated")
            sys.exit(1)

        if args.raw:
            print(plaintext.hex())
            return

        if args.direction == "task":
            results = parse_tasks(plaintext)
            label = "Task Commands"
        else:
            results = parse_callbacks(plaintext)
            label = "Callbacks"

        if args.json_output:
            print(json.dumps(results, indent=2))
        else:
            print(f"Decrypted {label}:")
            print("=" * 50)
            for entry in results:
                for k, v in entry.items():
                    print(f"  {k}: {v}")
                print("-" * 50)
        return

    # No valid mode selected
    parser.print_help()


if __name__ == "__main__":
    main()
