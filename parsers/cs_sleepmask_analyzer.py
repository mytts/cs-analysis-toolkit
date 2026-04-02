#!/usr/bin/env python3
"""
Cobalt Strike Sleep Mask BOF Analyzer
======================================
Parses MSVC-compiled COFF object files (.o) used as Beacon Object Files (BOFs)
for the Cobalt Strike sleep mask kit.

Analyzes:
  - COFF headers, section tables, symbol tables, relocations
  - .text section hex dump with annotations
  - XOR-based encryption loop detection
  - Cross-file comparison across all 6 variants
  - C pseudocode reconstruction of sleep mask logic

Usage: python3 cs_sleepmask_analyzer.py /path/to/sleeve_decrypted/

No external dependencies -- Python 3.6+ stdlib only.
"""

import struct
import sys
import os
import hashlib
from collections import OrderedDict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# COFF constants
# ---------------------------------------------------------------------------

MACHINE_TYPES = {
    0x0000: "IMAGE_FILE_MACHINE_UNKNOWN",
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
}

STORAGE_CLASSES = {
    0:   "IMAGE_SYM_CLASS_NULL",
    1:   "IMAGE_SYM_CLASS_AUTOMATIC",
    2:   "IMAGE_SYM_CLASS_EXTERNAL",
    3:   "IMAGE_SYM_CLASS_STATIC",
    4:   "IMAGE_SYM_CLASS_REGISTER",
    5:   "IMAGE_SYM_CLASS_EXTERNAL_DEF",
    6:   "IMAGE_SYM_CLASS_LABEL",
    100: "IMAGE_SYM_CLASS_BLOCK",
    101: "IMAGE_SYM_CLASS_FUNCTION",
    103: "IMAGE_SYM_CLASS_FILE",
    104: "IMAGE_SYM_CLASS_SECTION",
}

SECTION_FLAGS = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA",
    0x00000200: "LNK_INFO",
    0x00000800: "LNK_REMOVE",
    0x00001000: "LNK_COMDAT",
    0x00100000: "ALIGN_1BYTES",
    0x00200000: "ALIGN_2BYTES",
    0x00300000: "ALIGN_4BYTES",
    0x00400000: "ALIGN_8BYTES",
    0x00500000: "ALIGN_16BYTES",
    0x00600000: "ALIGN_32BYTES",
    0x00700000: "ALIGN_64BYTES",
    0x01000000: "LNK_NRELOC_OVFL",
    0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED",
    0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}

# x86 relocation types
RELOC_TYPES_I386 = {
    0x0000: "IMAGE_REL_I386_ABSOLUTE",
    0x0001: "IMAGE_REL_I386_DIR16",
    0x0002: "IMAGE_REL_I386_REL16",
    0x0006: "IMAGE_REL_I386_DIR32",
    0x0007: "IMAGE_REL_I386_DIR32NB",
    0x0009: "IMAGE_REL_I386_SEG12",
    0x000A: "IMAGE_REL_I386_SECTION",
    0x000B: "IMAGE_REL_I386_SECREL",
    0x000C: "IMAGE_REL_I386_TOKEN",
    0x000D: "IMAGE_REL_I386_SECREL7",
    0x0014: "IMAGE_REL_I386_REL32",
}

# x64 relocation types
RELOC_TYPES_AMD64 = {
    0x0000: "IMAGE_REL_AMD64_ABSOLUTE",
    0x0001: "IMAGE_REL_AMD64_ADDR64",
    0x0002: "IMAGE_REL_AMD64_ADDR32",
    0x0003: "IMAGE_REL_AMD64_ADDR32NB",
    0x0004: "IMAGE_REL_AMD64_REL32",
    0x0005: "IMAGE_REL_AMD64_REL32_1",
    0x0006: "IMAGE_REL_AMD64_REL32_2",
    0x0007: "IMAGE_REL_AMD64_REL32_3",
    0x0008: "IMAGE_REL_AMD64_REL32_4",
    0x0009: "IMAGE_REL_AMD64_REL32_5",
    0x000A: "IMAGE_REL_AMD64_SECTION",
    0x000B: "IMAGE_REL_AMD64_SECREL",
    0x000C: "IMAGE_REL_AMD64_SECREL7",
    0x000D: "IMAGE_REL_AMD64_TOKEN",
    0x000E: "IMAGE_REL_AMD64_SREL32",
    0x000F: "IMAGE_REL_AMD64_PAIR",
    0x0010: "IMAGE_REL_AMD64_SSPAN32",
}

# Common x86 opcode annotations
X86_OPCODES = {
    0x55: "push ebp",
    0x8B: "mov",
    0xC9: "leave",
    0xC3: "ret",
    0x50: "push eax",
    0x51: "push ecx",
    0x52: "push edx",
    0x53: "push ebx",
    0x56: "push esi",
    0x57: "push edi",
    0x58: "pop eax",
    0x59: "pop ecx",
    0x5A: "pop edx",
    0x5B: "pop ebx",
    0x5E: "pop esi",
    0x5F: "pop edi",
    0x33: "xor",
    0x30: "xor byte",
    0x31: "xor dword",
    0x32: "xor byte (src)",
    0x83: "arith imm8",
    0x89: "mov (store)",
    0x8A: "mov byte",
    0x88: "mov byte (store)",
    0x3B: "cmp",
    0x39: "cmp (rev)",
    0x74: "je",
    0x75: "jne",
    0x72: "jb",
    0x73: "jae",
    0x76: "jbe",
    0x7F: "jg",
    0xEB: "jmp short",
    0xE8: "call",
    0xFF: "indirect",
    0x6A: "push imm8",
    0x68: "push imm32",
    0xF7: "mul/div group",
    0x41: "inc ecx / REX.B",
    0x48: "REX.W",
    0x4C: "REX.WR",
    0x4D: "REX.WRB",
    0x45: "REX.RB",
    0x49: "REX.WB",
    0x4E: "REX.WRX",
    0x4A: "REX.WX",
}


# ---------------------------------------------------------------------------
# COFF parsing
# ---------------------------------------------------------------------------

class COFFSection:
    """Represents a single COFF section."""
    def __init__(self):
        self.name = ""
        self.virtual_size = 0
        self.virtual_address = 0
        self.size_of_raw_data = 0
        self.pointer_to_raw_data = 0
        self.pointer_to_relocations = 0
        self.pointer_to_linenumbers = 0
        self.number_of_relocations = 0
        self.number_of_linenumbers = 0
        self.characteristics = 0
        self.data = b""
        self.relocations = []

    def flag_strings(self):
        flags = []
        for bit, name in sorted(SECTION_FLAGS.items()):
            if self.characteristics & bit:
                flags.append(name)
        return flags


class COFFSymbol:
    """Represents a single COFF symbol table entry."""
    def __init__(self):
        self.name = ""
        self.value = 0
        self.section_number = 0
        self.type = 0
        self.storage_class = 0
        self.number_of_aux_symbols = 0
        self.index = 0


class COFFRelocation:
    """Represents a single COFF relocation entry."""
    def __init__(self):
        self.virtual_address = 0
        self.symbol_table_index = 0
        self.type = 0
        self.symbol_name = ""
        self.type_name = ""


class COFFFile:
    """Full COFF object file parser."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = b""
        self.machine = 0
        self.number_of_sections = 0
        self.timestamp = 0
        self.pointer_to_symbol_table = 0
        self.number_of_symbols = 0
        self.size_of_optional_header = 0
        self.characteristics = 0
        self.sections = []
        self.symbols = []
        self.string_table = b""
        self._parse()

    def _parse(self):
        with open(self.filepath, "rb") as f:
            self.data = f.read()
        self._parse_header()
        self._parse_sections()
        self._parse_string_table()
        self._parse_symbols()
        self._parse_relocations()

    def _parse_header(self):
        if len(self.data) < 20:
            raise ValueError("File too small for COFF header")
        (self.machine, self.number_of_sections, self.timestamp,
         self.pointer_to_symbol_table, self.number_of_symbols,
         self.size_of_optional_header, self.characteristics) = struct.unpack_from(
            "<HHIIIHH", self.data, 0
        )

    def _parse_sections(self):
        offset = 20 + self.size_of_optional_header
        for i in range(self.number_of_sections):
            sec = COFFSection()
            raw_name = self.data[offset:offset + 8]
            sec.name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
            (sec.virtual_size, sec.virtual_address,
             sec.size_of_raw_data, sec.pointer_to_raw_data,
             sec.pointer_to_relocations, sec.pointer_to_linenumbers,
             sec.number_of_relocations, sec.number_of_linenumbers,
             sec.characteristics) = struct.unpack_from("<IIIIIIHHI", self.data, offset + 8)
            if sec.size_of_raw_data > 0 and sec.pointer_to_raw_data > 0:
                start = sec.pointer_to_raw_data
                end = start + sec.size_of_raw_data
                sec.data = self.data[start:end]
            self.sections.append(sec)
            offset += 40

    def _parse_string_table(self):
        st_off = self.pointer_to_symbol_table + self.number_of_symbols * 18
        if st_off + 4 <= len(self.data):
            st_size = struct.unpack_from("<I", self.data, st_off)[0]
            if st_size > 4:
                self.string_table = self.data[st_off:st_off + st_size]
            else:
                self.string_table = self.data[st_off:st_off + 4]
        else:
            self.string_table = b""

    def _get_string(self, offset_in_strtab):
        """Read a null-terminated string from the string table."""
        if offset_in_strtab >= len(self.string_table):
            return "<invalid>"
        end = self.string_table.index(b"\x00", offset_in_strtab) if b"\x00" in self.string_table[offset_in_strtab:] else len(self.string_table)
        return self.string_table[offset_in_strtab:end].decode("ascii", errors="replace")

    def _parse_symbols(self):
        off = self.pointer_to_symbol_table
        idx = 0
        while idx < self.number_of_symbols:
            sym = COFFSymbol()
            sym.index = idx
            raw_name = self.data[off:off + 8]
            # If first 4 bytes are zero, name is in string table
            if raw_name[:4] == b"\x00\x00\x00\x00":
                str_offset = struct.unpack_from("<I", raw_name, 4)[0]
                sym.name = self._get_string(str_offset)
            else:
                sym.name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
            (sym.value, sym.section_number, sym.type,
             sym.storage_class, sym.number_of_aux_symbols) = struct.unpack_from(
                "<IhHBB", self.data, off + 8
            )
            self.symbols.append(sym)
            off += 18
            idx += 1
            # Skip auxiliary symbol records
            for _ in range(sym.number_of_aux_symbols):
                off += 18
                idx += 1

    def _parse_relocations(self):
        is_amd64 = (self.machine == 0x8664)
        reloc_types = RELOC_TYPES_AMD64 if is_amd64 else RELOC_TYPES_I386
        for sec in self.sections:
            if sec.number_of_relocations == 0:
                continue
            roff = sec.pointer_to_relocations
            for _ in range(sec.number_of_relocations):
                rel = COFFRelocation()
                (rel.virtual_address, rel.symbol_table_index,
                 rel.type) = struct.unpack_from("<IIH", self.data, roff)
                rel.type_name = reloc_types.get(rel.type, f"UNKNOWN(0x{rel.type:04X})")
                # Resolve symbol name
                for sym in self.symbols:
                    if sym.index == rel.symbol_table_index:
                        rel.symbol_name = sym.name
                        break
                else:
                    rel.symbol_name = f"<sym#{rel.symbol_table_index}>"
                sec.relocations.append(rel)
                roff += 10

    @property
    def machine_name(self):
        return MACHINE_TYPES.get(self.machine, f"UNKNOWN(0x{self.machine:04X})")

    @property
    def is_x64(self):
        return self.machine == 0x8664

    def get_text_section(self):
        for sec in self.sections:
            if sec.name == ".text":
                return sec
        return None

    def get_section_by_name(self, name):
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def file_hash(self):
        return hashlib.sha256(self.data).hexdigest()


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def hex_dump(data, base_offset=0, width=16, annotations=None):
    """Produce an annotated hex dump string."""
    lines = []
    ann_map = annotations or {}
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        addr = base_offset + i
        line = f"  {addr:04X}  {hex_part:<{width * 3 - 1}}  {ascii_part}"
        if addr in ann_map:
            line += f"  ; {ann_map[addr]}"
        lines.append(line)
    return "\n".join(lines)


def detect_xor_patterns_x86(data):
    """Scan x86 .text bytes for XOR-based encryption patterns."""
    patterns = []
    i = 0
    while i < len(data) - 2:
        # XOR reg, reg  (33 XX) -- clearing register or XOR operation
        if data[i] == 0x33:
            modrm = data[i + 1]
            src = (modrm >> 3) & 7
            dst = modrm & 7
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if src == dst:
                patterns.append((i, f"xor {reg_names[dst]}, {reg_names[src]}  (zero register)", "ZERO_REG"))
            else:
                patterns.append((i, f"xor {reg_names[dst]}, {reg_names[src]}  (XOR operation)", "XOR_OP"))
        # XOR byte ptr [...], reg  (30 XX)
        elif data[i] == 0x30:
            patterns.append((i, "xor byte ptr [mem], reg  (byte XOR -- encryption/decryption)", "XOR_BYTE_ENCRYPT"))
        # XOR reg, byte ptr [...] (32 XX)
        elif data[i] == 0x32:
            patterns.append((i, "xor reg, byte ptr [mem]  (byte XOR read -- key derivation)", "XOR_BYTE_KEY"))
        # 8A ... 30 sequence (mov byte; xor byte) -- classic single-byte XOR loop body
        elif data[i] == 0x8A and i + 4 < len(data):
            # Look ahead for a 30 (XOR store) within a few bytes
            for j in range(i + 2, min(i + 8, len(data))):
                if data[j] == 0x30:
                    patterns.append((i, "mov byte + xor byte sequence (XOR encryption loop body)", "XOR_LOOP_BODY"))
                    break
        i += 1
    return patterns


def detect_xor_patterns_x64(data):
    """Scan x64 .text bytes for XOR-based encryption patterns."""
    patterns = []
    i = 0
    while i < len(data) - 2:
        # 45 33 XX -- xor r8-r15d, r8-r15d (REX.RB prefix)
        if data[i] == 0x45 and i + 2 < len(data) and data[i + 1] == 0x33:
            modrm = data[i + 2]
            src = (modrm >> 3) & 7
            dst = modrm & 7
            reg_names = ["r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
            if src == dst:
                patterns.append((i, f"xor {reg_names[dst]}, {reg_names[src]}  (zero register)", "ZERO_REG"))
            else:
                patterns.append((i, f"xor {reg_names[dst]}, {reg_names[src]}  (XOR operation)", "XOR_OP"))
        # 33 XX -- xor r32, r32
        elif data[i] == 0x33 and (i == 0 or data[i - 1] not in (0x45, 0x41, 0x44, 0x48, 0x4C)):
            modrm = data[i + 1]
            src = (modrm >> 3) & 7
            dst = modrm & 7
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if src == dst:
                patterns.append((i, f"xor {reg_names[dst]}, {reg_names[src]}  (zero register)", "ZERO_REG"))
        # 41 30 0c XX -- xor byte ptr [rN + ...], cl  -- the actual encryption XOR
        elif data[i] == 0x41 and i + 1 < len(data) and data[i + 1] == 0x30:
            patterns.append((i, "xor byte ptr [r-reg + idx], cl  (byte XOR -- encryption/decryption)", "XOR_BYTE_ENCRYPT"))
        # 42 30 0c XX -- REX.X xor
        elif data[i] == 0x42 and i + 1 < len(data) and data[i + 1] == 0x30:
            patterns.append((i, "xor byte ptr [base + r-idx], cl  (byte XOR -- encryption/decryption)", "XOR_BYTE_ENCRYPT"))
        # The magic constant 0x4EC4EC4F used for modulo-by-13 via multiply
        elif i + 3 < len(data) and data[i:i + 4] == b"\x4F\xEC\xC4\x4E":
            patterns.append((i, "constant 0x4EC4EC4F (magic number for mod-13 via imul)", "MOD13_MAGIC"))
        i += 1
    return patterns


def detect_magic_constants(data):
    """Detect important constants embedded in .text."""
    findings = []
    # 0x4EC4EC4F -- magic multiplier for unsigned division by 13
    magic = b"\x4F\xEC\xC4\x4E"  # little-endian would be 4F EC C4 4E but it appears as immediate
    # Actually in the raw bytes we see: b8 4f ec c4 4e  (mov eax, 0x4EC4EC4F)
    idx = 0
    while True:
        pos = data.find(b"\xB8\x4F\xEC\xC4\x4E", idx)
        if pos == -1:
            break
        findings.append((pos, "mov eax, 0x4EC4EC4F  (magic constant for i % 13 optimization)"))
        idx = pos + 1
    # 0x0D (13) as immediate -- push 0x0d or similar
    idx = 0
    while True:
        pos = data.find(b"\x6A\x0D", idx)
        if pos == -1:
            break
        findings.append((pos, "push 0x0D  (constant 13 -- XOR key length)"))
        idx = pos + 1
    return findings


def identify_prologue_epilogue(data, is_x64):
    """Identify function prologue and epilogue patterns."""
    info = {}
    if is_x64:
        # x64: look for REX mov patterns at start
        if len(data) >= 4 and data[0:2] == b"\x48\x89":
            info["prologue"] = "x64 standard (register saves via mov)"
        if data[-1:] == b"\xC3":
            info["epilogue"] = "ret (0xC3)"
    else:
        # x86: push ebp; mov ebp, esp pattern
        if len(data) >= 3 and data[0:3] == b"\x55\x8B\xEC":
            info["prologue"] = "x86 standard (push ebp; mov ebp, esp)"
        if len(data) >= 2 and data[-2:] == b"\xC9\xC3":
            info["epilogue"] = "leave; ret"
    return info


def generate_pseudocode(coff, text_data, xor_patterns, variant_name):
    """Generate C pseudocode reconstruction of the sleep mask logic."""

    is_smb = "smb" in variant_name.lower()
    is_tcp = "tcp" in variant_name.lower()
    is_x64 = coff.is_x64

    # Count XOR encryption operations to understand loop structure
    encrypt_xors = [p for p in xor_patterns if p[2] == "XOR_BYTE_ENCRYPT"]
    zero_regs = [p for p in xor_patterns if p[2] == "ZERO_REG"]
    mod13_magic = [p for p in xor_patterns if p[2] == "MOD13_MAGIC"]

    # Determine the number of mask/unmask passes
    # HTTP: 3 passes (beacon data, heap records forward, heap records backward)
    # SMB/TCP: 3 passes + pipe/socket handling in middle
    num_xor_loops = len(encrypt_xors)

    lines = []
    lines.append(f"/* Reconstructed C pseudocode for {variant_name} */")
    lines.append(f"/* Architecture: {'x64' if is_x64 else 'x86'} */")
    lines.append(f"/* Detected {num_xor_loops} XOR byte operations, {len(mod13_magic)} mod-13 multiplies */")
    lines.append("")

    # The structure definition
    lines.append("typedef struct {")
    lines.append("    char* beacon_base;    /* +0x00: base of beacon in memory */")
    lines.append("    DWORD beacon_length;  /* +0x04/08: length of beacon code */")
    lines.append("    char  mask_key[13];   /* +0x08/10: 13-byte XOR mask key */")
    lines.append("} BEACON_INFO;")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    void* base;           /* +0x00: heap allocation base */")
    lines.append("    DWORD length;         /* +0x04/08: allocation length */")
    lines.append("} HEAP_RECORD;")
    lines.append("")

    if is_smb:
        lines.append("typedef struct {")
        lines.append("    DWORD type;           /* 0 = named pipe */")
        lines.append("    HANDLE pipe_handle;   /* pipe handle */")
        lines.append("    FN_PEEK  fnPeek;      /* PeekNamedPipe */")
        lines.append("    FN_CLOSE fnClose;     /* CloseHandle */")
        lines.append("    FN_CONN  fnConnect;   /* ConnectNamedPipe */")
        lines.append("    FN_READ  fnRead;      /* ReadFile via struct */")
        lines.append("} PIPE_INFO;")
        lines.append("")

    if is_tcp:
        lines.append("typedef struct {")
        lines.append("    DWORD type;           /* 1 = TCP socket */")
        lines.append("    HANDLE socket;        /* socket or handle */")
        lines.append("    FN_CLOSE fnClose;     /* closesocket */")
        lines.append("    FN_ACCEPT fnAccept;   /* accept */")
        lines.append("} SOCKET_INFO;")
        lines.append("")

    lines.append("void sleep_mask(SLEEPMASK_INFO* info) {")
    lines.append("    BEACON_INFO* beacon  = &info->beacon_info;")
    lines.append("    char*        base    = beacon->beacon_base;")
    lines.append("    DWORD        length  = beacon->beacon_length;")
    lines.append("    char*        key     = beacon->mask_key;  /* 13 bytes */")
    lines.append("")
    lines.append("    /* === Phase 1: XOR-encrypt the beacon code section === */")
    lines.append("    if (base != NULL && length != 0) {")
    lines.append("        for (DWORD i = 0; i < length; i++) {")
    lines.append("            base[i] ^= key[i % 13];")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    /* === Phase 2: XOR-encrypt heap allocations (forward pass) === */")
    lines.append("    HEAP_RECORD* heaps = info->heap_records;")
    lines.append("    DWORD heap_count = heaps->count;")
    lines.append("    for (DWORD h = 0; heaps[h].base != NULL; h++) {")
    lines.append("        char* hbase = heaps[h].base;")
    lines.append("        DWORD hlen  = heaps[h].length;")
    lines.append("        for (DWORD i = 0; i < hlen; i++) {")
    lines.append("            hbase[i] ^= key[i % 13];")
    lines.append("        }")
    lines.append("    }")
    lines.append("")

    if is_smb:
        lines.append("    /* === Phase 2b (SMB): Handle named pipe reconnection === */")
        lines.append("    PIPE_INFO* pipe = info->pipe_info;")
        lines.append("    if (pipe->type == 0) {")
        lines.append("        /* Peek to check if pipe is alive */")
        lines.append("        if (pipe->fnPeek(pipe->pipe_handle, NULL, 0, NULL, NULL, NULL) == 0) {")
        lines.append("            /* Pipe broken -- close and reconnect */")
        lines.append("            pipe->fnClose(pipe->pipe_handle);")
        lines.append("            DWORD err = GetLastError();")
        lines.append("            if (err != ERROR_PIPE_NOT_CONNECTED) break;")
        lines.append("        }")
        lines.append("    } else if (pipe->type == 1) {")
        lines.append("        /* Wait for connection with retry */")
        lines.append("        do {")
        lines.append("            if (counter++ > max) Sleep(10);")
        lines.append("            OVERLAPPED ov = {0};")
        lines.append("            result = pipe->fnConnect(pipe->pipe_handle, NULL, NULL, NULL, 0, &ov);")
        lines.append("        } while (result == 0);")
        lines.append("    }")
        lines.append("")

    if is_tcp:
        lines.append("    /* === Phase 2b (TCP): Handle socket accept === */")
        lines.append("    SOCKET_INFO* sock = info->socket_info;")
        lines.append("    if (sock->type == 1) {")
        lines.append("        /* Close existing client socket, accept new */")
        lines.append("        sock->fnClose(sock->socket, NULL, 0);")
        lines.append("        sock->socket = 0;  /* reset */")
        lines.append("    } else {")
        lines.append("        /* TCP bind pivot -- accept with addr struct */")
        lines.append("        SOCKADDR addr;")
        lines.append("        sock->socket = sock->fnAccept(sock->listen_socket, &addr, 1);")
        lines.append("    }")
        lines.append("")

    lines.append("    /* === Phase 3: Call the beacon's sleep function === */")
    lines.append("    info->sleep_fn(info->sleep_time);")
    lines.append("")
    lines.append("    /* === Phase 4: XOR-decrypt heap allocations (reverse pass) === */")
    lines.append("    for (DWORD h = 0; heaps[h].base != NULL; h++) {")
    lines.append("        char* hbase = heaps[h].base;")
    lines.append("        DWORD hlen  = heaps[h].length;")
    lines.append("        for (DWORD i = 0; i < hlen; i++) {")
    lines.append("            hbase[i] ^= key[i % 13];")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    /* === Phase 5: XOR-decrypt the beacon code section === */")
    lines.append("    if (base != NULL && length != 0) {")
    lines.append("        for (DWORD i = 0; i < length; i++) {")
    lines.append("            base[i] ^= key[i % 13];")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def analyze_single_file(filepath):
    """Analyze a single COFF file and return structured data."""
    coff = COFFFile(filepath)
    text_sec = coff.get_text_section()

    result = OrderedDict()
    result["filename"] = coff.filename
    result["filepath"] = filepath
    result["filesize"] = len(coff.data)
    result["sha256"] = coff.file_hash()
    result["coff"] = coff

    # COFF metadata
    meta = OrderedDict()
    meta["machine"] = f"0x{coff.machine:04X} ({coff.machine_name})"
    meta["timestamp"] = f"0x{coff.timestamp:08X} ({datetime.fromtimestamp(coff.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
    meta["number_of_sections"] = coff.number_of_sections
    meta["number_of_symbols"] = coff.number_of_symbols
    meta["pointer_to_symbol_table"] = f"0x{coff.pointer_to_symbol_table:08X}"
    result["metadata"] = meta

    # Sections
    sec_info = []
    for i, sec in enumerate(coff.sections):
        s = OrderedDict()
        s["index"] = i + 1
        s["name"] = sec.name
        s["raw_data_size"] = sec.size_of_raw_data
        s["raw_data_offset"] = f"0x{sec.pointer_to_raw_data:08X}"
        s["relocations"] = sec.number_of_relocations
        s["flags"] = " | ".join(sec.flag_strings())
        sec_info.append(s)
    result["sections"] = sec_info

    # Symbols
    sym_info = []
    for sym in coff.symbols:
        s = OrderedDict()
        s["index"] = sym.index
        s["name"] = sym.name
        s["value"] = f"0x{sym.value:08X}"
        s["section"] = sym.section_number
        s["type"] = f"0x{sym.type:04X}"
        sc = STORAGE_CLASSES.get(sym.storage_class, f"0x{sym.storage_class:02X}")
        s["storage_class"] = sc
        s["aux_symbols"] = sym.number_of_aux_symbols
        sym_info.append(s)
    result["symbols"] = sym_info

    # .text analysis
    if text_sec:
        result["text_size"] = text_sec.size_of_raw_data
        result["text_data"] = text_sec.data

        # Prologue/epilogue
        result["func_info"] = identify_prologue_epilogue(text_sec.data, coff.is_x64)

        # XOR patterns
        if coff.is_x64:
            xor_pats = detect_xor_patterns_x64(text_sec.data)
        else:
            xor_pats = detect_xor_patterns_x86(text_sec.data)
        result["xor_patterns"] = xor_pats

        # Magic constants
        result["magic_constants"] = detect_magic_constants(text_sec.data)

        # Relocations on .text
        reloc_info = []
        for rel in text_sec.relocations:
            r = OrderedDict()
            r["offset"] = f"0x{rel.virtual_address:04X}"
            r["symbol"] = rel.symbol_name
            r["type"] = rel.type_name
            reloc_info.append(r)
        result["text_relocations"] = reloc_info

        # Pseudocode
        variant = coff.filename.replace(".o", "")
        result["pseudocode"] = generate_pseudocode(coff, text_sec.data, xor_pats, variant)
    else:
        result["text_size"] = 0
        result["text_data"] = b""
        result["xor_patterns"] = []
        result["magic_constants"] = []
        result["text_relocations"] = []
        result["pseudocode"] = "/* No .text section found */"

    return result


def print_separator(char="=", width=80):
    print(char * width)


def print_header(title, char="=", width=80):
    print()
    print_separator(char, width)
    print(f"  {title}")
    print_separator(char, width)


def print_subheader(title, char="-", width=60):
    print()
    print(f"  {title}")
    print(f"  {char * len(title)}")


def format_report(result):
    """Print a full report for a single file."""
    coff = result["coff"]

    print_header(f"FILE: {result['filename']}")
    print(f"  Path:     {result['filepath']}")
    print(f"  Size:     {result['filesize']} bytes")
    print(f"  SHA-256:  {result['sha256']}")

    # COFF metadata
    print_subheader("COFF Header")
    for k, v in result["metadata"].items():
        print(f"    {k:30s}: {v}")

    # Sections
    print_subheader("Section Table")
    print(f"    {'#':>3s}  {'Name':<12s}  {'Size':>8s}  {'Offset':>10s}  {'Relocs':>6s}  Flags")
    print(f"    {'---':>3s}  {'----':<12s}  {'----':>8s}  {'------':>10s}  {'------':>6s}  -----")
    for s in result["sections"]:
        print(f"    {s['index']:3d}  {s['name']:<12s}  {s['raw_data_size']:8d}  {s['raw_data_offset']:>10s}  {s['relocations']:6d}  {s['flags']}")

    # Build path from debug section
    debug_sec = coff.get_section_by_name(".debug$S")
    if debug_sec and debug_sec.data:
        # Try to extract the build path
        try:
            text = debug_sec.data.decode("ascii", errors="ignore")
            # Look for path-like strings
            for segment in text.split("\x00"):
                segment = segment.strip()
                if ":\\" in segment and segment.endswith(".o"):
                    print_subheader("Build Information")
                    print(f"    Build path: {segment}")
                    break
            # Look for compiler string
            for segment in text.split("\x00"):
                segment = segment.strip()
                if "Microsoft" in segment:
                    print(f"    Compiler:   {segment}")
                    break
        except Exception:
            pass

    # Symbols
    print_subheader("Symbol Table")
    print(f"    {'Idx':>4s}  {'Name':<30s}  {'Value':>10s}  {'Sect':>5s}  {'Type':>6s}  Storage Class")
    print(f"    {'---':>4s}  {'----':<30s}  {'-----':>10s}  {'----':>5s}  {'----':>6s}  -------------")
    for s in result["symbols"]:
        print(f"    {s['index']:4d}  {s['name']:<30s}  {s['value']:>10s}  {s['section']:5d}  {s['type']:>6s}  {s['storage_class']}")

    # .text relocations (external API references)
    if result["text_relocations"]:
        print_subheader(".text Relocations (API/Symbol References)")
        print(f"    {'Offset':>8s}  {'Type':<30s}  Symbol")
        print(f"    {'------':>8s}  {'----':<30s}  ------")
        for r in result["text_relocations"]:
            print(f"    {r['offset']:>8s}  {r['type']:<30s}  {r['symbol']}")

    # .text hex dump
    if result["text_data"]:
        print_subheader(f".text Section Hex Dump ({result['text_size']} bytes)")

        # Build annotation map from XOR patterns and magic constants
        ann = {}
        for offset, desc, _ in result["xor_patterns"]:
            ann[offset] = desc
        for offset, desc in result["magic_constants"]:
            ann[offset] = desc

        # Add prologue/epilogue annotations
        func_info = result.get("func_info", {})
        if "prologue" in func_info:
            ann[0] = f"PROLOGUE: {func_info['prologue']}"
        if "epilogue" in func_info and result["text_data"]:
            # Mark last few bytes
            end_off = len(result["text_data"]) - 2
            if end_off >= 0:
                ann[end_off] = f"EPILOGUE: {func_info['epilogue']}"

        print(hex_dump(result["text_data"], annotations=ann))

    # XOR pattern analysis
    if result["xor_patterns"]:
        print_subheader("Detected XOR / Encryption Patterns")
        xor_encrypt = [p for p in result["xor_patterns"] if p[2] == "XOR_BYTE_ENCRYPT"]
        xor_key = [p for p in result["xor_patterns"] if p[2] == "XOR_BYTE_KEY"]
        zero_regs = [p for p in result["xor_patterns"] if p[2] == "ZERO_REG"]
        mod13 = [p for p in result["xor_patterns"] if p[2] == "MOD13_MAGIC"]
        loop_body = [p for p in result["xor_patterns"] if p[2] == "XOR_LOOP_BODY"]

        print(f"    XOR byte encrypt/decrypt ops : {len(xor_encrypt)}")
        print(f"    XOR byte key derivation ops  : {len(xor_key)}")
        print(f"    XOR loop body sequences      : {len(loop_body)}")
        print(f"    Register zeroing (xor r,r)   : {len(zero_regs)}")
        print(f"    Mod-13 magic constants       : {len(mod13)}")
        print()
        for offset, desc, ptype in result["xor_patterns"]:
            marker = "*" if "encrypt" in desc.lower() or "ENCRYPT" in ptype else " "
            print(f"    {marker} 0x{offset:04X}: {desc}")

    # Magic constants
    if result["magic_constants"]:
        print_subheader("Notable Constants")
        for offset, desc in result["magic_constants"]:
            print(f"    0x{offset:04X}: {desc}")

    # Pseudocode
    print_subheader("Reconstructed C Pseudocode")
    for line in result["pseudocode"].split("\n"):
        print(f"    {line}")


def print_comparison(results):
    """Print a cross-file comparison matrix."""
    print_header("CROSS-FILE COMPARISON MATRIX")

    # Group by variant
    variants = OrderedDict()
    for r in results:
        name = r["filename"].replace(".o", "")
        variants[name] = r

    # Comparison table
    names = list(variants.keys())
    col_w = 18

    # Header row
    print(f"    {'Property':<30s}", end="")
    for n in names:
        # Shorten name for display
        short = n.replace("sleepmask", "sm").replace("_", ".")
        print(f"  {short:>{col_w}s}", end="")
    print()
    print(f"    {'--------':<30s}", end="")
    for _ in names:
        print(f"  {'-' * col_w:>{col_w}s}", end="")
    print()

    # Rows
    def row(label, fn):
        print(f"    {label:<30s}", end="")
        for n in names:
            val = fn(variants[n])
            print(f"  {str(val):>{col_w}s}", end="")
        print()

    row("File size (bytes)", lambda r: r["filesize"])
    row("Machine", lambda r: "x86" if "I386" in r["metadata"]["machine"] else "x64")
    row("Num sections", lambda r: r["metadata"]["number_of_sections"])
    row("Num symbols", lambda r: r["metadata"]["number_of_symbols"])
    row(".text size (bytes)", lambda r: r["text_size"])

    # XOR analysis
    row("XOR encrypt ops", lambda r: len([p for p in r["xor_patterns"] if p[2] == "XOR_BYTE_ENCRYPT"]))
    row("XOR key derivation ops", lambda r: len([p for p in r["xor_patterns"] if p[2] in ("XOR_BYTE_KEY", "XOR_LOOP_BODY")]))
    row("Register zeroing ops", lambda r: len([p for p in r["xor_patterns"] if p[2] == "ZERO_REG"]))
    row("Mod-13 magic consts", lambda r: len([p for p in r["xor_patterns"] if p[2] == "MOD13_MAGIC"]))
    row("Magic const (mov eax)", lambda r: len(r["magic_constants"]))
    row(".text relocations", lambda r: len(r["text_relocations"]))

    # Prologue/epilogue
    row("Prologue type", lambda r: r.get("func_info", {}).get("prologue", "N/A")[:col_w])
    row("Epilogue type", lambda r: r.get("func_info", {}).get("epilogue", "N/A")[:col_w])

    # SHA256 (truncated)
    row("SHA-256 (first 16)", lambda r: r["sha256"][:16])

    # Byte-level comparison of .text sections
    print_subheader("Pairwise .text Section Similarity")
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            d1 = variants[names[i]]["text_data"]
            d2 = variants[names[j]]["text_data"]
            if not d1 or not d2:
                continue
            min_len = min(len(d1), len(d2))
            max_len = max(len(d1), len(d2))
            matching = sum(1 for k in range(min_len) if d1[k] == d2[k])
            pct = (matching / max_len * 100) if max_len > 0 else 0
            n1 = names[i].replace("sleepmask", "sm").replace("_", ".")
            n2 = names[j].replace("sleepmask", "sm").replace("_", ".")
            print(f"    {n1} vs {n2}: {matching}/{max_len} bytes match ({pct:.1f}%)")

    # Architecture comparison
    print_subheader("Architecture Differences")
    x86_files = [n for n in names if "x86" in n]
    x64_files = [n for n in names if "x64" in n]
    if x86_files and x64_files:
        print(f"    x86 variants: {len(x86_files)} files, sections: {variants[x86_files[0]]['metadata']['number_of_sections']}")
        print(f"    x64 variants: {len(x64_files)} files, sections: {variants[x64_files[0]]['metadata']['number_of_sections']}")
        print(f"    x64 has extra sections: .xdata (unwind info), .pdata (exception directory)")
        x86_avg = sum(variants[n]["text_size"] for n in x86_files) / len(x86_files)
        x64_avg = sum(variants[n]["text_size"] for n in x64_files) / len(x64_files)
        print(f"    Avg .text size: x86={x86_avg:.0f}B, x64={x64_avg:.0f}B (ratio: {x64_avg / x86_avg:.2f}x)")

    # Variant comparison (HTTP vs SMB vs TCP)
    print_subheader("Variant Differences (HTTP vs SMB vs TCP)")
    for arch in ("x86", "x64"):
        http_name = f"sleepmask.{arch}"
        smb_name = f"sleepmask_smb.{arch}"
        tcp_name = f"sleepmask_tcp.{arch}"
        if http_name in variants and smb_name in variants and tcp_name in variants:
            http_sz = variants[http_name]["text_size"]
            smb_sz = variants[smb_name]["text_size"]
            tcp_sz = variants[tcp_name]["text_size"]
            print(f"    {arch}: HTTP .text={http_sz}B, SMB .text={smb_sz}B (+{smb_sz - http_sz}B), TCP .text={tcp_sz}B (+{tcp_sz - http_sz}B)")
            print(f"      SMB adds: pipe peek/reconnect logic (PeekNamedPipe, ConnectNamedPipe)")
            print(f"      TCP adds: socket accept logic (closesocket/accept)")


def print_summary(results):
    """Print a high-level executive summary."""
    print_header("EXECUTIVE SUMMARY")

    print("""
    The Cobalt Strike sleep mask is a Beacon Object File (BOF) that XOR-encrypts
    the beacon's memory during sleep to evade memory scanners. It uses a 13-byte
    XOR key and operates in a symmetric encrypt-sleep-decrypt cycle.

    Key findings:
""")

    print(f"    Files analyzed: {len(results)}")
    print(f"    Compiler: Microsoft (R) Optimizing Compiler (MSVC)")
    print(f"    Build system: Z:\\devcenter\\aggressor\\external\\sleepmask\\")
    print()
    print("    Core algorithm:")
    print("      1. XOR-encrypt beacon code region with 13-byte rotating key")
    print("      2. XOR-encrypt all tracked heap allocations with same key")
    print("      3. [SMB/TCP only] Handle pipe reconnection or socket accept")
    print("      4. Call beacon sleep function (the actual sleep)")
    print("      5. XOR-decrypt all heap allocations")
    print("      6. XOR-decrypt beacon code region")
    print()
    print("    The mod-13 operation is optimized by the compiler into a multiply")
    print("    by magic constant 0x4EC4EC4F followed by shift, avoiding slow DIV.")
    print()
    print("    Variant differences:")
    print("      - HTTP/HTTPS: Base sleep mask (encrypt, sleep, decrypt)")
    print("      - SMB: Adds PeekNamedPipe check + ConnectNamedPipe reconnect logic")
    print("      - TCP: Adds closesocket + accept for bind pivot handling")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

EXPECTED_FILES = [
    "sleepmask.x86.o",
    "sleepmask.x64.o",
    "sleepmask_smb.x86.o",
    "sleepmask_smb.x64.o",
    "sleepmask_tcp.x86.o",
    "sleepmask_tcp.x64.o",
]


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/sleeve_decrypted/")
        print(f"       {sys.argv[0]} /path/to/single_file.o")
        sys.exit(1)

    target = sys.argv[1]

    if os.path.isfile(target):
        # Single file mode
        result = analyze_single_file(target)
        format_report(result)
        return

    if not os.path.isdir(target):
        print(f"Error: {target} is not a file or directory")
        sys.exit(1)

    # Directory mode -- find and analyze all sleep mask files
    results = []
    found_files = []
    for fname in EXPECTED_FILES:
        fpath = os.path.join(target, fname)
        if os.path.isfile(fpath):
            found_files.append(fpath)
        else:
            print(f"  [WARN] Expected file not found: {fpath}")

    if not found_files:
        # Try to find any .o files
        for fname in sorted(os.listdir(target)):
            if fname.endswith(".o") and "sleepmask" in fname.lower():
                found_files.append(os.path.join(target, fname))

    if not found_files:
        print(f"Error: No sleep mask .o files found in {target}")
        sys.exit(1)

    print(f"\n  Found {len(found_files)} sleep mask BOF file(s) to analyze.\n")

    for fpath in found_files:
        try:
            result = analyze_single_file(fpath)
            results.append(result)
            format_report(result)
        except Exception as e:
            print(f"\n  [ERROR] Failed to parse {fpath}: {e}")
            import traceback
            traceback.print_exc()

    # Cross-file comparison
    if len(results) > 1:
        print_comparison(results)

    # Executive summary
    print_summary(results)


if __name__ == "__main__":
    main()
