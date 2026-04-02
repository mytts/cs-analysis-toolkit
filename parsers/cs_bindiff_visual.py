#!/usr/bin/env python3
"""
cs_bindiff_visual.py - Visual byte-level binary diff tool for Cobalt Strike sleeve templates.

Generates HTML heatmap visualizations and statistics for comparing DLL/BOF files
between Cobalt Strike sleeve template versions.

Usage:
    # Single file comparison
    python3 cs_bindiff_visual.py --file1 v461/beacon.dll --file2 v491/beacon.dll -o diff_beacon.html

    # Batch directory comparison
    python3 cs_bindiff_visual.py --dir1 sleeve_461/ --dir2 sleeve_491/ -o diff_report/

    # Quick stats only (no HTML)
    python3 cs_bindiff_visual.py --dir1 sleeve_461/ --dir2 sleeve_491/ --stats-only

No external dependencies beyond Python stdlib.
"""

import argparse
import csv
import html
import json
import math
import os
import struct
import sys
from collections import OrderedDict
from pathlib import Path

# ---------------------------------------------------------------------------
# PE / COFF Parsing
# ---------------------------------------------------------------------------

class PESection:
    """Represents a PE or COFF section."""
    __slots__ = ("name", "virtual_address", "virtual_size", "raw_offset", "raw_size")

    def __init__(self, name, virtual_address, virtual_size, raw_offset, raw_size):
        self.name = name
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.raw_offset = raw_offset
        self.raw_size = raw_size

    def contains_offset(self, file_offset):
        return self.raw_offset <= file_offset < self.raw_offset + self.raw_size

    def __repr__(self):
        return (f"PESection({self.name!r}, va=0x{self.virtual_address:x}, "
                f"vs=0x{self.virtual_size:x}, ro=0x{self.raw_offset:x}, rs=0x{self.raw_size:x})")


class ExportEntry:
    __slots__ = ("ordinal", "name", "rva")
    def __init__(self, ordinal, name, rva):
        self.ordinal = ordinal
        self.name = name
        self.rva = rva


def _read_str(data, offset, max_len=256):
    """Read a null-terminated ASCII string from data."""
    end = data.find(b'\x00', offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    return data[offset:end].decode('ascii', errors='replace')


def parse_pe(data):
    """Parse PE headers. Returns (sections, exports, is_pe, bitness)."""
    sections = []
    exports = []
    is_pe = False
    bitness = 32

    if len(data) < 64:
        return sections, exports, False, 0

    # Check MZ
    if data[:2] != b'MZ':
        return parse_coff(data)

    is_pe = True
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return sections, exports, False, 0

    # COFF header
    coff_off = pe_offset + 4
    machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from('<HHIIIHH', data, coff_off)
    opt_off = coff_off + 20

    # Optional header magic
    if opt_size >= 2:
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic == 0x20b:
            bitness = 64

    # Parse data directories for exports
    if bitness == 32 and opt_size >= 96:
        num_dd = struct.unpack_from('<I', data, opt_off + 92)[0]
        if num_dd > 0:
            export_rva, export_size = struct.unpack_from('<II', data, opt_off + 96)
            if export_rva and export_size:
                exports = _parse_exports(data, sections, export_rva, export_size, pe_offset, coff_off, num_sections, opt_off, opt_size)
    elif bitness == 64 and opt_size >= 112:
        num_dd = struct.unpack_from('<I', data, opt_off + 108)[0]
        if num_dd > 0:
            export_rva, export_size = struct.unpack_from('<II', data, opt_off + 112)
            if export_rva and export_size:
                exports = _parse_exports(data, sections, export_rva, export_size, pe_offset, coff_off, num_sections, opt_off, opt_size)

    # Section headers
    sec_off = opt_off + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name_raw = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vs, va, rs, ro = struct.unpack_from('<IIII', data, off + 8)
        sections.append(PESection(name_raw, va, vs, ro, rs))

    # Now parse exports if we have sections
    if not exports and bitness == 32 and opt_size >= 96:
        num_dd = struct.unpack_from('<I', data, opt_off + 92)[0]
        if num_dd > 0:
            export_rva, export_size = struct.unpack_from('<II', data, opt_off + 96)
            if export_rva and export_size:
                exports = _parse_exports_with_sections(data, sections, export_rva, export_size)
    elif not exports and bitness == 64 and opt_size >= 112:
        num_dd = struct.unpack_from('<I', data, opt_off + 108)[0]
        if num_dd > 0:
            export_rva, export_size = struct.unpack_from('<II', data, opt_off + 112)
            if export_rva and export_size:
                exports = _parse_exports_with_sections(data, sections, export_rva, export_size)

    return sections, exports, True, bitness


def _rva_to_offset(sections, rva):
    """Convert RVA to file offset using section table."""
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return rva - s.virtual_address + s.raw_offset
    return None


def _parse_exports(data, sections_placeholder, export_rva, export_size, pe_offset, coff_off, num_sections, opt_off, opt_size):
    """Attempt to parse exports - needs sections first, so we build them inline."""
    sections = []
    sec_off = opt_off + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name_raw = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vs, va, rs, ro = struct.unpack_from('<IIII', data, off + 8)
        sections.append(PESection(name_raw, va, vs, ro, rs))
    return _parse_exports_with_sections(data, sections, export_rva, export_size)


def _parse_exports_with_sections(data, sections, export_rva, export_size):
    """Parse PE export directory."""
    exports = []
    if not sections:
        return exports
    exp_off = _rva_to_offset(sections, export_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return exports
    try:
        (_, _, _, name_rva, ordinal_base, num_funcs, num_names,
         funcs_rva, names_rva, ords_rva) = struct.unpack_from('<IIIIIIIII I', data, exp_off)
    except struct.error:
        return exports

    funcs_off = _rva_to_offset(sections, funcs_rva)
    names_off = _rva_to_offset(sections, names_rva) if names_rva else None
    ords_off = _rva_to_offset(sections, ords_rva) if ords_rva else None

    if funcs_off is None:
        return exports

    # Build name->ordinal mapping
    name_map = {}
    if names_off and ords_off and num_names:
        for i in range(min(num_names, 4096)):
            no = names_off + i * 4
            oo = ords_off + i * 2
            if no + 4 > len(data) or oo + 2 > len(data):
                break
            name_rva_i = struct.unpack_from('<I', data, no)[0]
            ordinal_idx = struct.unpack_from('<H', data, oo)[0]
            str_off = _rva_to_offset(sections, name_rva_i)
            if str_off and str_off < len(data):
                name_map[ordinal_idx] = _read_str(data, str_off)

    for i in range(min(num_funcs, 4096)):
        fo = funcs_off + i * 4
        if fo + 4 > len(data):
            break
        func_rva = struct.unpack_from('<I', data, fo)[0]
        if func_rva == 0:
            continue
        ordinal = ordinal_base + i
        name = name_map.get(i, None)
        exports.append(ExportEntry(ordinal, name, func_rva))

    return exports


def parse_coff(data):
    """Parse COFF object file sections."""
    sections = []
    exports = []
    if len(data) < 20:
        return sections, exports, False, 0

    machine, num_sections, _, sym_off, num_syms, opt_size, _ = struct.unpack_from('<HHIIIHH', data, 0)

    # Validate machine type for COFF
    valid_machines = {0x14c, 0x8664, 0xaa64}  # i386, x64, arm64
    if machine not in valid_machines:
        return sections, exports, False, 0

    bitness = 64 if machine == 0x8664 else 32
    sec_off = 20 + opt_size

    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name_raw = data[off:off+8]
        # Handle long names via string table
        if name_raw[0:1] == b'/':
            try:
                str_table_off = sym_off + num_syms * 18
                idx = int(name_raw[1:8].rstrip(b'\x00').decode('ascii'))
                name = _read_str(data, str_table_off + idx)
            except (ValueError, IndexError):
                name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
        else:
            name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
        vs = struct.unpack_from('<I', data, off + 8)[0]
        va = struct.unpack_from('<I', data, off + 12)[0]
        rs = struct.unpack_from('<I', data, off + 16)[0]
        ro = struct.unpack_from('<I', data, off + 20)[0]
        sections.append(PESection(name, va, vs, ro, rs))

    return sections, exports, True, bitness


# ---------------------------------------------------------------------------
# Entropy Calculation
# ---------------------------------------------------------------------------

def shannon_entropy(data_block):
    """Calculate Shannon entropy of a data block (0.0 - 8.0)."""
    if not data_block:
        return 0.0
    freq = [0] * 256
    for b in data_block:
        freq[b] += 1
    length = len(data_block)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return ent


def entropy_blocks(data, block_size=256):
    """Calculate entropy per block. Returns list of floats."""
    result = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        result.append(shannon_entropy(block))
    return result


# ---------------------------------------------------------------------------
# Diff Engine
# ---------------------------------------------------------------------------

DIFF_IDENTICAL = 0
DIFF_MODIFIED = 1
DIFF_ADDED = 2
DIFF_REMOVED = 3

DIFF_COLORS = {
    DIFF_IDENTICAL: "#1c2128",
    DIFF_MODIFIED: "#f85149",
    DIFF_ADDED: "#3fb950",
    DIFF_REMOVED: "#6e7681",
}

DIFF_LABELS = {
    DIFF_IDENTICAL: "identical",
    DIFF_MODIFIED: "modified",
    DIFF_ADDED: "added",
    DIFF_REMOVED: "removed",
}


def compute_byte_diff(data1, data2):
    """Compute per-byte diff status array. Returns list of (byte_val_file2, status)."""
    max_len = max(len(data1), len(data2))
    result = []
    for i in range(max_len):
        if i < len(data1) and i < len(data2):
            if data1[i] == data2[i]:
                result.append((data2[i], DIFF_IDENTICAL))
            else:
                result.append((data2[i], DIFF_MODIFIED))
        elif i >= len(data1):
            result.append((data2[i], DIFF_ADDED))
        else:
            result.append((data1[i], DIFF_REMOVED))
    return result


class DiffStats:
    """Statistics for a single file comparison."""
    def __init__(self, name, data1, data2):
        self.name = name
        self.size1 = len(data1)
        self.size2 = len(data2)

        self.sections1, self.exports1, self.is_pe1, self.bits1 = parse_pe(data1)
        self.sections2, self.exports2, self.is_pe2, self.bits2 = parse_pe(data2)

        self.diff = compute_byte_diff(data1, data2)
        max_len = max(len(data1), len(data2))

        # Global counts
        self.identical = sum(1 for _, s in self.diff if s == DIFF_IDENTICAL)
        self.modified = sum(1 for _, s in self.diff if s == DIFF_MODIFIED)
        self.added = sum(1 for _, s in self.diff if s == DIFF_ADDED)
        self.removed = sum(1 for _, s in self.diff if s == DIFF_REMOVED)
        self.total = max_len

        # Per-section stats (use file2 sections as reference, fall back to file1)
        ref_sections = self.sections2 if self.sections2 else self.sections1
        self.section_stats = OrderedDict()
        accounted = set()
        for sec in ref_sections:
            sec_modified = 0
            sec_added = 0
            sec_removed = 0
            sec_identical = 0
            sec_total = 0
            for j in range(sec.raw_offset, min(sec.raw_offset + sec.raw_size, max_len)):
                if j < len(self.diff):
                    _, st = self.diff[j]
                    sec_total += 1
                    accounted.add(j)
                    if st == DIFF_IDENTICAL:
                        sec_identical += 1
                    elif st == DIFF_MODIFIED:
                        sec_modified += 1
                    elif st == DIFF_ADDED:
                        sec_added += 1
                    elif st == DIFF_REMOVED:
                        sec_removed += 1
            changed = sec_modified + sec_added + sec_removed
            pct = (changed / sec_total * 100) if sec_total else 0.0
            self.section_stats[sec.name] = {
                "total": sec_total,
                "identical": sec_identical,
                "modified": sec_modified,
                "added": sec_added,
                "removed": sec_removed,
                "changed": changed,
                "pct_change": pct,
            }

        # "other" / headers
        other_changed = 0
        other_total = 0
        for j in range(max_len):
            if j not in accounted and j < len(self.diff):
                other_total += 1
                _, st = self.diff[j]
                if st != DIFF_IDENTICAL:
                    other_changed += 1
        if other_total:
            self.section_stats["(headers/other)"] = {
                "total": other_total,
                "identical": other_total - other_changed,
                "modified": other_changed,
                "added": 0,
                "removed": 0,
                "changed": other_changed,
                "pct_change": (other_changed / other_total * 100) if other_total else 0.0,
            }

        # Entropy
        self.entropy1 = entropy_blocks(data1)
        self.entropy2 = entropy_blocks(data2)

        # Section entropy averages
        self.section_entropy = {}
        for sec in ref_sections:
            blk_start = sec.raw_offset // 256
            blk_end = (sec.raw_offset + sec.raw_size + 255) // 256
            e1_vals = self.entropy1[blk_start:blk_end] if blk_start < len(self.entropy1) else []
            e2_vals = self.entropy2[blk_start:blk_end] if blk_start < len(self.entropy2) else []
            self.section_entropy[sec.name] = {
                "avg_entropy1": sum(e1_vals) / len(e1_vals) if e1_vals else 0.0,
                "avg_entropy2": sum(e2_vals) / len(e2_vals) if e2_vals else 0.0,
            }

        # Export diff
        self.export_diff = self._diff_exports()

        # Data refs for HTML gen
        self._data1 = data1
        self._data2 = data2

    def _diff_exports(self):
        """Diff export tables."""
        exp1 = {e.name or f"ord_{e.ordinal}": e for e in self.exports1}
        exp2 = {e.name or f"ord_{e.ordinal}": e for e in self.exports2}
        all_names = sorted(set(exp1.keys()) | set(exp2.keys()))
        result = []
        for n in all_names:
            e1 = exp1.get(n)
            e2 = exp2.get(n)
            if e1 and e2:
                if e1.rva == e2.rva:
                    result.append((n, "unchanged", e1.rva, e2.rva))
                else:
                    result.append((n, "moved", e1.rva, e2.rva))
            elif e1 and not e2:
                result.append((n, "removed", e1.rva, None))
            else:
                result.append((n, "added", None, e2.rva))
        return result

    @property
    def pct_change(self):
        if self.total == 0:
            return 0.0
        return (self.modified + self.added + self.removed) / self.total * 100

    def format_stats(self):
        """Return human-readable stats string."""
        lines = []
        lines.append(f"=== {self.name} ===")
        lines.append(f"  File 1 size: {self.size1:,} bytes")
        lines.append(f"  File 2 size: {self.size2:,} bytes")
        lines.append(f"  Total compared: {self.total:,} bytes")
        lines.append(f"  Identical: {self.identical:,} ({self.identical/self.total*100:.1f}%)" if self.total else "  Identical: 0")
        lines.append(f"  Modified:  {self.modified:,} ({self.modified/self.total*100:.1f}%)" if self.total else "  Modified: 0")
        lines.append(f"  Added:     {self.added:,} ({self.added/self.total*100:.1f}%)" if self.total else "  Added: 0")
        lines.append(f"  Removed:   {self.removed:,} ({self.removed/self.total*100:.1f}%)" if self.total else "  Removed: 0")
        lines.append(f"  Overall change: {self.pct_change:.1f}%")
        lines.append("")
        lines.append("  Per-section breakdown:")
        for sec_name, ss in self.section_stats.items():
            lines.append(f"    {sec_name:15s}: {ss['changed']:6,} / {ss['total']:6,} changed ({ss['pct_change']:.1f}%)")
            if sec_name in self.section_entropy:
                se = self.section_entropy[sec_name]
                lines.append(f"      {'':15s}  entropy: {se['avg_entropy1']:.3f} -> {se['avg_entropy2']:.3f}")
        if self.export_diff:
            lines.append("")
            lines.append("  Export diff:")
            for name, status, rva1, rva2 in self.export_diff:
                if status == "unchanged":
                    lines.append(f"    {name}: unchanged (0x{rva1:x})")
                elif status == "moved":
                    lines.append(f"    {name}: moved 0x{rva1:x} -> 0x{rva2:x}")
                elif status == "removed":
                    lines.append(f"    {name}: REMOVED (was 0x{rva1:x})")
                elif status == "added":
                    lines.append(f"    {name}: ADDED (at 0x{rva2:x})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML Generation - Single File Diff
# ---------------------------------------------------------------------------

def _section_boundaries_json(sections):
    """Return JSON array of section boundaries for JS overlay."""
    result = []
    for s in sections:
        result.append({
            "name": s.name,
            "offset": s.raw_offset,
            "size": s.raw_size,
        })
    return json.dumps(result)


def _entropy_json(entropy_list):
    return json.dumps([round(e, 3) for e in entropy_list])


def generate_single_html(stats, output_path):
    """Generate self-contained HTML heatmap for a single file comparison."""
    # Downsample diff for heatmap if file is very large
    # Each cell = 1 byte, but we cap the grid for performance
    MAX_BYTES_DISPLAY = 200000  # show up to 200KB directly
    diff_data = stats.diff
    total_bytes = len(diff_data)
    sample_factor = 1
    if total_bytes > MAX_BYTES_DISPLAY:
        sample_factor = (total_bytes + MAX_BYTES_DISPLAY - 1) // MAX_BYTES_DISPLAY

    # Build compact diff arrays for JS
    # For each displayed cell: [byte_val_file1, byte_val_file2, status]
    cells_json_parts = []
    data1 = stats._data1
    data2 = stats._data2
    display_count = (total_bytes + sample_factor - 1) // sample_factor

    for i in range(0, total_bytes, sample_factor):
        if sample_factor == 1:
            b1 = data1[i] if i < len(data1) else -1
            b2 = data2[i] if i < len(data2) else -1
            _, st = diff_data[i]
        else:
            # Summarize block: worst status wins
            block_end = min(i + sample_factor, total_bytes)
            worst = DIFF_IDENTICAL
            for j in range(i, block_end):
                _, st = diff_data[j]
                if st == DIFF_MODIFIED:
                    worst = DIFF_MODIFIED
                    break
                elif st == DIFF_ADDED and worst < DIFF_ADDED:
                    worst = DIFF_ADDED
                elif st == DIFF_REMOVED and worst < DIFF_REMOVED:
                    worst = DIFF_REMOVED
            b1 = data1[i] if i < len(data1) else -1
            b2 = data2[i] if i < len(data2) else -1
            st = worst
        cells_json_parts.append(f"[{b1},{b2},{st}]")

    cells_json = "[" + ",".join(cells_json_parts) + "]"

    ref_sections = stats.sections2 if stats.sections2 else stats.sections1
    sections_json = _section_boundaries_json(ref_sections)
    entropy1_json = _entropy_json(stats.entropy1)
    entropy2_json = _entropy_json(stats.entropy2)

    # Section stats for the stats bar
    sec_stats_rows = []
    for sec_name, ss in stats.section_stats.items():
        sec_stats_rows.append(f"<tr><td>{html.escape(sec_name)}</td>"
                              f"<td>{ss['total']:,}</td>"
                              f"<td>{ss['modified']:,}</td><td>{ss['added']:,}</td>"
                              f"<td>{ss['removed']:,}</td>"
                              f"<td>{ss['pct_change']:.1f}%</td></tr>")
    sec_stats_html = "\n".join(sec_stats_rows)

    # Entropy per section
    entropy_rows = []
    for sec_name, se in stats.section_entropy.items():
        delta = se['avg_entropy2'] - se['avg_entropy1']
        arrow = "+" if delta > 0 else ""
        entropy_rows.append(f"<tr><td>{html.escape(sec_name)}</td>"
                            f"<td>{se['avg_entropy1']:.3f}</td>"
                            f"<td>{se['avg_entropy2']:.3f}</td>"
                            f"<td>{arrow}{delta:.3f}</td></tr>")
    entropy_html = "\n".join(entropy_rows)

    # Export diff
    export_rows = []
    for name, status, rva1, rva2 in stats.export_diff:
        cls = {"unchanged": "exp-same", "moved": "exp-moved", "removed": "exp-removed", "added": "exp-added"}.get(status, "")
        r1 = f"0x{rva1:x}" if rva1 is not None else "-"
        r2 = f"0x{rva2:x}" if rva2 is not None else "-"
        export_rows.append(f'<tr class="{cls}"><td>{html.escape(name or "?")}</td>'
                           f'<td>{status}</td><td>{r1}</td><td>{r2}</td></tr>')
    export_html = "\n".join(export_rows) if export_rows else "<tr><td colspan='4'>No exports</td></tr>"

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Binary Diff: {html.escape(stats.name)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0d1117; color: #c9d1d9; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 13px; }}
h1 {{ padding: 16px 24px; font-size: 18px; border-bottom: 1px solid #21262d; }}
h2 {{ font-size: 14px; color: #8b949e; margin: 12px 0 8px 0; }}
.top-bar {{ display: flex; gap: 24px; padding: 12px 24px; background: #161b22; border-bottom: 1px solid #21262d; flex-wrap: wrap; align-items: center; }}
.stat-box {{ background: #21262d; border-radius: 6px; padding: 8px 14px; }}
.stat-box .label {{ color: #8b949e; font-size: 11px; }}
.stat-box .value {{ font-size: 16px; font-weight: bold; }}
.stat-box.mod .value {{ color: #f85149; }}
.stat-box.add .value {{ color: #3fb950; }}
.stat-box.rem .value {{ color: #6e7681; }}
.stat-box.pct .value {{ color: #f0883e; }}
.panels {{ display: flex; gap: 0; height: calc(100vh - 350px); min-height: 300px; }}
.panel {{ flex: 1; overflow: hidden; position: relative; border-right: 1px solid #21262d; }}
.panel-header {{ background: #161b22; padding: 6px 12px; font-size: 12px; color: #8b949e; border-bottom: 1px solid #21262d; display: flex; justify-content: space-between; }}
.heatmap-wrap {{ overflow: auto; height: calc(100% - 28px); }}
.heatmap {{ position: relative; }}
canvas {{ display: block; image-rendering: pixelated; }}
.section-overlay {{ position: absolute; top: 0; left: 0; pointer-events: none; }}
.section-label {{ position: absolute; color: #58a6ff; font-size: 10px; background: rgba(13,17,23,0.85); padding: 1px 4px; border-left: 2px solid #58a6ff; pointer-events: none; white-space: nowrap; }}
.bottom {{ padding: 16px 24px; overflow: auto; max-height: 350px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
th, td {{ padding: 4px 10px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ color: #8b949e; font-weight: normal; font-size: 11px; }}
.exp-moved td {{ color: #f0883e; }}
.exp-removed td {{ color: #f85149; }}
.exp-added td {{ color: #3fb950; }}
.legend {{ display: flex; gap: 16px; padding: 8px 24px; background: #161b22; border-top: 1px solid #21262d; }}
.legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 11px; color: #8b949e; }}
.legend-color {{ width: 12px; height: 12px; border-radius: 2px; }}
#entropy-canvas {{ width: 100%; height: 60px; background: #0d1117; border: 1px solid #21262d; border-radius: 4px; }}
.tabs {{ display: flex; gap: 0; border-bottom: 1px solid #21262d; margin-bottom: 8px; }}
.tab {{ padding: 6px 16px; cursor: pointer; color: #8b949e; border-bottom: 2px solid transparent; }}
.tab.active {{ color: #c9d1d9; border-bottom-color: #f0883e; }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}
.tooltip {{ position: fixed; background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 6px 10px; font-size: 11px; pointer-events: none; z-index: 100; display: none; }}
</style>
</head>
<body>
<h1>Binary Diff: {html.escape(stats.name)}</h1>
<div class="top-bar">
  <div class="stat-box"><div class="label">File 1</div><div class="value">{stats.size1:,} B</div></div>
  <div class="stat-box"><div class="label">File 2</div><div class="value">{stats.size2:,} B</div></div>
  <div class="stat-box mod"><div class="label">Modified</div><div class="value">{stats.modified:,}</div></div>
  <div class="stat-box add"><div class="label">Added</div><div class="value">{stats.added:,}</div></div>
  <div class="stat-box rem"><div class="label">Removed</div><div class="value">{stats.removed:,}</div></div>
  <div class="stat-box pct"><div class="label">Change</div><div class="value">{stats.pct_change:.1f}%</div></div>
  <div class="stat-box"><div class="label">Sample</div><div class="value">1:{sample_factor}</div></div>
</div>

<div class="panels">
  <div class="panel" id="panel-left">
    <div class="panel-header"><span>File 1 ({stats.size1:,} B)</span><span id="pos-left"></span></div>
    <div class="heatmap-wrap" id="wrap-left">
      <canvas id="canvas-left"></canvas>
      <div class="section-overlay" id="overlay-left"></div>
    </div>
  </div>
  <div class="panel" id="panel-right">
    <div class="panel-header"><span>File 2 ({stats.size2:,} B)</span><span id="pos-right"></span></div>
    <div class="heatmap-wrap" id="wrap-right">
      <canvas id="canvas-right"></canvas>
      <div class="section-overlay" id="overlay-right"></div>
    </div>
  </div>
</div>

<div class="legend">
  <div class="legend-item"><div class="legend-color" style="background:#1c2128"></div>Identical</div>
  <div class="legend-item"><div class="legend-color" style="background:#f85149"></div>Modified</div>
  <div class="legend-item"><div class="legend-color" style="background:#3fb950"></div>Added</div>
  <div class="legend-item"><div class="legend-color" style="background:#6e7681"></div>Removed</div>
</div>

<div class="bottom">
  <div class="tabs">
    <div class="tab active" onclick="switchTab(this, 'tab-sections')">Sections</div>
    <div class="tab" onclick="switchTab(this, 'tab-entropy')">Entropy</div>
    <div class="tab" onclick="switchTab(this, 'tab-exports')">Exports</div>
  </div>
  <div class="tab-content active" id="tab-sections">
    <table>
      <tr><th>Section</th><th>Size</th><th>Modified</th><th>Added</th><th>Removed</th><th>% Changed</th></tr>
      {sec_stats_html}
    </table>
  </div>
  <div class="tab-content" id="tab-entropy">
    <table>
      <tr><th>Section</th><th>Entropy (File1)</th><th>Entropy (File2)</th><th>Delta</th></tr>
      {entropy_html}
    </table>
    <h2>Entropy Graph (256-byte blocks)</h2>
    <canvas id="entropy-canvas" width="900" height="60"></canvas>
  </div>
  <div class="tab-content" id="tab-exports">
    <table>
      <tr><th>Name</th><th>Status</th><th>RVA (File1)</th><th>RVA (File2)</th></tr>
      {export_html}
    </table>
  </div>
</div>

<div class="tooltip" id="tooltip"></div>

<script>
const CELLS = {cells_json};
const SECTIONS = {sections_json};
const ENTROPY1 = {entropy1_json};
const ENTROPY2 = {entropy2_json};
const SAMPLE = {sample_factor};
const TOTAL_BYTES = {total_bytes};
const COLORS = ["#1c2128","#f85149","#3fb950","#6e7681"];
const COLS = 128;

function switchTab(el, id) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(id).classList.add('active');
  if (id === 'tab-entropy') drawEntropy();
}}

function drawHeatmap() {{
  const rows = Math.ceil(CELLS.length / COLS);
  const cellSize = 4;
  const w = COLS * cellSize;
  const h = rows * cellSize;

  ['left','right'].forEach(side => {{
    const canvas = document.getElementById('canvas-' + side);
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    const img = ctx.createImageData(w, h);
    const d = img.data;

    for (let i = 0; i < CELLS.length; i++) {{
      const [b1, b2, st] = CELLS[i];
      const bval = side === 'left' ? b1 : b2;
      const col = COLORS[st];
      // parse hex color
      const r = parseInt(col.slice(1,3), 16);
      const g = parseInt(col.slice(3,5), 16);
      const b = parseInt(col.slice(5,7), 16);
      // Modulate brightness by byte value for non-identical
      let br = 1.0;
      if (st === 0 && bval >= 0) {{
        br = 0.3 + (bval / 255) * 0.7;
      }}
      const row = Math.floor(i / COLS);
      const c = i % COLS;
      for (let dy = 0; dy < cellSize; dy++) {{
        for (let dx = 0; dx < cellSize; dx++) {{
          const px = ((row * cellSize + dy) * w + (c * cellSize + dx)) * 4;
          d[px] = Math.floor(r * br);
          d[px+1] = Math.floor(g * br);
          d[px+2] = Math.floor(b * br);
          d[px+3] = 255;
        }}
      }}
    }}
    ctx.putImageData(img, 0, 0);

    // Section overlays
    const overlay = document.getElementById('overlay-' + side);
    overlay.style.width = w + 'px';
    overlay.style.height = h + 'px';
    SECTIONS.forEach(sec => {{
      const startCell = Math.floor(sec.offset / SAMPLE);
      const endCell = Math.floor((sec.offset + sec.size) / SAMPLE);
      const startRow = Math.floor(startCell / COLS);
      const lbl = document.createElement('div');
      lbl.className = 'section-label';
      lbl.textContent = sec.name;
      lbl.style.top = (startRow * cellSize) + 'px';
      lbl.style.left = '0px';
      overlay.appendChild(lbl);
    }});
  }});
}}

// Sync scroll
(function() {{
  const wl = document.getElementById('wrap-left');
  const wr = document.getElementById('wrap-right');
  let syncing = false;
  function syncScroll(src, dst) {{
    if (syncing) return;
    syncing = true;
    dst.scrollTop = src.scrollTop;
    dst.scrollLeft = src.scrollLeft;
    syncing = false;
  }}
  wl.addEventListener('scroll', () => syncScroll(wl, wr));
  wr.addEventListener('scroll', () => syncScroll(wr, wl));
}})();

// Tooltip
(function() {{
  const tip = document.getElementById('tooltip');
  ['left','right'].forEach(side => {{
    const canvas = document.getElementById('canvas-' + side);
    canvas.addEventListener('mousemove', e => {{
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const cellSize = 4;
      const col = Math.floor(x / cellSize);
      const row = Math.floor(y / cellSize);
      const idx = row * COLS + col;
      if (idx >= 0 && idx < CELLS.length) {{
        const [b1, b2, st] = CELLS[idx];
        const fileOff = idx * SAMPLE;
        const labels = ['identical','modified','added','removed'];
        let secName = '(header)';
        for (const s of SECTIONS) {{
          if (fileOff >= s.offset && fileOff < s.offset + s.size) {{ secName = s.name; break; }}
        }}
        tip.innerHTML = `Offset: 0x${{fileOff.toString(16)}} | ${{secName}}<br>` +
          `File1: 0x${{(b1>=0?b1.toString(16):'--')}} | File2: 0x${{(b2>=0?b2.toString(16):'--')}}<br>` +
          `Status: ${{labels[st]}}`;
        tip.style.display = 'block';
        tip.style.left = (e.clientX + 12) + 'px';
        tip.style.top = (e.clientY + 12) + 'px';
      }}
    }});
    canvas.addEventListener('mouseleave', () => {{ tip.style.display = 'none'; }});
  }});
}})();

function drawEntropy() {{
  const canvas = document.getElementById('entropy-canvas');
  if (!canvas) return;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = Math.max(rect.width - 48, 400);
  canvas.height = 60;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const maxBlocks = Math.max(ENTROPY1.length, ENTROPY2.length);
  if (maxBlocks === 0) return;
  const bw = canvas.width / maxBlocks;

  // File 1 - blue
  ctx.beginPath();
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 1;
  for (let i = 0; i < ENTROPY1.length; i++) {{
    const x = i * bw;
    const y = canvas.height - (ENTROPY1[i] / 8.0) * canvas.height;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }}
  ctx.stroke();

  // File 2 - orange
  ctx.beginPath();
  ctx.strokeStyle = '#f0883e';
  ctx.lineWidth = 1;
  for (let i = 0; i < ENTROPY2.length; i++) {{
    const x = i * bw;
    const y = canvas.height - (ENTROPY2[i] / 8.0) * canvas.height;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }}
  ctx.stroke();

  // Labels
  ctx.fillStyle = '#58a6ff'; ctx.font = '10px monospace';
  ctx.fillText('File 1', 4, 12);
  ctx.fillStyle = '#f0883e';
  ctx.fillText('File 2', 54, 12);
}}

drawHeatmap();
</script>
</body>
</html>"""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(doc)
    return output_path


# ---------------------------------------------------------------------------
# HTML Generation - Dashboard
# ---------------------------------------------------------------------------

def generate_dashboard_html(all_stats, output_dir):
    """Generate batch comparison dashboard."""
    os.makedirs(output_dir, exist_ok=True)

    # Sort by % change descending
    all_stats.sort(key=lambda s: s.pct_change, reverse=True)

    # Generate individual diffs
    file_links = []
    for st in all_stats:
        fname = st.name.replace('/', '_').replace('\\', '_') + ".html"
        fpath = os.path.join(output_dir, fname)
        generate_single_html(st, fpath)
        file_links.append((st, fname))

    # Pie chart data: aggregate changes by section category
    cat_changes = {"text": 0, "rdata": 0, "data": 0, "other": 0}
    for st in all_stats:
        for sec_name, ss in st.section_stats.items():
            sn = sec_name.lower().strip('.')
            if 'text' in sn:
                cat_changes["text"] += ss["changed"]
            elif 'rdata' in sn:
                cat_changes["rdata"] += ss["changed"]
            elif 'data' in sn and 'rdata' not in sn:
                cat_changes["data"] += ss["changed"]
            else:
                cat_changes["other"] += ss["changed"]

    total_changes = sum(cat_changes.values()) or 1
    pie_data = json.dumps(cat_changes)

    # File table rows
    table_rows = []
    for st, fname in file_links:
        bar_w = min(st.pct_change, 100)
        spark_mod = st.modified / max(st.total, 1) * 100
        spark_add = st.added / max(st.total, 1) * 100
        spark_rem = st.removed / max(st.total, 1) * 100
        table_rows.append(f"""<tr onclick="window.open('{html.escape(fname)}','_blank')" style="cursor:pointer">
  <td>{html.escape(st.name)}</td>
  <td>{st.size1:,}</td><td>{st.size2:,}</td>
  <td>{st.modified:,}</td><td>{st.added:,}</td><td>{st.removed:,}</td>
  <td>{st.pct_change:.1f}%</td>
  <td><div class="spark-bar">
    <div class="spark-seg" style="width:{spark_mod:.1f}%;background:#f85149"></div>
    <div class="spark-seg" style="width:{spark_add:.1f}%;background:#3fb950"></div>
    <div class="spark-seg" style="width:{spark_rem:.1f}%;background:#6e7681"></div>
  </div></td>
</tr>""")
    table_html = "\n".join(table_rows)

    dashboard = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Binary Diff Dashboard</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0d1117; color: #c9d1d9; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 13px; }}
h1 {{ padding: 20px 24px; font-size: 20px; border-bottom: 1px solid #21262d; }}
.summary {{ display: flex; gap: 24px; padding: 16px 24px; flex-wrap: wrap; align-items: flex-start; }}
.summary-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; min-width: 200px; }}
.summary-card h3 {{ color: #8b949e; font-size: 12px; margin-bottom: 8px; }}
.big-num {{ font-size: 28px; font-weight: bold; color: #f0883e; }}
.file-table {{ padding: 0 24px 24px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 6px 12px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ color: #8b949e; font-weight: normal; font-size: 11px; position: sticky; top: 0; background: #0d1117; }}
tr:hover {{ background: #161b22; }}
.spark-bar {{ display: flex; height: 10px; width: 120px; background: #1c2128; border-radius: 2px; overflow: hidden; }}
.spark-seg {{ height: 100%; }}
canvas {{ display: block; }}
.pie-wrap {{ width: 160px; height: 160px; }}
.pie-legend {{ margin-top: 8px; font-size: 11px; }}
.pie-legend div {{ display: flex; align-items: center; gap: 6px; margin: 2px 0; }}
.pie-legend .dot {{ width: 10px; height: 10px; border-radius: 2px; }}
</style>
</head>
<body>
<h1>CS Sleeve Binary Diff Dashboard</h1>
<div class="summary">
  <div class="summary-card">
    <h3>Files Compared</h3>
    <div class="big-num">{len(all_stats)}</div>
  </div>
  <div class="summary-card">
    <h3>Total Bytes Changed</h3>
    <div class="big-num">{sum(s.modified + s.added + s.removed for s in all_stats):,}</div>
  </div>
  <div class="summary-card">
    <h3>Avg Change</h3>
    <div class="big-num">{sum(s.pct_change for s in all_stats)/max(len(all_stats),1):.1f}%</div>
  </div>
  <div class="summary-card">
    <h3>Change Distribution</h3>
    <div class="pie-wrap"><canvas id="pie" width="160" height="160"></canvas></div>
    <div class="pie-legend">
      <div><div class="dot" style="background:#f85149"></div>.text: {cat_changes['text']:,}</div>
      <div><div class="dot" style="background:#3fb950"></div>.rdata: {cat_changes['rdata']:,}</div>
      <div><div class="dot" style="background:#58a6ff"></div>.data: {cat_changes['data']:,}</div>
      <div><div class="dot" style="background:#6e7681"></div>other: {cat_changes['other']:,}</div>
    </div>
  </div>
</div>

<div class="file-table">
<h2 style="padding:8px 0;color:#8b949e;font-size:14px">Per-File Summary (click to open diff)</h2>
<table>
<tr><th>File</th><th>Size 1</th><th>Size 2</th><th>Modified</th><th>Added</th><th>Removed</th><th>% Change</th><th>Distribution</th></tr>
{table_html}
</table>
</div>

<script>
const PIE = {pie_data};
const colors = {{"text":"#f85149","rdata":"#3fb950","data":"#58a6ff","other":"#6e7681"}};
const total = Object.values(PIE).reduce((a,b)=>a+b, 0) || 1;
const canvas = document.getElementById('pie');
const ctx = canvas.getContext('2d');
const cx = 80, cy = 80, r = 70;
let startAngle = -Math.PI/2;
for (const [key, val] of Object.entries(PIE)) {{
  const slice = (val / total) * Math.PI * 2;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, r, startAngle, startAngle + slice);
  ctx.closePath();
  ctx.fillStyle = colors[key];
  ctx.fill();
  startAngle += slice;
}}
// Center hole for donut
ctx.beginPath();
ctx.arc(cx, cy, 35, 0, Math.PI*2);
ctx.fillStyle = '#161b22';
ctx.fill();
</script>
</body>
</html>"""

    dash_path = os.path.join(output_dir, "index.html")
    with open(dash_path, 'w') as f:
        f.write(dashboard)
    return dash_path


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def export_csv(all_stats, output_path):
    """Export per-file statistics to CSV."""
    with open(output_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["file", "size1", "size2", "identical", "modified", "added", "removed",
                     "pct_change", "section", "sec_total", "sec_modified", "sec_added",
                     "sec_removed", "sec_pct_change", "sec_entropy1", "sec_entropy2"])
        for st in all_stats:
            for sec_name, ss in st.section_stats.items():
                se = st.section_entropy.get(sec_name, {})
                w.writerow([st.name, st.size1, st.size2, st.identical, st.modified,
                            st.added, st.removed, f"{st.pct_change:.2f}",
                            sec_name, ss["total"], ss["modified"], ss["added"],
                            ss["removed"], f"{ss['pct_change']:.2f}",
                            f"{se.get('avg_entropy1',0):.4f}", f"{se.get('avg_entropy2',0):.4f}"])


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def compare_single(file1, file2, output, stats_only=False):
    """Compare two individual files."""
    with open(file1, 'rb') as f:
        data1 = f.read()
    with open(file2, 'rb') as f:
        data2 = f.read()

    name = f"{os.path.basename(file1)} vs {os.path.basename(file2)}"
    stats = DiffStats(name, data1, data2)
    print(stats.format_stats())

    if not stats_only:
        out_path = generate_single_html(stats, output)
        print(f"\nHTML diff written to: {out_path}")
    return stats


def compare_dirs(dir1, dir2, output_dir, stats_only=False):
    """Compare matching files across two directories."""
    if not os.path.isdir(dir1):
        print(f"Error: {dir1} is not a directory")
        sys.exit(1)
    if not os.path.isdir(dir2):
        print(f"Error: {dir2} is not a directory")
        print("Hint: use --file1/--file2 for individual file comparison")
        sys.exit(1)

    files1 = set(os.listdir(dir1))
    files2 = set(os.listdir(dir2))
    common = sorted(files1 & files2)
    only1 = sorted(files1 - files2)
    only2 = sorted(files2 - files1)

    if only1:
        print(f"Only in dir1: {', '.join(only1[:10])}{'...' if len(only1) > 10 else ''}")
    if only2:
        print(f"Only in dir2: {', '.join(only2[:10])}{'...' if len(only2) > 10 else ''}")

    all_stats = []
    for fname in common:
        p1 = os.path.join(dir1, fname)
        p2 = os.path.join(dir2, fname)
        if not os.path.isfile(p1) or not os.path.isfile(p2):
            continue
        with open(p1, 'rb') as f:
            data1 = f.read()
        with open(p2, 'rb') as f:
            data2 = f.read()
        stats = DiffStats(fname, data1, data2)
        all_stats.append(stats)
        print(stats.format_stats())
        print()

    if not stats_only and all_stats:
        dash = generate_dashboard_html(all_stats, output_dir)
        csv_path = os.path.join(output_dir, "diff_stats.csv")
        export_csv(all_stats, csv_path)
        print(f"\nDashboard: {dash}")
        print(f"CSV stats: {csv_path}")
        print(f"Individual diffs: {output_dir}/")
    elif stats_only and all_stats:
        csv_path = output_dir.rstrip('/') + "_stats.csv"
        export_csv(all_stats, csv_path)
        print(f"\nCSV stats: {csv_path}")

    return all_stats


def main():
    parser = argparse.ArgumentParser(
        description="Visual byte-level binary diff for Cobalt Strike sleeve templates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --file1 v461/beacon.dll --file2 v491/beacon.dll -o diff.html
  %(prog)s --dir1 sleeve_461/ --dir2 sleeve_491/ -o diff_report/
  %(prog)s --dir1 sleeve_461/ --dir2 sleeve_491/ --stats-only
""")
    parser.add_argument('--file1', help='First file to compare')
    parser.add_argument('--file2', help='Second file to compare')
    parser.add_argument('--dir1', help='First directory to compare')
    parser.add_argument('--dir2', help='Second directory to compare')
    parser.add_argument('-o', '--output', default='diff_output.html',
                        help='Output file (single) or directory (batch)')
    parser.add_argument('--stats-only', action='store_true',
                        help='Print statistics only, no HTML generation')

    args = parser.parse_args()

    if args.file1 and args.file2:
        compare_single(args.file1, args.file2, args.output, args.stats_only)
    elif args.dir1 and args.dir2:
        compare_dirs(args.dir1, args.dir2, args.output, args.stats_only)
    elif args.dir1 and not args.dir2:
        print(f"Error: --dir2 not provided.")
        print("For single file comparison, use --file1 and --file2.")
        sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
