#!/usr/bin/env python3
"""
Cobalt Strike Sleeve 模板对比 + 自动 YARA 生成器
==================================================
对比不同版本的 Sleeve 模板, 分析差异, 自动生成 YARA 规则。

功能:
1. 版本对比: 4.6.1 vs 4.9.1 文件差异
2. 模板分析: PE 结构、导出函数、标记位置
3. YARA 生成: 从解密模板自动提取特征生成 YARA 规则

用法:
    python3 cs_sleeve_compare.py compare --v1 sleeve_461/ --v2 sleeve_491/
    python3 cs_sleeve_compare.py analyze --dir sleeve_decrypted/
    python3 cs_sleeve_compare.py yara --dir sleeve_decrypted/ -o generated.yar
"""

import argparse
import hashlib
import os
import struct
import sys
from pathlib import Path
from collections import defaultdict

# ─── PE 分析工具 ─────────────────────────────────────────────
def analyze_pe(data: bytes) -> dict:
    """分析 PE 文件基本结构"""
    result = {"valid_pe": False}

    if len(data) < 64 or data[:2] != b'MZ':
        # 检查是否是 COFF object
        if len(data) >= 20:
            machine = struct.unpack("<H", data[0:2])[0]
            if machine in (0x14C, 0x8664):
                num_sec = struct.unpack("<H", data[2:4])[0]
                if 1 <= num_sec <= 30:
                    result["format"] = "COFF"
                    result["arch"] = "x86" if machine == 0x14C else "x64"
                    result["sections"] = num_sec
                    return result
        result["format"] = "unknown"
        return result

    result["valid_pe"] = True
    result["format"] = "PE"

    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if e_lfanew + 24 > len(data):
        return result

    machine = struct.unpack("<H", data[e_lfanew+4:e_lfanew+6])[0]
    result["arch"] = "x86" if machine == 0x14C else "x64" if machine == 0x8664 else f"0x{machine:04X}"
    result["sections"] = struct.unpack("<H", data[e_lfanew+6:e_lfanew+8])[0]

    opt_offset = e_lfanew + 24
    opt_magic = struct.unpack("<H", data[opt_offset:opt_offset+2])[0]
    result["pe_type"] = "PE32" if opt_magic == 0x10B else "PE32+"

    # 导出函数
    exports = []
    for name in [b"ReflectiveLoader", b"_ReflectiveLoader", b"DllMain", b"DllEntryPoint"]:
        if name in data:
            exports.append(name.decode())
    result["exports"] = exports

    # 标记搜索
    markers = {}
    marker_defs = {
        "StringTable": b"TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ",
        "Guardrails": b"GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd",
        "PostEx": b"ZZZZZZZXXXXWYYYY",
        "Settings": b"AAAABBBBCCCCDDDDEEEEFFFF",
    }
    for mname, mval in marker_defs.items():
        pos = data.find(mval)
        if pos != -1:
            markers[mname] = pos
    result["markers"] = markers

    return result


def classify_file(name: str) -> tuple:
    """分类 Sleeve 文件 → (类别, 架构, 变体)"""
    name_lower = name.lower()

    # 架构
    if ".x64." in name or name.endswith(".x64.dll") or name.endswith(".x64.o"):
        arch = "x64"
    elif ".x86." in name or name.endswith(".x86.o"):
        arch = "x86"
    else:
        arch = "x86"  # 默认

    # 变体
    if ".rl100k." in name:
        variant = "rl100k"
    elif ".rl0k." in name:
        variant = "rl0k"
    else:
        variant = "base"

    # 类别
    if name.startswith("beacon"):
        category = "Beacon Core"
    elif name.startswith("dnsb"):
        category = "DNS Beacon"
    elif name.startswith("winhttpb"):
        category = "WinHTTP Beacon"
    elif name.startswith("pivot"):
        category = "Pivot (SMB/TCP)"
    elif name.startswith("extc2"):
        category = "External C2"
    elif name.startswith("BeaconLoader") or name.startswith("Loader."):
        category = "Reflective Loader"
    elif name.startswith("sleepmask"):
        category = "Sleep Mask"
    elif name.startswith("mimikatz"):
        category = "Mimikatz"
    elif name.startswith("browserpivot"):
        category = "Browser Pivot"
    elif name.startswith("bypassuac") or name.startswith("uactoken"):
        category = "UAC Bypass"
    elif name.startswith("hashdump"):
        category = "Credential Dump"
    elif name.startswith("screenshot"):
        category = "Screenshot"
    elif name.startswith("powershell"):
        category = "PowerShell"
    elif name.startswith("keylogger"):
        category = "Keylogger"
    elif name.startswith("invokeassembly"):
        category = "Assembly Loader"
    elif name.startswith("netview"):
        category = "Network Enum"
    elif name.startswith("portscan"):
        category = "Port Scanner"
    elif name.startswith("sshagent"):
        category = "SSH Agent"
    elif name.startswith("clipboard"):
        category = "Clipboard"
    elif name.startswith("dllload"):
        category = "DLL Loader"
    elif name.startswith("timestomp"):
        category = "Timestomp"
    elif name.endswith(".o"):
        category = "BOF Module"
    else:
        category = "Other"

    return category, arch, variant


# ─── 版本对比 ───────────────────────────────────────────────
def compare_versions(dir_v1: str, dir_v2: str):
    """对比两个版本的 Sleeve 目录"""
    v1_files = {f.name: f for f in Path(dir_v1).iterdir() if f.is_file()}
    v2_files = {f.name: f for f in Path(dir_v2).iterdir() if f.is_file()}

    v1_names = set(v1_files.keys())
    v2_names = set(v2_files.keys())

    added = sorted(v2_names - v1_names)
    removed = sorted(v1_names - v2_names)
    common = sorted(v1_names & v2_names)

    print(f"\n{'='*70}")
    print(f"Sleeve 模板版本对比")
    print(f"{'='*70}")
    print(f"  V1: {dir_v1} ({len(v1_names)} 文件)")
    print(f"  V2: {dir_v2} ({len(v2_names)} 文件)")
    print(f"  共同: {len(common)} | 新增: {len(added)} | 移除: {len(removed)}")

    if added:
        print(f"\n  ── 新增文件 ({len(added)}) ──")
        for name in added:
            size = v2_files[name].stat().st_size
            cat, arch, var = classify_file(name)
            print(f"  [+] {name:<45s} {size:>8,}B  ({cat}, {arch})")

    if removed:
        print(f"\n  ── 移除文件 ({len(removed)}) ──")
        for name in removed:
            size = v1_files[name].stat().st_size
            cat, arch, var = classify_file(name)
            print(f"  [-] {name:<45s} {size:>8,}B  ({cat}, {arch})")

    if common:
        print(f"\n  ── 大小变化 (共同文件) ──")
        changes = []
        for name in common:
            s1 = v1_files[name].stat().st_size
            s2 = v2_files[name].stat().st_size
            if s1 != s2:
                delta = s2 - s1
                pct = (delta / s1 * 100) if s1 > 0 else 0
                changes.append((name, s1, s2, delta, pct))

        if changes:
            changes.sort(key=lambda x: -abs(x[3]))
            for name, s1, s2, delta, pct in changes:
                sign = "+" if delta > 0 else ""
                print(f"  [~] {name:<40s} {s1:>8,}B → {s2:>8,}B  ({sign}{delta:,}B, {sign}{pct:.1f}%)")
        else:
            print("  (所有共同文件大小相同)")

    # 分类统计
    print(f"\n  ── 按类别统计 ──")
    v2_cats = defaultdict(list)
    for name in v2_names:
        cat, arch, var = classify_file(name)
        v2_cats[cat].append((name, v2_files[name].stat().st_size if name in v2_files else 0))

    for cat in sorted(v2_cats.keys()):
        files = v2_cats[cat]
        total_size = sum(s for _, s in files)
        print(f"  {cat:<25s} {len(files):3d} 文件  {total_size:>10,}B")

    print()


# ─── 模板分析 ───────────────────────────────────────────────
def analyze_templates(dir_path: str):
    """深度分析解密后的 Sleeve 模板"""
    print(f"\n{'='*70}")
    print(f"Sleeve 模板深度分析: {dir_path}")
    print(f"{'='*70}\n")

    files = sorted(Path(dir_path).iterdir())
    pe_files = []
    coff_files = []
    other_files = []

    for f in files:
        if not f.is_file():
            continue
        data = f.read_bytes()
        info = analyze_pe(data)
        info["name"] = f.name
        info["size"] = len(data)
        info["md5"] = hashlib.md5(data).hexdigest()
        info["category"], info["arch_class"], info["variant"] = classify_file(f.name)

        if info.get("format") == "PE":
            pe_files.append(info)
        elif info.get("format") == "COFF":
            coff_files.append(info)
        else:
            other_files.append(info)

    # PE DLL 分析
    if pe_files:
        print(f"  ── PE DLL 文件 ({len(pe_files)}) ──")
        print(f"  {'名称':<40s} {'大小':>8s} {'架构':>5s} {'节数':>3s} {'导出':>20s} {'标记'}")
        print(f"  {'-'*40} {'-'*8} {'-'*5} {'-'*3} {'-'*20} {'-'*20}")
        for info in pe_files:
            exports = ", ".join(info.get("exports", []))[:20]
            markers = ", ".join(info.get("markers", {}).keys())[:20]
            print(f"  {info['name']:<40s} {info['size']:>8,} {info['arch']:>5s} {info['sections']:>3d} {exports:>20s} {markers}")

    # COFF Object 分析
    if coff_files:
        print(f"\n  ── COFF Object 文件 ({len(coff_files)}) ──")
        print(f"  {'名称':<40s} {'大小':>8s} {'架构':>5s} {'节数':>3s}")
        print(f"  {'-'*40} {'-'*8} {'-'*5} {'-'*3}")
        for info in coff_files:
            print(f"  {info['name']:<40s} {info['size']:>8,} {info['arch']:>5s} {info['sections']:>3d}")

    # 统计
    print(f"\n  ── 统计 ──")
    print(f"  PE DLL:    {len(pe_files)}")
    print(f"  COFF .o:   {len(coff_files)}")
    print(f"  其他:      {len(other_files)}")
    print(f"  总计:      {len(pe_files) + len(coff_files) + len(other_files)}")

    total_size = sum(f.stat().st_size for f in files if f.is_file())
    print(f"  总大小:    {total_size:,} bytes ({total_size/1024/1024:.1f} MB)")

    # 反射加载器对比
    loaders = [f for f in pe_files + coff_files if "Loader" in f["name"] or "loader" in f["name"]]
    if loaders:
        print(f"\n  ── 反射加载器清单 ({len(loaders)}) ──")
        for info in sorted(loaders, key=lambda x: x["name"]):
            print(f"  {info['name']:<40s} {info['size']:>6,}B  {info['arch']}")

    print()
    return pe_files, coff_files


# ─── YARA 规则生成 ───────────────────────────────────────────
def generate_yara(dir_path: str, output: str):
    """从解密后的模板自动生成 YARA 规则"""
    pe_files, coff_files = analyze_templates(dir_path)

    rules = []

    # 规则 1: 通用 Beacon DLL 检测 (基于共同字节序列)
    beacon_dlls = [f for f in pe_files if f["category"] == "Beacon Core"]
    if beacon_dlls:
        # 提取所有 beacon DLL 的共同导出
        all_exports = set()
        for f in beacon_dlls:
            all_exports.update(f.get("exports", []))

        rules.append(f"""
rule CS_Beacon_DLL_Generic {{
    meta:
        description = "Cobalt Strike Beacon DLL (自动生成)"
        date = "2026-04-01"
        source = "sleeve_decrypted 模板分析"
        count = "{len(beacon_dlls)} variants"

    strings:
        $export_rl = "ReflectiveLoader" ascii
        $marker_st = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"
        $marker_cfg = "AAAABBBBCCCCDDDDEEEEFFFF"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and filesize < 500KB and
        $export_rl and
        ($marker_st or $marker_cfg)
}}""")

    # 规则 2: 各 Beacon 变体检测 (按大小范围)
    for cat_name, size_range, extra_condition in [
        ("DNS_Beacon", (200000, 350000), '$marker_st'),
        ("Pivot_Beacon", (190000, 350000), '$marker_st'),
        ("WinHTTP_Beacon", (200000, 370000), '$marker_st'),
        ("ExtC2_Beacon", (190000, 340000), '$marker_st'),
    ]:
        cat_files = [f for f in pe_files if cat_name.split("_")[0].lower() in f["category"].lower()]
        if cat_files:
            min_size = min(f["size"] for f in cat_files) - 10000
            max_size = max(f["size"] for f in cat_files) + 50000
            rules.append(f"""
rule CS_{cat_name}_DLL {{
    meta:
        description = "Cobalt Strike {cat_name.replace('_', ' ')} DLL"
        date = "2026-04-01"

    strings:
        $export_rl = "ReflectiveLoader" ascii
        $marker_st = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"

    condition:
        uint16(0) == 0x5A4D and
        filesize > {min_size} and filesize < {max_size} and
        $export_rl and {extra_condition}
}}""")

    # 规则 3: PostEx 模块检测
    postex_cats = ["Mimikatz", "Screenshot", "Keylogger", "Browser Pivot",
                   "Port Scanner", "Network Enum", "UAC Bypass", "Credential Dump"]
    for cat in postex_cats:
        cat_files = [f for f in pe_files if f["category"] == cat]
        if cat_files:
            min_size = min(f["size"] for f in cat_files)
            max_size = max(f["size"] for f in cat_files)
            safe_name = cat.replace(" ", "_").replace("/", "_")
            rules.append(f"""
rule CS_PostEx_{safe_name} {{
    meta:
        description = "Cobalt Strike PostEx: {cat}"
        date = "2026-04-01"
        variants = "{len(cat_files)}"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > {max(min_size - 5000, 1000)} and filesize < {max_size + 20000} and
        $export_rl
}}""")

    # 规则 4: COFF Loader 检测
    loader_coffs = [f for f in coff_files if "Loader" in f["name"]]
    if loader_coffs:
        rules.append(f"""
rule CS_ReflectiveLoader_COFF {{
    meta:
        description = "Cobalt Strike Reflective Loader COFF Object"
        date = "2026-04-01"
        variants = "{len(loader_coffs)}"

    strings:
        $func = "ReflectiveLoader" ascii
        $va = "VirtualAlloc" ascii
        $gpa = "GetProcAddress" ascii
        $lla = "LoadLibraryA" ascii

    condition:
        (uint16(0) == 0x014C or uint16(0) == 0x8664) and
        filesize > 2000 and filesize < 10000 and
        $func and 2 of ($va, $gpa, $lla)
}}""")

    # 规则 5: Sleep Mask 检测
    sleepmask_files = [f for f in coff_files if "sleepmask" in f["name"]]
    if sleepmask_files:
        rules.append(f"""
rule CS_SleepMask_COFF {{
    meta:
        description = "Cobalt Strike Sleep Mask BOF"
        date = "2026-04-01"
        variants = "{len(sleepmask_files)}"

    condition:
        (uint16(0) == 0x014C or uint16(0) == 0x8664) and
        filesize > 500 and filesize < 5000
}}""")

    # 规则 6: MD5 精确匹配 (解密后模板)
    all_files = pe_files + coff_files
    md5_strings = []
    for f in sorted(all_files, key=lambda x: x["name"]):
        md5_strings.append(f'        // {f["name"]}: {f["md5"]}')

    rules.append(f"""
rule CS_Sleeve_Template_MD5 {{
    meta:
        description = "Cobalt Strike 解密后 Sleeve 模板 (精确 MD5 匹配)"
        date = "2026-04-01"
        total_templates = "{len(all_files)}"
        note = "MD5 列表见 condition 注释"

    condition:
        // 使用外部 hash 匹配, 此规则需要配合 YARA 的 hash 模块
        // 或在部署时转换为 IOC hash 列表
        false  // 占位 — 实际部署时替换为 hash.md5(0, filesize) 匹配
}}
/*
模板 MD5 列表:
{chr(10).join(md5_strings)}
*/""")

    # 输出
    header = """/*
 * Cobalt Strike Sleeve 模板自动生成 YARA 规则
 * 生成日期: 2026-04-01
 * 来源: 解密后的 Sleeve 模板分析
 * 模板数: %d PE + %d COFF = %d 总计
 *
 * 注意: 这些规则基于模板特征, 实际 Beacon 经过
 *       MalleablePE 处理后部分特征可能被修改
 */

import "pe"
""" % (len(pe_files), len(coff_files), len(pe_files) + len(coff_files))

    full_output = header + "\n".join(rules) + "\n"

    if output:
        Path(output).write_text(full_output)
        print(f"\n[+] YARA 规则已保存到: {output}")
        print(f"[+] 共生成 {len(rules)} 条规则")
    else:
        print(full_output)

    return rules


# ─── 主程序 ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CS Sleeve 模板对比 + YARA 生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(dest="command")

    # compare
    p_cmp = subparsers.add_parser("compare", help="对比两个版本的 Sleeve 目录")
    p_cmp.add_argument("--v1", required=True, help="版本 1 目录 (如 4.6.1)")
    p_cmp.add_argument("--v2", required=True, help="版本 2 目录 (如 4.9.1)")

    # analyze
    p_ana = subparsers.add_parser("analyze", help="分析解密后的 Sleeve 模板")
    p_ana.add_argument("--dir", required=True, help="解密后的 Sleeve 目录")

    # yara
    p_yara = subparsers.add_parser("yara", help="从模板生成 YARA 规则")
    p_yara.add_argument("--dir", required=True, help="解密后的 Sleeve 目录")
    p_yara.add_argument("-o", "--output", help="输出 YARA 文件路径")

    args = parser.parse_args()

    if args.command == "compare":
        compare_versions(args.v1, args.v2)
    elif args.command == "analyze":
        analyze_templates(args.dir)
    elif args.command == "yara":
        generate_yara(args.dir, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
