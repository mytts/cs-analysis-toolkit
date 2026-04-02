/*
 * Cobalt Strike 4.9.1 检测规则集
 * 基于完整逆向分析 (Docs 01-28)
 *
 * 分类:
 *   1. Beacon DLL 内存特征 (进程扫描)
 *   2. Sleeve 加密模板 (文件扫描)
 *   3. TeamServerImage 二进制 (文件扫描)
 *   4. 网络载荷 (流量/内存)
 *   5. Auth/授权文件 (文件扫描)
 *   6. Stager 特征 (内存/文件)
 */

import "pe"
import "elf"
import "math"

// ═══════════════════════════════════════════════════════════
// 1. BEACON DLL 内存特征
// ═══════════════════════════════════════════════════════════

rule CS_Beacon_StringTable_Marker
{
    meta:
        description = "CS Beacon DLL 字符串表标记 (MalleablePE.java)"
        severity = "critical"
        reference = "Doc 22 - MalleablePE strings() method"
        target = "memory, file"

    strings:
        $marker = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"

    condition:
        $marker
}

rule CS_Beacon_Guardrails_Marker
{
    meta:
        description = "CS Beacon Guardrails 补丁标记"
        severity = "critical"
        reference = "Doc 21 - Guardrails XOR encoding"
        target = "memory, file"

    strings:
        $guard = "GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd"

    condition:
        $guard
}

rule CS_Beacon_PostEx_Marker
{
    meta:
        description = "CS PostEx 反射加载器配置标记"
        severity = "high"
        reference = "Doc 22 - PostExLoader ZZZZZZZXXXXWYYYY"
        target = "memory, file"

    strings:
        $postex = "ZZZZZZZXXXXWYYYY"

    condition:
        $postex
}

rule CS_Beacon_Settings_TLV
{
    meta:
        description = "CS Beacon Settings 配置块 (TLV 格式, 6144 bytes)"
        severity = "critical"
        reference = "Doc 22 - Settings.java PATCH_SIZE=6144"
        target = "memory"

    strings:
        // SETTING_PROTOCOL(1) + TYPE_SHORT(1) + LEN(2) 后跟
        // SETTING_PORT(2) + TYPE_SHORT(1) + LEN(2)
        $tlv_start = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }

        // 替代模式: PROTOCOL 后直接跟 SLEEPTIME
        $tlv_alt = { 00 01 00 01 00 02 ?? ?? 00 03 00 02 00 04 }

    condition:
        any of them
}

rule CS_Beacon_Config_Watermark
{
    meta:
        description = "CS Beacon 配置中的 Watermark ID (Setting 26)"
        severity = "high"
        reference = "Doc 22 - SETTING_WATERMARK"
        target = "memory"

    strings:
        // Setting ID 26 (0x001A) + TYPE_INT (0x0002) + LEN 4 (0x0004)
        $watermark_tlv = { 00 1A 00 02 00 04 }

    condition:
        $watermark_tlv
}

rule CS_Beacon_Reflective_Loader
{
    meta:
        description = "CS Beacon 反射加载器特征 (BeaconRDLL.java)"
        severity = "critical"
        reference = "Doc 22 - ReflectiveLoader"
        target = "memory, file"

    strings:
        // 反射加载器导出函数名
        $export1 = "ReflectiveLoader" ascii
        $export2 = "_ReflectiveLoader@4" ascii

        // 加载器标记字符串
        $loader_ha = "BeaconLoader.HA" ascii
        $loader_mvf = "BeaconLoader.MVF" ascii
        $loader_va = "BeaconLoader.VA" ascii

    condition:
        any of ($export*) or any of ($loader*)
}

rule CS_Beacon_DLL_Memory
{
    meta:
        description = "CS Beacon DLL 运行时内存特征组合"
        severity = "critical"
        reference = "Docs 22-23"
        target = "memory"

    strings:
        $s1 = "beacon.dll" ascii nocase
        $s2 = "beacon.x64.dll" ascii nocase
        $s3 = "%s.%s:%d" ascii          // DNS beacon format
        $s4 = "could not connect to pipe" ascii
        $s5 = "%s as %s\\%s: %d" ascii  // Token impersonation
        $s6 = "IEX (New-Object Net.Webclient).DownloadString" ascii
        $s7 = "powershell -nop -exec bypass" ascii
        $s8 = "Content-Type: application/octet-stream" ascii

    condition:
        3 of them
}


// ═══════════════════════════════════════════════════════════
// 2. SLEEVE 加密模板
// ═══════════════════════════════════════════════════════════

rule CS_Sleeve_Encrypted_Template
{
    meta:
        description = "CS Sleeve 加密模板文件 (AES-128-CBC + HMAC-SHA256)"
        severity = "high"
        reference = "Doc 22 - SleeveSecurity.java"
        target = "file"

    condition:
        // Sleeve 文件特征: 16字节对齐 + 末尾16字节 HMAC
        filesize > 32 and
        filesize < 2000000 and
        (filesize - 16) % 16 == 0 and
        // 高熵值 (加密数据)
        math.entropy(0, filesize) > 7.5
}


// ═══════════════════════════════════════════════════════════
// 3. TEAMSERVERIMAGE 二进制
// ═══════════════════════════════════════════════════════════

rule CS_TeamServerImage_Cracked_Pwn3rs
{
    meta:
        description = "Pwn3rs 团队破解的 CS 4.9.1 TeamServerImage"
        severity = "critical"
        reference = "Doc 24 - 重打包版 vs 原版对比"
        target = "file"

    strings:
        $elf = { 7F 45 4C 46 }
        $pwn3rs = "(Pwn3rs)" nocase
        $forever = "forever"
        $perpetual = "perpetual"

    condition:
        $elf at 0 and
        filesize > 35MB and filesize < 45MB and
        // Section headers stripped
        uint16(0x3C) == 0 and
        any of ($pwn3rs, $forever, $perpetual)
}

rule CS_TeamServerImage_GraalVM
{
    meta:
        description = "CS TeamServerImage (GraalVM Native Image)"
        severity = "high"
        reference = "Doc 19 - GraalVM AOT"
        target = "file"

    strings:
        $elf = { 7F 45 4C 46 }
        $svm1 = "com.oracle.svm" ascii
        $svm2 = "SubstrateVM" ascii
        $cs1 = "cobaltstrike" ascii nocase
        $cs2 = "TeamServer" ascii
        $cs3 = "SleeveSecurity" ascii
        $cs4 = "BeaconPayload" ascii

    condition:
        $elf at 0 and
        any of ($svm*) and
        2 of ($cs*)
}

rule CS_TeamServerImage_Dist_Starter
{
    meta:
        description = "CS 官方 Dist TeamServerImage (CSTeamServerStarter)"
        severity = "medium"
        reference = "Doc 24 - CSTeamServerStarter launcher"
        target = "file"

    strings:
        $elf = { 7F 45 4C 46 }
        $starter = "CSTeamServerStarter" ascii
        $update_msg = "Please run the 'update' program" ascii

    condition:
        $elf at 0 and
        filesize > 5MB and filesize < 15MB and
        any of ($starter, $update_msg)
}


// ═══════════════════════════════════════════════════════════
// 4. 网络载荷 / C2 通信
// ═══════════════════════════════════════════════════════════

rule CS_Default_C2_URIs
{
    meta:
        description = "CS 默认 Malleable C2 Profile URI 集合"
        severity = "medium"
        reference = "Doc 23 - default.profile"
        target = "network, log"

    strings:
        // HTTP-GET URIs (default.profile 的 21 个 URI)
        $u1 = "/ca" ascii
        $u2 = "/dpixel" ascii
        $u3 = "/__utm.gif" ascii
        $u4 = "/pixel.gif" ascii
        $u5 = "/g.pixel" ascii
        $u6 = "/dot.gif" ascii
        $u7 = "/updates.rss" ascii
        $u8 = "/fwlink" ascii
        $u9 = "/cm" ascii
        $u10 = "/cx" ascii
        $u11 = "/pixel" ascii
        $u12 = "/match" ascii
        $u13 = "/visit.js" ascii
        $u14 = "/load" ascii
        $u15 = "/push" ascii
        $u16 = "/ptj" ascii
        $u17 = "/j.ad" ascii
        $u18 = "/ga.js" ascii
        $u19 = "/en_US/all.js" ascii
        $u20 = "/activity" ascii
        $u21 = "/IE9CompatViewList.xml" ascii

        // HTTP-POST URI
        $post = "/submit.php" ascii

    condition:
        3 of ($u*) or $post
}

rule CS_Beacon_Metadata_Cookie
{
    meta:
        description = "CS Beacon HTTP 元数据 (Base64 Cookie)"
        severity = "medium"
        reference = "Doc 23 - HTTP-GET metadata encoding"
        target = "network"

    strings:
        // default.profile: Cookie header with base64 metadata
        // Cookie: <base64 RSA-encrypted metadata>
        // Metadata 结构: [BeaconID:4][PID:4][Port:2][Flags:1]...
        $cookie_pattern = /Cookie: [A-Za-z0-9+\/=]{44,512}\r\n/

        // POST 参数模式
        $post_id = /id=[0-9]{1,10}&/ ascii

    condition:
        any of them
}

rule CS_DNS_Beacon_Subdomain
{
    meta:
        description = "CS DNS Beacon 子域名编码模式"
        severity = "high"
        reference = "Doc 23 - DNS encoding format strings"
        target = "network, log"

    strings:
        // DNS 数据编码: 前缀数字 (1-4) + hex 编码数据
        // 格式: [prefix].[digit][hex_data].[hex_data].[domain]
        $dns_pattern1 = /\.[1-4][0-9a-f]{8}\.[0-9a-f]{8,56}\./
        $dns_pattern2 = /cdn\.[0-9a-f]{8,}/
        $dns_pattern3 = /www6\.[0-9a-f]{8,}/
        $dns_pattern4 = /api\.[0-9a-f]{8,}/
        $dns_pattern5 = /post\.[0-9a-f]{8,}/

    condition:
        any of them
}


// ═══════════════════════════════════════════════════════════
// 5. AUTH / 授权文件
// ═══════════════════════════════════════════════════════════

rule CS_Auth_File
{
    meta:
        description = "CS cobaltstrike.auth 授权文件 (512 bytes)"
        severity = "critical"
        reference = "Doc 18 - Auth 双 RSA 块"
        target = "file"

    condition:
        // Auth 文件固定 512 字节 = 2 × 256 RSA 块
        filesize == 512 and
        // 高熵 (RSA 加密数据)
        math.entropy(0, 256) > 7.0 and
        math.entropy(256, 256) > 7.0
}

rule CS_AuthKey_Public
{
    meta:
        description = "CS authkey.pub RSA 公钥 (MD5: 8bb4df00...)"
        severity = "critical"
        reference = "Doc 22 - AuthCrypto.java"
        target = "file"

    strings:
        // X509EncodedKeySpec 的 DER 前缀 (RSA 2048 公钥)
        $der_header = { 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 }

    condition:
        $der_header at 0 and
        filesize > 290 and filesize < 300
}


// ═══════════════════════════════════════════════════════════
// 6. STAGER 特征
// ═══════════════════════════════════════════════════════════

rule CS_Stager_EICAR_AntiPiracy
{
    meta:
        description = "CS 未授权版本 Stager (EICAR 防盗版填充)"
        severity = "critical"
        reference = "Doc 22 - ListenerConfig EICAR padding"
        target = "file, memory"

    strings:
        $eicar = "5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule CS_Stager_x86_WinINet
{
    meta:
        description = "CS HTTP Stager (x86 WinINet)"
        severity = "high"
        reference = "Doc 22 - GenericHTTPStager.java"
        target = "memory, file"

    strings:
        // WinINet API 调用序列 + 典型 flags
        $wininet1 = "wininet" ascii nocase
        $wininet2 = "InternetOpenA" ascii
        $wininet3 = "InternetConnectA" ascii
        $wininet4 = "HttpOpenRequestA" ascii
        $wininet5 = "HttpSendRequestA" ascii

        // 标志组合: RELOAD|NO_CACHE|NO_REDIRECT|KEEP_CONN|SECURE|IGNORE_CERT
        $flags = { 00 00 A0 84 }  // 0x84A00000 常见标志组合

    condition:
        3 of ($wininet*) or $flags
}

rule CS_Beacon_Sleep_Mask
{
    meta:
        description = "CS Sleep Mask 内存加密特征"
        severity = "high"
        reference = "Doc 22 - Sleep Mask"
        target = "memory"

    strings:
        // Sleep Mask Kit 的典型代码模式
        // VirtualProtect 调用序列 (修改 RWX→RW→Sleep→RW→RWX)
        $vp_call = { FF 15 ?? ?? ?? ?? 85 C0 }  // call [VirtualProtect]; test eax,eax
        $sleep_call = { FF 15 ?? ?? ?? ?? }       // call [Sleep]

        // XOR 加密循环 (典型的 4字节密钥)
        $xor_loop = { 31 ?? 83 ?? 04 ?? ?? F8 }  // xor [reg]; add reg,4; cmp ...

    condition:
        $vp_call and $sleep_call and $xor_loop
}


// ═══════════════════════════════════════════════════════════
// 7. 综合检测 (组合规则)
// ═══════════════════════════════════════════════════════════

rule CS_Beacon_Full_Detection
{
    meta:
        description = "CS Beacon 综合检测 (高置信度)"
        severity = "critical"
        reference = "完整逆向分析 Docs 01-28"
        target = "memory, file"

    strings:
        $marker1 = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"
        $marker2 = "GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd"
        $marker3 = "ZZZZZZZXXXXWYYYY"
        $tlv = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
        $reflective = "ReflectiveLoader"
        $iv = "abcdefghijklmnop"
        $submit = "/submit.php"

    condition:
        2 of them
}

rule CS_Sleeve_Key_Material
{
    meta:
        description = "CS Sleeve 加密密钥材料 (内存中)"
        severity = "critical"
        reference = "Doc 22 - SleeveSecurity hardcoded IV"
        target = "memory"

    strings:
        $iv = "abcdefghijklmnop"
        $algo1 = "AES/CBC/NoPadding" ascii
        $algo2 = "HmacSHA256" ascii
        $sleeve_path = "sleeve/" ascii

    condition:
        $iv and ($algo1 or $algo2) and $sleeve_path
}
