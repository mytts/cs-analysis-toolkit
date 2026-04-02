/*
 * Cobalt Strike Sleeve 模板自动生成 YARA 规则
 * 生成日期: 2026-04-01
 * 来源: 解密后的 Sleeve 模板分析
 * 模板数: 42 PE + 44 COFF = 86 总计
 *
 * 注意: 这些规则基于模板特征, 实际 Beacon 经过
 *       MalleablePE 处理后部分特征可能被修改
 */

import "pe"

rule CS_Beacon_DLL_Generic {
    meta:
        description = "Cobalt Strike Beacon DLL (自动生成)"
        date = "2026-04-01"
        source = "sleeve_decrypted 模板分析"
        count = "4 variants"

    strings:
        $export_rl = "ReflectiveLoader" ascii
        $marker_st = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"
        $marker_cfg = "AAAABBBBCCCCDDDDEEEEFFFF"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and filesize < 500KB and
        $export_rl and
        ($marker_st or $marker_cfg)
}

rule CS_DNS_Beacon_DLL {
    meta:
        description = "Cobalt Strike DNS Beacon DLL"
        date = "2026-04-01"

    strings:
        $export_rl = "ReflectiveLoader" ascii
        $marker_st = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 202480 and filesize < 436048 and
        $export_rl and $marker_st
}

rule CS_Pivot_Beacon_DLL {
    meta:
        description = "Cobalt Strike Pivot Beacon DLL"
        date = "2026-04-01"

    strings:
        $export_rl = "ReflectiveLoader" ascii
        $marker_st = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 63728 and filesize < 427344 and
        $export_rl and $marker_st
}

rule CS_PostEx_Mimikatz {
    meta:
        description = "Cobalt Strike PostEx: Mimikatz"
        date = "2026-04-01"
        variants = "6"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 248440 and filesize < 807968 and
        $export_rl
}

rule CS_PostEx_Screenshot {
    meta:
        description = "Cobalt Strike PostEx: Screenshot"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 158840 and filesize < 219680 and
        $export_rl
}

rule CS_PostEx_Keylogger {
    meta:
        description = "Cobalt Strike PostEx: Keylogger"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 62072 and filesize < 102944 and
        $export_rl
}

rule CS_PostEx_Browser_Pivot {
    meta:
        description = "Cobalt Strike PostEx: Browser Pivot"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 68728 and filesize < 107552 and
        $export_rl
}

rule CS_PostEx_Port_Scanner {
    meta:
        description = "Cobalt Strike PostEx: Port Scanner"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 70264 and filesize < 113696 and
        $export_rl
}

rule CS_PostEx_Network_Enum {
    meta:
        description = "Cobalt Strike PostEx: Network Enum"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 82552 and filesize < 124960 and
        $export_rl
}

rule CS_PostEx_UAC_Bypass {
    meta:
        description = "Cobalt Strike PostEx: UAC Bypass"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 96376 and filesize < 130592 and
        $export_rl
}

rule CS_PostEx_Credential_Dump {
    meta:
        description = "Cobalt Strike PostEx: Credential Dump"
        date = "2026-04-01"
        variants = "2"

    strings:
        $export_rl = "ReflectiveLoader" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 58488 and filesize < 102432 and
        $export_rl
}

rule CS_ReflectiveLoader_COFF {
    meta:
        description = "Cobalt Strike Reflective Loader COFF Object"
        date = "2026-04-01"
        variants = "12"

    strings:
        $func = "ReflectiveLoader" ascii
        $va = "VirtualAlloc" ascii
        $gpa = "GetProcAddress" ascii
        $lla = "LoadLibraryA" ascii

    condition:
        (uint16(0) == 0x014C or uint16(0) == 0x8664) and
        filesize > 2000 and filesize < 10000 and
        $func and 2 of ($va, $gpa, $lla)
}

rule CS_SleepMask_COFF {
    meta:
        description = "Cobalt Strike Sleep Mask BOF"
        date = "2026-04-01"
        variants = "6"

    condition:
        (uint16(0) == 0x014C or uint16(0) == 0x8664) and
        filesize > 500 and filesize < 5000
}

rule CS_Sleeve_Template_MD5 {
    meta:
        description = "Cobalt Strike 解密后 Sleeve 模板 (精确 MD5 匹配)"
        date = "2026-04-01"
        total_templates = "86"
        note = "MD5 列表见 condition 注释"

    condition:
        // 使用外部 hash 匹配, 此规则需要配合 YARA 的 hash 模块
        // 或在部署时转换为 IOC hash 列表
        false  // 占位 — 实际部署时替换为 hash.md5(0, filesize) 匹配
}
/*
模板 MD5 列表:
        // BeaconLoader.HA.x64.o: 6d1b470f671ce60dca2d472e2bf36ff0
        // BeaconLoader.HA.x86.o: ebe0aa0eb120b47a36ca7d5552f073a9
        // BeaconLoader.MVF.x64.o: 230ffc8bed6690ae44513c2ab84ffd74
        // BeaconLoader.MVF.x86.o: b6d8ee93ab27a7b3f1a89b7805151981
        // BeaconLoader.VA.x64.o: ceeaf351f6b8411449b60a051ebfb108
        // BeaconLoader.VA.x86.o: a53990ff370b0cec4f4f7cd10c74bd9d
        // BeaconLoader.x64.o: c8f1a5b895e935f27b59ff688a07dd89
        // BeaconLoader.x86.o: 620149627d7527e6115c521c0fa2dcb4
        // Loader.Beacon.x64.o: 9c3e99a6460724bcc4fab7fd6f607750
        // Loader.Beacon.x86.o: f8bf9f4a1c97bf33356e01837d5fa355
        // Loader.Generic.x64.o: c403a576c1917ee7988578a199fbc620
        // Loader.Generic.x86.o: 04327eb7041cd5578a65000c275cd009
        // beacon.dll: 3b5d57147737e3a0aeeddee67a79ed05
        // beacon.rl100k.dll: abee0c7e7aa5ca1f56a656595eb625ac
        // beacon.x64.dll: 71c0763e4a752e24547dab34911c091f
        // beacon.x64.rl100k.dll: 1340b3ac6caab672d10ac8e4527b54ca
        // browserpivot.dll: 45553af87b6844b2bfb3391754a7c6e6
        // browserpivot.x64.dll: 8d7acb9bc59f4879e3c083d9b1bafb73
        // bypassuac.dll: 0220d0af41b8db1b9771d1c7b47ed2c0
        // bypassuac.x64.dll: 08ecc1c9679f7a6422423cfacf84c946
        // dllload.x64.o: eda9e243938cd96851dadeb9c4e704c5
        // dllload.x86.o: 42ba31ead170f68460589b9fdf1fb65e
        // dnsb.dll: 9f18c1360d52e869cb2f2098d2e15101
        // dnsb.rl100k.dll: 6ff26347b82c3a613f1545c5d9968963
        // dnsb.x64.dll: 9d27d6451655fabd3fb612043a96bbe8
        // dnsb.x64.rl100k.dll: f8fc3f397177e37fb2485198fa8349a0
        // extc2.dll: 137a76388a86b7cf50ee0f1ea8cd7c2b
        // extc2.rl100k.dll: 907052b0dbe706bc2bbee3e8d2bea757
        // extc2.x64.dll: 8d079cee488b12f0761e20f615703b0a
        // extc2.x64.rl100k.dll: 79249359ff5a6fa7e88c6dbb5f0e279f
        // getsystem.x64.o: fae25009ef01e2e1d8c6967b6f21c082
        // getsystem.x86.o: ee6753023501f755c00317659385322f
        // hashdump.dll: 29293d7ab9df836daa93a08c4364435f
        // hashdump.x64.dll: 45e43fc86b994a8b227434fc08e73e93
        // injector.x64.o: a739f0af21ee750640d19ae4089f9089
        // injector.x86.o: 610228425e4b6254edee805e7cd28d84
        // interfaces.x64.o: 41190b444fb07c9425ad10d31afc2eab
        // interfaces.x86.o: 4529689a36c7ebceeb1e0ca7bf7d7783
        // invokeassembly.dll: 7629b216a87c250c0c06ee44a156f12f
        // invokeassembly.x64.dll: 133b75b79dd4838fcc4fe48f309818e8
        // kerberos.x64.o: 7b915b7afe7fb047814e7aa0fb6cce31
        // kerberos.x86.o: 8a958f8360babfb035bbbe6764177bea
        // keylogger.dll: a017eb0745a613e6fecaedbcf5d973e9
        // keylogger.x64.dll: 91f75854f06f0bf61d01a9a899565565
        // mimikatz-chrome.x64.dll: 0bf44417c5e1a849cd4cb0873f3627a3
        // mimikatz-chrome.x86.dll: 95082456c5e270b738b674174b414ec3
        // mimikatz-full.x64.dll: ba080fc756aaf03bb1061e5fa7614e39
        // mimikatz-full.x86.dll: 8f6d131a56636e495fc3158943639d41
        // mimikatz-min.x64.dll: 3c916d527168ff1e6d97b7f355d96f85
        // mimikatz-min.x86.dll: 3ca9ff292123f1a7c8d02831990961c3
        // net_domain.x64.o: cf3f94e96ede8f71b5df8f44051e4ae7
        // net_domain.x86.o: 837faa895ac419ef9324aadc6130c9d0
        // netview.dll: e460cb95d4b262aa414e3b4ad13806b9
        // netview.x64.dll: 80fb80331a78ce0d69d35a5a9c125b89
        // pivot.dll: 8c99f6c2498d525bc907dc6fbabab9b9
        // pivot.rl100k.dll: 52411e24f484aa4457b31750e98246a6
        // pivot.x64.dll: 4e1542b7fb26a44d62131aeb2b86f2c0
        // pivot.x64.rl100k.dll: ffd2d67075d7973b4bb635992a097859
        // portscan.dll: 1d2e200b33ebb4b6c6bc7dcf69b356a2
        // portscan.x64.dll: b98acda20db9b464d5211b65d94cb915
        // powershell.dll: ffc6fa5d267c22acdd3e690ffbab1139
        // powershell.x64.dll: a9f1f41db923b3a462c45d0ce94ab60e
        // psexec_command.x64.o: cdeffd1276482bd4db5d3a8718d49f34
        // psexec_command.x86.o: 47a5378f8b62a1f24250e3d94b99b3af
        // registry.x64.o: 327bfd00c96d95fa0876340d800d71af
        // registry.x86.o: d8bfb89deb0fc798601f143b84594b19
        // screenshot.dll: 09bd06655bc2de1167b3928565e823b6
        // screenshot.x64.dll: be162a3fd2b4dada3fe60c91b81ea4c6
        // sleepmask.x64.o: 15940e9ce328b73d0bca210ec3306c53
        // sleepmask.x86.o: 6591d55cd3347fa6a392eab42f3f8430
        // sleepmask_smb.x64.o: 37db6203b63c3c286cc7f7899e828b06
        // sleepmask_smb.x86.o: 3207fb340dac874f928ac40911d48b3f
        // sleepmask_tcp.x64.o: 58ce5946cb6a3ee3fd9101d994b9249c
        // sleepmask_tcp.x86.o: 0f64baf7fe7a74078eb52989571c3df4
        // sshagent.dll: e61ad126ede65b842ef6df84ebb2eada
        // sshagent.x64.dll: 70fa712f291dfb684cc14527592a53c1
        // timestomp.x64.o: 07c0d2c873506a5308799f4b26dcb926
        // timestomp.x86.o: ec05b8e34c5f038f0f71e4b4e94bfc87
        // uaccmstp.x64.o: 395cfa2648a6d98fa376e5b7d6442a72
        // uaccmstp.x86.o: d56cd83106a15c4ebaa1cdc399309c0d
        // uactoken.x64.o: ea7f140945e0c81289e7eb4406eb5db9
        // uactoken.x86.o: edbe4c5e08d092fcb2b4b9607a15dcd7
        // uactoken2.x64.o: cde679c6834d3921afa308b98a11bc03
        // uactoken2.x86.o: 0ac37e517f99f20e402af4b7e8f930f6
        // wmiexec.x64.o: 73f8040b7c878951700876dd1ac50ae6
        // wmiexec.x86.o: 769a5013edbf66aab8a85e3ce64e82a3
*/
