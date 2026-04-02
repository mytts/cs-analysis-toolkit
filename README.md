# Cobalt Strike Analysis Toolkit

> Reverse engineering tools and detection rules for Cobalt Strike 4.x (4.6.1 / 4.9.1)

A comprehensive toolkit built from deep reverse engineering of Cobalt Strike's Java source, Beacon DLLs, and Sleeve-encrypted templates. Includes configuration parsers, decryption tools, a web-based analyzer, and 52 detection rules.

## Quick Start

```bash
# Clone
git clone https://github.com/mytts/cs-analysis-toolkit.git
cd cs-analysis-toolkit

# Install dependencies
pip3 install pycryptodome flask

# Parse a Beacon config (CLI)
python3 parsers/cs_config_parser.py beacon.dll

# Launch web analyzer
python3 web/app.py
# Open http://127.0.0.1:5000

# Compare Sleeve versions
python3 parsers/cs_sleeve_compare.py --dir1 sleeve_461/ --dir2 sleeve_491/
```

## Tools

### 1. Beacon Config Parser (`parsers/cs_config_parser.py`)

Extracts C2 configuration from Beacon DLLs, shellcode, or memory dumps.

**5 search strategies:**

| # | Strategy | Description |
|---|----------|-------------|
| 1 | Plain marker | Searches for `AAAABBBBCCCCDDDDEEEEFFFF` (24 bytes) |
| 2 | XOR 0x2E marker | Standard `beacon_obfuscate()` encoding |
| 3 | XOR 0x69 marker | Known alternate XOR key |
| 4 | XOR brute-force | Tries all single-byte keys (0x01-0xFF) |
| 5 | TLV pattern match | Direct TLV sequence detection (for memory dumps) |

**60+ Setting IDs** decoded: protocol, port, C2 domains, User-Agent, POST URI, watermark, RSA public key, spawn-to processes, named pipes, kill dates, injection options, and more.

```bash
# Basic parse
python3 parsers/cs_config_parser.py beacon.dll

# JSON output
python3 parsers/cs_config_parser.py beacon.dll --format json -o report.json

# Scan all known CS markers
python3 parsers/cs_config_parser.py beacon.dll --scan-markers

# Brute-force XOR scan
python3 parsers/cs_config_parser.py beacon.bin --xor-scan
```

### 2. Sleeve Decryptor (`parsers/cs_sleeve_decryptor.py`)

Decrypts Cobalt Strike's Sleeve-encrypted binary templates.

**Encryption chain:**
```
cobaltstrike.auth → RSA decrypt → SleeveKey (16B)
                                      ↓
                                SHA-256(SleeveKey)
                                      ↓
                              AES key [0:16] + HMAC key [16:32]
                                      ↓
                           AES-128-CBC decrypt (IV = "abcdefghijklmnop")
                           HMAC-SHA256 verify (Encrypt-then-MAC)
```

```bash
# Decrypt all Sleeve files
python3 parsers/cs_sleeve_decryptor.py \
  --auth cobaltstrike.auth \
  --pubkey authkey.pub \
  --sleeve-dir sleeve/ \
  --output decrypted/

# Parse a decrypted Beacon DLL
python3 parsers/cs_sleeve_decryptor.py --parse-beacon decrypted/beacon.dll
```

### 3. Sleeve Version Comparator (`parsers/cs_sleeve_compare.py`)

Compares Sleeve templates between CS versions and auto-generates YARA rules.

- PE/COFF deep analysis (architecture, sections, exports, markers)
- Auto-classification into 22 module categories
- Diff report: additions, removals, size changes
- **Auto-generates 14 YARA rules** from template characteristics

```bash
# Compare 4.6.1 vs 4.9.1
python3 parsers/cs_sleeve_compare.py \
  --dir1 sleeve_461_decrypted/ \
  --dir2 sleeve_491_decrypted/ \
  --yara-output rules/yara/generated.yar
```

### 4. Web Analyzer (`web/app.py`)

Browser-based Beacon config analysis platform.

**Features:**
- Drag-and-drop file upload (DLL/EXE/shellcode/memory dumps, up to 50MB)
- Auto PE detection (x86/x64, DLL/EXE)
- 4 known CS marker scanning
- IOC extraction with severity classification (Critical/High/Medium/Info)
- Settings table with group filtering
- JSON export + IOC clipboard copy

```bash
python3 web/app.py
# Open http://127.0.0.1:5000
```

A test sample generator is included:

```bash
python3 web/gen_test_sample.py
# Generates test_beacon_sim.bin with 21 config settings
```

### 5. Sleep Mask Analyzer (`parsers/cs_sleepmask_analyzer.py`)

Reverse engineers Sleep Mask BOF files (COFF format) from Sleeve templates.

- COFF header/section/symbol/relocation parsing
- `.text` hex dump with XOR loop pattern detection
- Cross-file comparison (x86 vs x64, HTTP vs SMB vs TCP)
- C pseudocode reconstruction of the masking logic
- Build path and compiler identification

```bash
# Analyze all sleep mask BOFs in a directory
python3 parsers/cs_sleepmask_analyzer.py /path/to/sleeve_decrypted/

# Single file analysis
python3 parsers/cs_sleepmask_analyzer.py sleepmask.x64.o --format json
```

### 6. C2 Traffic Decryptor (`parsers/cs_traffic_decryptor.py`)

Decrypts Cobalt Strike Beacon C2 traffic for incident response.

**Three modes:**

| Mode | Input | Output |
|------|-------|--------|
| Session decrypt | Session key + encrypted data | Decoded commands/callbacks |
| RSA metadata | Private key + Base64 cookie | Session key + beacon info |
| PCAP pipeline | PCAP + private key | Full operation timeline |

```bash
# Decrypt task data with known session key
python3 parsers/cs_traffic_decryptor.py \
  --session-key 0123456789abcdef0123456789abcdef \
  --data <encrypted_hex> --direction task

# Decrypt beacon metadata (from Cookie header)
python3 parsers/cs_traffic_decryptor.py \
  --private-key beacon_keys.pem --metadata "Base64..."

# Full PCAP decryption
python3 parsers/cs_traffic_decryptor.py \
  --pcap traffic.pcap --private-key beacon_keys.pem

# Self-test (9 automated tests)
python3 parsers/cs_traffic_decryptor.py --self-test
```

Decodes 30+ command IDs (SHELL, SLEEP, INJECT, SPAWN, BOF, etc.) and 15+ callback types.

### 7. Binary Diff Visualizer (`parsers/cs_bindiff_visual.py`)

Generates visual byte-level diffs between Sleeve template versions.

- HTML heatmap with color-coded bytes (identical/modified/added/removed)
- PE section overlay (.text, .rdata, .data, .reloc boundaries)
- Shannon entropy per 256-byte block
- Per-section change statistics
- Export table diff
- Batch directory comparison dashboard

```bash
# Single file diff → HTML heatmap
python3 parsers/cs_bindiff_visual.py \
  --file1 v461/beacon.dll --file2 v491/beacon.dll -o diff.html

# Batch directory comparison
python3 parsers/cs_bindiff_visual.py \
  --dir1 sleeve_461/ --dir2 sleeve_491/ -o diff_report/

# Stats only (no HTML)
python3 parsers/cs_bindiff_visual.py \
  --dir1 sleeve_461/ --dir2 sleeve_491/ --stats-only
```

## Detection Rules

### YARA Rules (32 total)

| File | Count | Description |
|------|-------|-------------|
| `rules/yara/cobalt_strike_491.yar` | 18 | Hand-crafted rules covering Beacon DLL memory, Sleeve templates, TeamServerImage, C2 traffic, auth files, stagers, combined detection |
| `rules/yara/cobalt_strike_sleeve_generated.yar` | 14 | Auto-generated from Sleeve template analysis (per-module-type, based on size ranges and export combinations) |

**Top detection indicators:**

| Indicator | Detection Rate | False Positive Rate | Profile-Resistant |
|-----------|---------------|--------------------|--------------------|
| String Table marker (30B) | ~95% | ~0% | Yes |
| Settings TLV format (14B) | ~95% | ~0% | Yes |
| ReflectiveLoader export | ~80% | ~1% | Partial |
| Default TLS certificate | ~70% | ~0% | No |

### Sigma Rules (5)

`rules/sigma/cs_c2_traffic.yml` — Log/EDR detection rules:

1. HTTP C2 traffic (URI + Cookie Base64 pattern)
2. DNS Beacon subdomains (prefix + hex encoding)
3. Process injection patterns (Sysmon events)
4. Named pipe indicators (MSSE-/postex_ prefixes)
5. REST API access (port 50443)

### Suricata/Snort Rules (15)

`rules/suricata/cs_suricata.rules` — Network IDS rules (SID 4091001-4091080):

- HTTP GET/POST URI patterns
- DNS subdomain prefixes
- SMB named pipe names
- REST API port detection
- TLS certificate fingerprints
- EICAR anti-piracy detection

## Technical Background

### Cobalt Strike Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Client     │────│  TeamServer   │────│   Beacon     │
│  (Java GUI)  │RPC │  (Java/       │ C2 │  (C DLL,     │
│  + CNA       │    │   GraalVM)    │    │   x86/x64)   │
│  Scripts     │    │              │    │              │
└─────────────┘     └──────────────┘     └─────────────┘
```

### Key Constants

| Constant | Value | Source |
|----------|-------|--------|
| Sleeve IV | `abcdefghijklmnop` | SleeveSecurity.java |
| Settings XOR key | `0x2E` | BeaconPayload.java |
| Config marker | `AAAABBBBCCCCDDDDEEEEFFFF` (24B) | BeaconPayload.java |
| String Table marker | `TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ` (32B) | MalleablePE.java |
| Auth magic | `0xCAFEC0D3` | Authorization.java |
| PATCH_SIZE (4.6.x) | 4096 | Settings.java |
| PATCH_SIZE (4.9.1+) | 6144 | Settings.java |

### Encryption Stack

| Layer | Algorithm | Key Source |
|-------|-----------|------------|
| Auth file | RSA-2048 / ECB / PKCS1 | authkey.pub |
| Sleeve resources | AES-128-CBC + HMAC-SHA256 | SHA-256(SleeveKey) |
| Beacon session | AES-128-CBC + HMAC-SHA256 | SHA-256(SessionKey) |
| C2 transport | TLS 1.2 (optional) | ssl.store |

### Version Differences (4.6.1 → 4.9.1)

| Aspect | 4.6.1 | 4.9.1 |
|--------|-------|-------|
| Server | Java JAR | GraalVM Native Image |
| Auth file | 256B (1 RSA block) | 512B (2 RSA blocks) |
| Sleeve files | 86 | 100 (+18/-4) |
| PATCH_SIZE | 4096 | 6144 |
| Obfuscation | 2-tier (Base, RL100K) | 3-tier (+RL0K) |
| New features | — | Guardrails, WinHTTP, Direct Syscall, Kerberos BOF |

### MITRE ATT&CK Coverage

| Technique | CS Feature |
|-----------|------------|
| T1059.001 PowerShell | powershell, powershell-import |
| T1055.001 DLL Injection | dllinject, inject |
| T1021.002 SMB/Admin Shares | psexec lateral movement |
| T1071.001 Web Protocols | HTTP/HTTPS Beacon |
| T1071.004 DNS | DNS Beacon (A/AAAA/TXT) |
| T1573.001 Symmetric Crypto | AES-128-CBC session |
| T1573.002 Asymmetric Crypto | RSA-2048 handshake |
| T1620 Reflective Code Loading | Reflective Loader (VA/HA/MVF) |
| T1027 Obfuscated Files | Sleeve AES, Sleep Mask |

## Project Structure

```
cs-analysis-toolkit/
├── README.md                              # This file
├── LICENSE                                # MIT License
├── requirements.txt                       # Python dependencies
├── parsers/
│   ├── cs_config_parser.py               # Beacon config extractor (CLI)
│   ├── cs_sleeve_decryptor.py            # Sleeve AES decryptor
│   ├── cs_sleeve_compare.py             # Version comparator + YARA gen
│   ├── cs_sleepmask_analyzer.py         # Sleep Mask BOF reverse engineer
│   ├── cs_traffic_decryptor.py          # C2 traffic decryptor (RSA+AES)
│   └── cs_bindiff_visual.py             # Binary diff heatmap visualizer
├── web/
│   ├── app.py                            # Flask web analyzer
│   └── gen_test_sample.py               # Test sample generator
├── rules/
│   ├── yara/
│   │   ├── cobalt_strike_491.yar         # 18 hand-crafted YARA rules
│   │   └── cobalt_strike_sleeve_generated.yar  # 14 auto-generated rules
│   ├── sigma/
│   │   └── cs_c2_traffic.yml            # 5 Sigma rules
│   └── suricata/
│       └── cs_suricata.rules            # 15 Suricata/Snort rules
└── docs/
    └── TECHNICAL.md                      # Detailed technical notes
```

## Requirements

- Python 3.8+
- `pycryptodome` — AES/RSA decryption
- `flask` — Web analyzer (optional)

```bash
pip3 install -r requirements.txt
```

## Disclaimer

This toolkit is intended for **security research, incident response, and threat intelligence** purposes only. The tools analyze artifacts from Cobalt Strike, a commercial adversary simulation framework. No Cobalt Strike source code or proprietary binaries are included in this repository.

Use responsibly and in accordance with applicable laws.

## License

MIT License — See [LICENSE](LICENSE) for details.

## References

- Cobalt Strike official documentation
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CobaltStrikeParser by Sentinel-One](https://github.com/Sentinel-One/CobaltStrikeParser)
- [dissect.cobaltstrike by Fox-IT](https://github.com/fox-it/dissect.cobaltstrike)
