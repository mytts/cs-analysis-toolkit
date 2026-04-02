# Technical Notes

Detailed reverse engineering findings from Cobalt Strike 4.6.1 and 4.9.1 analysis.

## 1. Authorization & Key Derivation

### Auth File Structure

**4.6.1 (256 bytes, single RSA block):**
```
RSA_Decrypt(256B) → 0xCAFEC0D3 | validTo | watermark | version(>=46)
                     | 6×extension_arrays | watermarkHash | sleeveKey[16B]
```

**4.9.1 (512 bytes, dual RSA blocks):**
```
Block 1: RSA_Decrypt(256B) → 0xCAFEC0D3 | sleeveKey[16B] | padding
                               | version(==49) | validTo | id
Block 2: 256B — Not decrypted by Client (likely for GraalVM Server)
```

### SleeveKey Derivation Chain

```
cobaltstrike.auth ──RSA/ECB/PKCS1──→ sleeveKey (16 bytes)
                                          │
                                     SHA-256(sleeveKey)
                                          │
                                    ┌─────┴─────┐
                                bytes[0:16]  bytes[16:32]
                                    │           │
                               AES-128 Key  HMAC-SHA256 Key
```

The same derivation pattern is used for Beacon session keys:
`SHA-256(sessionKey) → AES[0:16] + HMAC[16:32]`

### Sleeve Encrypted Format

```
┌─────────┬──────────┬─────────────┬───────────┬──────────────┐
│ 4B rand │ 4B len   │ payload     │ 0x41 pad  │ 16B HMAC     │
│ nonce   │ (actual) │ (raw data)  │ (align 16)│ (truncated)  │
└─────────┴──────────┴─────────────┴───────────┘──────────────┘
├──── AES-128-CBC encrypted (Encrypt-then-MAC) ─┤
```

- IV: `"abcdefghijklmnop"` (hardcoded, weakness mitigated by random nonce)
- Padding: Non-standard 0x41 (not PKCS7)
- MAC: Truncated HMAC-SHA256 of ciphertext (correct EtM ordering)

## 2. Beacon Payload Generation Pipeline

### 7-Stage Pipeline

```
[1] Sleeve Decrypt → [2] String Table Patch → [3] Settings TLV Patch
         │                    │                        │
    AES-128-CBC          32B marker              6144B config block
    HMAC verify      "TTTTSSSSUUUU..."         60+ Setting IDs
         │                    │                        │
         ▼                    ▼                        ▼
[4] PE Transform → [5] Reflective Loader → [6] Guardrails Embed
         │                    │                        │
    MalleablePE         3 strategies:          XOR double mask
    12 options        VA / HA / MVF          64B marker replace
         │                    │                        │
         ▼                    ▼                        ▼
                    [7] Final Packaging
                   EXE/DLL/PS/HTA/VBS/
                   Macro/Python
```

### 5 Known Markers

| Marker | Size | Block Size | Purpose |
|--------|------|------------|---------|
| `AAAABBBBCCCCDDDDEEEEFFFF` | 24B | 4096/6144B | Settings TLV config |
| `TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ` | 32B | 4096B | Profile string table |
| `GGGGuuuuaaaa...` (64 chars) | 64B | 2048B | Guardrails conditions |
| `ZZZZZZZXXXXWYYYY` | 16B | — | PostEx loader |
| Screenshot marker | 72B | — | Screenshot config |

### Settings TLV Format

```
┌──────────┬──────────┬──────────┬──────────┐
│ ID (2B)  │ Type (2B)│ Len (2B) │ Value    │
│ big-end  │ 1=SHORT  │ big-end  │ variable │
│          │ 2=INT    │          │          │
│          │ 3=PTR    │          │          │
└──────────┴──────────┴──────────┴──────────┘
```

XOR encoded with key `0x2E` via `beacon_obfuscate()` before embedding.

### Reflective Loader Strategies

| Strategy | API | EDR Risk | Description |
|----------|-----|----------|-------------|
| VirtualAlloc (VA) | VirtualAlloc | High | RWX memory, easily detected |
| HeapAlloc (HA) | HeapAlloc + VirtualProtect | Low | Heap memory, staged permissions |
| MapViewOfFile (MVF) | NtCreateSection + NtMapView | Medium | File mapping, avoids RWX |

## 3. C2 Protocol

### Channel Matrix

| Channel | Transport | Bandwidth | Stealth |
|---------|-----------|-----------|---------|
| HTTP | TCP 80 | High | Medium |
| HTTPS | TCP 443 | High | Medium-High |
| WinHTTP (4.9+) | TCP 80/443 | High | High (different JA3) |
| DNS-A | UDP 53 | 4B/query | High |
| DNS-TXT | UDP 53 | 252B/query | Medium-High |
| SMB | TCP 445 | High | Internal only |
| TCP | Custom | High | Internal only |
| ExtC2 | Named Pipe | Varies | Custom |
| UDC2 (4.12) | BOF-defined | Unlimited | Fully custom |

### Key Negotiation

1. Beacon generates 16-byte random `sessionKey`
2. Bundles with metadata (BeaconID, PID, OS, IP, user, computer)
3. RSA-2048 encrypts the package → sends to TeamServer
4. Server derives: `SHA-256(sessionKey) → AES[0:16] + HMAC[16:32]`
5. All subsequent traffic uses AES-128-CBC + HMAC-SHA256

### Malleable C2 Profile — 16 Transform Operations

| Op | Description | Op | Description |
|----|-------------|----|-------------|
| base64 | Base64 encode | base64url | URL-safe Base64 |
| netbios | NetBIOS encode | netbiosu | Uppercase NetBIOS |
| mask | XOR mask | prepend | Add prefix |
| append | Add suffix | strrep | String replace |
| header | Place in HTTP header | parameter | Place in URL param |
| uri-append | Append to URI | print | Raw output |

## 4. Version Evolution (4.6 → 4.12)

### Timeline

| Version | Date | Key Features |
|---------|------|-------------|
| 4.6.1 | 2022.05 | Baseline (full JAR decompilable) |
| 4.7 | 2022.08 | Exportless Reflective Loader |
| 4.8 | 2023.02 | Independent PostEx Loader |
| 4.9 | 2023.05 | GraalVM Native Server, Guardrails, Direct Syscall |
| 4.9.1 | 2023.08 | WinHTTP Beacon, BOF-ification trend |
| 4.10 | 2024.Q1 | **BeaconGate**, Sleep Mask 32KB |
| 4.11 | 2024.Q3 | Indirect Syscall, DNS over HTTPS |
| 4.12 | 2025.Q1 | **UDC2**, Drip Loader, REST API, 4 new injection methods |

### BeaconGate (4.10+)

RPC-style proxy layer intercepting ~20 sensitive Windows APIs:
- VirtualAlloc, VirtualProtect, OpenProcess, CreateRemoteThread
- WriteProcessMemory, ReadProcessMemory, etc.

Three syscall modes per API:
- **None** — Normal IAT call (hookable by EDR)
- **Direct** — In-process `syscall` instruction (bypasses user-mode hooks, abnormal call stack)
- **Indirect** — Jump to ntdll's syscall instruction (normal call stack)

### UDC2 (4.12)

User-Defined C2 via BOF interface:
```c
void init(char* data, int len);
int  udc2Proxy(char* in, int inLen, char** out, int* outLen);
void udc2Close();
```
Enables arbitrary transport protocols (WebSocket, cloud APIs, social media, etc.)

## 5. Detection Guidance

### Immutable Detection Points

Regardless of Malleable Profile customization:

1. **Periodic communication pattern** — sleep + jitter statistical regularity
2. **Traffic asymmetry** — Small GET heartbeats, large POST callbacks
3. **High-entropy encrypted payloads** — AES ciphertext entropy ≈ 8.0
4. **DNS query frequency anomaly** — DNS Beacon subdomain query density
5. **Settings TLV format** — Binary config block structure unchanged across versions
6. **String Table marker** — 4096B string block structure unchanged

### Blue Team Priority

| Priority | Action |
|----------|--------|
| P0 | Deploy String Table + Settings TLV YARA rules (memory scanning) |
| P0 | Enable Sysmon + PowerShell ScriptBlock + WinRM Operational logging |
| P1 | Deploy Suricata rules for Default Profile traffic |
| P1 | Monitor anomalous Named Pipe creation (MSSE-/postex_/msagent_ patterns) |
| P2 | Implement JA3/JA3S fingerprinting + TLS certificate transparency |
| P2 | Deploy communication periodicity analysis (sleep + jitter detection) |
| P3 | Evaluate ETW Threat Intelligence + kernel callbacks (vs BeaconGate 4.10+) |
