# BANE — Banner Analysis & Network Enumeration Engine

Protocol fingerprinting tool for protocl CTI. Parses raw port banner data from tools like Shodan and Censys to identify services, OT/ICS protocols, C2 frameworks, and TA relevant indicators. Outputs pivot queries to help analysts track TA infra.

---

## Usage

```
python bane_cti.py                          # interactive mode
python bane_cti.py -f banners.txt           # batch file (one banner per line)
python bane_cti.py -f banners.txt -j        # JSON output to stdout
python bane_cti.py -f banners.txt -j -o results.json   # JSON output to file
echo "SSH-2.0-OpenSSH_8.9p1" | python bane_cti.py --pipe
python bane_cti.py --port 502               # provide port context for pivot queries
```

---

## False Positives to be mindful of !!

The detectors vary in how specific their signatures ar as I wrote this to be windows native and didn't have access to magic bytes the same way a linux box would. The sections below explain which detectors are prone to false positives and why, so analysts know when to apply extra scepticism!

### High-risk detectors (low specificity)

**NTP (`detect_ntp`)**
NTP has no magic bytes. The entire detection relies on a single byte (`li_vn_mode`) whose bit fields must decode to a valid NTP version (3 or 4) and mode (4=server, 5=broadcast). This byte pattern appears in many unrelated binary protocols by coincidence. Three guards reduce this:
- Minimum 48 bytes
- Entropy must be below 6.5/8.0 (encrypted/compressed data is excluded)
- Stratum byte must be ≤ 15 (RFC defined range)

Even with these guards, a short binary payload whose first byte happens to satisfy the bit pattern will still match. Always confirm NTP with port context (UDP/123) and check whether the rest of the packet has the structure NTP timestamp layout.

**HART-IP (`detect_hart_ip`)**
The first byte must be `0x01` (version) and the second must be in `{0,1,2,3}` (message type). These are extremely common values. The detector adds a length-field match (`byte_count` must be within 4 bytes of actual length) and restricts the status byte to known HART status codes, but short binary payloads can still match. Port 5094 context strongly recommended before acting on this.

**IEC 61850 GOOSE (`detect_iec_goose`)**
Triggered by a single byte: `0x61` at offset 0. This is an ASN.1 tag for a SEQUENCE OF, which appears in many certificate and LDAP-adjacent protocols. Without port 102 context, treat this as LOW confidence.

**IEC 61850 MMS (`detect_iec61850_mms`)**
Looks for ASN.1 tags `0xa8`, `0xa9`, or `0xa0` at offsets 0, 4, 7, or 10. These are context-specific ASN.1 tags common in many X.509 and LDAP structures. On port 102 alongside S7comm indicators the detection is meaningful; in isolation it is not.

**GE SRTP (`detect_ge_srtp`)**
Matches `0x01 0x00` at the start (extremely common) plus a service code byte in `0x01–0x1F`. The detector already excludes X11 (`0x01 0x00 0x0b 0x00`), but this pattern is still broad. Confidence is intentionally LOW. Port 18245 is the expected context.

**PC Worx / CC-Link (`detect_pcworx`, `detect_cc_link`)**
Both match only 2–3 bytes with no further validation. These are set to LOW confidence and should never be acted on without port context (1962 and 61450 respectively).

**CODESYS (`detect_codesys`)**
Matches `0x00` at byte 0 and a small set of service gruop bytes at byte 1. `0x00` as a leading byte is extremely common in many binary protocols. LOW–MEDIUM confidence; always confirm with port 1217.

**Generic C2 heuristic (`detect_generic_c2`)**
Fires on any banner with entropy > 6.8 and low printable ratio. This intentionally casts a wide net — it will fire on TLS application data, compressed streams, encrypted tunnels, and genuinely unknown C2. It is a flag for manual review, not a confirmed detection. Never report this as a confirmed C2 without corroborating evidence.

**Cobalt Strike entropy path (`detect_cobalt_strike`)**
When no HTTP indicators or known certificate CNs are found, the detector falls back to checking entropy > 7.2 over a payload >512 bytes. This is the same broad heuristic as `detect_generic_c2` and will fire on any high-entropy blob. If this is the only indicator that matched, the confidence is MEDIUM and should be treated as "unknown encrypted channel", not as a confirmed Cobalt Strike instance.

---

### Medium-risk detectors

**RDP (`detect_rdp`)**
Matches the TPKT header: `0x03 0x00` + a 2 byte length. This is the same framing used by Siemens S7comm (ISO-TSAP/COTP) and other ISO 8073 transports. On port 3389 this is RDP; on port 102 the S7comm detector takes priority (runs earlier in the chain). On any other port, treat the match with caution.

**Telnet (`detect_telnet`)**
Requires at least 2 genuine IAC+command pairs where the command byte is in the defined Telnet command range (0xF0–0xFE). Earlier versions matched on raw `0xFF` byte counts, which caused false positives on MySQL capability flags and MSMQ packets. The current version is significantly more specific, but any protocol carrying binary data with bytes in the 0xF0–0xFE range can still trigger it.

**NetBIOS Session Service (inside `detect_smb`)**
The session type byte must be one of the five defined NetBIOS session types, and the length field must not look like DNS flags. Packets with a high bit set at byte 2 and 12+ bytes of data that could be a DNS response are excluded, but edge cases exist on non-standard ports.

**DNS (`detect_dns`)**
Full RFC 1035 parsing with opcode/rcode/count validation, but binary protocols whose first 4 bytes happen to produce plausible DNS flag fields will still match at MEDIUM confidence. On non-port 53 data, treat DNS detections cautiously.

**MongoDB (`detect_mongodb`)**
Requires the `messageLength` field to be within 8 bytes of the actual data length, plus known opCodes (1 or 2013), plus `requestID` and `responseTo` both below 100,000. Previously this was matching on `opCode=1` alone, which overlapped with DCE/RPC `call_id=1`. The current implementation is substantially tighter.

---

### Low false positive rate (high specificity)

These detectors match on explicit ASCII strings, multi-byte magic sequences, or layered binary structs and are unlikely to produce false positives in practice:

- **SSH** — `SSH-` ASCII prefix, hard to fake accidentally
- **SMB1 / SMB2** — `\xffSMB` / `\xfeSMB` magic
- **MySQL** — protocol version byte + null-terminated version string + packet length validation
- **Modbus TCP** — MBAP protocol ID `0x0000` + plausible length field
- **DNP3** — `0x05 0x64` start bytes
- **OPC UA** — 3-byte ASCII message type (`HEL`, `ACK`, `OPN`, etc.) + valid chunk type
- **FINS** — `FINS` ASCII magic
- **MSMQ** — `LIOR` magic at offset 4
- **DCE/RPC** — version 5, valid PTYPE, packed_drep, fragment length validation
- **HTTP** — regex on `HTTP/x.x NNN` or method verb at line start
- **TLS** — `0x16 0x03 0x00–0x04` record type + version
- **MQTT CONNACK** — `0x20 0x02` fixed header
- **Bitcoin P2P** — 4 byte network magic
- **IRC / SIP / SMTP / POP3 / IMAP** — specific ASCII greeting patterns

---

## Adding Pivot Query Targets (Shodan, Censys, and Others)

Pivot queries are built in the `extract_signature()` function, starting around the line:

```python
# Build pivot queries
pivot_parts = [f for f in unique if f.pivot_value and len(f.pivot_value) >= 4]

shodan_parts = []
censys_parts = []
```

The query is assembled by iterating `pivot_parts` and pulling from each field's `search_hint` (for Shodan) or constructing a `services.banner:"value"` expression (for Censys). The final dict is:

```python
pivot_queries = {
    "shodan": " ".join(shodan_parts) if shodan_parts else "...",
    "censys": " ".join(censys_parts) if censys_parts else "...",
}
```

### To add a new platform (ie fofa, zoomeye)
You need to know what the syntax of the platform is and the correct vars for the query, below is an example using fofa and zoomeye syntax

**Step 1 Add the platform to the `pivot_queries` dict** (around line 3158):

```python
fofa_parts   = []
zoomeye_parts = []

for f in pivot_parts:
    val = f.pivot_value

    # Shodan (existing)
    shodan_parts.append(f.search_hint if f.search_hint else f'"{val}"')

    # Censys (existing)
    censys_parts.append(f'services.banner:"{val}"')

    # Fofa  — uses key=value syntax, banner field
    fofa_parts.append(f'banner="{val}"')

    # ZoomEye — uses fulltext search syntax
    zoomeye_parts.append(f'banner:"{val}"')

if port:
    shodan_parts.insert(0, f"port:{port}")
    censys_parts.insert(0, f"services.port={port}")
    fofa_parts.insert(0,   f'port="{port}"')
    zoomeye_parts.insert(0, f'port:{port}')

pivot_queries = {
    "shodan":   " ".join(shodan_parts)   if shodan_parts   else "(no pivot values found)",
    "censys":   " && ".join(censys_parts) if censys_parts   else "(no pivot values found)",
    "fofa":     " && ".join(fofa_parts)   if fofa_parts     else "(no pivot values found)",
    "zoomeye":  " ".join(zoomeye_parts)  if zoomeye_parts  else "(no pivot values found)",
}
```

**Step 2 — Add the platform to the `SignatureReport` dataclass** (around line 1966) if you want it in JSON output. The `pivot_queries` field is already a plain `dict`, so no dataclass change is strictly needed — the new key will appear automatically in JSON output.

**Step 3 — Add a print block in `print_signature()`** (around line 3315):

```python
print(f"  {BOLD}Shodan  :{RESET}")
print(f"    {CYAN}{sig.pivot_queries['shodan']}{RESET}")

print(f"\n  {BOLD}Censys  :{RESET}")
print(f"    {CYAN}{sig.pivot_queries['censys']}{RESET}")

# Add your new platform here:
print(f"\n  {BOLD}Fofa    :{RESET}")
print(f"    {CYAN}{sig.pivot_queries.get('fofa', 'n/a')}{RESET}")

print(f"\n  {BOLD}ZoomEye :{RESET}")
print(f"    {CYAN}{sig.pivot_queries.get('zoomeye', 'n/a')}{RESET}")
```

### To add platform-specific search hints per protocol

Each individual field has a `search_hint` attribute that is populated by the per-protocol dissectors (`_dissect_mysql`, `_dissect_ssh`, `_dissect_http`, etc..) These hints are currently written for Shodan syntax. To add Fofa-style hints at the field level, extend the `SigField` dataclass:

```python
@dataclass
class SigField:
    label:       str
    raw_hex:     str
    printable:   str
    offset:      int
    length:      int
    uniqueness:  str
    pivot_value: str
    reason:      str
    search_hint: str          # Shodan query fragment (existing)
    fofa_hint:   str = ""     # Fofa query fragment (new)
    zoomeye_hint: str = ""    # ZoomEye query fragment (new)
```

Then update each dissector to populate the new fields where known. For example, in `_dissect_ssh`:

```python
normal.append(SigField(
    ...
    search_hint=f'"SSH-{proto}-{base_ver}"',
    fofa_hint=f'banner="SSH-{proto}-{base_ver}"',
    zoomeye_hint=f'banner:"SSH-{proto}-{base_ver}"',
))
```

---

## Adding a New Protocol Detector

Every protocol detector is a standalone function that takes `data: bytes` and returns either a `DetectionResult` or `None`. Adding a new one is four steps.

### Step 1 — Write the detector function

Add your function anywhere in the detectors block (roughly lines 111–1840). Follow the existing pattern:

```python
def detect_myprotocol(data):
    """
    Brief description of what the protocol is and what bytes identify it.
    Explain any known false positive risks here.
    """
    # Guard: minimum viable length before you touch any offsets
    if len(data) < 8:
        return None

    # Check magic bytes / header fields that uniquely identify the protocol
    if data[0:4] != b"\xAB\xCD\xEF\x00":
        return None

    # Optional: add secondary validation to reduce false positives
    declared_len = int.from_bytes(data[4:6], "big")
    if declared_len < 6 or declared_len > len(data):
        return None

    # Extract useful fields for the detail string
    version  = data[6]
    msg_type = data[7]

    return DetectionResult(
        service    = "MyProtocol (Vendor / Use-case)",
        category   = "OT_ICS",          # see category list below
        confidence = "HIGH",             # HIGH / MEDIUM / LOW
        detail     = f"MyProtocol v{version} message type {msg_type:#04x}",
        version    = str(version),
        port_hint  = 12345,              # expected port — used in pivot queries
        ioc_flags  = ["MyProtocol has no authentication — direct device access"],
        references = ["T0821"]           # MITRE ATT&CK or CVE refs
    )
```

**Category values** (pick the closest one):

| Category | When to use |
|---|---|
| `C2_FRAMEWORK` | Known offensive tooling (Cobalt Strike, Sliver, etc.) |
| `THREAT_INDICATOR` | Anonymisation, proxies, tunnels |
| `OT_ICS` | Industrial control system protocols |
| `REMOTE_ACCESS` | SSH, RDP, VNC, SMB, WinRM, etc. |
| `DATABASE` | Any database wire protocol |
| `WEB` | HTTP, REST APIs |
| `MAIL` | SMTP, POP3, IMAP |
| `MESSAGING` | MQTT, AMQP, IRC, SIP |
| `CRYPTO` | TLS/SSL |
| `DIRECTORY` | LDAP, X.509 |
| `VOIP` | SIP, RTP |
| `OTHER` | Everything else |

### Step 2 — Register the detector

Open the `DETECTORS` list (around line 1601). The list runs top to bottom — the first match wins for the protocol label in signature analysis, though all matches are returned. Place your detector in the right priority group:

```python
DETECTORS = [
    # C2 / Threat indicators — always first
    detect_cobalt_strike,
    ...

    # OT/ICS — add here for ICS protocols
    detect_s7comm,
    detect_modbus,
    detect_myprotocol,   # <-- add here
    ...

    # Remote access
    detect_ssh,
    ...
]
```

Put your detector **before** any broader detectors that might match the same bytes. For example, if your protocol uses a TPKT header (`0x03 0x00`), put it before `detect_rdp` so the more specific match wins.

### Step 3 — Add a field dissector for signature analysis (optional but recommended)

The signature analysis section breaks the banner into NORMAL / UNIQUE / VARIABLE fields so analysts know what to pivot on. If you skip this step, the generic dissector will handle it, which produces reasonable but less precise output.

Add a function following the naming convention `_dissect_myprotocol(data)` in the dissectors block (around lines 2041–3130):

```python
def _dissect_myprotocol(data: bytes) -> tuple[list, list, list]:
    normal, unique, variable = [], [], []

    # NORMAL: fields that are identical on every server running this protocol/version
    normal.append(SigField(
        label      = "Magic header",
        raw_hex    = _to_hex(data[0:4]),
        printable  = "\\xAB\\xCD\\xEF\\x00",
        offset     = 0,
        length     = 4,
        uniqueness = "NORMAL",
        pivot_value= "",
        reason     = "Fixed protocol magic — present on every MyProtocol server",
        search_hint= ""
    ))

    # UNIQUE: operator-configured values good for pivoting
    device_name_end = data.find(b"\x00", 8)
    if device_name_end != -1:
        name = data[8:device_name_end].decode("ascii", errors="replace")
        unique.append(SigField(
            label      = "Device name",
            raw_hex    = _to_hex(data[8:device_name_end]),
            printable  = name,
            offset     = 8,
            length     = device_name_end - 8,
            uniqueness = "UNIQUE",
            pivot_value= name,
            reason     = "Operator-assigned device name — pivot on this to find related nodes",
            search_hint= f'"{name}"'   # Shodan query fragment
        ))

    # VARIABLE: per-connection values — warn analyst not to pivot on these
    variable.append(SigField(
        label      = "Session nonce",
        raw_hex    = _to_hex(data[16:24]),
        printable  = _to_escaped(data[16:24]),
        offset     = 16,
        length     = 8,
        uniqueness = "VARIABLE",
        pivot_value= "",
        reason     = "Random nonce — changes every connection, do not pivot",
        search_hint= ""
    ))

    return normal, unique, variable
```

Then wire it into the router inside `extract_signature()` (around line 3100):

```python
if _has("MySQL") or _has("MariaDB"):
    normal, unique, variable = _dissect_mysql(data)
elif _has("MyProtocol"):               # <-- add this block
    normal, unique, variable = _dissect_myprotocol(data)
    protocol = next((r.service for r in results if "MyProtocol" in r.service), protocol)
elif _has("SSH"):
    ...
```

### Step 4 — Test it

Paste a real banner from Shodan or Censys in interactive mode and confirm:
- The correct service name and category appear
- Confidence level is appropriate for how specific your signature is
- No other detectors fire on the same data that shouldn't (check the full detection list, not just the first result)
- VARIABLE fields are not appearing in the pivot query output

If you see an unexpected co-detection (e.g. Telnet or LDAP firing alongside your new protocol), check whether your magic bytes happen to satisfy those detectors' conditions and consider adding exclusion logic. see how `detect_ge_srtp` excludes X11 headers for an example.

---

## File Structure

```
bane_cti.py   — main script (all code in one file and avoid dependencies)
README.md     — this file
bane_test.py - create a branch or use bane_test.py to test new features (ie new platform search syntax, new protocol support etc)
```

### Key sections inside `bane_cti.py`

quick and nasty explantion of each section of the script in blocks per line (look out for changes on the script not reflected below)

| Line range | Section |
|---|---|
| 1 – 110 | Data model, decode helpers, entropy/printable utilities |
| 111 – 280 | Database detectors (MySQL, Postgres, MSSQL, MongoDB, Redis, etc.) |
| 281 – 450 | Remote access detectors (SSH, RDP, VNC, Telnet, SMB, WinRM, etc.) |
| 451 – 990 | OT/ICS detectors (Modbus, DNP3, S7comm, IEC104, BACnet, OPC-UA, etc.) |
| 991 – 1280 | C2 framework detectors (Cobalt Strike, Metasploit, Sliver, Empire, etc.) |
| 1281 – 1600 | Web, TLS, mail, network infra, messaging detectors |
| 1601 – 1840 | Detector registry (`DETECTORS` list — controls run order) |
| 1841 – 1960 | Analysis engine (`analyze()`, `analyze_summary()`) |
| 1961 – 2040 | Signature extraction data model (`SigField`, `SignatureReport`) |
| 2041 – 3130 | Per-protocol field dissectors (`_dissect_mysql`, `_dissect_ssh`, etc.) |
| 3131 – 3177 | `extract_signature()` — pivot query builder |
| 3178 – 3340 | Output formatting (`print_result`, `print_signature`) |
| 3337 – 3345 | `BANNER_ART` — ASCII art displayed on launch |
| 3350 – end  | `main()` — CLI argument parsing and entry point |
