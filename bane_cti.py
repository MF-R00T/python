#!/usr/bin/env python3
"""
Banner Analyzer v1.0 - Protocol fingerprinting for threat intelligence
Identifies services, OT/ICS protocols, and C2 framework signatures
from raw port banner data.

Examples:
  python bane_cti.py
  python bane_cti.py -f banners.txt -j -o results.json
  echo 'SSH-2.0-OpenSSH_8.9p1' | python bane_cti.py --pipe
"""

import re
import sys
import math
import json
import codecs
import argparse
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional



# Data model
@dataclass
class DetectionResult:
    service:    str
    category:   str   # C2_FRAMEWORK | THREAT_INDICATOR | OT_ICS | REMOTE_ACCESS |
                      # DATABASE | WEB | MAIL | MESSAGING | DIRECTORY | CRYPTO |
                      # VOIP | OTHER
    confidence: str   # HIGH / MEDIUM / LOW
    detail:     str
    version:    Optional[str]  = None
    port_hint:  Optional[int]  = None
    extra:      Optional[str]  = None
    ioc_flags:  list = field(default_factory=list)
    references: list = field(default_factory=list)


# Helpers
def decode_banner(raw: str) -> tuple[bytes, bool]:
    """
    Decode a banner string containing Python-style escape sequences.
    Returns (decoded_bytes, double_escaped_warning).

    Handles three cases:
    1. Normal:  \\x10\\x00LIOR  - bytes 0x10 0x00 'L' 'I' 'O' 'R'
    2. Double-escaped (one extra layer): \\\\x10\\\\x00LIOR - first pass gives
       literal '\\x10', second pass gives 0x10.  We detect and fix automatically.
    3. Mixed: printable text + some escape sequences — decoded as-is.
    """
    try:
        decoded = codecs.decode(raw.encode("utf-8"), "unicode_escape")
        result = decoded.encode("latin-1")
    except Exception:
        result = raw.encode("latin-1", errors="replace")

    # Detect double-escaping: result is >85% printable AND still contains
    # literal \\xNN sequences that were not interpreted
    pr = sum(1 for b in result if 32 <= b < 127) / max(len(result), 1)
    has_literal_escapes = b"\\x" in result or (b"\\n" in result and b"\\r" in result)
    double_escaped = pr > 0.85 and has_literal_escapes

    if double_escaped:
        # Apply a second decode pass to resolve the remaining \\xNN sequences
        try:
            second_pass = codecs.decode(result, "unicode_escape").encode("latin-1")
            result = second_pass
        except Exception:
            # If second pass fails, fall back to manual replacement
            try:
                interim = result.decode("ascii", errors="replace")
                second_pass = codecs.decode(interim.encode("utf-8"), "unicode_escape").encode("latin-1")
                result = second_pass
            except Exception:
                pass  # leave result as-is, warning will still show

    return result, double_escaped

def safe_ascii(data: bytes, max_len: int = 200) -> str:
    result = ""
    for b in data[:max_len]:
        result += chr(b) if 32 <= b < 127 else f"\\x{b:02x}"
    if len(data) > max_len:
        result += f"  ... ({len(data)-max_len} more bytes)"
    return result

def byte_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def printable_ratio(data: bytes) -> float:
    if not data: return 0.0
    return sum(1 for b in data if 32 <= b < 127) / len(data)

def u16be(b, o): return struct.unpack_from(">H", b, o)[0]
def u16le(b, o): return struct.unpack_from("<H", b, o)[0]
def u32be(b, o): return struct.unpack_from(">I", b, o)[0]
def u32le(b, o): return struct.unpack_from("<I", b, o)[0]


# DATABASES

def detect_mysql(data):
    if len(data) < 5: return None
    payload_len = int.from_bytes(data[0:3], "little")
    seq, proto = data[3], data[4]
    if proto == 10 and seq == 0 and payload_len < len(data):
        end = data.find(b"\x00", 5)
        if end == -1: return None
        version = data[5:end].decode("ascii", errors="replace")
        auth_plugin = ""
        last_null = data.rfind(b"\x00")
        if last_null > end:
            ps = data.rfind(b"\x00", end+1, last_null)
            if ps != -1:
                auth_plugin = data[ps+1:last_null].decode("ascii", errors="replace")
        ioc = []
        if any(version.startswith(v) for v in ("5.5","5.6")):
            ioc.append("EOL MySQL version — common on unpatched targets")
        return DetectionResult(
            service="MySQL / MariaDB Database", category="DATABASE",
            confidence="HIGH", detail=f"MySQL handshake (protocol v{proto})",
            version=version, port_hint=3306,
            extra=f"Auth plugin: {auth_plugin}" if auth_plugin else None,
            ioc_flags=ioc)
    return None

def detect_postgres(data):
    if len(data) >= 9 and data[0:1] == b"R":
        length = u32be(data, 1)
        if 8 <= length <= 32:
            return DetectionResult(
                service="PostgreSQL Database", category="DATABASE",
                confidence="MEDIUM", detail="PostgreSQL authentication request — 'R' byte + small length (not conclusive alone; needs error message or protocol string to confirm),",
                port_hint=5432)
    if data[0:1] == b"E" and b"PostgreSQL" in data:
        return DetectionResult(
            service="PostgreSQL Database", category="DATABASE",
            confidence="HIGH", detail="PostgreSQL error response with server identifier",
            port_hint=5432)
    return None

def detect_mssql(data):
    if len(data) >= 8 and data[0] == 0x04 and data[1] in (0x01, 0x00):
        return DetectionResult(
            service="Microsoft SQL Server (MSSQL)", category="DATABASE",
            confidence="MEDIUM", detail="TDS protocol pre-login response", port_hint=1433)
    if b"Microsoft SQL Server" in data or b"MSSQLSERVER" in data:
        return DetectionResult(
            service="Microsoft SQL Server (MSSQL)", category="DATABASE",
            confidence="HIGH", detail="MSSQL identifier in banner", port_hint=1433)
    return None

def detect_mongodb(data):
    """
    MongoDB wire protocol: MsgHeader = requestID(4LE) + responseTo(4LE) +
                                       opCode(4LE) + messageLength(4LE, first field)
    Actually layout is: messageLength(4LE) + requestID(4LE) + responseTo(4LE) + opCode(4LE)
    OP_REPLY=1 (legacy), OP_MSG=2013.
    Require: messageLength at [0-3] matches actual data length (±tolerance),
    AND opCode is a known MongoDB value.
    opCode=1 at offset 12 alone matches DCE/RPC call_id=1 and many other protocols.
    """
    if len(data) < 16:
        return None
    msg_len = u32le(data, 0)
    op_code = u32le(data, 12)
    if op_code not in (1, 2013):
        return None
    # messageLength must be plausible — within 8 bytes of actual data length
    if msg_len < 16 or abs(msg_len - len(data)) > 8:
        return None
    # requestID and responseTo should be small integers, not 0x00000000/0xFFFFFFFF
    request_id  = u32le(data, 4)
    response_to = u32le(data, 8)
    if request_id > 100000 or response_to > 100000:
        return None
    return DetectionResult(
        service="MongoDB (NoSQL Database)", category="DATABASE",
        confidence="MEDIUM", detail=f"MongoDB wire protocol (opCode={op_code})",
        port_hint=27017,
        ioc_flags=["MongoDB on default port — often internet-exposed without auth"])

def detect_redis(data):
    txt = data[:128].decode("ascii", errors="replace")
    if "NOAUTH" in txt or "Authentication required" in txt:
        return DetectionResult(
            service="Redis (Cache / Key-Value Store)", category="DATABASE",
            confidence="HIGH", detail="Redis RESP — auth required response", port_hint=6379)
    if re.match(r"^\+PONG", txt):
        return DetectionResult(
            service="Redis (Cache / Key-Value Store)", category="DATABASE",
            confidence="HIGH", detail="Redis PINGPONG (unauthenticated access)",
            port_hint=6379,
            ioc_flags=["Unauthenticated Redis — common C2 data store and pivot target"])
    if txt.startswith("-ERR") and "Redis" in txt:
        return DetectionResult(
            service="Redis (Cache / Key-Value Store)", category="DATABASE",
            confidence="HIGH", detail="Redis RESP error response", port_hint=6379)
    if txt and txt[0] in ("+","-","*","$",":"):
        return DetectionResult(
            service="Redis or RESP-compatible service", category="DATABASE",
            confidence="MEDIUM", detail="RESP protocol framing detected", port_hint=6379)
    return None

def detect_memcached(data):
    txt = data[:128].decode("ascii", errors="replace")
    if re.search(r"^(VERSION|STORED|NOT_STORED|ERROR|CLIENT_ERROR|VALUE|END|STAT)", txt, re.M):
        return DetectionResult(
            service="Memcached (Distributed Cache)", category="DATABASE",
            confidence="HIGH", detail="Memcached text protocol response", port_hint=11211,
            ioc_flags=["Memcached 11211 used in DDoS amplification attacks"])
    return None

def detect_elasticsearch(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "elasticsearch" in txt.lower() or '"cluster_name"' in txt or '"tagline"' in txt:
        m = re.search(r'"number"\s*:\s*"([^"]+)"', txt)
        return DetectionResult(
            service="Elasticsearch", category="DATABASE", confidence="HIGH",
            detail="Elasticsearch JSON response", version=m.group(1) if m else None,
            port_hint=9200,
            ioc_flags=["Unauthenticated Elasticsearch — frequent data breach vector"])
    return None

def detect_cassandra(data):
    if len(data) >= 9 and data[0] in (0x83,0x84,0x04,0x05) and data[3] == 0x02:
        return DetectionResult(
            service="Apache Cassandra (NoSQL Database)", category="DATABASE",
            confidence="MEDIUM", detail="CQL native protocol READY response", port_hint=9042)
    return None

def detect_couchdb(data):
    txt = data[:256].decode("utf-8", errors="replace")
    if "couchdb" in txt.lower() or '"couchdb"' in txt:
        return DetectionResult(
            service="Apache CouchDB", category="DATABASE", confidence="HIGH",
            detail="CouchDB HTTP JSON response", port_hint=5984,
            ioc_flags=["CouchDB admin API — exposed instances linked to cryptomining deployments"])
    return None

def detect_influxdb(data):
    txt = data[:256].decode("utf-8", errors="replace")
    if "influxdb" in txt.lower() or "X-Influxdb-Version" in txt:
        return DetectionResult(
            service="InfluxDB (Time-Series Database)", category="DATABASE",
            confidence="HIGH", detail="InfluxDB HTTP response", port_hint=8086)
    return None

def detect_etcd(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "etcd" in txt.lower() or '"etcdserver"' in txt:
        return DetectionResult(
            service="etcd (Kubernetes Key-Value Store)", category="DATABASE",
            confidence="HIGH", detail="etcd server response", port_hint=2379,
            ioc_flags=["Exposed etcd = full Kubernetes secrets access (service accounts, TLS keys)"],
            references=["T1552"])
    return None

# REMOTE ACCESS

def detect_ssh(data):
    if not data.startswith(b"SSH-"): return None
    line = data.split(b"\n")[0].decode("ascii", errors="replace").strip()
    parts = line.split("-", 2)
    version = parts[2] if len(parts) >= 3 else "unknown"
    proto   = parts[1] if len(parts) >= 2 else "?"
    ioc = []
    suspicious = ["libssh","dropbear","paramiko","AsyncSSH","ROSSSH"]
    for s in suspicious:
        if s.lower() in version.lower():
            ioc.append(f"SSH impl '{s}' — seen in threat actor tooling/implants")
    if re.match(r"OpenSSH_[1-5]\.", version):
        ioc.append("Very old OpenSSH — likely unpatched or deliberate decoy")
    return DetectionResult(
        service="SSH (Secure Shell)", category="REMOTE_ACCESS",
        confidence="HIGH", detail=f"SSH protocol {proto}", version=version,
        port_hint=22, ioc_flags=ioc, references=["T1021.004"])

def detect_rdp(data):
    if len(data) >= 4 and data[0] == 0x03 and data[1] == 0x00:
        length = u16be(data, 2)
        if 5 <= length <= 512:
            return DetectionResult(
                service="RDP (Remote Desktop Protocol)", category="REMOTE_ACCESS",
                confidence="MEDIUM", detail="TPKT header (0x03 0x00 + plausible length) — consistent with RDP but also S7comm and ISO-TSAP; port context needed to confirm", port_hint=3389,
                ioc_flags=["RDP on default port — top ransomware initial access vector"],
                references=["T1021.001"])
    return None

def detect_vnc(data):
    txt = data[:32].decode("ascii", errors="replace")
    m = re.match(r"^RFB (\d+\.\d+)", txt)
    if m:
        return DetectionResult(
            service="VNC (Remote Frame Buffer)", category="REMOTE_ACCESS",
            confidence="HIGH", detail=f"RFB protocol {m.group(1)}", version=m.group(1),
            port_hint=5900,
            ioc_flags=["VNC without auth frequently found on C2 jump boxes"],
            references=["T1021.005"])
    return None

def detect_telnet(data):
    """
    Telnet IAC sequences: 0xFF (IAC) followed by a command byte.
    Valid command bytes are 0xF0-0xFE (SE, NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, SB)
    and 0xFB-0xFE (WILL, WONT, DO, DONT).
    0xFF 0xFF is an escaped literal 0xFF — NOT a command pair.
    Simply counting raw 0xFF bytes is far too loose; many binary protocols
    (MSMQ, MySQL capability flags) contain 0xFF bytes that are not Telnet.
    Require at least 2 genuine IAC+command pairs where the command byte
    is in the defined Telnet command range and is NOT 0xFF itself.
    """
    # Telnet command bytes: SE(240) NOP(241) DM(242) BRK(243) IP(244) AO(245)
    # AYT(246) EC(247) EL(248) GA(249) SB(250) WILL(251) WONT(252) DO(253) DONT(254)
    TELNET_CMDS = set(range(240, 255))  # 0xF0-0xFE, excludes 0xFF (that's IAC escape)
    iac_pairs = 0
    i = 0
    while i < len(data) - 1:
        if data[i] == 0xFF:
            cmd = data[i + 1]
            if cmd in TELNET_CMDS:
                iac_pairs += 1
                i += 2
                continue
        i += 1
    if iac_pairs >= 2:
        return DetectionResult(
            service="Telnet", category="REMOTE_ACCESS",
            confidence="HIGH" if iac_pairs >= 4 else "MEDIUM",
            detail=f"Telnet IAC negotiation ({iac_pairs} IAC+command pairs)",
            port_hint=23,
            ioc_flags=["Cleartext Telnet — credentials in plaintext; IoT botnet entry point"],
            references=["T1021"])
    return None

def detect_smb(data):
    if data[:4] == b"\xffSMB":
        return DetectionResult(
            service="SMB1 (Windows File Sharing)", category="REMOTE_ACCESS",
            confidence="HIGH", detail="SMBv1 header (\\xffSMB)", port_hint=445,
            ioc_flags=["SMBv1 vulnerable to EternalBlue (MS17-010)"],
            references=["T1021.002","CVE-2017-0144"])
    if data[:4] == b"\xfeSMB":
        return DetectionResult(
            service="SMB2/3 (Windows File Sharing)", category="REMOTE_ACCESS",
            confidence="HIGH", detail="SMB2/3 header (\\xfeSMB)", port_hint=445,
            references=["T1021.002"])
    # NetBIOS Session Service: 0x81 = Session Request, but ONLY if followed by
    # a valid length and the data looks like a NetBIOS name (printable ASCII run)
    # 0x81 alone is too broad — DNS QR flags also start with 0x81
    NETBIOS_TYPES = {0x00:"Session Message", 0x81:"Session Request",
                     0x82:"Positive Session Response", 0x83:"Negative Session Response",
                     0x84:"Retarget Session Response", 0x85:"Session Keepalive"}
    if len(data) >= 4 and data[0] in NETBIOS_TYPES:
        # Require length field (bytes 1-3) to be plausible and not look like DNS flags
        nb_len = int.from_bytes(data[1:4], "big")
        # DNS responses have flags at bytes 2-3 with QR=1 (0x80xx) — if byte 2 has
        # high bit set AND data contains a DNS label structure, it's not NetBIOS
        if data[2] & 0x80 and len(data) >= 12:
            # Looks like DNS flags field — skip
            pass
        elif nb_len <= 65535:
            return DetectionResult(
                service="NetBIOS Session Service", category="REMOTE_ACCESS",
                confidence="MEDIUM",
                detail=f"NetBIOS {NETBIOS_TYPES[data[0]]} (declared len={nb_len})",
                port_hint=139)
    return None

def detect_winrm(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "WSMan" in txt or "wsman" in txt.lower():
        return DetectionResult(
            service="WinRM (Windows Remote Management)", category="REMOTE_ACCESS",
            confidence="MEDIUM", detail="WinRM/WS-Management HTTP response", port_hint=5985,
            ioc_flags=["WinRM used by CrackMapExec, Evil-WinRM, and lateral movement tooling"],
            references=["T1021.006"])
    return None

def detect_ipmi(data):
    if len(data) >= 4 and data[0]==0x06 and data[1]==0x00 and data[2]==0xff and data[3]==0x07:
        return DetectionResult(
            service="IPMI (Intelligent Platform Management Interface)", category="REMOTE_ACCESS",
            confidence="HIGH", detail="IPMI RMCP packet header", port_hint=623,
            ioc_flags=["IPMI 2.0 RAKP allows offline BMC password hash cracking",
                       "Exposed IPMI = full out-of-band server control"],
            references=["CVE-2013-4786"])
    return None

def detect_teamviewer(data):
    txt = data[:256].decode("ascii", errors="replace")
    if "TeamViewer" in txt:
        return DetectionResult(
            service="TeamViewer (Remote Access Software)", category="REMOTE_ACCESS",
            confidence="MEDIUM", detail="TeamViewer banner detected", port_hint=5938,
            ioc_flags=["TeamViewer abused for persistent access by threat actors"],
            references=["T1219"])
    return None

def detect_anydesk(data):
    txt = data[:256].decode("ascii", errors="replace")
    if "AnyDesk" in txt:
        return DetectionResult(
            service="AnyDesk (Remote Access Software)", category="REMOTE_ACCESS",
            confidence="MEDIUM", detail="AnyDesk banner detected", port_hint=7070,
            ioc_flags=["AnyDesk frequently deployed by ransomware groups for persistent access"],
            references=["T1219"])
    return None

def detect_docker_api(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "Docker" in txt or '"ApiVersion"' in txt or (
            "HTTP" in txt and re.search(r"/v\d+\.\d+/", txt)):
        return DetectionResult(
            service="Docker API (Container Management)", category="REMOTE_ACCESS",
            confidence="HIGH", detail="Docker REST API response", port_hint=2375,
            ioc_flags=["Unauthenticated Docker API = container escape to host — "
                       "actively exploited by cryptomining/backdoor campaigns"],
            references=["T1610","CVE-2019-5736"])
    return None

def detect_kubernetes_api(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "Kubernetes" in txt or '"apiVersion"' in txt or "k8s.io" in txt:
        return DetectionResult(
            service="Kubernetes API Server", category="REMOTE_ACCESS",
            confidence="HIGH", detail="Kubernetes API server response", port_hint=6443,
            ioc_flags=["Exposed K8s API — full cluster takeover vector"],
            references=["T1610"])
    return None


# OT / ICS PROTOCOLS
def detect_modbus(data):
    """Modbus TCP: MBAP header protocol_id=0x0000"""
    if len(data) < 8: return None
    if u16be(data, 2) != 0x0000: return None
    length = u16be(data, 4)
    if length < 2 or length > 260: return None
    func_code = data[7] & 0x7F
    exception = bool(data[7] & 0x80)
    func_names = {
        1:"Read Coils", 2:"Read Discrete Inputs",
        3:"Read Holding Registers", 4:"Read Input Registers",
        5:"Write Single Coil", 6:"Write Single Register",
        15:"Write Multiple Coils", 16:"Write Multiple Registers",
        43:"Read Device Identification",
    }
    name = func_names.get(func_code, f"Function {func_code}")
    if exception: name = f"Exception response to {name}"
    return DetectionResult(
        service="Modbus TCP (ICS/SCADA)", category="OT_ICS",
        confidence="HIGH", detail=f"Modbus MBAP — {name}", port_hint=502,
        ioc_flags=["Modbus has NO authentication — any device can send commands",
                   "Internet-exposed Modbus = direct PLC/RTU access"],
        references=["T0843","T0855"])

def detect_dnp3(data):
    """DNP3 — electric utilities and water treatment"""
    if len(data) >= 10 and data[0] == 0x05 and data[1] == 0x64:
        dst = u16le(data, 4)
        src = u16le(data, 6)
        ctrl = data[3]
        fc_map = {0:"DL Confirm",1:"DL Reset",2:"Test DL",3:"DL Status",
                  9:"Unconfirmed User Data"}
        fc = fc_map.get(ctrl & 0x0F, f"FC={ctrl&0x0F}")
        return DetectionResult(
            service="DNP3 (Distributed Network Protocol 3 — ICS/SCADA)", category="OT_ICS",
            confidence="HIGH", detail=f"DNP3 frame — {fc} | src={src} dst={dst}",
            port_hint=20000,
            ioc_flags=["DNP3 no built-in auth — replay attacks possible",
                       "Targeted in attacks on electric grid / water (CRASHOVERRIDE)"],
            references=["T0812","T0855"])
    return None

def detect_iec104(data):
    """IEC 60870-5-104 — European power grid SCADA"""
    if len(data) >= 6 and data[0] == 0x68:
        apdu_len = data[1]
        if 4 <= apdu_len <= 253:
            ctrl = data[2]
            ft = ctrl & 0x03
            frame_types = {0:"I-frame",1:"S-frame",3:"U-frame"}
            u_funcs = {0x07:"STARTDT act",0x0B:"STARTDT con",0x13:"STOPDT act",
                       0x23:"STOPDT con",0x43:"TESTFR act",0x83:"TESTFR con"}
            desc = frame_types.get(3 if ft==3 else ft&1, "unknown")
            if ft == 3:
                u_func = u_funcs.get(ctrl & 0xFC, f"ctrl={ctrl:#x}")
                desc += f" ({u_func})"
            return DetectionResult(
                service="IEC 60870-5-104 (IEC 104 — Power Grid SCADA)", category="OT_ICS",
                confidence="MEDIUM", detail=f"IEC 104 APDU — {desc} (0x68 start byte + valid length; confirm with port 2404 context)", port_hint=2404,
                ioc_flags=["IEC 104 controls power grid RTUs/IEDs — targeted by Sandworm/Industroyer2"],
                references=["T0812","T0831"])
    return None

def detect_enip_cip(data):
    """EtherNet/IP (CIP) — Allen-Bradley / Rockwell PLCs"""
    if len(data) < 24: return None
    command = u16le(data, 0)
    enip_cmds = {
        0x0065:"ListServices", 0x0066:"ListIdentity", 0x0063:"ListInterfaces",
        0x0064:"RegisterSession", 0x006F:"SendRRData", 0x0070:"SendUnitData",
    }
    if command not in enip_cmds: return None
    cmd_name = enip_cmds[command]
    detail = f"EtherNet/IP command: {cmd_name}"
    if command == 0x0066 and len(data) > 30:
        try:
            pd_start = 26
            pd_len = data[pd_start]
            if pd_len > 0 and pd_start+1+pd_len <= len(data):
                prod = data[pd_start+1:pd_start+1+pd_len].decode("ascii", errors="replace")
                detail += f" | product: {prod}"
        except Exception:
            pass
    return DetectionResult(
        service="EtherNet/IP / CIP (Industrial Ethernet — Allen-Bradley/Rockwell)",
        category="OT_ICS", confidence="HIGH", detail=detail, port_hint=44818,
        ioc_flags=["EtherNet/IP exposes PLCs directly — no auth on legacy devices",
                   "Targeted by CHERNOVITE/PIPEDREAM (Incontroller) malware"],
        references=["T0821","T0855"])

def detect_s7comm(data):
    """Siemens S7comm over ISO-TSAP/COTP (port 102)"""
    if len(data) < 7: return None
    if data[0] == 0x03 and data[1] == 0x00:
        cotp_len  = data[4] if len(data) > 4 else 0
        cotp_type = data[5] if len(data) > 5 else 0
        cotp_types = {0xE0:"CR (Connection Request)",0xD0:"CC (Connection Confirm)",
                      0xF0:"DT (Data Transfer)",0x80:"DR (Disconnect Request)"}
        if cotp_type in cotp_types:
            cotp_name = cotp_types[cotp_type]
            s7_off = 4 + cotp_len + 1
            if s7_off < len(data) and data[s7_off] == 0x32:
                pdu_type = data[s7_off+1] if s7_off+1 < len(data) else 0
                pdu_types = {1:"Job Request",2:"Ack",3:"Ack-Data",7:"Userdata"}
                pdu_name = pdu_types.get(pdu_type, f"PDU type {pdu_type}")
                return DetectionResult(
                    service="Siemens S7comm (S7 PLC — ISO-TSAP/COTP)", category="OT_ICS",
                    confidence="HIGH", detail=f"S7comm {pdu_name} over COTP {cotp_name}",
                    port_hint=102,
                    ioc_flags=["S7comm used by Stuxnet and TRITON/TRISIS for PLC manipulation",
                               "Port 102 directly accesses Siemens S7-300/400/1200/1500"],
                    references=["T0821","T0843","CVE-2019-13945"])
            return DetectionResult(
                service="ISO-TSAP / COTP (Siemens S7 or IEC 61850 MMS)", category="OT_ICS",
                confidence="MEDIUM", detail=f"TPKT + COTP {cotp_name}", port_hint=102)
    return None

def detect_vnetip(data):
    """
    Unknown structured binary protocol with embedded ASCII device name.

    What the banner bytes directly confirm:
    - Binary frame with big-endian length field matching actual packet size
    - Flags byte 0x80 (high bit set — consistent with response/direction flag)
    - Null-terminated ASCII string in format [alphanum]_[alphanum]_[alphanum]
      at a fixed offset — consistent with industrial asset naming conventions

    What this does NOT confirm from a single banner:
    - Specific vendor or product
    - Whether this is ICS/SCADA at all vs another binary protocol with similar
      framing that happens to carry an asset-style name string

    The ICS classification is based on: port range correlation + structured
    binary framing + device-name-format string. MEDIUM confidence is appropriate.
    Do NOT upgrade to HIGH without additional corroboration (adjacent port
    banners, full packet capture, or vendor documentation match).
    """
    if len(data) < 12:
        return None

    msg_type  = data[0]
    flags     = data[2]
    total_len = u32be(data, 4)

    # Total length field must match actual packet exactly
    if total_len != len(data):
        return None
    # Flags byte must be a plausible direction indicator
    if flags not in (0x00, 0x80):
        return None
    # msg_type in plausible range
    if not (0x10 <= msg_type <= 0x3F):
        return None

    # Extract and validate device name string
    if len(data) <= 12:
        return None
    end = data.find(b'\x00', 12)
    end = end if end != -1 else len(data)
    try:
        node_name = data[12:end].decode("ascii")
    except Exception:
        return None
    # Must look like an industrial asset ID: alphanum parts separated by underscores
    if not node_name or '_' not in node_name:
        return None
    if not re.match(r'^[A-Za-z0-9]+(_[A-Za-z0-9]+){1,}$', node_name):
        return None

    domain_id = data[10] if len(data) > 10 else 0
    node_type = data[11] if len(data) > 11 else 0
    direction = "response" if flags == 0x80 else "request"

    return DetectionResult(
        service="Unknown Structured Binary Protocol (possible ICS/SCADA)",
        category="OT_ICS",
        confidence="MEDIUM",
        detail=(
            f"Binary {direction} frame — length-verified header, "
            f"embedded device name: '{node_name}' "
            f"(msg_type={msg_type:#04x}, flags={flags:#04x}, "
            f"domain={domain_id}, node_type={node_type})"
        ),
        version=node_name,
        port_hint=2126,
        extra=(
            "Confirmed from banner: structured binary framing, length-verified header, "
            "ASCII device identifier in asset-naming format. "
            "NOT confirmed: vendor, product, or specific protocol. "
            "To identify: capture additional banners from ports 2125-2130 on the same "
            "host, run a full packet capture, or match against vendor protocol documentation."
        ),
        ioc_flags=[
            f"Device name '{node_name}' — operator-assigned; pivot on this to track "
            "the same asset across scans",
            "Binary protocol with asset identifier on non-standard port — "
            "warrants investigation; may be ICS infrastructure",
        ],
        references=["T0842"]
    )


def detect_bacnet(data):
    """BACnet/IP — building automation (HVAC, lighting, access control)
    BACnet BVLL header: 0x81 + known function code + length(2BE) + NPDU
    Function byte MUST be a defined BVLL code — 0x80 is the DNS QR flags byte,
    not a BACnet function, so we require an explicit whitelist match.
    """
    BVLL_FUNCS = {
        0x00:"BVLC-Result", 0x01:"Write-Broadcast-Distribution-Table",
        0x02:"Read-Broadcast-Distribution-Table",
        0x03:"Read-Broadcast-Distribution-Table-Ack",
        0x04:"Forward-NPDU", 0x05:"Register-Foreign-Device",
        0x06:"Read-Foreign-Device-Table", 0x07:"Read-Foreign-Device-Table-Ack",
        0x08:"Delete-Foreign-Device-Table-Entry",
        0x09:"Distribute-Broadcast-To-Network",
        0x0A:"Original-Unicast-NPDU",
        0x0B:"Original-Broadcast-NPDU",
        0x0C:"Secure-BVLL",
    }
    if len(data) >= 6 and data[0] == 0x81 and data[1] in BVLL_FUNCS:
        func = data[1]
        length = u16be(data, 2)
        # Sanity check: declared length should be close to actual data length
        if abs(length - len(data)) > 32:
            return None
        return DetectionResult(
            service="BACnet/IP (Building Automation — HVAC/Lighting/Access)", category="OT_ICS",
            confidence="HIGH", detail=f"BACnet BVLL: {BVLL_FUNCS[func]} (len={length})",
            port_hint=47808,
            ioc_flags=["BACnet has no authentication — HVAC/door control accessible on network"],
            references=["T0821"])
    return None

def detect_opc_ua(data):
    """OPC UA binary — industrial integration layer"""
    if len(data) >= 8:
        msg_type = data[0:3]
        chunk_type = data[3:4]
        opc_types = {b"HEL":"Hello",b"ACK":"Acknowledge",b"ERR":"Error",
                     b"MSG":"Message",b"OPN":"OpenSecureChannel",b"CLO":"CloseSecureChannel"}
        if msg_type in opc_types and chunk_type in (b"F",b"C",b"A"):
            size = u32le(data, 4)
            return DetectionResult(
                service="OPC UA (OPC Unified Architecture — Industrial Integration)",
                category="OT_ICS", confidence="HIGH",
                detail=f"OPC UA binary {opc_types[msg_type]} message (size={size})",
                port_hint=4840,
                ioc_flags=["OPC UA bridges IT and OT networks — pivot point for lateral movement"],
                references=["T0846"])
    return None

def detect_fins(data):
    """FINS (Omron PLC Network Protocol)"""
    if data.startswith(b"FINS"):
        length = u32be(data, 4) if len(data) >= 8 else 0
        cmd = u16be(data, 16) if len(data) >= 18 else 0
        return DetectionResult(
            service="FINS (Omron PLC Network Protocol)", category="OT_ICS",
            confidence="HIGH", detail=f"FINS TCP frame (cmd={cmd:#06x}, len={length})",
            port_hint=9600,
            ioc_flags=["FINS has no built-in auth — direct memory read/write on Omron PLCs"],
            references=["T0821"])
    return None

def detect_profinet(data):
    """
    PROFINET DCP — Siemens industrial Ethernet discovery (UDP multicast, port 34964).
    DCP frame: ServiceID(1) + ServiceType(1) + XID(4) + ResponseDelay(2) + DCPDataLength(2)
    ServiceID 0x05 = Identify, ServiceType 0x00 = Request, 0x01 = Response.
    MUST also have a plausible XID and DCPDataLength — simply matching 0x05 0x00
    overlaps with DCE/RPC (version 5, minor 0) and many other protocols.
    Require minimum 10 bytes AND the DCPDataLength at [8-9] to be plausible.
    """
    if len(data) < 10:
        return None
    if data[0] != 0x05 or data[1] not in (0x00, 0x01):
        return None
    # DCPDataLength at bytes 8-9 (LE) must be <= actual remaining data
    dcp_data_len = u16be(data, 8)
    if dcp_data_len == 0 or dcp_data_len > len(data):
        return None
    # XID at bytes 2-5 should be non-zero (scanners use sequential XIDs)
    xid = u32be(data, 2)
    if xid == 0:
        return None
    return DetectionResult(
        service="PROFINET DCP (Siemens Industrial Ethernet)", category="OT_ICS",
        confidence="MEDIUM", detail=f"PROFINET DCP frame (ServiceID={data[0]:#x}, XID={xid:#010x})",
        port_hint=34964,
        ioc_flags=["PROFINET device discovery — Siemens factory automation"])

def detect_iec61850_mms(data):
    """IEC 61850 MMS — substation automation"""
    if len(data) >= 4:
        for start in (0,4,7,10):
            if start >= len(data): break
            if data[start] in (0xa8,0xa9,0xa0):
                return DetectionResult(
                    service="IEC 61850 MMS (Substation Automation)", category="OT_ICS",
                    confidence="MEDIUM",
                    detail=f"MMS ASN.1 PDU tag {data[start]:#x} — substation IED communication",
                    port_hint=102,
                    ioc_flags=["IEC 61850 controls protection relays and circuit breakers"],
                    references=["T0812"])
    return None

def detect_iec_goose(data):
    """IEC 61850 GOOSE — real-time protection relay events"""
    if len(data) >= 4 and data[0] == 0x61:
        return DetectionResult(
            service="IEC 61850 GOOSE (Substation Event Messaging)", category="OT_ICS",
            confidence="MEDIUM", detail="GOOSE APDU (tag 0x61) — protection relay messaging",
            ioc_flags=["GOOSE injection can cause false trip/close of circuit breakers"],
            references=["T0812"])
    return None

def detect_x11(data):
    """
    X11 (X Window System) ServerConnectReply — port 6000+6001 etc.
    Structure (little-endian):
      [0]    status: 1=Success, 0=Failed, 2=Authenticate
      [1]    padding
      [2-3]  protocol-major-version (always 11)
      [4-5]  protocol-minor-version (always 0)
      [6-7]  additional-data-length in 4-byte units
      [8-11] release-number (uint32)
      ... fixed server info fields ...
      [24-25] vendor-string-length (uint16)
      [40+]  vendor string
    """
    if len(data) < 8:
        return None
    status = data[0]
    if status not in (0, 1, 2):
        return None
    major = u16le(data, 2)
    minor = u16le(data, 4)
    # X11 protocol version is always 11.0
    if major != 11 or minor != 0:
        return None

    if status == 1 and len(data) >= 26:
        release    = u32le(data, 8) if len(data) >= 12 else 0
        vendor_len = u16le(data, 24)

        # Scanners sometimes capture truncated banners where the declared
        # vendor_len exceeds available bytes, or the standard offset 40 is
        # beyond the captured data. Search for the vendor string directly.
        VENDOR_MARKERS = [b"The X.Org", b"X.Org", b"XFree86", b"DECWINDOWS",
                          b"Silicon Graphics", b"Sun Microsystems",
                          b"Hewlett-Packard", b"MIT X Consortium", b"X Consortium"]
        vendor_offset = 40  # standard per RFC
        for vm in VENDOR_MARKERS:
            idx = data.find(vm)
            if idx != -1:
                vendor_offset = idx
                break

        actual_len = min(vendor_len, len(data) - vendor_offset) if vendor_len > 0 else len(data) - vendor_offset
        actual_len = max(actual_len, 0)
        vendor_raw = re.sub(r'[\x00-\x1f]+$', '',
            data[vendor_offset:vendor_offset + actual_len].decode("ascii", errors="replace"))

        # The vendor string often has a session-specific suffix appended
        # (MIT-MAGIC-COOKIE or build tag after the last space-separated word).
        # Known fixed vendor prefixes — these are NORMAL (shared by all instances
        # of that X server build):
        KNOWN_VENDORS = [
            "The X.Org Foundation",
            "X.Org Foundation",
            "XFree86",
            "DECWINDOWS Digital Equipment Corporation",
            "DECWINDOWS Digital Equipment Corporation Digital UNIX",
            "Silicon Graphics",
            "Sun Microsystems",
            "Hewlett-Packard Company",
            "MIT X Consortium",
            "X Consortium",
        ]
        vendor_fixed = vendor_raw
        vendor_session = ""
        for known in sorted(KNOWN_VENDORS, key=len, reverse=True):
            if vendor_raw.startswith(known):
                remainder = re.sub(r'[\x00-\x1f\s]+$', '', vendor_raw[len(known):]).strip()
                # Remainder after known prefix — check if it looks session-specific
                # Session tokens: no spaces, mixed case+digits+symbols, len 6-24
                if remainder and re.match(r'^[A-Za-z0-9_\-\.]{6,24}$', remainder):
                    vendor_fixed   = known
                    vendor_session = remainder
                else:
                    vendor_fixed = vendor_raw  # the whole thing is the fixed vendor
                break

        ioc = []
        # X11 on the internet is almost always unintentional exposure
        ioc.append("X11 server exposed — no auth or MIT-MAGIC-COOKIE auth; "
                   "remote display access possible (CVE class: information disclosure)")
        if "DECWINDOWS" in vendor_fixed:
            ioc.append("DECWINDOWS = DEC/Compaq/HP Tru64 UNIX or OpenVMS — "
                       "legacy system; extremely rare on public internet")

        extra_parts = [f"release={release}"]
        if vendor_session:
            extra_parts.append(f"session-suffix={vendor_session!r} (VARIABLE — do not pivot)")

        return DetectionResult(
            service="X11 (X Window System Display Server)",
            category="REMOTE_ACCESS",
            confidence="HIGH",
            detail=f"X11 ServerConnectReply [{'Success' if status==1 else 'Failed'}] "
                   f"protocol {major}.{minor}",
            version=vendor_fixed,
            port_hint=6000,
            extra="; ".join(extra_parts),
            ioc_flags=ioc,
            references=["T1021"])

    if status == 0:
        return DetectionResult(
            service="X11 (X Window System Display Server)",
            category="REMOTE_ACCESS",
            confidence="HIGH",
            detail="X11 ServerConnectReply [Failed] — server rejected connection",
            port_hint=6000,
            ioc_flags=["X11 server present but rejecting — may require auth cookie"])

    return None


def detect_hart_ip(data):
    """
    HART-IP — field instrument communication (IEC 61158).
    Frame: version(1) + msg_type(1) + msg_id(1) + status(1) + seq_no(2LE) + byte_count(2LE)
    Requires ALL of: version==1, valid msg_type, plausible byte_count vs actual length,
    AND the status byte must be 0x00 (success) for a well-formed frame.
    data[0]==1 and data[1] in (0-3) alone is far too broad — X11, many binary
    protocols also start with \x01\x00.
    """
    if len(data) < 8:
        return None
    version  = data[0]
    msg_type = data[1]
    msg_id   = data[2]
    status   = data[3]
    seq      = u16le(data, 4)
    bcount   = u16le(data, 6)
    # version must be 1, msg_type must be valid, byte_count must match actual length
    if version != 1:
        return None
    if msg_type not in (0, 1, 2, 3):
        return None
    # byte_count in HART-IP includes the 8-byte header — must be plausible
    if bcount < 8 or abs(bcount - len(data)) > 4:
        return None
    # status byte: 0=success, non-zero=error — X11 has 0x0b (11) here which is invalid
    if status not in (0, 1, 2, 3, 4, 0x20, 0x40, 0x80):
        return None
    msg_names = {0:"Request", 1:"Response", 2:"Publish", 3:"NAK"}
    return DetectionResult(
        service="HART-IP (HART Field Instrument Network)", category="OT_ICS",
        confidence="MEDIUM",
        detail=f"HART-IP v{version} {msg_names.get(msg_type,'?')} (seq={seq}, status={status:#x})",
        port_hint=5094,
        ioc_flags=["HART-IP exposes field instrumentation (flow/pressure/temp sensors)"])

def detect_codesys(data):
    """CODESYS Runtime — IEC 61131-3 PLC runtime"""
    if len(data) >= 8 and data[0] == 0x00 and data[1] in (0x01,0x02,0x03,0x04,0x11,0x30,0x40):
        return DetectionResult(
            service="CODESYS Runtime (IEC 61131-3 PLC Runtime)", category="OT_ICS",
            confidence="MEDIUM", detail=f"CODESYS protocol (service_group={data[1]:#x})",
            port_hint=1217,
            ioc_flags=["CVE-2021-30186 allows unauthenticated code execution on CODESYS PLCs"],
            references=["CVE-2021-30186","T0821"])
    return None

def detect_umas(data):
    """UMAS — Schneider Electric Modicon PLCs (Modbus FC 0x5A)"""
    if len(data) >= 8 and u16be(data, 2) == 0x0000 and len(data) > 7 and data[7] == 0x5A:
        return DetectionResult(
            service="UMAS / Schneider Modicon PLC (Unity Application)", category="OT_ICS",
            confidence="HIGH", detail="UMAS protocol (Modbus FC 0x5A) — Modicon M340/M580",
            port_hint=502,
            ioc_flags=["UMAS exploited by INCONTROLLER/PIPEDREAM for PLC firmware manipulation"],
            references=["T0821","CVE-2021-22716"])
    return None

def detect_ge_srtp(data):
    """
    GE SRTP — GE Fanuc / Automation PLCs (port 18245).
    SRTP request: 0x01 0x00 + service_code (0x01-0x1F) + subfunction + length(2LE)
    Requires the length field to be plausible AND service_code to be in the
    defined SRTP range. data[0]==0x01, data[1]==0x00 is too common — X11 and
    many other protocols also start with \x01\x00\x0b.
    """
    if len(data) < 6:
        return None
    if data[0] != 0x01 or data[1] != 0x00:
        return None
    service_code = data[2]
    if not (0x01 <= service_code <= 0x1F):
        return None
    # Require the declared length at bytes 4-5 to match actual data length
    if len(data) >= 6:
        declared_len = u16le(data, 4)
        if declared_len == 0 or abs(declared_len - len(data)) > 8:
            return None
    # X11 major version byte is 0x0b (11) which is in range, but X11 has
    # minor version 0x00 at byte 3 and data length >>6 — if those fit we
    # already catch it as X11. Only match SRTP if X11 check would fail.
    # X11 success: data[0]==1, data[1]==0, data[2]==11(major), data[3]==0(minor)
    if data[2] == 0x0b and data[3] == 0x00:
        return None   # this is X11 major=11 minor=0, not SRTP
    return DetectionResult(
        service="GE SRTP (GE Fanuc / Automation PLC)", category="OT_ICS",
        confidence="LOW", detail=f"Possible GE SRTP frame (service={service_code:#x})",
        port_hint=18245)

def detect_cc_link(data):
    """CC-Link IE — Mitsubishi industrial network"""
    if len(data) >= 4 and data[0] == 0x54 and data[1] == 0x00:
        return DetectionResult(
            service="CC-Link IE (Mitsubishi Industrial Network)", category="OT_ICS",
            confidence="LOW", detail="Possible CC-Link IE cyclic data frame", port_hint=61450)
    return None

def detect_pcworx(data):
    """PC Worx — Phoenix Contact PLCs"""
    if len(data) >= 4 and data[0:2] == b"\x01\x00" and data[2] in (0x00,0x01,0x02):
        return DetectionResult(
            service="PC Worx / Phoenix Contact PLC", category="OT_ICS",
            confidence="LOW", detail="Possible PC Worx protocol (Phoenix Contact ILC series)",
            port_hint=1962)
    return None

# C2 FRAMEWORK FINGERPRINTING
def detect_cobalt_strike(data):
    txt = data[:2048].decode("utf-8", errors="replace")
    indicators = []
    if "HTTP" in txt:
        if re.search(r"X-Recruiting\s*:", txt, re.I):
            indicators.append("Default 'X-Recruiting' header (CS default profile artifact)")
        if re.search(r"Server:\s*Apache\s*$", txt, re.M):
            indicators.append("Bare 'Server: Apache' (no version) — CS default profile fingerprint")
        if re.search(r"x-amz-id-\d+\s*:", txt, re.I) and "Content-Type: text/plain" in txt:
            indicators.append("Amazon malleable C2 profile pattern")
    cs_cns = ["Major Cobalt Strike","cobaltstrike.com","msupdate.net"]
    for cn in cs_cns:
        if cn.lower() in txt.lower():
            indicators.append(f"Known CS default certificate CN: '{cn}'")
    if not indicators and len(data) >= 4:
        if data[:2] == b"MZ" and len(data) > 200:
            indicators.append("MZ (PE) header — possible beacon stager payload")
        ent = byte_entropy(data)
        if ent > 7.2 and len(data) > 512:
            indicators.append(f"Very high entropy ({ent:.2f}) — possible encoded beacon stage")
    if indicators:
        return DetectionResult(
            service="Cobalt Strike (C2 Framework)", category="C2_FRAMEWORK",
            confidence="HIGH" if len(indicators) >= 2 else "MEDIUM",
            detail=f"{len(indicators)} indicator(s) matched",
            extra="; ".join(indicators), ioc_flags=indicators,
            references=["T1071.001","T1573","S0154"])
    return None

def detect_metasploit(data):
    txt = data[:1024].decode("utf-8", errors="replace")
    indicators = []
    if "HTTP" in txt:
        if re.search(r"Server:\s*Apache\s*$", txt, re.M) and "Set-Cookie" not in txt:
            indicators.append("Bare 'Server: Apache' — Metasploit multi/handler fingerprint")
        if "connection: close" in txt.lower() and "Content-Length: 0" in txt:
            indicators.append("Empty response (CL:0, Connection:close) — MSF handler pattern")
        if re.search(r"content-type:\s*application/octet-stream", txt, re.I):
            indicators.append("octet-stream delivery — possible Meterpreter stage")
    if len(data) >= 8 and not indicators:
        payload_size = u32le(data, 0)
        if 200 < payload_size < 1_000_000 and len(data) == payload_size + 4:
            indicators.append(f"DWORD-prefixed binary blob ({payload_size}B) — Meterpreter stage framing")
    for s in ["Metasploit","metasploit","msf4","localhost.localdomain"]:
        if s in txt:
            indicators.append(f"String '{s}' in cert/banner — MSF default certificate")
    if indicators:
        return DetectionResult(
            service="Metasploit Framework (C2 / Exploit Framework)", category="C2_FRAMEWORK",
            confidence="HIGH" if len(indicators) >= 2 else "MEDIUM",
            detail=f"{len(indicators)} indicator(s) matched",
            extra="; ".join(indicators), ioc_flags=indicators,
            references=["T1071.001","S0029"])
    return None

def detect_sliver(data):
    txt = data[:1024].decode("utf-8", errors="replace")
    indicators = []
    if "HTTP" in txt:
        if re.search(r"Cache-Control: no-store, no-cache", txt) and \
                re.search(r"Content-Type: application/octet-stream", txt):
            indicators.append("Sliver default HTTP C2 headers (no-store + octet-stream)")
        if re.search(r"Server:\s*$", txt, re.M):
            indicators.append("Empty 'Server' header — Sliver C2 default profile")
    if "sliver" in txt.lower() or "bishopfox" in txt.lower():
        indicators.append("Sliver/BishopFox string in banner")
    if indicators:
        return DetectionResult(
            service="Sliver C2 (BishopFox Open-Source C2)", category="C2_FRAMEWORK",
            confidence="MEDIUM", detail="; ".join(indicators),
            ioc_flags=indicators, references=["T1071.001","T1573","S1044"])
    return None

def detect_empire_havoc(data):
    txt = data[:1024].decode("utf-8", errors="replace")
    indicators = []
    if re.search(r"(index\.jsp|login/process|news\.php|admin/get\.php)", txt):
        indicators.append("Empire default staging URI pattern")
    if re.search(r"X-Havoc\s*:", txt, re.I):
        indicators.append("'X-Havoc' header — Havoc Framework Demon agent")
    if "havoc" in txt.lower():
        indicators.append("'havoc' string in response")
    if indicators:
        return DetectionResult(
            service="Empire / Havoc C2 Framework", category="C2_FRAMEWORK",
            confidence="MEDIUM", detail="; ".join(indicators),
            ioc_flags=indicators, references=["T1071.001","S0363"])
    return None

def detect_brute_ratel_covenant(data):
    txt = data[:1024].decode("utf-8", errors="replace")
    indicators = []
    if re.search(r"X-BRC4\s*:", txt, re.I) or "BruteRatel" in txt:
        indicators.append("Brute Ratel C4 header/string")
    if re.search(r"/grunt/|/api/grunts/", txt, re.I):
        indicators.append("Covenant Grunt staging URI")
    if indicators:
        return DetectionResult(
            service="Brute Ratel C4 / Covenant (C2 Framework)", category="C2_FRAMEWORK",
            confidence="MEDIUM", detail="; ".join(indicators),
            ioc_flags=indicators, references=["T1071.001"])
    return None

def detect_dns_tunnel_c2(data):
    """
    DNS tunnel C2 detection.
    dnscat2 and iodine have SPECIFIC handshake signatures — we require
    multiple corroborating bytes, NOT just a common 4-byte sequence like
    \x00\x01\x00\x00 which appears in nearly every binary protocol.

    dnscat2 client hello: starts with 0x00 0x01 0x00 0x00 AND is followed
    by a session_id (2 bytes) and packet_id (2 bytes), total >= 8 bytes,
    with the 5th byte being a valid dnscat2 message type (0x00-0x09).

    iodine: version exchange uses literal ASCII strings "VACK", "LAHE",
    "VCOD" etc in the first 32 bytes — these are very specific.
    """
    txt = data[:256].decode("ascii", errors="replace")
    indicators = []

    # iodine: specific ASCII control strings in first 32 bytes
    # These are literal protocol tokens, not just common words
    iodine_tokens = ["VACK", "LAHE", "VCOD", "VBAD", "IODINE"]
    for token in iodine_tokens:
        if token in txt[:32]:
            indicators.append(f"iodine DNS tunnel token '{token}' in first 32 bytes")

    # dnscat2: requires 0x00 0x01 as the TYPE field AND the 5th byte
    # must be a valid dnscat2 packet type (MSG=0x00, SYN=0x01, FIN=0x02, ENC=0x03)
    # AND total length must be plausible for a dnscat2 handshake (>= 12 bytes)
    # AND the data must NOT match common LE-uint32 binary protocols
    if (len(data) >= 12
            and data[0] == 0x00 and data[1] == 0x01   # packet_id field
            and data[2] == 0x00 and data[3] == 0x00   # flags = 0
            and data[4] in (0x00, 0x01, 0x02, 0x03)   # valid dnscat2 type byte
            and data[5] == 0x00):                       # reserved/padding
        indicators.append("dnscat2 SYN/MSG packet structure (type+flags+padding match)")

    if indicators:
        return DetectionResult(
            service="DNS Tunnel C2 (iodine / dnscat2 pattern)", category="C2_FRAMEWORK",
            confidence="MEDIUM", detail="; ".join(indicators),
            ioc_flags=indicators, references=["T1071.004","T1572"])
    return None

def detect_tor(data):
    """
    SOCKS5: version(1=5) + nmethods(1) + methods(nmethods)
    Client hello: \x05 + nmethods(1-255) + method_list
    Server hello: \x05 + chosen_method (0=none, 1=GSSAPI, 2=user/pass, 0xFF=no acceptable)
    Requires nmethods > 0 AND the remaining bytes to be plausible method codes,
    OR server response where chosen_method is a valid single byte.
    \x05\x00 alone (nmethods=0) is invalid per RFC 1928 and also matches
    DCE/RPC version 5 minor 0 — require at least one more corroborating byte.
    """
    txt = data[:512].decode("ascii", errors="replace")

    if len(data) >= 3 and data[0] == 0x05:
        nmethods = data[1]
        # Valid client hello: nmethods 1-255, each method byte <= 0x09
        if 1 <= nmethods <= 8 and len(data) >= 2 + nmethods:
            methods = list(data[2:2+nmethods])
            if all(m <= 0x09 for m in methods):
                return DetectionResult(
                    service="SOCKS5 Proxy (possible Tor/anonymization)",
                    category="THREAT_INDICATOR", confidence="MEDIUM",
                    detail=f"SOCKS5 client hello (nmethods={nmethods}, methods={methods})",
                    port_hint=9050,
                    ioc_flags=["SOCKS5 on 9050/9150 is characteristic of Tor Browser / Tor daemon"],
                    references=["T1090.003"])
        # Valid server response: \x05 + single valid method byte
        if nmethods in (0x00, 0x01, 0x02, 0xFF) and len(data) == 2:
            return DetectionResult(
                service="SOCKS5 Proxy (possible Tor/anonymization)",
                category="THREAT_INDICATOR", confidence="MEDIUM",
                detail=f"SOCKS5 server method selection ({nmethods:#04x})",
                port_hint=9050,
                ioc_flags=["SOCKS5 on 9050/9150 is characteristic of Tor Browser / Tor daemon"],
                references=["T1090.003"])

    if len(data) >= 5 and data[2] == 0x07:
        return DetectionResult(
            service="Tor Onion Router (OR Protocol)", category="THREAT_INDICATOR",
            confidence="MEDIUM", detail="Tor OR VERSIONS cell detected", port_hint=9001,
            ioc_flags=["Tor relay/bridge — traffic anonymization or C2 over hidden service"],
            references=["T1090.003"])

    if "Tor " in txt or "onion" in txt.lower():
        return DetectionResult(
            service="Tor (Anonymization Network)", category="THREAT_INDICATOR",
            confidence="LOW", detail="Tor-related string in banner",
            ioc_flags=["Tor infrastructure — may indicate C2 over hidden service"],
            references=["T1090.003"])
    return None

def detect_generic_c2(data):
    """Heuristic: high-entropy, unusual framing, possible encrypted beacon"""
    if len(data) < 16: return None
    ent = byte_entropy(data)
    pr  = printable_ratio(data)
    flags = []
    if ent > 7.4:
        flags.append(f"Extremely high entropy ({ent:.2f}/8.0) — strongly suggests encryption/compression")
    elif ent > 6.8:
        flags.append(f"High entropy ({ent:.2f}/8.0) — possible encrypted/encoded data")
    if pr < 0.1 and len(data) > 32:
        flags.append(f"Very low printable ratio ({pr:.0%}) — binary or encoded payload")
    if 16 <= len(data) <= 256 and len(data) % 8 == 0 and not flags:
        flags.append(f"Fixed-size {len(data)}-byte binary packet — possible C2 heartbeat/beacon")
    if len(flags) >= 2:
        return DetectionResult(
            service="Unknown / Custom Protocol (possible C2 or encrypted channel)",
            category="THREAT_INDICATOR", confidence="LOW",
            detail=f"{len(flags)} heuristic indicator(s) — manual review recommended",
            extra="; ".join(flags), ioc_flags=flags,
            references=["T1573","T1095"])
    return None


def detect_unknown_binary(data):
    """
    Catch-all for binary protocols that matched nothing else.
    Extracts printable strings and LE/BE integer fields as pivot candidates,
    and flags if the protocol is running on a well-known port for a different
    service (e.g. custom binary on port 53 instead of DNS).
    """
    if len(data) < 8: return None

    ent = byte_entropy(data)
    pr  = printable_ratio(data)

    # Only fire if: low-to-medium entropy (not random/encrypted — that's generic_c2),
    # low printable ratio (not a text protocol — those have dedicated detectors),
    # and contains at least one recognisable string of >= 4 chars.
    if ent > 6.5 or pr > 0.6:
        return None

    # Extract all printable runs >= 4 chars
    strings = re.findall(r'[ -~]{4,}', data.decode("latin-1", errors="replace"))
    if not strings:
        return None

    # Build a summary of what we found
    str_summary = ", ".join(f'"{s}"' for s in strings[:5])

    ioc = []
    # Flag if a port-bearing string contains a number that looks like a port
    for s in strings:
        if re.match(r'^\d{1,5}$', s.strip()):
            port_val = int(s.strip())
            if 1 <= port_val <= 65535:
                ioc.append(f"String '{s.strip()}' looks like a port number — "
                           f"possible proxy redirect or connection broker protocol")

    # Flag "Connect", "Redirect", "Forward" as proxy/broker commands
    for s in strings:
        sl = s.lower().strip()
        if sl in ("connect", "redirect", "forward", "bind", "associate"):
            ioc.append(f"Command string '{s.strip()}' — likely a proxy, broker, or "
                       f"connection-redirect protocol; not a standard service")

    # Describe the binary framing
    framing = []
    # Count sequences of 4-byte LE uint32s
    le_ints = [int.from_bytes(data[i:i+4], "little")
               for i in range(0, min(len(data), 24), 4)
               if len(data) >= i+4]
    if len([x for x in le_ints if x < 100000]) >= 3:
        framing.append("multiple small LE uint32 fields — structured binary TLV or header")

    detail = f"Unrecognised binary protocol — strings: {str_summary}"
    if framing:
        detail += f"; framing: {'; '.join(framing)}"

    return DetectionResult(
        service="Unknown Binary Protocol",
        category="OTHER",
        confidence="LOW",
        detail=detail,
        extra=f"Extracted strings: {str_summary}",
        ioc_flags=ioc,
        references=["T1095"] if ioc else []
    )

# WEB / TLS / MAIL
def detect_tls(data):
    if len(data) < 6: return None
    if data[0] == 0x16 and data[1] == 0x03 and data[2] <= 0x04:
        vers = {0:"SSLv3",1:"TLS 1.0",2:"TLS 1.1",3:"TLS 1.2",4:"TLS 1.3"}
        ver = vers.get(data[2], "TLS unknown")
        ioc = []
        if data[2] <= 0x01:
            ioc.append(f"{ver} is deprecated and vulnerable")
        if len(data) >= 6 and data[5] == 0x02:
            ioc.append("TLS ServerHello — check cert CN/SANs and JA3S fingerprint for C2 identification")
        return DetectionResult(
            service="TLS/SSL Encrypted Channel", category="CRYPTO",
            confidence="HIGH", detail=f"TLS handshake record ({ver})", port_hint=443,
            ioc_flags=ioc, references=["T1573.002"])
    if data[0] == 0x15 and data[1] == 0x03:
        return DetectionResult(
            service="TLS Alert", category="CRYPTO", confidence="MEDIUM",
            detail="TLS Alert record — connection rejected or error", port_hint=443)
    return None

def detect_http(data):
    txt = data[:1024].decode("ascii", errors="replace")
    m = re.match(r"^HTTP/(\S+)\s+(\d+)\s+(.*)", txt)
    if m:
        ioc = []
        if re.search(r"X-Recruiting\s*:", txt, re.I):
            ioc.append("Cobalt Strike default 'X-Recruiting' header")
        if re.search(r"Server:\s*Apache\s*$", txt, re.M):
            ioc.append("Bare 'Server: Apache' — CS/MSF redirector fingerprint")
        srv_m = re.search(r"Server:\s*([^\r\n]+)", txt, re.I)
        server = srv_m.group(1).strip() if srv_m else None
        return DetectionResult(
            service="HTTP Web Server", category="WEB",
            confidence="HIGH", detail=f"HTTP {m.group(2)} {m.group(3).split(chr(10))[0].strip()}",
            version=f"HTTP/{m.group(1)}", port_hint=80,
            extra=f"Server: {server}" if server else None,
            ioc_flags=ioc, references=["T1071.001"])
    if re.match(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ", txt):
        return DetectionResult(
            service="HTTP (incoming request)", category="WEB",
            confidence="MEDIUM", detail="HTTP request header", port_hint=80)
    return None

def detect_smtp(data):
    txt = data[:256].decode("ascii", errors="replace")
    if re.match(r"^220[\s\-].*?(ESMTP|SMTP)", txt, re.I):
        return DetectionResult(
            service="SMTP (Mail Server)", category="MAIL",
            confidence="HIGH", detail="ESMTP/SMTP service ready",
            version=txt.split("\n")[0].strip()[:80], port_hint=25)
    return None

def detect_pop3(data):
    txt = data[:128].decode("ascii", errors="replace")
    if txt.startswith("+OK"):
        return DetectionResult(
            service="POP3 (Mail Retrieval)", category="MAIL",
            confidence="HIGH", detail="POP3 greeting",
            version=txt.split("\n")[0][3:].strip()[:80], port_hint=110)
    return None

def detect_imap(data):
    txt = data[:128].decode("ascii", errors="replace")
    if re.match(r"^\* OK", txt, re.I):
        return DetectionResult(
            service="IMAP (Mail Retrieval)", category="MAIL",
            confidence="HIGH", detail="IMAP greeting",
            version=txt.split("\n")[0][4:].strip()[:80], port_hint=143)
    return None

# NETWORK INFRASTRUCTURE
def detect_ftp(data):
    txt = data[:128].decode("ascii", errors="replace")
    m = re.match(r"^220[\s\-](.*)", txt)
    if m and "ESMTP" not in txt.upper() and "SMTP" not in txt.upper():
        ioc = []
        if "vsftpd 2.3.4" in m.group(1):
            ioc.append("vsftpd 2.3.4 — contains backdoor (CVE-2011-2523)")
        return DetectionResult(
            service="FTP (File Transfer Protocol)", category="OTHER",
            confidence="HIGH", detail="FTP service ready (220)",
            version=m.group(1).strip()[:80], port_hint=21,
            ioc_flags=ioc, references=["CVE-2011-2523"] if ioc else [])
    return None

def detect_snmp(data):
    if len(data) >= 6 and data[0] == 0x30 and data[2] == 0x02 and data[3] == 0x01:
        ver = {0:"SNMPv1",1:"SNMPv2c",3:"SNMPv3"}.get(data[4], f"SNMP v{data[4]}")
        ioc = ["Community strings often default (public/private) — used for network recon"] if data[4] < 3 else []
        return DetectionResult(
            service=f"SNMP ({ver})", category="OTHER",
            confidence="HIGH", detail=f"SNMP PDU ({ver})", port_hint=161,
            ioc_flags=ioc)
    return None

def detect_ldap(data):
    if len(data) >= 7 and data[0] == 0x30 and data[2] == 0x02 and data[5] == 0x61:
        return DetectionResult(
            service="LDAP (Directory Service)", category="DIRECTORY",
            confidence="HIGH", detail="LDAP BindResponse", port_hint=389)
    if len(data) >= 2 and data[0] == 0x30:
        return DetectionResult(
            service="LDAP / X.509 (Directory or TLS certificate)", category="DIRECTORY",
            confidence="LOW", detail="BER/DER ASN.1 SEQUENCE — possibly LDAP or TLS cert",
            port_hint=389)
    return None

def _dns_decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS wire-format name, following compression pointers."""
    if depth > 10:
        return "<max-recursion>", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:           # compression pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = _dns_decode_name(data, ptr, depth + 1)
            labels.append(pointed)
            offset += 2
            break
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def _dns_normalise(data: bytes):
    """
    Return (normalised_bytes, txid_present).
    Some scanners capture DNS responses without the 2-byte TxID prefix —
    the banner starts directly at the flags field.

    Detection: treat bytes 0-1 as TxID and bytes 2-3 as flags (standard).
    If standard flags give QR=0 (query) with a non-zero RCODE — which is
    invalid per RFC 1035 — AND treating bytes 0-1 AS the flags gives a
    coherent response (QR=1, RCODE=0, plausible counts), then TxID is absent.
    """
    if len(data) < 10:
        return data, True

    # Standard interpretation
    flags_std  = u16be(data, 2)
    qr_std     = (flags_std >> 15) & 1
    rcode_std  = flags_std & 0xF
    qd_std     = u16be(data, 4)
    an_std     = u16be(data, 6)

    # No-TxID interpretation
    flags_alt  = u16be(data, 0)
    qr_alt     = (flags_alt >> 15) & 1
    opcode_alt = (flags_alt >> 11) & 0xF
    rcode_alt  = flags_alt & 0xF
    qd_alt     = u16be(data, 2)
    an_alt     = u16be(data, 4)

    std_contradicts = (qr_std == 0 and rcode_std != 0)   # query with error code = invalid
    alt_coherent    = (opcode_alt <= 5 and
                       0 < qd_alt <= 10 and an_alt <= 50 and
                       rcode_alt == 0)

    if std_contradicts and alt_coherent:
        return b'\x00\x00' + data, False   # prepend dummy TxID, flag as absent
    return data, True


def detect_dns(data: bytes):
    """
    DNS wire format (RFC 1035).
    Handles both full packets (TxID present) and scanner captures that
    start at the flags byte (TxID missing).
    """
    if len(data) < 10:
        return None

    d, txid_present = _dns_normalise(data)

    if len(d) < 12:
        return None

    flags   = u16be(d, 2)
    qr      = (flags >> 15) & 1
    opcode  = (flags >> 11) & 0xF
    rcode   = flags & 0xF
    qdcount = u16be(d, 4)
    ancount = u16be(d, 6)

    if opcode > 5 or qdcount > 20 or ancount > 100:
        return None
    # RFC 1035 defines rcodes 0-5 only. rcode 6-15 are undefined in base DNS
    # (EDNS extended rcodes are 16-bit but not present in the base header).
    # Reject undefined rcodes to prevent false positives from binary protocols
    # whose bytes happen to set QR=1 with a high rcode value.
    if rcode > 5:
        return None
    if qdcount == 0 and ancount == 0:
        return None

    txid = u16be(d, 0)

    # Decode question section
    qtypes = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",
              15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
    qnames = []
    offset = 12
    for _ in range(min(qdcount, 5)):
        if offset >= len(d): break
        name, offset = _dns_decode_name(d, offset)
        if offset + 4 > len(d): break
        qtype = u16be(d, offset)
        offset += 4
        qnames.append(f"{name} ({qtypes.get(qtype, f'type{qtype}')})")

    # Decode answer section
    answers = []
    for _ in range(min(ancount, 10)):
        if offset >= len(d): break
        name, offset = _dns_decode_name(d, offset)
        if offset + 10 > len(d): break
        rtype = u16be(d, offset)
        ttl   = u32be(d, offset + 4)
        rdlen = u16be(d, offset + 8)
        offset += 10
        if offset + rdlen > len(d): break
        rdata     = d[offset:offset + rdlen]
        rdata_off = offset
        offset   += rdlen

        if rtype == 1 and rdlen == 4:
            answers.append(f"A {'.'.join(str(b) for b in rdata)} (TTL {ttl})")
        elif rtype == 28 and rdlen == 16:
            groups = [f"{u16be(rdata, i):04x}" for i in range(0, 16, 2)]
            answers.append(f"AAAA {':'.join(groups)} (TTL {ttl})")
        elif rtype == 5:
            cname, _ = _dns_decode_name(d, rdata_off)
            answers.append(f"CNAME {cname} (TTL {ttl})")
        elif rtype == 15 and rdlen >= 3:
            mx_name, _ = _dns_decode_name(d, rdata_off + 2)
            answers.append(f"MX {mx_name} (TTL {ttl})")
        else:
            answers.append(f"type{rtype} rdlen={rdlen} (TTL {ttl})")

    ioc = []
    if txid_present and txid == 0x0000:
        ioc.append("DNS TxID is 0x0000 — seen in some C2/DNS-tunnel tools")
    if any("ANY" in q for q in qnames):
        ioc.append("DNS ANY query — used in DNS amplification DDoS")

    rcodes    = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}
    pkt_type  = "response" if qr else "query"
    rcode_str = rcodes.get(rcode, f"RCODE{rcode}")
    detail    = f"DNS {pkt_type} [{rcode_str}]"
    if qnames:  detail += f" — query: {', '.join(qnames)}"
    if answers: detail += f" — {'; '.join(answers)}"

    return DetectionResult(
        service="DNS (Domain Name Service)", category="OTHER",
        confidence="MEDIUM", detail=detail,
        version="; ".join(answers) if answers else None,
        port_hint=53, ioc_flags=ioc,
        references=["T1071.004"] if ioc else []
    )

def detect_ntp(data):
    """
    NTP packet: li_vn_mode byte at [0] encodes LI(2), Version(3), Mode(3).
    Version must be 3 or 4, mode must be 4 (server) or 5 (broadcast).

    Guards against false positives:
    1. Minimum 48 bytes (standard NTP packet length).
    2. Reject if data is suspiciously printable (double-escaped text input).
    3. Reject if entropy > 6.5 — real NTP packets contain many structured/zero
       fields (stratum, timestamps, reference IDs) giving entropy ~3-5. High
       entropy means encrypted or compressed data whose first byte happens to
       decode as a valid li_vn_mode — this was a confirmed false positive on
       port 20000 encrypted traffic (entropy 7.8).
    4. Reject if the 'stratum' byte (data[1]) is > 15 — RFC 5905 defines
       stratum 0-15 only; values 16-255 are reserved/unsynchronised.
    """
    if len(data) < 48:
        return None
    if printable_ratio(data) > 0.90:
        return None
    # Encrypted/compressed data produces entropy >> 6.5; real NTP does not
    if byte_entropy(data) > 6.5:
        return None
    # Stratum byte must be in RFC-defined range
    stratum = data[1]
    if stratum > 15:
        return None
    li_vn_mode = data[0]
    version = (li_vn_mode >> 3) & 0x7
    mode    = li_vn_mode & 0x7
    if version in (3, 4) and mode in (4, 5):
        return DetectionResult(
            service="NTP (Network Time Protocol)", category="OTHER",
            confidence="MEDIUM", detail=f"NTP v{version} server/broadcast packet (version/mode bits only — no magic bytes; may collide with other 48-byte binary protocols)",
            port_hint=123)
    return None

def detect_rsync(data):
    txt = data[:64].decode("ascii", errors="replace")
    m = re.match(r"^@RSYNCD:\s+(\S+)", txt)
    if m:
        return DetectionResult(
            service="rsync daemon", category="OTHER",
            confidence="HIGH", detail=f"rsync greeting (protocol {m.group(1)})",
            version=m.group(1), port_hint=873,
            ioc_flags=["Exposed rsync used for data exfiltration and dropper staging"],
            references=["T1048"])
    return None

# MESSAGING / MQ / VOIP / MISC

def detect_mqtt(data):
    if len(data) >= 4 and data[0] == 0x20 and data[1] == 0x02:
        rc = data[3] if len(data) > 3 else 0
        return DetectionResult(
            service="MQTT (IoT Message Broker)", category="MESSAGING",
            confidence="HIGH", detail=f"MQTT CONNACK (return code {rc})", port_hint=1883,
            ioc_flags=["Unauthenticated MQTT used by IoT botnets and C2 channels"] if rc==0 else [])
    if len(data) >= 2 and data[0] == 0x10 and (b"MQTT" in data[:16] or b"MQIsdp" in data[:16]):
        return DetectionResult(
            service="MQTT (IoT Message Broker)", category="MESSAGING",
            confidence="HIGH", detail="MQTT CONNECT packet", port_hint=1883)
    return None

def detect_dcerpc(data):
    """
    DCE/RPC (Distributed Computing Environment / Remote Procedure Call).
    MS-RPCE over TCP — used by virtually every Windows service (DCOM, WMI,
    SAMR, LSARPC, SVCCTL, DRSUAPI, etc.) and many third-party RPC services.

    PDU header (always 16 bytes, connection-oriented):
      [0]   rpc_vers        = 5  (major version, always 5 for CO RPC)
      [1]   rpc_vers_minor  = 0  (minor version, 0 or 1)
      [2]   PTYPE           = packet type (0x00-0x14 defined in MS-RPCE)
      [3]   pfc_flags       = fragment flags (bit 0 = first, bit 1 = last)
      [4-7] packed_drep     = data representation (0x10000000 = LE/ASCII/IEEE)
      [8-9] frag_length     = total PDU length in bytes
      [10-11] auth_length   = auth verifier length
      [12-15] call_id       = identifies the call (matches request to response)

    The combination of version=5, minor=0/1, a valid PTYPE, and the standard
    packed_drep value is extremely specific to DCE/RPC and will not collide
    with SOCKS5, PROFINET, or MongoDB when all fields are validated together.
    """
    if len(data) < 16:
        return None

    ver_major = data[0]
    ver_minor = data[1]
    ptype     = data[2]
    flags     = data[3]

    # Must be DCE/RPC version 5.0 or 5.1
    if ver_major != 5 or ver_minor not in (0, 1):
        return None

    # PTYPE must be a defined DCE/RPC packet type
    PTYPES = {
        0x00: "REQUEST",      0x01: "PING",          0x02: "RESPONSE",
        0x03: "FAULT",        0x04: "WORKING",        0x05: "NOCALL",
        0x06: "REJECT",       0x07: "ACK",            0x08: "CL_CANCEL",
        0x09: "FACK",         0x0A: "CANCEL_ACK",     0x0B: "BIND",
        0x0C: "BIND_ACK",     0x0D: "BIND_NACK",      0x0E: "ALTER_CONTEXT",
        0x0F: "ALTER_CONTEXT_RESP",                    0x10: "AUTH3",
        0x11: "SHUTDOWN",     0x12: "CO_CANCEL",       0x13: "ORPHANED",
        0x14: "RTS",
    }
    if ptype not in PTYPES:
        return None

    # packed_drep at [4-7]: byte order 0x10=LE or 0x00=BE, rest usually 0
    drep_byte_order = data[4]
    if drep_byte_order not in (0x00, 0x10):
        return None

    # frag_length must match or be close to actual data length
    frag_len = u16le(data, 8) if drep_byte_order == 0x10 else u16be(data, 8)
    if frag_len < 16 or frag_len > 65535:
        return None

    # flags: only defined flag bits should be set (bits 0-7 have specific meanings)
    # bits 0=FIRST_FRAG, 1=LAST_FRAG, 2=PEND_CANCEL, 3=RESERVED, 4=CONC_MPX,
    # 5=DID_NOT_EXECUTE, 6=MAYBE, 7=OBJECT_UUID
    # A complete single-fragment PDU should always have bits 0 and 1 set (0x03)

    call_id   = u32le(data, 12) if drep_byte_order == 0x10 else u32be(data, 12)
    ptype_name = PTYPES[ptype]
    byte_order = "little-endian" if drep_byte_order == 0x10 else "big-endian"

    # Decode BIND_NACK reason if present
    detail = f"DCE/RPC {ptype_name} (v{ver_major}.{ver_minor}, call_id={call_id}, {byte_order})"
    extra = None

    REJECT_REASONS = {
        0: "reason_not_specified",
        1: "temporary_congestion",
        2: "local_limit_exceeded",
        4: "protocol_version_not_supported",
        5: "default_context_not_supported",
        8: "user_data_not_readable",
    }

    if ptype == 0x0D and len(data) >= 18:  # BIND_NACK
        reason = u16le(data, 16) if drep_byte_order == 0x10 else u16be(data, 16)
        reason_str = REJECT_REASONS.get(reason, f"reason={reason}")
        detail = f"DCE/RPC BIND_NACK — {reason_str} (v{ver_major}.{ver_minor})"
        extra = f"Server rejected RPC bind; reason code {reason} ({reason_str})"

    elif ptype == 0x0C and len(data) >= 24:  # BIND_ACK
        sec_addr_len = u16le(data, 18) if drep_byte_order == 0x10 else u16be(data, 18)
        sec_addr = ""
        if sec_addr_len > 0 and 20 + sec_addr_len <= len(data):
            sec_addr = data[20:20+sec_addr_len].decode("ascii", errors="replace").strip("\x00")
        detail = f"DCE/RPC BIND_ACK (v{ver_major}.{ver_minor}, call_id={call_id})"
        if sec_addr:
            extra = f"Secondary address (endpoint): {sec_addr}"

    elif ptype == 0x03 and len(data) >= 24:  # FAULT
        status = u32le(data, 20) if drep_byte_order == 0x10 else u32be(data, 20)
        detail = f"DCE/RPC FAULT (v{ver_major}.{ver_minor}, status={status:#010x})"

    ioc = []
    # RPC on non-standard ports is worth flagging
    ioc.append("DCE/RPC endpoint — identifies a Windows RPC service; "
               "enumerate interfaces with rpcdump/impacket to identify the service")
    if ptype == 0x0B:  # BIND attempt from scanner
        ioc.append("RPC BIND packet — scanner or tool probing this endpoint")

    return DetectionResult(
        service="DCE/RPC (Windows Remote Procedure Call)",
        category="REMOTE_ACCESS",
        confidence="HIGH",
        detail=detail,
        port_hint=135,
        extra=extra,
        ioc_flags=ioc,
        references=["T1021.003"]
    )


def detect_msmq(data):
    """
    Microsoft Message Queuing (MSMQ) — port 1801/TCP.
    Session header: version(1) + flags(1) + length(2LE) + magic(4) + fields...
    Magic is b'LIOR' (bytes 4-7) — this is the definitive MSMQ identifier.
    Also matches MSMQ ping packets which start with 0x10 + 'LIOR'.
    """
    if len(data) < 8:
        return None
    # Primary check: 'LIOR' magic at offset 4
    if data[4:8] == b"LIOR":
        version_byte = data[0]
        flags        = data[1]
        ioc = [
            "MSMQ on internet — CVE-2023-21554 (QueueJumper) allows unauthenticated "
            "RCE; patch MS23-Apr critical",
        ]
        return DetectionResult(
            service="MSMQ (Microsoft Message Queuing)",
            category="MESSAGING",
            confidence="HIGH",
            detail=f"MSMQ session header (magic 'LIOR', version={version_byte:#04x}, flags={flags:#04x})",
            port_hint=1801,
            ioc_flags=ioc,
            references=["CVE-2023-21554", "T1203"])
    # Secondary: MSMQ ping packet starts with 0x10 0x00 and contains 'LIOR' anywhere
    if data[0] == 0x10 and b"LIOR" in data[:32]:
        return DetectionResult(
            service="MSMQ (Microsoft Message Queuing)",
            category="MESSAGING",
            confidence="HIGH",
            detail="MSMQ ping/session packet with 'LIOR' signature",
            port_hint=1801,
            ioc_flags=["MSMQ CVE-2023-21554 unauthenticated RCE — patch immediately"],
            references=["CVE-2023-21554", "T1203"])
    return None


def detect_amqp(data):
    if data.startswith(b"AMQP"):
        return DetectionResult(
            service="AMQP (Message Queue — RabbitMQ/ActiveMQ)", category="MESSAGING",
            confidence="HIGH", detail="AMQP protocol header", port_hint=5672)
    return None

def detect_irc(data):
    txt = data[:512].decode("ascii", errors="replace")
    for pat in [r"^:\S+\s+001\s+", r"^NOTICE AUTH", r"^:\S+\s+NOTICE\s+\*\s+:", r"PING :[A-Z0-9]+"]:
        if re.search(pat, txt, re.M):
            ioc = ["IRC C2 channels still used by botnets (T1071.003)"] if "PRIVMSG" in txt or "JOIN" in txt else []
            return DetectionResult(
                service="IRC (Internet Relay Chat)", category="MESSAGING",
                confidence="HIGH", detail="IRC server greeting", port_hint=6667,
                ioc_flags=ioc, references=["T1071.003"] if ioc else [])
    return None

def detect_sip(data):
    txt = data[:256].decode("ascii", errors="replace")
    if re.match(r"^SIP/2\.0\s+\d+", txt) or re.match(r"^(INVITE|REGISTER|OPTIONS|BYE) sip:", txt, re.I):
        return DetectionResult(
            service="SIP (VoIP / Session Initiation Protocol)", category="VOIP",
            confidence="HIGH", detail=txt.split("\n")[0].strip()[:80], port_hint=5060)
    return None

def detect_socks4(data):
    if len(data) >= 2 and data[0] == 0x00 and data[1] in (0x5A,0x5B,0x5C,0x5D):
        status = {0x5A:"granted",0x5B:"rejected",0x5C:"no identd",0x5D:"identd mismatch"}
        return DetectionResult(
            service="SOCKS4 Proxy", category="OTHER",
            confidence="HIGH", detail=f"SOCKS4 response: {status.get(data[1],'?')}",
            port_hint=1080,
            ioc_flags=["Open SOCKS proxy — commonly used in proxy-chain C2 infrastructure"],
            references=["T1090.002"])
    return None

def detect_bitcoin_p2p(data):
    MAGIC = {b"\xf9\xbe\xb4\xd9":"Bitcoin mainnet",b"\x0b\x11\x09\x07":"Bitcoin testnet",
             b"\xfa\xbf\xb5\xda":"Litecoin mainnet",b"\xfb\xc0\xb6\xdb":"Dogecoin mainnet"}
    if len(data) >= 24:
        magic = bytes(data[0:4])
        if magic in MAGIC:
            cmd = data[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
            return DetectionResult(
                service=f"Bitcoin P2P ({MAGIC[magic]})", category="OTHER",
                confidence="HIGH", detail=f"Bitcoin network message: '{cmd}'", port_hint=8333,
                ioc_flags=["Crypto node — may indicate compromised server used for mining"])
    return None

def detect_printer(data):
    txt = data[:256].decode("ascii", errors="replace")
    if txt.startswith("@PJL") or b"\x1b%-12345X@PJL" in data:
        return DetectionResult(
            service="HP JetDirect / PJL (Network Printer)", category="OTHER",
            confidence="HIGH", detail="PJL (Printer Job Language) banner", port_hint=9100,
            ioc_flags=["Network printers with PJL access can be exploited for data exfil (Printjack)"])
    if "HTTP" in txt and "application/ipp" in txt:
        return DetectionResult(
            service="IPP (Internet Printing Protocol)", category="OTHER",
            confidence="HIGH", detail="IPP over HTTP response", port_hint=631)
    return None

def detect_hadoop(data):
    txt = data[:512].decode("utf-8", errors="replace")
    if "hadoop" in txt.lower() or "namenode" in txt.lower() or "datanode" in txt.lower():
        return DetectionResult(
            service="Apache Hadoop (Big Data Framework)", category="DATABASE",
            confidence="HIGH", detail="Hadoop service response", port_hint=9000,
            ioc_flags=["Exposed Hadoop YARN — exploited by cryptomining campaigns"],
            references=["T1190"])
    return None

#DETECTOR REGISTRY (priority order: C2 - OT - Remote - DB - Web - Other)

DETECTORS = [
    # C2 / Threat indicators first
    detect_cobalt_strike,
    detect_metasploit,
    detect_sliver,
    detect_empire_havoc,
    detect_brute_ratel_covenant,
    detect_dns_tunnel_c2,
    detect_tor,
    # OT/ICS
    detect_s7comm,
    detect_modbus,
    detect_umas,
    detect_dnp3,
    detect_iec104,
    detect_enip_cip,
    detect_dns,
    detect_vnetip,
    detect_bacnet,
    detect_opc_ua,
    detect_fins,
    detect_profinet,
    detect_iec61850_mms,
    detect_iec_goose,
    detect_x11,
    detect_hart_ip,
    detect_codesys,
    detect_ge_srtp,
    detect_cc_link,
    detect_pcworx,
    # Remote access
    detect_dcerpc,
    detect_ssh,
    detect_rdp,
    detect_vnc,
    detect_telnet,
    detect_smb,
    detect_winrm,
    detect_ipmi,
    detect_teamviewer,
    detect_anydesk,
    detect_docker_api,
    detect_kubernetes_api,
    # Databases
    detect_mysql,
    detect_postgres,
    detect_mssql,
    detect_mongodb,
    detect_redis,
    detect_memcached,
    detect_elasticsearch,
    detect_cassandra,
    detect_couchdb,
    detect_influxdb,
    detect_etcd,
    detect_hadoop,
    # Web / TLS
    detect_tls,
    detect_http,
    # Mail
    detect_smtp,
    detect_pop3,
    detect_imap,
    # Network infra
    detect_ftp,
    detect_snmp,
    detect_ntp,
    detect_rsync,
    # Messaging / VoIP / misc
    detect_mqtt,
    detect_msmq,
    detect_amqp,
    detect_irc,
    detect_sip,
    detect_ldap,
    detect_socks4,
    detect_bitcoin_p2p,
    detect_printer,
    # Heuristic last
    detect_generic_c2,
    detect_unknown_binary,
]
# ANALYSIS ENGINE
def analyze(banner: str):
    data, double_escaped = decode_banner(banner.strip())
    results = []
    for detector in DETECTORS:
        try:
            r = detector(data)
            if r: results.append(r)
        except Exception:
            pass
    return results, data, double_escaped

def analyze_summary(results):
    return {
        "total_matches": len(results),
        "categories": list({r.category for r in results}),
        "max_confidence": (
            "HIGH"   if any(r.confidence=="HIGH"   for r in results) else
            "MEDIUM" if any(r.confidence=="MEDIUM" for r in results) else
            "LOW"    if results else "NONE"),
        "threat_indicators": [f for r in results for f in r.ioc_flags],
        "mitre_references":  sorted({ref for r in results for ref in r.references}),
        "matches": [asdict(r) for r in results],
    }


# SIGNATURE EXTRACTION ENGINE
#
# Goal: split a banner into NORMAL fields (version, protocol boilerplate that
# every instance of this service would share) vs UNIQUE fields (server-specific
# values like auth seeds, connection IDs, session tokens, timestamps, custom
# error strings) so the analyst can build a pivot query for Shodan/Censys.
#
# Architecture:
#   extract_signature(data, results)  -> SignatureReport
#   print_signature(sig, port)        -> formatted console output
#

@dataclass
class SigField:
    """One labelled field extracted from a banner."""
    label:       str    # human name
    raw_hex:     str    # hex representation  e.g. "08 00 40"
    printable:   str    # printable form where possible
    offset:      int    # byte offset in banner
    length:      int    # byte length
    uniqueness:  str    # UNIQUE | NORMAL | VARIABLE | UNKNOWN
    pivot_value: str    # the actual value to use in a search query
    reason:      str    # why this uniqueness classification was given
    search_hint: str    # Shodan/Censys query fragment


@dataclass
class SignatureReport:
    protocol:         str
    port_seen:        Optional[int]
    normal_fields:    list   # list of SigField
    unique_fields:    list   # list of SigField
    variable_fields:  list   # list of SigField — changes each connection
    pivot_queries:    dict   # {"shodan": str, "censys": str}
    full_hex:         str    # full banner as hex string for copy-paste
    escaped_hex:      str    # Python-style \x escaped form
    unique_score:     int    # 0-100: how "pivot-worthy" this banner is


def _to_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)

def _to_escaped(data: bytes) -> str:
    result = ""
    for b in data:
        if 32 <= b < 127 and chr(b) not in "\\'\"":
            result += chr(b)
        else:
            result += f"\\x{b:02x}"
    return result

def _is_high_entropy_block(block: bytes) -> bool:
    """True if a byte block looks like random/crypto material."""
    if len(block) < 4:
        return False
    return byte_entropy(block) > 5.5

def _looks_like_timestamp(val: int) -> bool:
    """Heuristic: 32-bit value in plausible Unix timestamp range (2000-2040)."""
    return 946_684_800 <= val <= 2_208_988_800

def _looks_like_counter(data: bytes, offset: int, length: int) -> bool:
    """Small sequential integer — likely a connection/session counter."""
    if length > 4:
        return False
    val = int.from_bytes(data[offset:offset+length], "little")
    return 0 < val < 100_000


# Per-protocol field dissectors
# Each returns (normal_fields, unique_fields, variable_fields)

def _dissect_mysql(data: bytes) -> tuple[list, list, list]:
    normal, unique, variable = [], [], []

    # Bytes 0-3: packet header (length + sequence)
    pkt_len = int.from_bytes(data[0:3], "little")
    normal.append(SigField(
        label="Packet header (length+seq)",
        raw_hex=_to_hex(data[0:4]),
        printable=f"payload_len={pkt_len}, seq={data[3]}",
        offset=0, length=4, uniqueness="NORMAL",
        pivot_value="",
        reason="Standard MySQL packet framing — identical on every MySQL server",
        search_hint=""))

    # Byte 4: protocol version
    normal.append(SigField(
        label="Protocol version",
        raw_hex=_to_hex(data[4:5]),
        printable=str(data[4]),
        offset=4, length=1, uniqueness="NORMAL",
        pivot_value=str(data[4]),
        reason="Protocol v10 = MySQL 5+/8+; present on every modern MySQL server",
        search_hint='mysql protocol_version:10'))

    # Bytes 5–end of null: version string
    end = data.find(b"\x00", 5)
    if end != -1:
        ver = data[5:end].decode("ascii", errors="replace")
        normal.append(SigField(
            label="Server version string",
            raw_hex=_to_hex(data[5:end]),
            printable=ver,
            offset=5, length=end-5, uniqueness="NORMAL",
            pivot_value=ver,
            reason="MySQL version string — shared by every instance of this exact build",
            search_hint=f'product:"MySQL" version:"{ver}"'))

        # Connection ID (4 bytes LE after null)
        cid_off = end + 1
        if cid_off + 4 <= len(data):
            cid = int.from_bytes(data[cid_off:cid_off+4], "little")
            variable.append(SigField(
                label="Connection ID",
                raw_hex=_to_hex(data[cid_off:cid_off+4]),
                printable=str(cid),
                offset=cid_off, length=4, uniqueness="VARIABLE",
                pivot_value="",
                reason="Auto-incremented per connection — changes every time you connect; "
                        "DO NOT use as pivot",
                search_hint=""))

            # Auth plugin data part 1 (8 bytes + null)
            seed1_off = cid_off + 4
            seed1_end = seed1_off + 8
            if seed1_end + 1 <= len(data):
                seed1 = data[seed1_off:seed1_end]
                variable.append(SigField(
                    label="Auth challenge seed part 1",
                    raw_hex=_to_hex(seed1),
                    printable=_to_escaped(seed1),
                    offset=seed1_off, length=8, uniqueness="VARIABLE",
                    pivot_value="",
                    reason="Cryptographically random per connection — changes every handshake; "
                            "DO NOT use as pivot",
                    search_hint=""))

            # Capability flags (2 bytes at seed1_end+1, then 2 more after char_set/status)
            cap1_off = seed1_end + 1  # skip null
            if cap1_off + 2 <= len(data):
                cap1 = u16le(data, cap1_off)
                normal.append(SigField(
                    label="Capability flags (lower 2 bytes)",
                    raw_hex=_to_hex(data[cap1_off:cap1_off+2]),
                    printable=f"0x{cap1:04x}",
                    offset=cap1_off, length=2, uniqueness="NORMAL",
                    pivot_value=f"0x{cap1:04x}",
                    reason="Server capability bitmask — same for every instance of this "
                            "MySQL build and config; useful combined with version",
                    search_hint=""))

            # MySQL fixed header layout after cap_lo (2 bytes):
            #   cap_hi(2) + charset(1) + status(2) + cap_ext(2) + auth_len(1) + reserved(10) = 18
            # Then seed2 starts at cap1_off + 2 + 18 = cap1_off + 20... BUT cap1_off already
            # points past the null, so: cap_lo(2) + charset(1) + status(2) + cap_hi(2) +
            # auth_len(1) + reserved(10) = 18 bytes, seed2 at cap1_off + 18
            seed2_off = cap1_off + 18
            if seed2_off + 12 <= len(data):
                seed2 = data[seed2_off:seed2_off+12]
                variable.append(SigField(
                    label="Auth challenge seed part 2",
                    raw_hex=_to_hex(seed2),
                    printable=_to_escaped(seed2),
                    offset=seed2_off, length=12, uniqueness="VARIABLE",
                    pivot_value="",
                    reason="Cryptographically random per connection — changes every handshake; "
                           "DO NOT use as pivot",
                    search_hint=""))

            # Auth plugin name: null-terminated string after seed2 + null
            plugin_off = seed2_off + 12 + 1  # skip null after seed2
            plugin_end = data.find(b"\x00", plugin_off)
            if plugin_end == -1:
                plugin_end = len(data)
            if plugin_off < len(data) and plugin_off < plugin_end:
                plugin = data[plugin_off:plugin_end].decode("ascii", errors="replace")
                if plugin and plugin.isprintable():
                    normal.append(SigField(
                        label="Auth plugin name",
                        raw_hex=_to_hex(data[plugin_off:plugin_end]),
                        printable=plugin,
                        offset=plugin_off, length=plugin_end-plugin_off,
                        uniqueness="NORMAL",
                        pivot_value=plugin,
                        reason="Auth plugin — config-level setting, same for all connections "
                               "to this server. 'mysql_native_password' = legacy config.",
                        search_hint=f'mysql "{plugin}"'))

            # Error packet: a SECOND MySQL packet may follow immediately after plugin_end+1.
            # Format: length(3LE) + seq(1) + 0xFF + errcode(2LE) + sqlstate(6) + message
            err_pkt_off = plugin_end + 1
            if err_pkt_off + 7 <= len(data):
                err_pkt = data[err_pkt_off:]
                # seq byte is at offset 3; error marker 0xFF at offset 4
                if len(err_pkt) >= 5 and err_pkt[4] == 0xFF:
                    err_code = int.from_bytes(err_pkt[5:7], "little") if len(err_pkt) >= 7 else 0
                    # sqlstate: 1 byte '#' + 5 bytes state = 6 bytes
                    err_msg_off = 7 + 6  # skip errcode(2) + sqlstate(6)
                    err_msg_raw = err_pkt[err_msg_off:] if len(err_pkt) > err_msg_off else b""
                    err_msg = err_msg_raw.decode("ascii", errors="replace").strip("\x00")
                    sqlstate_raw = err_pkt[7:13].decode("ascii", errors="replace") if len(err_pkt) >= 13 else ""
                    if err_msg:
                        unique.append(SigField(
                            label="MySQL error packet (appended to handshake)",
                            raw_hex=_to_hex(err_pkt),
                            printable=f"[{err_code}] SQLSTATE={sqlstate_raw} — {err_msg}",
                            offset=err_pkt_off, length=len(err_pkt),
                            uniqueness="UNIQUE",
                            pivot_value=err_msg,
                            reason="Error message emitted when a probe or scanner sent unexpected "
                                   "bytes before the handshake completed. The exact error string "
                                   "and error code are config-level — unusual MySQL wrappers, "
                                   "proxies, or custom builds may show different strings here.",
                            search_hint=f'"{err_msg}"'))

    return normal, unique, variable


def _dissect_ssh(data: bytes) -> tuple[list, list, list]:
    normal, unique, variable = [], [], []
    line = data.split(b"\n")[0].decode("ascii", errors="replace").strip()
    parts = line.split("-", 2)
    proto   = parts[1] if len(parts) >= 2 else "?"
    version = parts[2] if len(parts) >= 3 else ""

    # Protocol part: SSH-2.0 — normal
    normal.append(SigField(
        label="SSH protocol identifier",
        raw_hex=_to_hex(f"SSH-{proto}-".encode()),
        printable=f"SSH-{proto}",
        offset=0, length=len(f"SSH-{proto}-"), uniqueness="NORMAL",
        pivot_value=f"SSH-{proto}",
        reason="Standard SSH protocol prefix — present on every SSH server",
        search_hint='port:22 "SSH-2.0"'))

    # Software version: unique-ish
    if version:
        # Known common implementations are NORMAL; custom/unusual ones are UNIQUE
        common_impls = ["OpenSSH", "libssh", "Cisco", "dropbear", "PuTTY_Release"]
        is_common = any(version.startswith(c) for c in common_impls)
        # Comments after the version (space-separated) can be very unique
        ver_parts = version.split(" ", 1)
        base_ver = ver_parts[0]
        comment  = ver_parts[1] if len(ver_parts) > 1 else ""

        normal.append(SigField(
            label="SSH software version",
            raw_hex=_to_hex(base_ver.encode()),
            printable=base_ver,
            offset=len(f"SSH-{proto}-"), length=len(base_ver),
            uniqueness="NORMAL" if is_common else "UNIQUE",
            pivot_value=base_ver,
            reason="Common SSH implementation — shared across many servers" if is_common
                   else "Non-standard SSH implementation — unusual; good pivot candidate",
            search_hint=f'"SSH-{proto}-{base_ver}"'))

        if comment:
            # OS/distro comments in SSH banners are highly unique
            unique.append(SigField(
                label="SSH banner comment / OS hint",
                raw_hex=_to_hex(comment.encode()),
                printable=comment,
                offset=len(f"SSH-{proto}-{base_ver} "), length=len(comment),
                uniqueness="UNIQUE",
                pivot_value=comment,
                reason="Banner comment (OS, distro, build info) — operator-configured; "
                        "often specific to a deployment or image used",
                search_hint=f'"SSH-{proto}-{base_ver} {comment}"'))

    return normal, unique, variable


def _dissect_http(data: bytes) -> tuple[list, list, list]:
    normal, unique, variable = [], [], []
    txt = data.decode("utf-8", errors="replace")
    lines = txt.split("\n")

    status_line = lines[0].strip() if lines else ""
    m = re.match(r"^HTTP/(\S+)\s+(\d+)\s+(.*)", status_line)
    if m:
        normal.append(SigField(
            label="HTTP status line",
            raw_hex=_to_hex(status_line.encode()),
            printable=status_line,
            offset=0, length=len(status_line), uniqueness="NORMAL",
            pivot_value=f"HTTP/{m.group(1)} {m.group(2)}",
            reason="HTTP status code — normal for any web server",
            search_hint=f"http.status:{m.group(2)}"))

    for line in lines[1:]:
        line = line.strip()
        if not line:
            break
        hdr_m = re.match(r"^([^:]+):\s*(.*)", line)
        if not hdr_m:
            continue
        hname, hval = hdr_m.group(1).strip(), hdr_m.group(2).strip()
        hname_l = hname.lower()

        # Classify each header
        if hname_l == "server":
            # Server header with no version = possible C2 artifact
            if re.match(r"^(Apache|nginx|Microsoft-IIS|lighttpd)$", hval):
                unique.append(SigField(
                    label=f"Header: {hname}",
                    raw_hex=_to_hex(line.encode()),
                    printable=hval,
                    offset=0, length=len(line), uniqueness="UNIQUE",
                    pivot_value=hval,
                    reason="Server header with NO version string — atypical; "
                            "common in C2 framework profiles that fake a server header",
                    search_hint=f'http.headers.server:"{hval}"'))
            else:
                normal.append(SigField(
                    label=f"Header: {hname}",
                    raw_hex=_to_hex(line.encode()),
                    printable=hval,
                    offset=0, length=len(line), uniqueness="NORMAL",
                    pivot_value=hval,
                    reason="Standard server identification header",
                    search_hint=f'http.headers.server:"{hval}"'))

        elif hname_l in ("date", "last-modified", "expires"):
            variable.append(SigField(
                label=f"Header: {hname}",
                raw_hex=_to_hex(line.encode()),
                printable=hval,
                offset=0, length=len(line), uniqueness="VARIABLE",
                pivot_value="",
                reason="Timestamp header — changes per response; DO NOT use as pivot",
                search_hint=""))

        elif hname_l in ("set-cookie", "x-request-id", "x-correlation-id", "etag"):
            variable.append(SigField(
                label=f"Header: {hname}",
                raw_hex=_to_hex(line.encode()),
                printable=hval,
                offset=0, length=len(line), uniqueness="VARIABLE",
                pivot_value="",
                reason="Session/request-specific value — changes per connection",
                search_hint=""))

        elif hname_l.startswith("x-"):
            # Non-standard X- headers are often operator fingerprints
            unique.append(SigField(
                label=f"Header: {hname} (custom)",
                raw_hex=_to_hex(line.encode()),
                printable=hval,
                offset=0, length=len(line), uniqueness="UNIQUE",
                pivot_value=f"{hname}: {hval}",
                reason="Non-standard X- header — operator/framework specific; "
                        "excellent pivot candidate",
                search_hint=f'http.headers:"{hname}"'))

        elif hname_l in ("content-type", "connection", "transfer-encoding",
                          "content-encoding", "vary", "cache-control"):
            normal.append(SigField(
                label=f"Header: {hname}",
                raw_hex=_to_hex(line.encode()),
                printable=hval,
                offset=0, length=len(line), uniqueness="NORMAL",
                pivot_value="",
                reason="Standard HTTP header — too common to pivot on alone",
                search_hint=""))

        else:
            # Uncommon named headers = potentially unique
            unique.append(SigField(
                label=f"Header: {hname} (uncommon)",
                raw_hex=_to_hex(line.encode()),
                printable=hval,
                offset=0, length=len(line), uniqueness="UNIQUE",
                pivot_value=f"{hname}: {hval}",
                reason="Uncommon header name — may be operator/framework specific",
                search_hint=f'http.headers:"{hname}: {hval}"'))

    return normal, unique, variable


def _dissect_tls(data: bytes) -> tuple[list, list, list]:
    normal, unique, variable = [], [], []
    vers = {0:"SSLv3",1:"TLS 1.0",2:"TLS 1.1",3:"TLS 1.2",4:"TLS 1.3"}
    ver = vers.get(data[2], "unknown")

    normal.append(SigField(
        label="TLS record type + version",
        raw_hex=_to_hex(data[0:3]),
        printable=f"Handshake ({ver})",
        offset=0, length=3, uniqueness="NORMAL",
        pivot_value=ver,
        reason="TLS record type 0x16 + version — standard framing",
        search_hint=f"ssl.version:{ver}"))

    if len(data) >= 6 and data[5] == 0x02:
        # ServerHello — look for session ID (VARIABLE) and cipher suite (pivot candidate)
        off = 6  # after record header (5) + handshake type (1)
        if off + 3 <= len(data):
            off += 3  # skip handshake length
        if off + 2 <= len(data):
            off += 2  # skip server_version
        if off + 4 <= len(data):
            ts_candidate = u32be(data, off)
            if _looks_like_timestamp(ts_candidate):
                variable.append(SigField(
                    label="ServerHello random (timestamp component)",
                    raw_hex=_to_hex(data[off:off+4]),
                    printable=str(ts_candidate),
                    offset=off, length=4, uniqueness="VARIABLE",
                    pivot_value="",
                    reason="Unix timestamp embedded in ServerHello random — changes per session",
                    search_hint=""))
            off += 4
        if off + 28 <= len(data):
            rand = data[off:off+28]
            variable.append(SigField(
                label="ServerHello random (28 random bytes)",
                raw_hex=_to_hex(rand),
                printable=_to_escaped(rand),
                offset=off, length=28, uniqueness="VARIABLE",
                pivot_value="",
                reason="Cryptographic random — changes every TLS handshake; DO NOT pivot on this",
                search_hint=""))
            off += 28
        if off + 1 <= len(data):
            sid_len = data[off]
            off += 1
            if sid_len > 0 and off + sid_len <= len(data):
                sid = data[off:off+sid_len]
                variable.append(SigField(
                    label="Session ID",
                    raw_hex=_to_hex(sid),
                    printable=_to_escaped(sid),
                    offset=off, length=sid_len, uniqueness="VARIABLE",
                    pivot_value="",
                    reason="TLS session ID — random per session; DO NOT pivot",
                    search_hint=""))
                off += sid_len
            if off + 2 <= len(data):
                cs = u16be(data, off)
                cs_names = {
                    0xC02B:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    0xC02C:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    0xC02F:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    0xC030:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    0x009C:"TLS_RSA_WITH_AES_128_GCM_SHA256",
                    0x1301:"TLS_AES_128_GCM_SHA256",
                    0x1302:"TLS_AES_256_GCM_SHA384",
                    0x0035:"TLS_RSA_WITH_AES_256_CBC_SHA (legacy)",
                    0x002F:"TLS_RSA_WITH_AES_128_CBC_SHA (legacy)",
                }
                cs_name = cs_names.get(cs, f"0x{cs:04x}")
                u_type = "UNIQUE" if cs in (0x0035, 0x002F) else "NORMAL"
                reason = ("Legacy/weak cipher suite — unusual on modern servers; "
                          "possible old tooling or deliberate downgrade"
                          if u_type == "UNIQUE" else
                          "Standard cipher suite — common across many TLS servers")
                normal.append(SigField(
                    label="Selected cipher suite",
                    raw_hex=_to_hex(data[off:off+2]),
                    printable=cs_name,
                    offset=off, length=2, uniqueness=u_type,
                    pivot_value=cs_name,
                    reason=reason,
                    search_hint=f"ssl.cipher:{cs_name}" if u_type == "UNIQUE" else ""))

    return normal, unique, variable


def _dissect_dns(data: bytes) -> tuple[list, list, list]:
    """DNS wire format dissector — classifies each section properly."""
    normal, unique, variable = [], [], []

    # Normalise first — some scanners drop the 2-byte TxID prefix
    data, txid_present = _dns_normalise(data)

    # Header (always 12 bytes, fully fixed structure)
    txid  = u16be(data, 0)
    flags = u16be(data, 2)
    qr      = (flags >> 15) & 1
    opcode  = (flags >> 11) & 0xF
    aa      = (flags >> 10) & 1
    tc      = (flags >>  9) & 1
    rd      = (flags >>  8) & 1
    ra      = (flags >>  7) & 1
    rcode   = flags & 0xF
    qdcount = u16be(data, 4)
    ancount = u16be(data, 6)
    nscount = u16be(data, 8)
    arcount = u16be(data, 10)

    # TxID is VARIABLE — random per query
    variable.append(SigField(
        label="Transaction ID",
        raw_hex=_to_hex(data[0:2]),
        printable=f"0x{txid:04x}",
        offset=0, length=2, uniqueness="VARIABLE",
        pivot_value="",
        reason="Random per query — changes every request; DO NOT pivot on this",
        search_hint=""))

    # Flags are NORMAL for a given resolver/server config
    rcodes = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}
    pkt_type = "Response" if qr else "Query"
    flags_desc = (f"{pkt_type} opcode={opcode} AA={aa} TC={tc} RD={rd} "
                  f"RA={ra} RCODE={rcodes.get(rcode, rcode)}")
    normal.append(SigField(
        label="DNS flags",
        raw_hex=_to_hex(data[2:4]),
        printable=f"0x{flags:04x} — {flags_desc}",
        offset=2, length=2, uniqueness="NORMAL",
        pivot_value="",
        reason="Flags reflect query/response type and resolver behaviour — "
               "consistent per server config but not unique enough to pivot on alone",
        search_hint=""))

    # Record counts — NORMAL context
    normal.append(SigField(
        label="Record counts",
        raw_hex=_to_hex(data[4:12]),
        printable=f"QD={qdcount} AN={ancount} NS={nscount} AR={arcount}",
        offset=4, length=8, uniqueness="NORMAL",
        pivot_value="",
        reason="Section counts — reflect what was queried/answered; "
               "too variable per query to pivot on",
        search_hint=""))

    # Decode question section — the queried NAME is UNIQUE (operator-configured)
    offset = 12
    for i in range(min(qdcount, 5)):
        if offset >= len(data): break
        name, offset = _dns_decode_name(data, offset)
        if offset + 4 > len(data): break
        qtype  = u16be(data, offset)
        offset += 4
        qtypes = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",
                  15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
        tname = qtypes.get(qtype, f"type{qtype}")
        # The queried domain is operator/user specific — good pivot candidate
        # UNLESS it's a well-known resolver test domain (e.g. google.com, cloudflare.com)
        common_test_domains = {"google.com","cloudflare.com","example.com",
                               "microsoft.com","amazon.com","clients1.google.com",
                               "dns.google","one.one.one.one"}
        is_common = any(name.lower().endswith(d) for d in common_test_domains)
        ftype = "NORMAL" if is_common else "UNIQUE"
        reason = ("Well-known test/resolver domain — too common to pivot on"
                  if is_common else
                  "Queried domain name — operator or implant specific; "
                  "search for this to find related infrastructure querying the same domain")
        (normal if is_common else unique).append(SigField(
            label=f"Question #{i+1}: queried name",
            raw_hex="(wire-encoded label sequence)",
            printable=f"{name} ({tname})",
            offset=12, length=0, uniqueness=ftype,
            pivot_value=name if not is_common else "",
            reason=reason,
            search_hint=f'dns.question.name:"{name}"' if not is_common else ""))

    # Decode answer section — resolved IPs/CNAMEs are UNIQUE pivot values
    for i in range(min(ancount, 10)):
        if offset >= len(data): break
        name, offset = _dns_decode_name(data, offset)
        if offset + 10 > len(data): break
        rtype = u16be(data, offset)
        ttl   = u32be(data, offset + 4)
        rdlen = u16be(data, offset + 8)
        offset += 10
        if offset + rdlen > len(data): break
        rdata = data[offset:offset + rdlen]
        offset += rdlen

        if rtype == 1 and rdlen == 4:    # A record
            ip = ".".join(str(b) for b in rdata)
            unique.append(SigField(
                label=f"Answer #{i+1}: A record",
                raw_hex=_to_hex(rdata),
                printable=f"{name} - {ip} (TTL {ttl})",
                offset=0, length=4, uniqueness="UNIQUE",
                pivot_value=ip,
                reason="Resolved IP address — pivot on this to find other hostnames "
                       "resolving to the same infrastructure IP",
                search_hint=f'ip:{ip}'))
        elif rtype == 28 and rdlen == 16:  # AAAA
            groups = [f"{u16be(rdata, j):04x}" for j in range(0, 16, 2)]
            ipv6 = ":".join(groups)
            unique.append(SigField(
                label=f"Answer #{i+1}: AAAA record",
                raw_hex=_to_hex(rdata),
                printable=f"{name} - {ipv6} (TTL {ttl})",
                offset=0, length=16, uniqueness="UNIQUE",
                pivot_value=ipv6,
                reason="Resolved IPv6 address — pivot candidate",
                search_hint=f'ip:{ipv6}'))
        elif rtype == 5:   # CNAME
            cname, _ = _dns_decode_name(data, offset - rdlen)
            unique.append(SigField(
                label=f"Answer #{i+1}: CNAME",
                raw_hex="(wire-encoded)",
                printable=f"{name} - {cname} (TTL {ttl})",
                offset=0, length=rdlen, uniqueness="UNIQUE",
                pivot_value=cname,
                reason="CNAME target — operator-configured; pivot on this to find "
                       "related infrastructure using the same canonical name",
                search_hint=f'dns.answer.name:"{cname}"'))
        else:
            normal.append(SigField(
                label=f"Answer #{i+1}: type {rtype}",
                raw_hex=_to_hex(rdata[:16]),
                printable=f"rdlen={rdlen} TTL={ttl}",
                offset=0, length=rdlen, uniqueness="NORMAL",
                pivot_value="",
                reason=f"DNS RR type {rtype} — not decoded in detail",
                search_hint=""))

    return normal, unique, variable


def _dissect_dcerpc(data: bytes) -> tuple[list, list, list]:
    """DCE/RPC PDU header dissector — classifies all 16 fixed header fields."""
    normal, unique, variable = [], [], []
    if len(data) < 16:
        return normal, unique, variable

    ptype = data[2]
    drep_bo = data[4]
    frag_len = u16le(data, 8) if drep_bo == 0x10 else u16be(data, 8)
    call_id  = u32le(data, 12) if drep_bo == 0x10 else u32be(data, 12)
    byte_order = "little-endian" if drep_bo == 0x10 else "big-endian"

    PTYPES = {
        0x00:"REQUEST", 0x02:"RESPONSE", 0x03:"FAULT",
        0x0B:"BIND",    0x0C:"BIND_ACK", 0x0D:"BIND_NACK",
        0x0E:"ALTER_CONTEXT", 0x0F:"ALTER_CONTEXT_RESP",
        0x11:"SHUTDOWN", 0x14:"RTS",
    }

    # Version — NORMAL (always 5.x)
    normal.append(SigField(
        label="DCE/RPC version",
        raw_hex=_to_hex(data[0:2]),
        printable=f"v{data[0]}.{data[1]}",
        offset=0, length=2, uniqueness="NORMAL",
        pivot_value="",
        reason="DCE/RPC is always version 5.0 or 5.1 — present on every Windows RPC endpoint",
        search_hint='"DCE/RPC"'))

    # Packet type — NORMAL (reflects what the server sent)
    normal.append(SigField(
        label="Packet type (PTYPE)",
        raw_hex=_to_hex(data[2:3]),
        printable=f"{ptype:#04x} = {PTYPES.get(ptype, f'type{ptype}')}",
        offset=2, length=1, uniqueness="NORMAL",
        pivot_value="",
        reason="PDU type reflects the phase of the RPC handshake — normal for a given interaction",
        search_hint=""))

    # Data representation — NORMAL (almost always LE/ASCII/IEEE)
    normal.append(SigField(
        label="Data representation (packed_drep)",
        raw_hex=_to_hex(data[4:8]),
        printable=f"{data[4:8].hex()} ({byte_order})",
        offset=4, length=4, uniqueness="NORMAL",
        pivot_value="",
        reason="Byte/char/float encoding — 0x10000000 (LE) is universal on Windows",
        search_hint=""))

    # Fragment length — NORMAL (fixed for a given PDU type)
    normal.append(SigField(
        label="Fragment length",
        raw_hex=_to_hex(data[8:10]),
        printable=str(frag_len),
        offset=8, length=2, uniqueness="NORMAL",
        pivot_value="",
        reason="Total PDU size in bytes — fixed for a given packet type and payload",
        search_hint=""))

    # Call ID — VARIABLE (increments per call)
    variable.append(SigField(
        label="Call ID",
        raw_hex=_to_hex(data[12:16]),
        printable=str(call_id),
        offset=12, length=4, uniqueness="VARIABLE",
        pivot_value="",
        reason="Monotonically incrementing per RPC call — changes every connection; DO NOT pivot",
        search_hint=""))

    # BIND_NACK: reject reason is UNIQUE (identifies server's supported versions)
    if ptype == 0x0D and len(data) >= 18:
        reason = u16le(data, 16) if drep_bo == 0x10 else u16be(data, 16)
        REASONS = {0:"reason_not_specified", 1:"temporary_congestion",
                   2:"local_limit_exceeded", 4:"protocol_version_not_supported",
                   5:"default_context_not_supported"}
        reason_str = REASONS.get(reason, f"code_{reason}")
        unique.append(SigField(
            label="BIND_NACK reject reason",
            raw_hex=_to_hex(data[16:18]),
            printable=f"{reason} = {reason_str}",
            offset=16, length=2, uniqueness="UNIQUE",
            pivot_value=reason_str,
            reason="Reject reason code is consistent for a given server configuration — "
                   "combined with port, identifies the RPC service type",
            search_hint=f'"DCE/RPC" "{reason_str}"'))

    # BIND_ACK: secondary address (endpoint path) is UNIQUE
    elif ptype == 0x0C and len(data) >= 24:
        sec_len = u16le(data, 18) if drep_bo == 0x10 else u16be(data, 18)
        if sec_len > 0 and 20 + sec_len <= len(data):
            sec_addr = data[20:20+sec_len].decode("ascii", errors="replace").strip("\x00")
            if sec_addr:
                unique.append(SigField(
                    label="Secondary address (RPC endpoint path)",
                    raw_hex=_to_hex(data[20:20+sec_len]),
                    printable=sec_addr,
                    offset=20, length=sec_len, uniqueness="UNIQUE",
                    pivot_value=sec_addr,
                    reason="Named pipe or endpoint path — operator-configured; "
                           "identifies the specific Windows service behind this RPC endpoint",
                    search_hint=f'"{sec_addr}"'))

    return normal, unique, variable


def _dissect_vnetip(data: bytes) -> tuple[list, list, list]:
    """ICS/SCADA device discovery protocol dissector."""
    normal, unique, variable = [], [], []

    normal.append(SigField(
        label="Message type + subtype",
        raw_hex=_to_hex(data[0:2]),
        printable=f"{data[0]:#04x} {data[1]:#04x}",
        offset=0, length=2, uniqueness="NORMAL",
        pivot_value="",
        reason="Message class bytes — fixed for a given packet type; "
               "present on every response from this service",
        search_hint=""))

    normal.append(SigField(
        label="Flags",
        raw_hex=_to_hex(data[2:3]),
        printable=f"{data[2]:#04x} ({'Response' if data[2]==0x80 else 'Request'})",
        offset=2, length=1, uniqueness="NORMAL",
        pivot_value="",
        reason="Direction/response flag — consistent for a given exchange type",
        search_hint=""))

    total_len = u32be(data, 4)
    normal.append(SigField(
        label="Total length (BE)",
        raw_hex=_to_hex(data[4:8]),
        printable=str(total_len),
        offset=4, length=4, uniqueness="NORMAL",
        pivot_value="",
        reason="Packet length field (big-endian) matches actual size — "
               "confirms structured framing; fixed for this packet type",
        search_hint=""))

    if len(data) > 10:
        normal.append(SigField(
            label="Domain/unit IDs",
            raw_hex=_to_hex(data[10:12]),
            printable=f"id={data[10]} type={data[11]}",
            offset=10, length=2, uniqueness="NORMAL",
            pivot_value="",
            reason="Network/domain identifiers — reflect topology, not unique to one host",
            search_hint=""))

    # Device name — UNIQUE pivot value
    if len(data) > 12:
        end = data.find(b'\x00', 12)
        end = end if end != -1 else len(data)
        node_name = data[12:end].decode("ascii", errors="replace")
        if node_name:
            unique.append(SigField(
                label="Device/node name",
                raw_hex=_to_hex(data[12:end]),
                printable=node_name,
                offset=12, length=end-12, uniqueness="UNIQUE",
                pivot_value=node_name,
                reason="Operator-assigned asset identifier — unique to this physical device. "
                       "Pivot on the exact name to track this device, or on the domain "
                       "prefix to find related devices in the same installation.",
                search_hint=f'"{node_name}"'))

            parts = node_name.split("_")
            if len(parts) >= 2:
                prefix = parts[0]
                unique.append(SigField(
                    label="Domain prefix",
                    raw_hex=_to_hex(prefix.encode()),
                    printable=prefix,
                    offset=12, length=len(prefix), uniqueness="UNIQUE",
                    pivot_value=prefix,
                    reason=f"Prefix '{prefix}' likely shared by all devices in the same "
                           "ICS installation — broader pivot to cluster related nodes",
                    search_hint=f'"{prefix}_"'))

    return normal, unique, variable


def _dissect_msmq(data: bytes) -> tuple[list, list, list]:
    """
    MSMQ session header dissector.
    Layout: version(1) + flags(1) + length(2LE) + magic(4='LIOR') +
            fields(variable) + session_guid(16 hex ASCII) + crypto_material
    """
    normal, unique, variable = [], [], []

    if len(data) < 8:
        return normal, unique, variable

    # Bytes 0-3: fixed header
    normal.append(SigField(
        label="MSMQ version/type byte",
        raw_hex=_to_hex(data[0:1]),
        printable=f"{data[0]:#04x}",
        offset=0, length=1, uniqueness="NORMAL",
        pivot_value="",
        reason="MSMQ session packet type — 0x10 is standard session header",
        search_hint='port:1801 "LIOR"'))

    normal.append(SigField(
        label="MSMQ flags",
        raw_hex=_to_hex(data[1:2]),
        printable=f"{data[1]:#04x}",
        offset=1, length=1, uniqueness="NORMAL",
        pivot_value=f"{data[1]:#04x}",
        reason="Flags byte — reflects server configuration; same for a given MSMQ build",
        search_hint=""))

    length_field = u16le(data, 2) if len(data) >= 4 else 0
    normal.append(SigField(
        label="Header length",
        raw_hex=_to_hex(data[2:4]),
        printable=str(length_field),
        offset=2, length=2, uniqueness="NORMAL",
        pivot_value="",
        reason="Declared header length — standard for given MSMQ version",
        search_hint=""))

    # Bytes 4-7: 'LIOR' magic — always present, NORMAL
    normal.append(SigField(
        label="MSMQ magic signature",
        raw_hex=_to_hex(data[4:8]),
        printable="LIOR",
        offset=4, length=4, uniqueness="NORMAL",
        pivot_value="LIOR",
        reason="Fixed MSMQ protocol magic — present on every MSMQ server; "
               "use with port:1801 to find all MSMQ instances",
        search_hint='port:1801 "LIOR"'))

    # Bytes 12-15: 0xFFFFFFFF channel field — NORMAL
    if len(data) >= 16:
        chan = u32le(data, 12)
        normal.append(SigField(
            label="Channel/broadcast field",
            raw_hex=_to_hex(data[12:16]),
            printable=f"{chan:#010x}",
            offset=12, length=4, uniqueness="NORMAL",
            pivot_value="",
            reason="0xFFFFFFFF = broadcast/wildcard channel indicator — same on all MSMQ",
            search_hint=""))

    # Session GUID (hex ASCII string, 16 chars = 8 bytes hex) — VARIABLE
    # Find the hex string starting around offset 20
    guid_match = re.search(rb'[0-9a-f]{16}', data[16:40])
    if guid_match:
        guid_str = guid_match.group(0).decode("ascii")
        guid_off = 16 + guid_match.start()
        variable.append(SigField(
            label="Session correlation ID",
            raw_hex=_to_hex(data[guid_off:guid_off+16]),
            printable=guid_str,
            offset=guid_off, length=16, uniqueness="VARIABLE",
            pivot_value="",
            reason="Per-session correlation identifier — changes with every MSMQ "
                   "connection; DO NOT use as pivot",
            search_hint=""))

    # Everything after the GUID is crypto/session material — VARIABLE
    if len(data) > 40:
        tail = data[40:]
        tail_ent = byte_entropy(tail)
        if tail_ent > 3.0:
            variable.append(SigField(
                label="Session crypto material",
                raw_hex=_to_hex(tail[:16]),
                printable=_to_escaped(tail[:16]),
                offset=40, length=len(tail), uniqueness="VARIABLE",
                pivot_value="",
                reason=f"Entropy {tail_ent:.1f}/8.0 — session-specific cryptographic "
                       "material; changes per connection",
                search_hint=""))

    return normal, unique, variable


def _dissect_x11(data: bytes) -> tuple[list, list, list]:
    """
    X11 ServerConnectReply dissector.
    Correctly separates:
      NORMAL  — protocol version, release number, fixed server config fields
      UNIQUE  — vendor string (fixed OS/implementation prefix only)
      VARIABLE — session-specific suffix appended to vendor string,
                 resource ID base (per-session), motion buffer size
    """
    normal, unique, variable = [], [], []

    if len(data) < 8:
        return normal, unique, variable

    status = data[0]
    major  = u16le(data, 2)
    minor  = u16le(data, 4)

    normal.append(SigField(
        label="X11 protocol version",
        raw_hex=_to_hex(data[2:6]),
        printable=f"X11 protocol {major}.{minor}",
        offset=2, length=4, uniqueness="NORMAL",
        pivot_value="",
        reason="X11 is always protocol 11.0 — present on every X server; "
               "not useful as a pivot value",
        search_hint='port:6000 "X11"'))

    normal.append(SigField(
        label="Connection status",
        raw_hex=_to_hex(data[0:1]),
        printable={1:"Success", 0:"Failed", 2:"Authenticate"}.get(status, f"{status}"),
        offset=0, length=1, uniqueness="NORMAL",
        pivot_value="",
        reason="Status byte — 1=Success; too common to pivot on",
        search_hint=""))

    if status == 1 and len(data) >= 26:
        release     = u32le(data, 8) if len(data) >= 12 else 0
        rid_base    = u32le(data, 12) if len(data) >= 16 else 0
        vendor_len  = u16le(data, 24)
        max_req_len = u16le(data, 26) if len(data) >= 28 else 0
        n_screens   = data[28] if len(data) > 28 else 0
        byte_order  = data[30] if len(data) > 30 else 0
        min_key     = data[34] if len(data) > 34 else 0
        max_key     = data[35] if len(data) > 35 else 0

        # Search for vendor string directly — truncated banners may have
        # the vendor start before offset 40, or vendor_len > available bytes
        VENDOR_MARKERS = [b"The X.Org", b"X.Org", b"XFree86", b"DECWINDOWS",
                          b"Silicon Graphics", b"Sun Microsystems",
                          b"Hewlett-Packard", b"MIT X Consortium", b"X Consortium"]
        vendor_offset = 40
        for vm in VENDOR_MARKERS:
            idx = data.find(vm)
            if idx != -1:
                vendor_offset = idx
                break
        actual_len = min(vendor_len, len(data) - vendor_offset) if vendor_len > 0 else len(data) - vendor_offset
        actual_len = max(actual_len, 0)
        vendor_raw = re.sub(r'[\x00-\x1f]+$', '',
            data[vendor_offset:vendor_offset + actual_len].decode("ascii", errors="replace"))

        # Release number — NORMAL for a given X server build
        normal.append(SigField(
            label="Release number",
            raw_hex=_to_hex(data[8:12]),
            printable=str(release),
            offset=8, length=4, uniqueness="NORMAL",
            pivot_value=str(release) if release > 0 else "",
            reason="X server release/build number — same for all instances of "
                   "this exact server build; useful combined with vendor string",
            search_hint=f"x11 release:{release}" if release else ""))

        # Resource ID base is PER-SESSION — changes every connection
        variable.append(SigField(
            label="Resource ID base",
            raw_hex=_to_hex(data[12:16]),
            printable=f"{rid_base:#010x}",
            offset=12, length=4, uniqueness="VARIABLE",
            pivot_value="",
            reason="Allocated per client connection — changes every session; "
                   "DO NOT use as pivot",
            search_hint=""))

        # Server config fields — NORMAL (same for given server/display config)
        normal.append(SigField(
            label="Server configuration",
            raw_hex=_to_hex(data[26:36]),
            printable=(f"max_request={max_req_len}  screens={n_screens}  "
                       f"byte_order={'MSBFirst' if byte_order==1 else 'LSBFirst'}  "
                       f"keycodes={min_key}-{max_key}"),
            offset=26, length=10, uniqueness="NORMAL",
            pivot_value="",
            reason="Server display configuration — consistent for a given X server "
                   "setup but too common to pivot on alone",
            search_hint=""))

        # Vendor string — split into fixed prefix (UNIQUE) and session suffix (VARIABLE)
        VENDOR_MARKERS_D = [b"The X.Org", b"X.Org", b"XFree86", b"DECWINDOWS",
                            b"Silicon Graphics", b"Sun Microsystems",
                            b"Hewlett-Packard", b"MIT X Consortium", b"X Consortium"]
        v_off = 40
        for vm in VENDOR_MARKERS_D:
            ix = data.find(vm)
            if ix != -1:
                v_off = ix
                break
        v_len = min(vendor_len, len(data) - v_off) if vendor_len > 0 else len(data) - v_off
        vendor_raw = re.sub(r'[\x00-\x1f]+$', '',
            data[v_off:v_off + max(v_len, 0)].decode("ascii", errors="replace"))

        KNOWN_VENDORS = [
            "The X.Org Foundation",
            "X.Org Foundation",
            "XFree86",
            "DECWINDOWS Digital Equipment Corporation Digital UNIX",
            "DECWINDOWS Digital Equipment Corporation",
            "Silicon Graphics",
            "Sun Microsystems",
            "Hewlett-Packard Company",
            "MIT X Consortium",
            "X Consortium",
        ]

        vendor_fixed   = vendor_raw
        vendor_session = ""
        for known in sorted(KNOWN_VENDORS, key=len, reverse=True):
            if vendor_raw.startswith(known):
                remainder = vendor_raw[len(known):].strip()
                # Session-specific suffix: no spaces, alphanumeric+symbols, 6-24 chars
                if remainder and re.match(r'^[A-Za-z0-9_\-\.]{6,24}$', remainder):
                    vendor_fixed   = known
                    vendor_session = remainder
                else:
                    vendor_fixed = vendor_raw
                break

        # The fixed vendor prefix is UNIQUE — identifies the X server implementation
        # It is the same on every connection to this server
        unique.append(SigField(
            label="Vendor string (fixed prefix)",
            raw_hex=_to_hex(vendor_fixed.encode()),
            printable=vendor_fixed,
            offset=40, length=len(vendor_fixed),
            uniqueness="UNIQUE",
            pivot_value=vendor_fixed,
            reason="X server vendor/implementation identifier — same on every "
                   "connection to this host. Identifies the OS and X server "
                   "implementation. Searching for this exact string will find "
                   "other hosts running the same X server.",
            search_hint=f'"{vendor_fixed}"'))

        # The session-specific suffix is VARIABLE — do not pivot on it
        if vendor_session:
            variable.append(SigField(
                label="Vendor string (session-specific suffix)",
                raw_hex=_to_hex(vendor_session.encode()),
                printable=vendor_session,
                offset=40 + len(vendor_fixed) + 1,
                length=len(vendor_session),
                uniqueness="VARIABLE",
                pivot_value="",
                reason="Session-specific value appended to vendor string — "
                       "this is a MIT-MAGIC-COOKIE fragment, auth token, or "
                       "build tag that changes per connection or per server instance. "
                       "DO NOT use as a pivot value.",
                search_hint=""))

    return normal, unique, variable


def _dissect_generic(data: bytes, protocol: str) -> tuple[list, list, list]:
    """
    Generic dissector for protocols without a dedicated field-level dissector.
    Splits the banner into printable runs and binary blobs, classifies each.
    """
    normal, unique, variable = [], [], []
    i = 0
    while i < len(data):
        # Find a run of printable ASCII
        if 32 <= data[i] < 127:
            j = i
            while j < len(data) and 32 <= data[j] < 127:
                j += 1
            run = data[i:j]
            run_str = run.decode("ascii")
            # Short printable runs after a protocol header are likely boilerplate
            field_type = "NORMAL" if len(run) <= 8 else "UNIQUE"
            reason = ("Short printable string — likely protocol boilerplate"
                      if field_type == "NORMAL" else
                      "Longer printable string — may be operator-specific "
                      "(hostname, path, version, error message)")
            hint = f'"{run_str}"' if field_type == "UNIQUE" and len(run_str) >= 6 else ""
            (normal if field_type == "NORMAL" else unique).append(SigField(
                label=f"Printable string @ {i}",
                raw_hex=_to_hex(run),
                printable=run_str,
                offset=i, length=j-i, uniqueness=field_type,
                pivot_value=run_str if field_type == "UNIQUE" else "",
                reason=reason,
                search_hint=hint))
            i = j
        else:
            # Find a run of binary bytes
            j = i
            while j < len(data) and not (32 <= data[j] < 127):
                j += 1
            blob = data[i:j]
            # High-entropy blobs are random/crypto - VARIABLE
            # Low-entropy fixed blobs are protocol magic/flags - NORMAL
            ent = byte_entropy(blob)
            if ent > 5.0 and len(blob) >= 4:
                variable.append(SigField(
                    label=f"Binary blob @ {i} (high entropy, likely random/crypto)",
                    raw_hex=_to_hex(blob),
                    printable=_to_escaped(blob),
                    offset=i, length=j-i, uniqueness="VARIABLE",
                    pivot_value="",
                    reason=f"Entropy {ent:.1f}/8.0 — random seed, nonce, or key material; "
                            "changes per session",
                    search_hint=""))
            else:
                normal.append(SigField(
                    label=f"Binary field @ {i} (protocol flags/magic)",
                    raw_hex=_to_hex(blob),
                    printable=_to_escaped(blob),
                    offset=i, length=j-i, uniqueness="NORMAL",
                    pivot_value=_to_hex(blob),
                    reason=f"Low-entropy binary ({ent:.1f}/8.0) — likely fixed protocol "
                            "flags, magic bytes, or length fields",
                    search_hint=""))
            i = j

    return normal, unique, variable


# Protocol rter
def extract_signature(data: bytes, results: list, port: Optional[int] = None) -> SignatureReport:
    """
    Main entry: pick the right dissector, build a SignatureReport.
    Routing scans ALL matched results so that a false-positive (e.g. Telnet
    firing on 0xFF bytes in a MySQL banner) doesn't mask the real protocol.
    Priority order mirrors DETECTORS list: databases > remote > web > other.
    """
    # Flatten all service names from all matches for routing
    all_svcs = " ".join(r.service for r in results)

    # Pick the best protocol label for display — prefer the highest-specificity match
    # (not necessarily results[0] which is sorted by threat priority, not specificity)
    def _protocol_label():
        for r in results:
            # Skip known false-positive patterns: Telnet matched inside DB banners
            if r.service == "Telnet" and any(
                    kw in all_svcs for kw in ("MySQL","PostgreSQL","MongoDB","Redis")):
                continue
            return r.service
        return results[0].service if results else "Unknown"

    protocol = _protocol_label()

    # Route to the most specific dedicated dissector by scanning all results
    def _has(keyword):
        return keyword.lower() in all_svcs.lower()

    if _has("MySQL") or _has("MariaDB"):
        normal, unique, variable = _dissect_mysql(data)
        protocol = next((r.service for r in results if "MySQL" in r.service or "MariaDB" in r.service), protocol)
    elif _has("PostgreSQL"):
        normal, unique, variable = _dissect_generic(data, protocol)
    elif _has("Vnet/IP") or _has("Yokogawa"):
        normal, unique, variable = _dissect_vnetip(data)
        protocol = next((r.service for r in results if "Vnet" in r.service or "Yokogawa" in r.service), protocol)
    elif _has("DCE/RPC") or _has("Windows Remote Procedure"):
        normal, unique, variable = _dissect_dcerpc(data)
        protocol = next((r.service for r in results if "DCE/RPC" in r.service or "RPC" in r.service), protocol)
    elif _has("SSH"):
        normal, unique, variable = _dissect_ssh(data)
        protocol = next((r.service for r in results if "SSH" in r.service), protocol)
    elif _has("DNS"):
        normal, unique, variable = _dissect_dns(data)
        protocol = next((r.service for r in results if "DNS" in r.service), protocol)
    elif _has("MSMQ"):
        normal, unique, variable = _dissect_msmq(data)
        protocol = next((r.service for r in results if "MSMQ" in r.service), protocol)
    elif _has("X11"):
        normal, unique, variable = _dissect_x11(data)
        protocol = next((r.service for r in results if "X11" in r.service), protocol)
    elif _has("TLS") or _has("SSL"):
        normal, unique, variable = _dissect_tls(data)
        protocol = next((r.service for r in results if "TLS" in r.service or "SSL" in r.service), protocol)
    elif any("HTTP" in r.service for r in results):
        normal, unique, variable = _dissect_http(data)
        protocol = next((r.service for r in results if "HTTP" in r.service), protocol)
    else:
        normal, unique, variable = _dissect_generic(data, protocol)

    # Build pivot queries
    pivot_parts = [f for f in unique if f.pivot_value and len(f.pivot_value) >= 4]

    shodan_parts = []
    censys_parts = []

    for f in pivot_parts:
        val = f.pivot_value
        # Shodan
        if f.search_hint:
            shodan_parts.append(f.search_hint)
        else:
            shodan_parts.append(f'"{val}"')
        # Censys
        censys_parts.append(f'services.banner:"{val}"')

    if port:
        shodan_parts.insert(0, f"port:{port}")
        censys_parts.insert(0, f"services.port={port}")

    # Protocol-aware fallback: if no unique pivot values were found, use the
    # best NORMAL field as a cluster query (e.g. MSMQ "LIOR", MQTT CONNACK, etc.)
    if not shodan_parts or (len(shodan_parts) == 1 and shodan_parts[0].startswith("port:")):
        for f in normal:
            if f.search_hint and len(f.pivot_value) >= 3:
                # Strip any "port:NNNN" prefix from the hint to avoid duplication
                hint = re.sub(r"^port:\d+\s*", "", f.search_hint).strip()
                if hint:
                    shodan_parts.append(hint)
                    censys_parts.append(f'services.banner:"{f.pivot_value}"')
                break

    pivot_queries = {
        "shodan": " ".join(shodan_parts) if shodan_parts else "(no pivot values found — use port filter only)",
        "censys": " && ".join(censys_parts) if censys_parts else "(no pivot values found — use port filter only)",
    }

    # Unique score: 0-100
    unique_score = min(100, len(unique) * 20 + len([f for f in unique if len(f.pivot_value) > 8]) * 15)

    return SignatureReport(
        protocol=protocol,
        port_seen=port,
        normal_fields=normal,
        unique_fields=unique,
        variable_fields=variable,
        pivot_queries=pivot_queries,
        full_hex=" ".join(f"{b:02x}" for b in data),
        escaped_hex=_to_escaped(data),
        unique_score=unique_score,
    )


# OUTPUT FORMATTING

RESET  = "\033[0m";  BOLD   = "\033[1m"; DIM    = "\033[2m"
RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
CYAN   = "\033[96m"; ORANGE = "\033[33m"; BLUE   = "\033[94m"

CATEGORY_COLORS = {
    "C2_FRAMEWORK":    RED,    "THREAT_INDICATOR": ORANGE,
    "OT_ICS":          YELLOW, "REMOTE_ACCESS":    CYAN,
    "DATABASE":        BLUE,   "WEB":              GREEN,
    "MAIL":            GREEN,  "MESSAGING":        GREEN,
    "DIRECTORY":       BLUE,   "CRYPTO":           CYAN,
    "VOIP":            CYAN,   "OTHER":            RESET,
}
CATEGORY_LABELS = {
    "C2_FRAMEWORK":    "[!] C2 FRAMEWORK",    "THREAT_INDICATOR": "[!] THREAT INDICATOR",
    "OT_ICS":          "[OT] OT/ICS",          "REMOTE_ACCESS":    "[->] REMOTE ACCESS",
    "DATABASE":        "[DB] DATABASE",         "WEB":              "[W] WEB",
    "MAIL":            "[M] MAIL",              "MESSAGING":        "[MQ] MESSAGING",
    "DIRECTORY":       "[D] DIRECTORY",         "CRYPTO":           "[~] CRYPTO/TLS",
    "VOIP":            "[V] VOIP",              "OTHER":            "[-] OTHER",
}
CONF_COLORS = {"HIGH": GREEN, "MEDIUM": YELLOW, "LOW": RED}
PRIORITY = ["C2_FRAMEWORK","THREAT_INDICATOR","OT_ICS","REMOTE_ACCESS",
            "DATABASE","WEB","MAIL","MESSAGING","DIRECTORY","CRYPTO","VOIP","OTHER"]


def print_result(results, data, banner, port=None, double_escaped=False):
    w = 70
    print()
    print(f"{BOLD}{'='*w}{RESET}")
    print(f"{BOLD}  BANNER ANALYZER v1.0 — RESULTS{RESET}")
    print(f"{BOLD}{'-'*w}{RESET}")

    if double_escaped:
        print(f"{YELLOW}{BOLD}  ⚠ DOUBLE-ESCAPED INPUT DETECTED — auto-corrected{RESET}")
        print(f"{YELLOW}  Input contained literal \\x sequences (e.g. \\\\x10 instead of \\x10).")
        print(f"  A second decode pass was applied automatically.{RESET}")
        print(f"{BOLD}{'-'*w}{RESET}")

    print(f"{DIM}  Input   : {len(banner)} chars -> {len(data)} decoded bytes{RESET}")
    print(f"{DIM}  Entropy : {byte_entropy(data):.2f}/8.0  |  Printable: {printable_ratio(data):.0%}{RESET}")
    if double_escaped:
        print(f"{YELLOW}{DIM}  Note    : 100% printable + low entropy strongly suggests double-escaping{RESET}")
    print(f"{DIM}  Preview : {safe_ascii(data, 80)}{RESET}")
    print(f"{BOLD}{'-'*w}{RESET}\n")

    if not results:
        print(f"  {BOLD}No known protocol detected.{RESET}")
        ent = byte_entropy(data)
        note = "consider manual review for C2" if ent > 6.5 else "within normal range"
        print(f"  {DIM}Entropy {ent:.2f}/8.0 — {note}{RESET}\n")
        print(f"{BOLD}{'='*w}{RESET}\n")
        return

    sorted_results = sorted(results,
        key=lambda r: PRIORITY.index(r.category) if r.category in PRIORITY else 99)

    all_refs = sorted({ref for r in sorted_results for ref in r.references})

    for i, r in enumerate(sorted_results, 1):
        cc = CATEGORY_COLORS.get(r.category, RESET)
        lbl = CATEGORY_LABELS.get(r.category, r.category)
        print(f"  {BOLD}[{i}] {cc}{lbl}{RESET}")
        print(f"      {BOLD}Service   :{RESET} {BOLD}{CYAN}{r.service}{RESET}")
        print(f"      {BOLD}Confidence:{RESET} {CONF_COLORS.get(r.confidence,RESET)}{r.confidence}{RESET}")
        print(f"      {BOLD}Detail    :{RESET} {r.detail}")
        if r.version:   print(f"      {BOLD}Version   :{RESET} {r.version}")
        if r.port_hint: print(f"      {BOLD}Port      :{RESET} {r.port_hint}")
        if r.extra:     print(f"      {BOLD}Extra     :{RESET} {r.extra}")
        for flag in r.ioc_flags:
            print(f"      {RED}[IOC] {flag}{RESET}")
        if r.references:
            print(f"      {DIM}Refs: {', '.join(r.references)}{RESET}")
        print()

    if all_refs:
        print(f"{BOLD}{'-'*w}{RESET}")
        print(f"  {BOLD}MITRE ATT&CK / CVE:{RESET} {', '.join(all_refs)}")
    print(f"{BOLD}{'='*w}{RESET}\n")

    # Signature analysis
    sig = extract_signature(data, results, port)
    print_signature(sig, port)



def print_signature(sig, port=None):
    """Print the signature analysis section."""
    w = 70
    SCORE_COLOR = GREEN if sig.unique_score >= 60 else YELLOW if sig.unique_score >= 30 else RED

    print(f"\n{BOLD}{'─'*w}{RESET}")
    print(f"{BOLD}  SIGNATURE ANALYSIS — PIVOT INTELLIGENCE{RESET}")
    print(f"{BOLD}{'─'*w}{RESET}")
    print(f"  Protocol    : {CYAN}{sig.protocol}{RESET}")
    if sig.port_seen:
        print(f"  Port seen   : {sig.port_seen}")
    print(f"  Pivot score : {SCORE_COLOR}{sig.unique_score}/100{RESET}  "
          f"{DIM}(higher = more pivot-worthy){RESET}")

    # -- NORMAL fields 
    if sig.normal_fields:
        print(f"\n  {BOLD}{GREEN}[ NORMAL ] Standard protocol fields{RESET}")
        print(f"  {DIM}Shared by every server running this service/version.")
        print(f"  Use to CONFIRM the protocol but NOT to uniquely identify a host.{RESET}")
        for f in sig.normal_fields:
            print(f"\n    • {BOLD}{f.label}{RESET}")
            print(f"      Value  : {GREEN}{f.printable}{RESET}")
            if f.search_hint:
                print(f"      Query  : {DIM}{f.search_hint}{RESET}")
            print(f"      Why    : {DIM}{f.reason}{RESET}")

    # -- UNIQUE fields 
    if sig.unique_fields:
        print(f"\n  {BOLD}{YELLOW}[ UNIQUE ] Operator/instance-specific  ← PIVOT ON THESE{RESET}")
        print(f"  {DIM}Unlikely to appear on unrelated infrastructure.")
        print(f"  Searching for these values will cluster related nodes.{RESET}")
        for f in sig.unique_fields:
            print(f"\n    {YELLOW}★{RESET} {BOLD}{f.label}{RESET}")
            print(f"      Value     : {YELLOW}{f.printable}{RESET}")
            if f.pivot_value:
                print(f"      Pivot on  : {BOLD}{f.pivot_value}{RESET}")
            print(f"      Why       : {DIM}{f.reason}{RESET}")
            if f.search_hint:
                print(f"      Query hint: {CYAN}{f.search_hint}{RESET}")

    # -- VAR fields 
    if sig.variable_fields:
        print(f"\n  {BOLD}{RED}[ VARIABLE ] Per-connection values  — DO NOT pivot on these{RESET}")
        print(f"  {DIM}Change on every connection: random seeds, timestamps, session IDs.{RESET}")
        for f in sig.variable_fields:
            print(f"\n    {RED}✗{RESET} {BOLD}{f.label}{RESET}")
            print(f"      Value  : {DIM}{f.printable}{RESET}")
            print(f"      Why    : {DIM}{f.reason}{RESET}")

    # -- Pivot queries 
    print(f"\n  {BOLD}{'─'*w}{RESET}")
    print(f"  {BOLD}PIVOT QUERIES  — paste into threat intel platforms{RESET}")
    print(f"  {DIM}Find related infrastructure using these search strings:{RESET}\n")
    print(f"  {BOLD}Shodan :{RESET}")
    print(f"    {CYAN}{sig.pivot_queries['shodan']}{RESET}")
    print(f"\n  {BOLD}Censys :{RESET}")
    print(f"    {CYAN}{sig.pivot_queries['censys']}{RESET}")

    # -- Raw representations 
    print(f"\n  {BOLD}{'─'*w}{RESET}")
    print(f"  {BOLD}RAW BANNER  (for YARA / grep / network signatures){RESET}\n")
    print(f"  {BOLD}Escaped  :{RESET}")
    esc = sig.escaped_hex
    for i in range(0, len(esc), 68):
        print(f"    {DIM}{esc[i:i+68]}{RESET}")
    print(f"\n  {BOLD}Hex stream:{RESET}")
    hx = sig.full_hex
    for i in range(0, len(hx), 68):
        print(f"    {DIM}{hx[i:i+68]}{RESET}")
    print(f"\n{BOLD}{'─'*w}{RESET}\n")

BANNER_ART = f"""{BOLD}{CYAN}
                ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
               ▄████████████████████
             ▄███████▀▀▀▀▀▀▀▀████████▄
            █████▀              ▀████████
           ████▀   ▄▄        ▄▄   ▀███████
          ████    ████      ████    ███████
          ████    ▀▀▀   ██   ▀▀▀    ███████
          █████▄       ████       ▄███████
           ███████▄▄  ██████  ▄▄████████
            █████████████████████████
              ▀███████████████████▀
                   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀

        ██████╗  █████╗ ███╗   ██╗███████╗
        ██╔══██╗██╔══██╗████╗  ██║██╔════╝
        ██████╦╝███████║██╔██╗ ██║█████╗
        ██╔══██╗██╔══██║██║╚██╗██║██╔══╝
        ██████╦╝██║  ██║██║ ╚████║███████╗
        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝

  {DIM}Banner Analysis & Network Enumeration Engine  |  v1.0{RESET}{CYAN}
  {DIM}Protocol fingerprinting | C2 detection | OT/ICS | Pivot Options{RESET}
{RESET}"""



# ENTRY POIN
def main():
    parser = argparse.ArgumentParser(
        description="Banner Analyzer v1.0 — Protocol and C2 fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python bane_cti.py\n"
               "  python bane_cti.py -f banners.txt -j -o results.json\n"
               "  echo 'SSH-2.0-OpenSSH_8.9p1' | python bane_cti.py --pipe")
    parser.add_argument("-f","--file",  help="File of banners (one per line)")
    parser.add_argument("-j","--json",  action="store_true", help="JSON output")
    parser.add_argument("-o","--output", help="Write JSON output to this file (requires -j)")
    parser.add_argument("--pipe",       action="store_true", help="Read from stdin")
    parser.add_argument("--port", type=int, default=None, help="Port the banner was captured on (used in pivot queries)")
    args = parser.parse_args()

    def _write_json(data_obj, outfile=None):
        """Write JSON to a file if -o is given, otherwise print to stdout."""
        text = json.dumps(data_obj, indent=2)
        if outfile:
            try:
                with open(outfile, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                print(f"[+] JSON written to: {outfile}", file=sys.stderr)
            except OSError as e:
                print(f"Error writing to {outfile}: {e}", file=sys.stderr)
                print(text)
        else:
            print(text)

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                banners = [l.rstrip("\n") for l in f if l.strip()]
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        if args.json:
            output = []
            for i, banner in enumerate(banners):
                results, data, _ = analyze(banner)
                output.append({"index":i,"banner_preview":safe_ascii(data,60),
                                "entropy":round(byte_entropy(data),2),
                                "analysis":analyze_summary(results)})
            _write_json(output, args.output)
        else:
            print(BANNER_ART)
            for i, banner in enumerate(banners, 1):
                print(f"{BOLD}{'#'*70}\n  Banner #{i}{RESET}")
                results, data, double_escaped = analyze(banner)
                print_result(results, data, banner, double_escaped=double_escaped)
        return

    if args.pipe:
        banner = sys.stdin.read()
        results, data, double_escaped = analyze(banner)
        if args.json:
            _write_json(analyze_summary(results), args.output)
        else:
            print_result(results, data, banner, port=args.port, double_escaped=double_escaped)
        return


    # Interactive mode -- suppress banner art and send prompts to stderr when
    # JSON mode is active so stdout carries only clean JSON output.
    def _prompt(msg):
        """Print a user prompt. Goes to stderr in -j mode to keep stdout clean."""
        if args.json:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()
        else:
            print(msg)

    if not args.json:
        print(BANNER_ART)
    while True:
        _prompt(f"{BOLD}Paste banner data (Enter twice to analyze, 'quit' to exit):{RESET}")
        lines = []
        try:
            while True:
                line = input()
                if line.lower() in ("quit","exit","q"):
                    _prompt("\nBye!\n"); sys.exit(0)
                if line == "" and lines:
                    break
                lines.append(line)
        except (KeyboardInterrupt, EOFError):
            _prompt("\n\nInterrupted. Bye!\n"); sys.exit(0)
        banner = "\n".join(lines)
        if not banner.strip(): continue

        port = None
        try:
            default = f" [{args.port}]" if args.port else ""
            prompt_txt = f"{BOLD}Port number{default} (press Enter to skip): {RESET}"
            if args.json:
                sys.stderr.write(prompt_txt)
                sys.stderr.flush()
                port_str = input("").strip()
            else:
                port_str = input(prompt_txt).strip()
            if port_str.isdigit():
                port = int(port_str)
            elif not port_str and args.port:
                port = args.port
        except (KeyboardInterrupt, EOFError):
            pass

        results, decoded, double_escaped = analyze(banner)
        if args.json:
            _write_json(analyze_summary(results), args.output)
        else:
            print_result(results, decoded, banner, port=port, double_escaped=double_escaped)


if __name__ == "__main__":
    main()
