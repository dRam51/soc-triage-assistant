"""
Feature extraction from pcap files using scapy.
Produces structured JSON features for LLM analysis.
The LLM never receives raw packet bytes -- only derived metadata.

Extracted fields:
  - Protocol distribution, connection summaries, top talkers
  - DNS queries, HTTP requests (with suspicious download flagging), TLS SNI
  - Payload entropy, packet size stats, TCP flags, ICMP
  - Host details: MAC address (Ethernet), hostname (NBNS), Windows user (Kerberos)
  - Full name (LDAP givenName / sn)
  - Known malware C2 port hits
"""
import math
import collections
from typing import Any


# ---------------------------------------------------------------------------
# Known malware C2 ports
# ---------------------------------------------------------------------------

KNOWN_MALWARE_PORTS: dict[int, tuple[str, str]] = {
    12132: ("STRRAT",                   "Default C2 port for STRRAT Java RAT"),
    1177:  ("njRAT/Bladabindi",         "Common njRAT C2 port"),
    5552:  ("AsyncRAT",                 "Default AsyncRAT C2 port"),
    6606:  ("AsyncRAT",                 "AsyncRAT alternative C2 port"),
    7707:  ("AsyncRAT",                 "AsyncRAT alternative C2 port"),
    8808:  ("AsyncRAT",                 "AsyncRAT alternative C2 port"),
    4444:  ("Metasploit/Meterpreter",   "Default Metasploit reverse shell port"),
    1604:  ("DarkComet RAT",            "Default DarkComet RAT C2 port"),
    9999:  ("QuasarRAT/Various",        "Common RAT C2 port"),
    3460:  ("XWorm",                    "XWorm default C2 port"),
    4782:  ("QuasarRAT",                "QuasarRAT default C2 port"),
    1500:  ("XenoRAT",                  "XenoRAT default C2 port"),
    6655:  ("NjRAT",                    "NjRAT alternative port"),
    8848:  ("Gh0stRAT",                 "Gh0stRAT C2 port"),
}

# ---------------------------------------------------------------------------
# Suspicious file extensions for download detection
# ---------------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS: frozenset[str] = frozenset({
    ".jar", ".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd",
    ".hta", ".jse", ".wsf", ".scr", ".pif", ".msi", ".cab",
    ".iso", ".img", ".lnk", ".reg",
})


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def _calc_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0-8 scale)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# TLS SNI
# ---------------------------------------------------------------------------

def _extract_sni(payload: bytes) -> str | None:
    """Parse TLS SNI from a raw TCP payload containing a TLS ClientHello."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        if payload[5] != 0x01:
            return None
        offset = 5 + 4 + 2 + 32
        if len(payload) <= offset:
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if len(payload) <= offset + 2:
            return None
        cs_len = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2 + cs_len
        if len(payload) <= offset:
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        if len(payload) <= offset + 2:
            return None
        ext_block_len = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        end = offset + ext_block_len
        while offset + 4 <= end and offset + 4 <= len(payload):
            ext_type = int.from_bytes(payload[offset : offset + 2], "big")
            ext_data_len = int.from_bytes(payload[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == 0:
                if offset + 5 <= len(payload):
                    name_len = int.from_bytes(payload[offset + 3 : offset + 5], "big")
                    if offset + 5 + name_len <= len(payload):
                        return payload[offset + 5 : offset + 5 + name_len].decode(
                            "utf-8", errors="ignore"
                        )
            offset += ext_data_len
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _get_suspicious_extension(path: str) -> str:
    """Return the file extension if the HTTP path ends in a suspicious one, else ''."""
    clean = path.lower().split("?")[0].split("#")[0]
    for ext in SUSPICIOUS_EXTENSIONS:
        if clean.endswith(ext):
            return ext
    return ""


def _parse_http_request(payload: bytes, src: str, dst: str) -> dict | None:
    """Parse an HTTP/1.x request from raw TCP payload bytes."""
    http_methods = (
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    )
    if not any(payload.startswith(m) for m in http_methods):
        return None
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        request_line = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v

        # Extract path for extension check
        parts = request_line.split(" ")
        path = parts[1] if len(parts) >= 2 else ""
        suspicious_ext = _get_suspicious_extension(path)

        return {
            "request_line": request_line,
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "authorization": "present" if "authorization" in headers else "",
            "suspicious_download": suspicious_ext if suspicious_ext else None,
            "src": src,
            "dst": dst,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# NBNS -- Windows hostname
# ---------------------------------------------------------------------------

def _decode_nbns_name(encoded: bytes) -> str | None:
    """Decode a 32-byte NetBIOS-encoded name into a plain hostname string."""
    try:
        if len(encoded) < 30:
            return None
        name = ""
        for i in range(0, 30, 2):
            b = ((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41)
            if b == 0x20:
                break
            if 0x20 <= b <= 0x7E:
                name += chr(b)
        return name.strip() or None
    except Exception:
        return None


def _extract_nbns_hostname(payload: bytes) -> str | None:
    """Extract hostname from NBNS (UDP port 137) packet payload."""
    try:
        if len(payload) < 47 or payload[12] != 0x20:
            return None
        return _decode_nbns_name(payload[13:45])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Kerberos -- Windows user account
# ---------------------------------------------------------------------------

def _extract_kerberos_cname(payload: bytes, is_tcp: bool = False) -> str | None:
    """Extract CNameString from a Kerberos AS-REQ packet (TCP/UDP port 88)."""
    EXCLUDED = frozenset({"krbtgt", "kerberos", "kadmin", "changepw"})
    try:
        data = payload[4:] if is_tcp else payload
        if not data or data[0] != 0x6A:
            return None
        i = 0
        while i < len(data) - 2:
            if data[i] == 0x1B:
                length = data[i + 1]
                if 1 <= length <= 64 and i + 2 + length <= len(data):
                    try:
                        candidate = data[i + 2 : i + 2 + length].decode("ascii")
                        if candidate and all(c.isalnum() or c in "._-$@" for c in candidate):
                            if candidate.lower() not in EXCLUDED:
                                return candidate
                    except (UnicodeDecodeError, ValueError):
                        pass
            i += 1
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# LDAP -- full name (givenName / sn / displayName)
# ---------------------------------------------------------------------------

def _extract_ldap_attributes(payload: bytes) -> dict[str, str]:
    """
    Extract user attribute values from LDAP SearchResultEntry packets (TCP port 389).

    LDAP SearchResultEntry has application tag 0x64.
    Each attribute is encoded as:
      OctetString (0x04) + length + <attr_name>
      SET (0x31) + length + OctetString (0x04) + length + <value>

    Strategy: find known attribute name byte strings, verify the OctetString
    encoding prefix, then extract the value from the SET that follows.
    """
    # Only process packets that look like LDAP SearchResultEntry (tag 0x64)
    if 0x64 not in payload[:32]:
        return {}

    ATTRS: dict[bytes, str] = {
        b"givenName":      "given_name",
        b"sn":             "surname",
        b"displayName":    "display_name",
        b"sAMAccountName": "sam_account_name",
        b"cn":             "common_name",
    }
    results: dict[str, str] = {}

    for attr_bytes, field_name in ATTRS.items():
        if field_name in results:
            continue
        idx = 0
        while True:
            idx = payload.find(attr_bytes, idx)
            if idx == -1:
                break
            # Verify OctetString encoding: 0x04 <len> precedes the attribute name
            if (idx >= 2
                    and payload[idx - 1] == len(attr_bytes)
                    and payload[idx - 2] == 0x04):
                after = idx + len(attr_bytes)
                # Scan forward up to 10 bytes for SET tag (0x31)
                for j in range(after, min(after + 10, len(payload) - 3)):
                    if payload[j] == 0x31:          # SET OF values
                        k = j + 2                   # skip SET tag + length byte
                        if k < len(payload) - 1 and payload[k] == 0x04:
                            val_len = payload[k + 1]
                            end = k + 2 + val_len
                            if 0 < val_len <= 128 and end <= len(payload):
                                try:
                                    s = payload[k + 2 : end].decode("utf-8", errors="ignore").strip()
                                    if s and all(0x20 <= ord(c) or ord(c) > 0x7F for c in s):
                                        results[field_name] = s
                                except Exception:
                                    pass
                        break
            idx += 1

    return results


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------

def extract_features(pcap_path: str) -> dict[str, Any]:
    """
    Parse a pcap file and return structured features suitable for LLM analysis.
    """
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw  # noqa

    packets = rdpcap(pcap_path)

    proto_counts: collections.Counter = collections.Counter()
    conn_counts: dict = collections.defaultdict(int)
    ip_counts: collections.Counter = collections.Counter()
    sizes: list[int] = []
    all_payload_bytes = bytearray()

    dns_queries: set[str] = set()
    http_requests: list[dict] = []
    sni_set: set[str] = set()
    tcp_flag_counts: collections.Counter = collections.Counter()
    icmp_type_counts: collections.Counter = collections.Counter()

    # Host identity
    ip_to_mac: dict[str, str] = {}
    ip_to_hostnames: dict[str, set] = collections.defaultdict(set)
    kerberos_users: set[str] = set()

    # LDAP user attributes
    ldap_users: list[dict] = []
    ldap_seen: set[str] = set()          # deduplicate by sAMAccountName / common_name

    # Known malware port tracking: port -> list of connection strings
    malware_port_hits: dict[int, list[str]] = collections.defaultdict(list)

    for pkt in packets:
        pkt_len = len(pkt)
        sizes.append(pkt_len)

        if not pkt.haslayer("IP"):
            if pkt.haslayer("IPv6"):
                proto_counts["IPv6"] += 1
            else:
                proto_counts["Other"] += 1
            continue

        src_ip: str = pkt["IP"].src
        dst_ip: str = pkt["IP"].dst
        ip_proto: int = pkt["IP"].proto
        ip_counts[src_ip] += 1
        ip_counts[dst_ip] += 1

        if pkt.haslayer("Ether") and src_ip not in ip_to_mac:
            ip_to_mac[src_ip] = pkt["Ether"].src

        # ---- TCP ----
        if pkt.haslayer("TCP"):
            proto_counts["TCP"] += 1
            sport: int = pkt["TCP"].sport
            dport: int = pkt["TCP"].dport
            tcp_flag_counts[str(pkt["TCP"].flags)] += 1
            conn_counts[(src_ip, sport, dst_ip, dport, "TCP")] += 1

            # Known malware port check (destination port only to avoid noise)
            if dport in KNOWN_MALWARE_PORTS:
                conn_str = f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                if conn_str not in malware_port_hits[dport]:
                    malware_port_hits[dport].append(conn_str)

            if pkt.haslayer("Raw"):
                raw: bytes = bytes(pkt["Raw"].load)
                all_payload_bytes.extend(raw)

                req = _parse_http_request(raw, f"{src_ip}:{sport}", f"{dst_ip}:{dport}")
                if req:
                    http_requests.append(req)

                sni = _extract_sni(raw)
                if sni:
                    sni_set.add(sni)

                # Kerberos over TCP (port 88)
                if sport == 88 or dport == 88:
                    cname = _extract_kerberos_cname(raw, is_tcp=True)
                    if cname:
                        kerberos_users.add(cname)

                # LDAP (port 389)
                if sport == 389 or dport == 389:
                    attrs = _extract_ldap_attributes(raw)
                    if attrs:
                        dedup_key = attrs.get("sam_account_name") or attrs.get("common_name", "")
                        if dedup_key and dedup_key not in ldap_seen:
                            ldap_seen.add(dedup_key)
                            ldap_users.append(attrs)

        # ---- UDP ----
        elif pkt.haslayer("UDP"):
            proto_counts["UDP"] += 1
            sport = pkt["UDP"].sport
            dport = pkt["UDP"].dport
            conn_counts[(src_ip, sport, dst_ip, dport, "UDP")] += 1

            if pkt.haslayer("Raw"):
                raw = bytes(pkt["Raw"].load)
                all_payload_bytes.extend(raw)

                if sport == 137:
                    hostname = _extract_nbns_hostname(raw)
                    if hostname:
                        ip_to_hostnames[src_ip].add(hostname)

                if sport == 88 or dport == 88:
                    cname = _extract_kerberos_cname(raw, is_tcp=False)
                    if cname:
                        kerberos_users.add(cname)

        # ---- ICMP ----
        elif pkt.haslayer("ICMP"):
            proto_counts["ICMP"] += 1
            icmp_type_counts[pkt["ICMP"].type] += 1

        else:
            proto_counts[f"IP_proto_{ip_proto}"] += 1

        # DNS
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            if dns.qr == 0 and dns.qdcount > 0:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    if qname:
                        dns_queries.add(qname)
                except Exception:
                    pass

    # ---- Aggregate ----

    top_connections = [
        {
            "src": f"{k[0]}:{k[1]}",
            "dst": f"{k[2]}:{k[3]}",
            "proto": k[4],
            "packets": v,
        }
        for k, v in sorted(conn_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    pkt_stats: dict = {}
    if sizes:
        pkt_stats = {
            "min": min(sizes),
            "max": max(sizes),
            "mean": round(sum(sizes) / len(sizes), 2),
            "total_bytes": sum(sizes),
            "packet_count": len(sizes),
        }

    entropy_info: dict = {}
    if all_payload_bytes:
        entropy_val = _calc_entropy(bytes(all_payload_bytes))
        entropy_info = {
            "entropy": round(entropy_val, 4),
            "note": (
                "High entropy (>7.0) often indicates encryption or compression. "
                "Low entropy (<3.0) may indicate plaintext or structured data."
            ),
        }

    icmp_type_names = {
        0: "Echo Reply", 3: "Destination Unreachable",
        8: "Echo Request", 11: "Time Exceeded", 5: "Redirect",
    }
    icmp_summary = {
        icmp_type_names.get(t, f"type_{t}"): count
        for t, count in icmp_type_counts.items()
    }

    # Host details
    all_ips = set(ip_to_mac) | set(ip_to_hostnames)
    host_details = []
    for ip in sorted(all_ips):
        entry: dict[str, Any] = {"ip": ip}
        if ip in ip_to_mac:
            entry["mac_address"] = ip_to_mac[ip]
        hostnames = sorted(ip_to_hostnames.get(ip, set()))
        if hostnames:
            entry["hostnames"] = hostnames
        host_details.append(entry)

    # Known malware port hits
    known_malware_port_hits = []
    for port, conns in malware_port_hits.items():
        family, description = KNOWN_MALWARE_PORTS[port]
        known_malware_port_hits.append({
            "port": port,
            "malware_family": family,
            "description": description,
            "connections": conns[:10],
        })

    # Suspicious downloads from HTTP requests
    suspicious_downloads = [
        {
            "request_line": r["request_line"],
            "host": r["host"],
            "extension": r["suspicious_download"],
            "src": r["src"],
        }
        for r in http_requests
        if r.get("suspicious_download")
    ]

    return {
        "total_packets": len(packets),
        "protocol_distribution": dict(proto_counts),
        "connections": top_connections,
        "dns_queries": sorted(dns_queries),
        "http_requests": http_requests[:50],
        "tls_sni": sorted(sni_set),
        "top_talkers": dict(ip_counts.most_common(10)),
        "packet_size_stats": pkt_stats,
        "payload_entropy": entropy_info,
        "tcp_flags_summary": dict(tcp_flag_counts.most_common(10)),
        "icmp_summary": icmp_summary,
        "host_details": host_details,
        "windows_users": sorted(kerberos_users),
        "ldap_users": ldap_users,
        "known_malware_port_hits": known_malware_port_hits,
        "suspicious_downloads": suspicious_downloads,
    }
