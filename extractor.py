"""
Feature extraction from pcap files using scapy.
Produces structured JSON features for LLM analysis.
The LLM never receives raw packet bytes — only derived metadata.
"""
import json
import math
import collections
from typing import Any


def _calc_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0–8 scale)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _extract_sni(payload: bytes) -> str | None:
    """
    Parse TLS SNI extension from a raw TCP payload containing a TLS ClientHello.
    Returns the SNI hostname string, or None if not found.
    """
    try:
        # TLS record header: content_type=22 (Handshake), version (2), length (2)
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        # Handshake header starts at byte 5: type=1 (ClientHello)
        if payload[5] != 0x01:
            return None

        # Skip: record header (5) + handshake header (4) + client_version (2) + random (32)
        offset = 5 + 4 + 2 + 32
        if len(payload) <= offset:
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if len(payload) <= offset + 2:
            return None

        # Cipher suites
        cs_len = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2 + cs_len
        if len(payload) <= offset:
            return None

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len
        if len(payload) <= offset + 2:
            return None

        # Extensions block
        ext_block_len = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        end = offset + ext_block_len

        while offset + 4 <= end and offset + 4 <= len(payload):
            ext_type = int.from_bytes(payload[offset : offset + 2], "big")
            ext_data_len = int.from_bytes(payload[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == 0:  # server_name extension
                # server_name_list_length (2), name_type (1), name_length (2), name
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


def _parse_http_request(payload: bytes, src: str, dst: str) -> dict | None:
    """
    Attempt to parse an HTTP/1.x request from raw TCP payload bytes.
    Returns a dict of key fields or None if not an HTTP request.
    """
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
        return {
            "request_line": request_line,
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "authorization": "present" if "authorization" in headers else "",
            "src": src,
            "dst": dst,
        }
    except Exception:
        return None


def extract_features(pcap_path: str) -> dict[str, Any]:
    """
    Parse a pcap file and return structured features suitable for LLM analysis.
    """
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw  # noqa

    packets = rdpcap(pcap_path)

    proto_counts: collections.Counter = collections.Counter()
    # (src_ip, src_port, dst_ip, dst_port, proto) -> packet count
    conn_counts: dict = collections.defaultdict(int)
    ip_counts: collections.Counter = collections.Counter()
    sizes: list[int] = []
    all_payload_bytes = bytearray()

    dns_queries: set[str] = set()
    http_requests: list[dict] = []
    sni_set: set[str] = set()
    tcp_flag_counts: collections.Counter = collections.Counter()
    icmp_type_counts: collections.Counter = collections.Counter()

    for pkt in packets:
        pkt_len = len(pkt)
        sizes.append(pkt_len)

        if pkt.haslayer("IP"):
            src_ip: str = pkt["IP"].src
            dst_ip: str = pkt["IP"].dst
            ip_proto: int = pkt["IP"].proto
            ip_counts[src_ip] += 1
            ip_counts[dst_ip] += 1

            if pkt.haslayer("TCP"):
                proto_counts["TCP"] += 1
                sport: int = pkt["TCP"].sport
                dport: int = pkt["TCP"].dport
                tcp_flag_counts[str(pkt["TCP"].flags)] += 1
                conn_counts[(src_ip, sport, dst_ip, dport, "TCP")] += 1

                if pkt.haslayer("Raw"):
                    raw: bytes = bytes(pkt["Raw"].load)
                    all_payload_bytes.extend(raw)
                    req = _parse_http_request(raw, f"{src_ip}:{sport}", f"{dst_ip}:{dport}")
                    if req:
                        http_requests.append(req)
                    sni = _extract_sni(raw)
                    if sni:
                        sni_set.add(sni)

            elif pkt.haslayer("UDP"):
                proto_counts["UDP"] += 1
                sport = pkt["UDP"].sport
                dport = pkt["UDP"].dport
                conn_counts[(src_ip, sport, dst_ip, dport, "UDP")] += 1
                if pkt.haslayer("Raw"):
                    all_payload_bytes.extend(bytes(pkt["Raw"].load))

            elif pkt.haslayer("ICMP"):
                proto_counts["ICMP"] += 1
                icmp_type_counts[pkt["ICMP"].type] += 1

            else:
                proto_counts[f"IP_proto_{ip_proto}"] += 1

            # DNS (can sit on top of UDP or TCP)
            if pkt.haslayer("DNS"):
                dns = pkt["DNS"]
                if dns.qr == 0 and dns.qdcount > 0:  # query
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        if qname:
                            dns_queries.add(qname)
                    except Exception:
                        pass

        elif pkt.haslayer("IPv6"):
            proto_counts["IPv6"] += 1
        else:
            proto_counts["Other"] += 1

    # ---- Aggregate ----

    # Top connections by packet count (cap at 20)
    top_connections = [
        {
            "src": f"{k[0]}:{k[1]}",
            "dst": f"{k[2]}:{k[3]}",
            "proto": k[4],
            "packets": v,
        }
        for k, v in sorted(conn_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    # Packet size statistics
    pkt_stats: dict = {}
    if sizes:
        pkt_stats = {
            "min": min(sizes),
            "max": max(sizes),
            "mean": round(sum(sizes) / len(sizes), 2),
            "total_bytes": sum(sizes),
            "packet_count": len(sizes),
        }

    # Payload entropy
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

    # ICMP type names
    icmp_type_names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded",
        5: "Redirect",
    }
    icmp_summary = {
        icmp_type_names.get(t, f"type_{t}"): count
        for t, count in icmp_type_counts.items()
    }

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
    }
