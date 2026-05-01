"""
Claude API integration for SOC triage analysis.
Runs an agentic tool-use loop: Claude calls IP/domain reputation tools,
then submits a structured triage report via the submit_triage_report tool.
"""
import json
import os
import socket

import anthropic
import requests

client = anthropic.Anthropic()

# ── Tool Definitions ──────────────────────────────────────────────────────────

REPUTATION_TOOLS = [
    {
        "name": "lookup_ip_reputation",
        "description": (
            "Check the reputation of an IP address against threat intelligence. "
            "Call this for any external IP that appears in unusual traffic patterns, "
            "unusual ports, or high-volume connections."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IPv4 or IPv6 address to check.",
                }
            },
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_domain_reputation",
        "description": (
            "Check the reputation of a domain name against threat intelligence. "
            "Call this for DNS queries, HTTP Host headers, or TLS SNI values that "
            "appear suspicious (high entropy, unusual TLDs, DGA-like patterns)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Fully-qualified domain name to check.",
                }
            },
            "required": ["domain"],
        },
    },
]

REPORT_TOOL = {
    "name": "submit_triage_report",
    "description": (
        "Submit the completed, structured triage report. "
        "Call this ONCE after all reputation lookups are done."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "traffic_summary": {
                "type": "string",
                "description": "2–4 sentence overview of what the traffic contains.",
            },
            "indicators": {
                "type": "array",
                "description": "Suspicious indicators. Only include items directly supported by extracted features.",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Short name for the indicator.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Exact values from extracted features supporting this indicator.",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["Low", "Medium", "High"],
                        },
                    },
                    "required": ["description", "evidence", "severity"],
                },
            },
            "overall_risk": {
                "type": "string",
                "enum": ["Low", "Medium", "High"],
                "description": "Overall risk rating.",
            },
            "confidence_level": {
                "type": "string",
                "enum": ["Low", "Medium", "High"],
                "description": "Confidence in the assessment. Use Low for heavily encrypted or sparse traffic.",
            },
            "next_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concrete recommended actions for the analyst.",
            },
            "insufficient_data": {
                "type": "boolean",
                "description": "True if features are too sparse for meaningful payload analysis.",
            },
            "insufficient_data_reason": {
                "type": "string",
                "description": "Explain why data is insufficient (e.g., 'all traffic is TLS-encrypted').",
            },
        },
        "required": [
            "traffic_summary",
            "indicators",
            "overall_risk",
            "confidence_level",
            "next_steps",
        ],
    },
}

ALL_TOOLS = REPUTATION_TOOLS + [REPORT_TOOL]

# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior SOC analyst reviewing extracted network metadata from a pcap file. \
Your output assists junior analysts in making triage decisions.

RULES — follow these strictly:
1. Only report indicators that are DIRECTLY supported by values in the extracted features. \
   Never invent IPs, domains, URIs, or user agents not present in the data.
2. If features are sparse (e.g., all TLS with no SNI, no DNS, no HTTP), \
   set insufficient_data=true and say "insufficient data for payload analysis". Do not guess.
3. Use lookup_ip_reputation for external IPs involved in unusual or high-volume connections, \
   and ALWAYS look up any IP that appears in known_malware_port_hits connections.
4. Use lookup_domain_reputation for DNS queries or SNI values that appear high-entropy, \
   DGA-like, unusual TLD, or otherwise suspicious.
5. Risk rating rules (apply the HIGHEST matching rule):
   a. AUTOMATIC HIGH — if known_malware_port_hits is present and non-empty, the traffic \
      contains confirmed malware-associated port activity. Name the specific malware family \
      (e.g., "STRRAT C2 traffic on port 12132") and rate overall_risk=High regardless of \
      other indicators.
   b. AUTOMATIC HIGH — if any connection uses a non-standard port (not 80/443/53/25/587/993/ \
      8080/8443) to a non-RFC1918 IP AND geolocation shows a foreign country, rate High.
   c. AUTOMATIC HIGH — if suspicious_downloads is non-empty (executable or script file \
      downloaded over HTTP), rate at least High.
   d. Medium = suspicious indicators without confirmation (unusual ports, high entropy, \
      suspicious domains — but no confirmed malware match).
   e. Low = routine traffic with no meaningful indicators.
6. Malware-port co-occurrence rule: if known_malware_port_hits is present, also examine \
   whether software-repository domains appear in dns_queries, tls_sni, or http_requests \
   (github.com, raw.githubusercontent.com, objects.githubusercontent.com, repo1.maven.org, \
   pypi.org, npmjs.com). If they do, flag this as a HIGH indicator: "Malware delivery via \
   software repository infrastructure" — attackers often stage payloads on GitHub/Maven.
7. Victim attribution: if ldap_users is present, include the victim's full name in the \
   traffic_summary (e.g., "The infected host belongs to [displayName], account [sAMAccountName]").
8. Suspicious downloads: if suspicious_downloads is present, create a High indicator for \
   each entry: "Executable/script file downloaded over cleartext HTTP — possible malware \
   delivery". Include the URI and file extension as evidence.
9. Always call submit_triage_report once at the end.

Each indicator's "evidence" field must contain specific values from the features \
(IP addresses, domain names, URIs, port numbers, malware family names, etc.)."""


# ── Tool Implementations ──────────────────────────────────────────────────────

def _lookup_ip_reputation(ip: str) -> dict:
    """AbuseIPDB if key configured, else ipapi.co geolocation fallback."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if api_key:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=6,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "ip": ip,
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "total_reports": d.get("totalReports"),
                    "is_tor": d.get("isTor"),
                    "source": "AbuseIPDB",
                }
        except Exception:
            pass

    # Fallback: free geolocation (no API key required)
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
        if resp.status_code == 200:
            d = resp.json()
            if "error" not in d:
                return {
                    "ip": ip,
                    "country": d.get("country_name"),
                    "org": d.get("org"),
                    "city": d.get("city"),
                    "abuse_score": "unknown — set ABUSEIPDB_API_KEY for reputation data",
                    "source": "ipapi.co (geolocation only)",
                }
    except Exception:
        pass

    return {"ip": ip, "error": "Reputation lookup unavailable", "source": "none"}


def _lookup_domain_reputation(domain: str) -> dict:
    """VirusTotal if key configured, else plain DNS resolution fallback."""
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if vt_key:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
                timeout=6,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "domain": domain,
                    "malicious_votes": stats.get("malicious", 0),
                    "suspicious_votes": stats.get("suspicious", 0),
                    "harmless_votes": stats.get("harmless", 0),
                    "categories": attrs.get("categories", {}),
                    "source": "VirusTotal",
                }
        except Exception:
            pass

    # Fallback: DNS resolution check
    try:
        _, _, addrs = socket.gethostbyname_ex(domain)
        return {
            "domain": domain,
            "resolves_to": addrs,
            "reputation_score": "unknown — set VIRUSTOTAL_API_KEY for reputation data",
            "source": "DNS resolution only",
        }
    except socket.gaierror:
        return {
            "domain": domain,
            "resolves": False,
            "note": "Domain does not resolve — possible DGA, sinkhole, or typosquat",
            "reputation_score": "unknown — set VIRUSTOTAL_API_KEY for reputation data",
            "source": "DNS resolution only",
        }
    except Exception:
        pass

    return {"domain": domain, "error": "Domain lookup unavailable", "source": "none"}


# ── Main Analysis Function ────────────────────────────────────────────────────

def analyze_pcap(features: dict) -> dict:
    """
    Run an agentic Claude loop to analyze pcap features.
    Claude may call reputation tools before submitting the final structured report.
    Returns the triage report dict (the input to submit_triage_report).
    """
    features_json = json.dumps(features, indent=2)
    messages = [
        {
            "role": "user",
            "content": (
                "Analyze the following extracted network features from a pcap file "
                "and produce a triage report.\n\n"
                f"EXTRACTED FEATURES:\n{features_json}\n\n"
                "Check reputation of any suspicious IPs or domains, "
                "then submit your report with submit_triage_report."
            ),
        }
    ]

    tool_calls_log: list[dict] = []

    # Agentic loop: continue until submit_triage_report is called
    for _ in range(10):  # safety limit
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            temperature=0.2,
            system=SYSTEM_PROMPT,
            tools=ALL_TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Shouldn't happen before report submission
            return {
                "traffic_summary": "Analysis ended without a structured report.",
                "indicators": [],
                "overall_risk": "Unknown",
                "confidence_level": "Low",
                "next_steps": ["Re-run analysis; model did not call submit_triage_report."],
            }

        if response.stop_reason != "tool_use":
            break

        tool_results = []
        report: dict | None = None

        for block in response.content:
            if not hasattr(block, "type") or block.type != "tool_use":
                continue

            if block.name == "submit_triage_report":
                report = dict(block.input)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": "Report accepted."}
                )

            elif block.name == "lookup_ip_reputation":
                result = _lookup_ip_reputation(block.input["ip"])
                tool_calls_log.append(
                    {"tool": "lookup_ip_reputation", "input": block.input, "output": result}
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result),
                    }
                )

            elif block.name == "lookup_domain_reputation":
                result = _lookup_domain_reputation(block.input["domain"])
                tool_calls_log.append(
                    {"tool": "lookup_domain_reputation", "input": block.input, "output": result}
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result),
                    }
                )

        if report is not None:
            report["tool_calls"] = tool_calls_log
            return report

        # Feed tool results back and continue
        messages.append({"role": "user", "content": tool_results})

    return {
        "traffic_summary": "Analysis loop reached iteration limit without completing.",
        "indicators": [],
        "overall_risk": "Unknown",
        "confidence_level": "Low",
        "next_steps": ["Re-run analysis."],
    }
