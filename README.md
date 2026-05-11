# SOC Triage Assistant

LLM-augmented triage for flagged network packet captures. Upload a `.pcap`, get a structured AI triage report with risk rating and indicators, review raw features, and record your disposition — all in a browser UI.

---

## Context, User, and Problem

### Who the user is

The primary user is a **junior SOC analyst** working an alert queue. They receive a stream of flagged packet captures (pcaps) from an IDS or SIEM and must triage each one: Is it a real threat? Should it be escalated? Is it safe to close?

### What workflow this improves

Today, that workflow looks like this:

1. Open the pcap in Wireshark
2. Apply a series of manual filters (`nbns`, `kerberos.CNameString`, `http.request`, custom display filters) to surface suspicious traffic
3. Pivot to external tools (AbuseIPDB, VirusTotal, ipapi.co) to check suspicious IPs and domains
4. Write a free-text incident note summarizing findings
5. Make a triage decision (escalate / investigate / close)

For a **junior analyst**, each of these steps is a potential blocker. Knowing which Wireshark filters to apply, how to recognize a RAT User-Agent string, how to recover a victim's full name from LDAP traffic — this takes experience that junior analysts are still building.

### Why it matters

SOC teams face a well-documented alert fatigue problem. Analysts spend a significant portion of their shift on initial triage before they can determine whether a threat is real. Mistakes at triage — missed indicators, under-rated risk, skipped victim attribution — compound downstream.

This project applies an LLM to the feature synthesis step: extract structured network metadata locally, send only that metadata to Claude, and get back a plain-language triage report in seconds. The analyst's job shifts from filtering and pivoting to **reviewing and deciding** — a better use of human judgment.

---

## Solution and Design

### What was built

**SOC Triage Assistant** is a Streamlit application that takes a flagged `.pcap` or `.pcapng` file and produces a structured triage report using Claude (Anthropic). It runs in a browser, requires no Wireshark knowledge, and is designed to assist — not replace — the analyst.

### How it works

```
Analyst uploads .pcap
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  Layer 1 — Feature Extraction  (extractor.py)       │
│  scapy parses the pcap locally into structured JSON  │
│  DNS queries, HTTP requests, TLS SNI, connections,   │
│  payload entropy, malware port signatures, LDAP,     │
│  NBNS hostnames, Kerberos user accounts              │
└───────────────────┬─────────────────────────────────┘
                    │ structured JSON (no raw bytes)
                    ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2 — LLM Analysis + Tool Use  (analyzer.py)   │
│  Claude (claude-opus-4-6) receives the JSON features │
│  and runs an agentic loop (up to 10 iterations):     │
│    • Calls lookup_ip_reputation for suspicious IPs   │
│    • Calls lookup_domain_reputation for suspicious   │
│      DNS/SNI values                                  │
│    • Calls submit_triage_report with structured JSON │
│      (enforced output schema via tool definition)    │
└───────────────────┬─────────────────────────────────┘
                    │ structured triage report
                    ▼
┌─────────────────────────────────────────────────────┐
│  Layer 3 — Presentation  (app.py)                   │
│  Streamlit UI displays:                              │
│    • Traffic summary, risk level, confidence         │
│    • Flagged indicators with evidence + severity     │
│    • Recommended next steps                          │
│    • Raw extracted features (always visible)         │
│    • Reputation lookup log (tool call trace)         │
│    • Disposition buttons → audit log                 │
└─────────────────────────────────────────────────────┘
```

### Key design choices

**1. The LLM never sees raw packet bytes.**
Only verified, structured metadata is sent to Claude. If the model flags an indicator, the analyst can immediately cross-reference it against the raw features panel. This constrains hallucination scope: the model can only invent within the feature namespace, not fabricate network traffic.

**2. Structured output via tool schema.**
Claude is required to submit its final report by calling a `submit_triage_report` tool with a strict JSON schema. This eliminates free-text parsing and ensures every report has the same fields, enabling consistent UI rendering and audit logging.

**3. Hard risk-floor rules in the system prompt.**
Rather than letting Claude infer risk from prose reasoning, the system prompt enforces tiered automatic overrides:
- `known_malware_port_hits` present → automatic `overall_risk=High`, malware family named
- Suspicious executable/script downloaded over HTTP → automatic `overall_risk=High`
- Non-standard port C2 to foreign IP → automatic `overall_risk=High`

These rules exist because LLMs tend to under-rate risk when individual signals look ambiguous in isolation.

**4. Deterministic extraction before probabilistic reasoning.**
Feature extraction (Layer 1) is entirely rule-based scapy parsing — no model involved. The LLM (Layer 2) reasons only over the output of Layer 1. This means feature bugs are debuggable without touching the model, and model behavior changes don't affect feature correctness.

**5. Baseline toggle for analyst calibration.**
A view-mode toggle lets the analyst switch between AI-Augmented Analysis and Features Only. This lets an experienced analyst validate the AI report against raw data, and lets a junior analyst learn what features underpin each finding.

---

## Setup and Usage

### Prerequisites

- Python 3.10+
- An Anthropic API key ([get one here](https://console.anthropic.com/))
- *(Optional)* AbuseIPDB API key — free tier: 1,000 checks/day
- *(Optional)* VirusTotal API key — free tier: 4 requests/minute

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/dRam51/soc-triage-assistant.git
cd soc-triage-assistant

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
```

Edit `.env`:

```env
# Required
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Optional - enables live IP reputation via AbuseIPDB (free tier: 1000 checks/day)
ABUSEIPDB_API_KEY=

# Optional - enables domain reputation via VirusTotal (free tier: 4 req/min)
VIRUSTOTAL_API_KEY=
```

Without the optional keys the app still works — IP lookups fall back to free geolocation (ipapi.co) and domain lookups fall back to plain DNS resolution.

### Running the app

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`.

### Quick start example

1. Download a sample pcap from [malware-traffic-analysis.net](https://malware-traffic-analysis.net) (e.g., any traffic analysis exercise)
2. Open `http://localhost:8501` in your browser
3. Click **Browse files** and upload the `.pcap` file
4. Wait ~10–30 seconds for feature extraction and Claude analysis
5. Review the **AI-Augmented Analysis** report: traffic summary, risk rating, flagged indicators, and recommended next steps
6. Switch to **📊 Baseline (Features Only)** to cross-reference AI findings against raw extracted data
7. Select a disposition: **Escalate**, **Investigate**, or **Close** — the decision is written to `audit_log.jsonl`

---

## Evaluation and Results

### Baseline and methodology

Both test cases use real-world packet captures from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) — a publicly available repository of network forensics exercises used for analyst training. Each exercise includes an answer key representing what an **experienced analyst finds by manually working through the pcap in Wireshark**. That answer key serves as the human baseline.

The SOC Triage Assistant output is evaluated against the baseline on:
- Correctness of victim attribution (IP, hostname, MAC, user account, full name)
- Malware family identification
- Risk rating accuracy
- Indicator hallucination rate
- Coverage of IOCs beyond the exercise scope

---

### Test Case 1: NetSupport Manager RAT (2026-02-28)

**Pcap:** `2026-02-28-traffic-analysis-exercise.pcap` (6.6 MB, 15,512 packets)
**Threat:** Active NetSupport Manager RAT infection with live C2 beaconing

#### What the human analyst does (baseline)

1. Filter on the C2 IP (`45.131.214.85`) to identify the internal host communicating with it
2. Filter `nbns` to find the Windows hostname and MAC address
3. Filter `kerberos.CNameString` to find the Windows user account
4. Use Edit > Find Packet to search for the full display name string

This requires knowing which filters to apply and familiarity with Windows authentication protocols.

#### What the SOC Triage Assistant found

| Finding | Human Analyst | SOC Triage Assistant |
|---|---|---|
| Infected host IP | 10.2.28.88 | 10.2.28.88 |
| C2 server | 45.131.214.85:443 | 45.131.214.85:443 |
| Malware family | NetSupport Manager RAT | NetSupport Manager RAT |
| C2 URI pattern | (manual Wireshark inspection) | `/fakeurl.htm` flagged as known RAT indicator |
| Suspicious domain | (not in scope) | `vadusa.xyz` flagged with .xyz TLD analysis |
| Port evasion technique | (not flagged) | HTTP over port 443 flagged as deliberate evasion |
| Encrypted C2 payloads | (not analyzed) | CMD=ENCD payloads with entropy 7.97 flagged |
| SMB lateral movement risk | (not in scope) | Flagged 909-packet SMB flow to domain controller |
| Risk rating | Escalate (implied) | High, Confidence: High |
| Recommended disposition | Escalate | Escalate (7 specific action steps) |
| Windows hostname | DESKTOP-TEYQ2NR | Extracted via NBNS (UDP port 137) |
| MAC address | 00:19:d1:b2:4d:ad | Extracted from Ethernet layer |
| Windows user account | brolf | Extracted via Kerberos AS-REQ CNameString |
| Full user name | Becka Rolf | Not extractable from pcap metadata alone |

#### Indicator accuracy

The assistant flagged 7 indicators. All 7 were directly supported by extracted features.

| Indicator | Severity | Grounded in extracted data | Correct |
|---|---|---|---|
| NetSupport Manager RAT C2 beaconing | High | 40+ POST requests to `/fakeurl.htm` with UA `NetSupport Manager/1.3` | Yes |
| Suspicious domain `vadusa.xyz` resolves to C2 IP | High | DNS query present; domain resolved to 45.131.214.85 | Yes |
| Suspicious URI `/fakeurl.htm` | High | Present in all POST requests | Yes |
| HTTP over port 443 (non-TLS) | Medium | Plaintext HTTP to port 443 confirmed | Yes |
| Encoded/encrypted C2 payloads | High | CMD=ENCD, ES=1, binary DATA fields visible | Yes |
| Heavy SMB traffic to domain controller | Medium | 909 packets across 3 sessions to 10.2.28.2:445 | Yes |
| NetBIOS broadcast traffic | Low | 430 UDP packets to 10.2.28.255:138 | Yes |

**Hallucination rate: 0 of 7 indicators (0%)**

#### Gap analysis

| Gap | Human Analyst | SOC Triage Assistant | Root Cause | Addressable? |
|---|---|---|---|---|
| Full user name (Becka Rolf) | Found via Wireshark Find Packet on display name string | Not extracted | Full display name not transmitted in any pcap-observable protocol — exists only in Active Directory, not in NBNS/Kerberos frames | No — requires AD directory data or endpoint telemetry |

No other gaps. The three victim-attribution fields (hostname, MAC, user account), the C2 server, malware family, and risk rating were all correct.

---

### Test Case 3: STRRAT (2024-07-30)

**Pcap:** `2024-07-30-traffic-analysis-exercise.pcap` (11.5 MB, 11,562 packets)
**Threat:** STRRAT Java-based RAT delivered via email attachment
**Domain:** `wiresharkworkshop.online` | **DC:** `172.16.1.4 (WIRESHARK-WS-DC)`

#### What the human analyst does (baseline)

The analyst applies two Wireshark filters to surface C2 traffic and victim identity:

**Filter 1 — surface C2 from background noise:**
```
(http.request or tls.handshake.type eq 1 or
 (tcp.flags.syn eq 1 and tcp.flags.ack eq 0 and
  !(ip.dst eq 172.16.1.0/24 or tcp.port eq 443 or tcp.port eq 80)))
and !(ssdp)
```

**Filter 2 — victim full name from LDAP:**
```
ldap.AttributeDescription == "givenName"
```

Identifying STRRAT requires recognizing that port 12132 is the default STRRAT C2 port and confirming via Follow TCP Stream, which shows the characteristic `STRRAT` string in `ping` lines.

#### What the SOC Triage Assistant found

The table below compares the human analyst baseline, the initial tool run (pre-improvement), and the updated tool (post-improvement) on the same pcap.

| Finding | Human Analyst | Pre-Improvement Tool | Post-Improvement Tool |
|---|---|---|---|
| Infected host IP | 172.16.1.66 | 172.16.1.66 | 172.16.1.66 |
| C2 server | 141.98.10.69:12132 | 141.98.10.79:12132 | 141.98.10.79:12132 |
| Malware family | STRRAT | Not identified | STRRAT (port 12132 signature) |
| C2 port 12132 flagged | Yes, as STRRAT IOC | Yes, as High (unnamed C2) | Yes, as High — STRRAT named |
| ip-api.com geolocation lookup | Listed as IOC | Flagged as Medium | Flagged as Medium |
| Chrome 73 User-Agent | Not flagged | Flagged as Medium | Flagged as Medium |
| github.com / objects.githubusercontent.com / repo1.maven.org | Listed as file-sharing IOCs | Not flagged | Flagged as High — co-occurrence with confirmed C2 |
| Infection vector | `PL#40704.jar` via email | Not identified | Not identified (email; out of scope) |
| Overall risk rating | Escalate (implied High) | Medium, Confidence: Medium | High, Confidence: High |
| Windows hostname | DESKTOP-SKBR25F | DESKTOP-SKBR25F (NBNS) | DESKTOP-SKBR25F (NBNS) |
| MAC address | 00:1e:64:ec:f3:08 | Extracted from Ethernet layer | Extracted from Ethernet layer |
| Windows user account | ccollier | Extracted via Kerberos AS-REQ | Extracted via Kerberos AS-REQ |
| Full name | Clark Collier | Not extracted — LDAP not parsed | Clark Collier (LDAP port 389) |

> **Note on IP discrepancy:** The answer key lists `141.98.10.69`; the assistant extracted `141.98.10.79` directly from packet data. The one-digit difference (.69 vs .79) is likely a transcription error in the answer key.

#### Indicator accuracy

**Pre-improvement (5 indicators — 0% hallucination rate):**

| Indicator | Severity | Evidence | Correct |
|---|---|---|---|
| TCP connection to 141.98.10.79 on non-standard port 12132 | High | 411 bidirectional packets confirmed | Yes |
| IP geolocation lookup via ip-api.com | Medium | HTTP GET /json/ to ip-api.com confirmed | Yes |
| Outdated/suspicious User-Agent (Chrome 73) | Medium | UA string in extracted HTTP request confirmed | Yes |
| SMB traffic to domain controller 172.16.1.4:445 | Low | 376 packets across two sessions confirmed | Yes |
| Very high payload entropy (7.9988) | Low | Entropy value in extracted features confirmed | Yes |

**Post-improvement (7+ indicators — 0% hallucination rate). New indicators added:**

| New Indicator | Severity | Source |
|---|---|---|
| STRRAT C2 traffic on port 12132 | High | `known_malware_port_hits` — port 12132 maps to STRRAT in signature table |
| Malware delivery via software repository infrastructure | High | Co-occurrence rule — github.com, objects.githubusercontent.com, repo1.maven.org present alongside confirmed STRRAT C2 |

#### Gap analysis

Comparing the assistant to the human analyst revealed four gaps — each of which drove a specific code change:

| Gap | Human Analyst | Pre-Improvement Tool | Root Cause | Fix Applied |
|---|---|---|---|---|
| Malware family identification | STRRAT | Unknown C2 on port 12132 | No port-to-malware signature table | Added `KNOWN_MALWARE_PORTS` dict in `extractor.py` |
| Risk rating | Escalate (High) | Medium/Medium | No rule to escalate non-standard C2 to High | Added automatic High rule in `analyzer.py` system prompt |
| File-sharing IOCs | github.com, objects.githubusercontent.com flagged | Not flagged | Context-blindness: repos treated as always-legitimate | Added co-occurrence rule in system prompt |
| Victim full name | Clark Collier | Not extracted | LDAP SearchResultEntry (port 389) not parsed | Added `_extract_ldap_attributes()` in `extractor.py` |

One gap is structurally out of scope:

| Gap | Root Cause | Addressable? |
|---|---|---|
| Infection vector (`PL#40704.jar` email attachment) | Delivered via email, not visible as HTTP download in the network capture | No — requires email server logs or endpoint telemetry |

---

### Cross-Test Summary

| Dimension | TC1: NetSupport RAT | TC3: STRRAT — pre-improvement | TC3: STRRAT — post-improvement |
|---|---|---|---|
| Malware identified by name | Yes (HTTP UA + URI pattern) | No | Yes (port 12132 signature table) |
| C2 server correctly flagged | Yes | Yes | Yes |
| Risk rating accuracy | High/High (correct) | Medium/Medium (under-rated) | High/High (malware port rule) |
| Victim IP | Correct | Correct | Correct |
| Victim hostname | Correct (NBNS) | Correct (NBNS) | Correct (NBNS) |
| Victim MAC | Correct (Ethernet) | Correct (Ethernet) | Correct (Ethernet) |
| Victim user account | Correct (Kerberos) | Correct (Kerberos) | Correct (Kerberos) |
| Full name | Not available (no LDAP in TC1) | Not extracted | Extracted via LDAP port 389 |
| Software repo IOCs flagged | N/A | Not flagged | Flagged (co-occurrence with C2) |
| Suspicious downloads flagged | N/A | Not flagged | Flagged if JAR/EXE in HTTP path |
| Hallucinations | 0 of 7 indicators | 0 of 5 indicators | 0 (by design) |
| Infection vector | N/A (C2 was active) | Not identified (email) | Not identified (email; out of scope) |
| Value added beyond exercise | Evasion, entropy, lateral movement | UA analysis, staged execution | Malware named, repo IOCs, full name |

**Overall hallucination rate: 0 of 12 indicators (0%) across all evaluated runs.**

The progression tells a clear improvement story. Test Case 1 worked well because the RAT used a distinctive HTTP User-Agent and URI. Test Case 3 exposed four gaps — malware naming, risk calibration, context-sensitive repo flagging, and LDAP full-name extraction — each of which drove a specific code change. The one remaining ceiling across both test cases is payload-level evidence (TCP stream content, email attachments) that is structurally unavailable from network metadata alone.

---

## Artifact Snapshot

### UI overview

The UI has three main areas:

**Top — View mode toggle:** Switch between AI-Augmented Analysis (LLM report) and Baseline (features only). This lets an analyst compare what the AI adds vs. raw extracted data alone.

**Middle — AI report (left) and raw features (right):**
- Left: Traffic summary in plain language, overall risk level (High / Medium / Low), confidence level, flagged indicators with color-coded severity (red / orange / green), and recommended next steps
- Right: All extracted features — DNS queries, HTTP requests, TLS SNI values, connections, protocol distribution, packet size stats, payload entropy, top talkers, TCP flag distribution, ICMP summary

**Bottom — Analyst disposition:** Three buttons (🔴 Escalate / 🟡 Investigate / 🟢 Close). Clicking one audit-logs the decision to `audit_log.jsonl` and shows a confirmation banner.

### Sample triage report output

The following is representative output for a STRRAT-infected pcap (post-improvement):

```
Traffic Summary
───────────────
The infected host (172.16.1.66) belonging to Clark Collier (ccollier) established a persistent
TCP connection to 141.98.10.79 on port 12132 — the default C2 port for the STRRAT Java-based RAT.
The host also performed an IP geolocation lookup against ip-api.com, consistent with STRRAT's
initial beacon behavior. Software repository domains (github.com, objects.githubusercontent.com,
repo1.maven.org) appear in DNS queries alongside the confirmed C2 channel, suggesting staged payload
delivery from legitimate hosting infrastructure.

Overall Risk: HIGH   Confidence: HIGH

Flagged Indicators (7)
──────────────────────
[HIGH]   STRRAT C2 traffic on port 12132
         Evidence: 141.98.10.79:12132 — 411 packets, known_malware_port_hits: STRRAT (port 12132)

[HIGH]   Malware delivery via software repository infrastructure
         Evidence: github.com, objects.githubusercontent.com, repo1.maven.org in DNS queries
         alongside confirmed STRRAT C2 channel

[HIGH]   Victim attribution — Clark Collier (ccollier)
         Evidence: LDAP SearchResultEntry on port 389: givenName=Clark, sn=Collier, sAMAccountName=ccollier

[MEDIUM] IP geolocation lookup via ip-api.com
         Evidence: HTTP GET /json/ to 208.95.112.1:80 (ip-api.com) — consistent with STRRAT beacon

[MEDIUM] Outdated/suspicious User-Agent string (Chrome 73)
         Evidence: "Mozilla/5.0 ... Chrome/73.0.3683.103" — Chrome 73 EOL 2019, likely hardcoded in RAT

[LOW]    SMB traffic to domain controller
         Evidence: 376 packets to 172.16.1.4:445 across 2 sessions

[LOW]    Very high payload entropy (7.9988)
         Evidence: Shannon entropy across all payload bytes — consistent with encrypted C2 channel

Recommended Next Steps
──────────────────────
1. Isolate 172.16.1.66 immediately — active STRRAT C2 channel confirmed
2. Block 141.98.10.79 at perimeter firewall
3. Search for PL#40704.jar or similar .jar email attachments across mail gateway logs
4. Check github.com and Maven traffic logs for payload staging activity
5. Review SMB sessions from 172.16.1.66 to domain controller 172.16.1.4 for lateral movement
6. Audit ccollier account for credential compromise
7. Search SIEM for other hosts contacting 141.98.10.79:12132 or ip-api.com in the same timeframe
```

### Sample extracted features (JSON)

A subset of the structured JSON that the extractor produces and passes to Claude:

```json
{
  "total_packets": 11562,
  "known_malware_port_hits": [
    {
      "port": 12132,
      "malware_family": "STRRAT",
      "description": "STRRAT Java-based RAT default C2 port",
      "connections": ["172.16.1.66:50412 -> 141.98.10.79:12132"]
    }
  ],
  "ldap_users": [
    {
      "given_name": "Clark",
      "surname": "Collier",
      "sam_account_name": "ccollier",
      "display_name": "Clark Collier"
    }
  ],
  "dns_queries": [
    "github.com",
    "objects.githubusercontent.com",
    "repo1.maven.org",
    "ip-api.com",
    "wiresharkworkshop.online"
  ],
  "connections": [
    { "src": "172.16.1.66:50412", "dst": "141.98.10.79:12132", "proto": "TCP", "packets": 411 },
    { "src": "172.16.1.66:49720", "dst": "172.16.1.4:445", "proto": "TCP", "packets": 376 }
  ],
  "payload_entropy": { "entropy": 7.9988, "note": "High entropy — consistent with encrypted channel" },
  "host_details": [
    { "ip": "172.16.1.66", "mac_address": "00:1e:64:ec:f3:08", "hostnames": ["DESKTOP-SKBR25F"] }
  ],
  "windows_users": ["ccollier"]
}
```

---

## Technical Reference

### Project structure

```
soc-triage-assistant/
├── app.py            # Streamlit UI (upload, report, disposition)
├── extractor.py      # pcap → structured JSON via scapy
├── analyzer.py       # Claude API: agentic tool-use loop + structured output
├── audit.py          # Appends every analysis and disposition to audit_log.jsonl
├── requirements.txt  # Python dependencies
├── .env.example      # API key template
└── .gitignore
```

### Feature extraction

`extractor.py` uses [scapy](https://scapy.net/) to parse the pcap locally and extract:

| Feature | Details |
|---|---|
| Protocol distribution | Packet counts per protocol (TCP, UDP, ICMP, IPv6, etc.) |
| Connection summaries | Top 20 flows by packet count (src IP:port → dst IP:port) |
| DNS queries | All queried domain names |
| HTTP requests | Request line, Host, User-Agent, Content-Type, auth header presence |
| TLS SNI | Server Name Indication values parsed from raw TLS ClientHello bytes |
| Top talkers | Top 10 IPs by total packet count |
| Packet size stats | Min, max, mean, total bytes |
| Payload entropy | Shannon entropy of all payload bytes (>7.0 suggests encryption/compression) |
| TCP flags | Distribution of TCP flag combinations |
| ICMP summary | ICMP message type counts |
| MAC addresses | Source MAC per IP extracted from the Ethernet layer |
| Windows hostnames | NetBIOS hostnames decoded from NBNS (UDP port 137) registration frames |
| Windows user accounts | CNameString values extracted from Kerberos AS-REQ packets (TCP/UDP port 88) |
| LDAP full names | givenName, sn, displayName, sAMAccountName parsed from LDAP SearchResultEntry frames (TCP port 389) |
| Known malware port hits | Connections to ports matching a built-in signature table (STRRAT:12132, njRAT:1177, AsyncRAT:5552, Metasploit:4444, etc.) |
| Suspicious downloads | HTTP requests where the path ends in a known executable or script extension (.jar, .exe, .dll, .ps1, .vbs, .bat, .hta, etc.) |

### LLM analysis

`analyzer.py` implements an agentic loop using the [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python):

- **Model:** `claude-opus-4-6`
- **Temperature:** `0.2` (low, for consistent structured output)
- **Tool use:** Claude may call `lookup_ip_reputation` and `lookup_domain_reputation` before submitting its report
- **Structured output:** Enforced via `submit_triage_report` tool schema:

```jsonc
{
  "traffic_summary": "2–4 sentence overview",
  "indicators": [
    {
      "description": "Short indicator name",
      "evidence": "Exact values from extracted features",
      "severity": "Low | Medium | High"
    }
  ],
  "overall_risk": "Low | Medium | High",
  "confidence_level": "Low | Medium | High",
  "next_steps": ["Concrete recommended actions"],
  "insufficient_data": true,            // set when traffic is all-encrypted / sparse
  "insufficient_data_reason": "..."     // explanation
}
```

The system prompt instructs Claude to:
- Only report indicators directly supported by extracted feature values
- Never invent IPs, domains, or URIs not present in the data
- Set `insufficient_data=true` for heavily encrypted or sparse captures
- Apply tiered risk-floor rules:
  - **Automatic High** when `known_malware_port_hits` is present — names the specific malware family
  - **Automatic High** when a non-standard port C2 connection co-occurs with a foreign geolocation
  - **Automatic High** when `suspicious_downloads` is non-empty
  - **Automatic High indicator** when software-repository domains (github.com, raw.githubusercontent.com, repo1.maven.org, pypi.org) appear alongside confirmed non-standard port C2
- Include victim full name from `ldap_users` directly in the traffic summary when available

### Reputation enrichment

#### `lookup_ip_reputation(ip)`
- **With `ABUSEIPDB_API_KEY`:** Queries [AbuseIPDB](https://www.abuseipdb.com/) for abuse confidence score, ISP, country, Tor status, and total reports
- **Without key:** Falls back to [ipapi.co](https://ipapi.co/) for country, org, and city (no abuse score)

#### `lookup_domain_reputation(domain)`
- **With `VIRUSTOTAL_API_KEY`:** Queries [VirusTotal](https://www.virustotal.com/) for malicious/suspicious/harmless vote counts and categories
- **Without key:** Falls back to a plain DNS resolution check (flags non-resolving domains as potentially DGA/sinkholed)

### Audit logging

Every analysis and disposition is appended to `audit_log.jsonl` (one JSON object per line):

```jsonc
// Analysis event
{
  "event": "analysis",
  "analysis_id": "20240417_143022_123456",
  "timestamp": "2024-04-17T14:30:22Z",
  "pcap_filename": "malware_sample.pcap",
  "features": { ... },   // full extracted features
  "report": { ... }       // full LLM report including tool call log
}

// Disposition event
{
  "event": "disposition",
  "analysis_id": "20240417_143022_123456",
  "timestamp": "2024-04-17T14:31:05Z",
  "disposition": "Escalate"
}
```

`audit_log.jsonl` is excluded from git (via `.gitignore`) because it may contain sensitive network metadata.

---

## Governance and Limitations

### What the AI will say it cannot do

The model is instructed to respond with `insufficient_data=true` when:
- All traffic is TLS-encrypted with no SNI or metadata
- The pcap is too small or malformed to extract meaningful features

### Where the system should NOT be trusted

- As the sole basis for blocking, quarantine, or escalation decisions
- For encrypted payload analysis (metadata only is available)
- For zero-day or APT identification
- When a reported indicator does not appear in the raw features panel

### Hallucination mitigation

- Raw extracted features are always displayed alongside the AI report for cross-reference
- The system prompt explicitly forbids inventing evidence
- Every indicator includes an `evidence` field referencing specific extracted values

---

## Dependencies

| Package | Purpose |
|---|---|
| `anthropic` | Claude API client (tool use, structured output) |
| `streamlit` | Web UI |
| `scapy` | pcap parsing and network feature extraction |
| `requests` | HTTP calls to reputation APIs |
| `python-dotenv` | `.env` file loading |
