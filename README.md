# SOC Triage Assistant

An triage tool for junior SOC analysts. Upload a flagged `.pcap` file, get a triage report automatically generated with risk rating and actionable indicators, then record your disposition - all in a browser UI.

---

## What it does

When an IDS flags a packet capture, a junior analyst typically opens it in Wireshark, manually sifts through traffic, and decides whether to escalate, investigate, or close. This is slow and error-prone. SOC Triage Assistant automates the feature extraction and synthesis step:

1. **Upload** a `.pcap` or `.pcapng` file
2. **Extract** structured network metadata (DNS queries, HTTP requests, TLS SNI, connections, payload entropy, etc.) - all locally, no raw bytes sent anywhere
3. **Enrich** suspicious IPs and domains via live reputation APIs (optional)
4. **Analyze** with Claude - produces a plain-language triage report with flagged indicators, a risk level, and recommended next steps
5. **Decide** - select Escalate / Investigate / Close; the decision is audit-logged

A **baseline toggle** switches to a features-only view (no LLM), so you can compare what the AI adds vs. raw extracted data alone.

---

## Architecture

The system is deliberately layered to separate deterministic processing from probabilistic reasoning:

```
.pcap file
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Layer 1 - Feature Extraction  (extractor.py)       │
│  scapy parses the pcap locally into structured JSON  │
│  Protocol counts, connections, DNS, HTTP, TLS SNI,   │
│  payload entropy, packet size stats, top talkers     │
└───────────────────┬─────────────────────────────────┘
                    │ structured JSON (no raw bytes)
                    ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2 - LLM Analysis + Tool Use  (analyzer.py)   │
│  Claude (claude-opus-4-6) receives the JSON features │
│  and runs an agentic loop:                           │
│    • Calls lookup_ip_reputation for suspicious IPs   │
│    • Calls lookup_domain_reputation for suspicious   │
│      DNS/SNI values                                  │
│    • Calls submit_triage_report with structured JSON │
│      (enforced output schema)                        │
└───────────────────┬─────────────────────────────────┘
                    │ structured triage report
                    ▼
┌─────────────────────────────────────────────────────┐
│  Layer 3 - Presentation  (app.py)                   │
│  Streamlit UI displays:                              │
│    • Traffic summary, risk level, confidence         │
│    • Flagged indicators with evidence                │
│    • Recommended next steps                          │
│    • Raw extracted features (always visible)         │
│    • Reputation lookup log                           │
│    • Disposition buttons → audit log                 │
└─────────────────────────────────────────────────────┘
```

**Key design decision:** The LLM never sees raw packet bytes. It only operates on verified, structured metadata. If it flags an indicator, the analyst can immediately cross-check it against the raw features panel displayed alongside the report.

---

## Project structure

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

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/dRam51/soc-triage-assistant.git
cd soc-triage-assistant
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys

```bash
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

Without the optional keys the app still works - IP lookups fall back to free geolocation (ipapi.co) and domain lookups fall back to plain DNS resolution.

### 5. Run

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`.

---

## Feature extraction details

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

---

## LLM analysis details

`analyzer.py` implements an agentic loop using the [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python):

- **Model:** `claude-opus-4-6`
- **Temperature:** `0.2` (low, for consistent structured output)
- **Tool use:** Claude may call `lookup_ip_reputation` and `lookup_domain_reputation` before submitting its report
- **Structured output:** The final report is enforced via a `submit_triage_report` tool schema with these fields:

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
- Use conservative risk ratings (High = clear corroborated IOCs, not just unusual traffic)

---

## Reputation enrichment

When Claude identifies a suspicious IP or domain it calls one of two tools:

### `lookup_ip_reputation(ip)`
- **With `ABUSEIPDB_API_KEY`:** Queries [AbuseIPDB](https://www.abuseipdb.com/) for abuse confidence score, ISP, country, Tor status, and total reports
- **Without key:** Falls back to [ipapi.co](https://ipapi.co/) for country, org, and city (no abuse score)

### `lookup_domain_reputation(domain)`
- **With `VIRUSTOTAL_API_KEY`:** Queries [VirusTotal](https://www.virustotal.com/) for malicious/suspicious/harmless vote counts and categories
- **Without key:** Falls back to a plain DNS resolution check (flags non-resolving domains as potentially DGA/sinkholed)

---

## Audit logging

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

## Governance and limitations

### What the AI will say it cannot do
The model is instructed to respond with `insufficient_data=true` when:
- All traffic is TLS-encrypted with no SNI or metadata
- The pcap is too small or malformed to extract meaningful features

### Where the system should NOT be trusted
- As the sole basis for blocking, quarantine, or escalation decisions
- For encrypted payload analysis (metadata only is available)
- For zero-day or APT identification
- When a reported indicator doesn't appear in the raw features panel

### Hallucination mitigation
- Raw extracted features are always displayed alongside the AI report for cross-reference
- The system prompt explicitly forbids inventing evidence
- Every indicator includes an `evidence` field referencing specific extracted values

---

## Example scenarios

| Scenario | Expected behavior |
|---|---|
| HTTP malware download + C2 beaconing | Flags download URI and beaconing pattern, rates High, recommends escalation |
| DNS tunneling (high-entropy TXT queries) | Flags DNS volume/entropy, suspicious domain, rates Medium–High |
| Normal HTTPS browsing | Summarizes as routine, rates Low, recommends closing |
| SYN scan across /24 subnet | Identifies scan pattern, flags source IP, rates Medium |
| Mixed traffic with cleartext credentials | Surfaces credential leak amid benign traffic, rates Medium |
| All-TLS traffic, no SNI | Sets `insufficient_data=true`, limits assessment to connection metadata |

---

## Evaluation: SOC Triage Assistant vs. Human Analyst

This section compares the SOC Triage Assistant against a real-world traffic analysis exercise from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2026/02/28/index.html). The answers file represents the human analyst baseline: what an experienced analyst would find by manually working through the pcap in Wireshark. The SOC Triage Assistant output represents the GenAI approach.

**Test case:** `2026-02-28-traffic-analysis-exercise.pcap` (6.6 MB, 15,512 packets) — a live NetSupport Manager RAT infection with active C2 communication.

---

### What the human analyst does (baseline)

The human analyst opens the pcap in Wireshark and applies a series of manual filters to answer the incident report questions:

1. Filter on the C2 IP (`45.131.214.85`) to identify the internal host communicating with it
2. Filter `nbns` to find the Windows hostname and MAC address from NetBIOS Name Service frames
3. Filter `kerberos.CNameString` and inspect frame details to find the Windows user account name
4. Use Edit > Find Packet to search packet details for the full name string

This requires knowledge of which Wireshark filters to apply, how to navigate frame details, and familiarity with Windows authentication protocols. For a junior analyst, each step is a potential blocker.

---

### What the SOC Triage Assistant found

The assistant processed the same pcap in under 60 seconds and produced the following without any manual filtering:

| Finding | Human Analyst | SOC Triage Assistant |
|---|---|---|
| Infected host IP | 10.2.28.88 | 10.2.28.88 |
| C2 server | 45.131.214.85:443 | 45.131.214.85:443 |
| Malware family | NetSupport Manager RAT | NetSupport Manager RAT |
| C2 URI pattern | (manual Wireshark inspection) | `/fakeurl.htm` flagged as known RAT indicator |
| Suspicious domain | (not in scope for exercise) | `vadusa.xyz` flagged with .xyz TLD analysis |
| Port evasion technique | (not flagged) | HTTP over port 443 flagged as deliberate evasion |
| Encrypted C2 payloads | (not analyzed) | CMD=ENCD payloads with entropy 7.97 flagged |
| SMB lateral movement risk | (not in scope) | Flagged 909-packet SMB flow to domain controller |
| Risk rating | (Escalate - implied) | High, Confidence: High |
| Recommended disposition | Escalate | Escalate (7 specific action steps) |
| Windows hostname | DESKTOP-TEYQ2NR | Not extracted |
| MAC address | 00:19:d1:b2:4d:ad | Not extracted |
| Windows user account | brolf | Not extracted |
| Full user name | Becka Rolf | Not extracted |

---

### Indicator accuracy

The assistant flagged 7 indicators. All 7 were directly supported by extracted features — no hallucinations.

| Indicator | Severity | Grounded in extracted data | Correct |
|---|---|---|---|
| NetSupport Manager RAT C2 beaconing | High | 40+ POST requests to `/fakeurl.htm` with UA `NetSupport Manager/1.3` | Yes |
| Suspicious domain `vadusa.xyz` resolves to C2 IP | High | DNS query present; domain resolved to 45.131.214.85 | Yes |
| Suspicious URI `/fakeurl.htm` | High | Present in all POST requests | Yes |
| HTTP over port 443 (non-TLS) | Medium | Plaintext HTTP to port 443 confirmed | Yes |
| Encoded/encrypted C2 payloads | High | CMD=ENCD, ES=1, binary DATA fields visible | Yes |
| Heavy SMB traffic to domain controller | Medium | 909 packets across 3 sessions to 10.2.28.2:445 | Yes |
| NetBIOS broadcast traffic | Low | 430 UDP packets to 10.2.28.255:138 | Yes |

**Hallucination rate: 0%** - Every indicator was traceable to specific values in the extracted features panel.

---

### Where the assistant added value beyond the exercise

The exercise asked the analyst to identify the victim machine. The assistant went further:

- **Threat identification in plain language:** Named the specific RAT family, its C2 protocol mechanics (CMD=POLL, CMD=ENCD), and the known `/fakeurl.htm` indicator without any prompt engineering for this specific threat
- **Evasion technique detection:** Identified that the attacker used plaintext HTTP on port 443 to bypass port-based filtering — a detail not surfaced by the exercise answer key
- **Lateral movement flag:** Detected 909 packets of SMB traffic to the domain controller and correctly noted this as a potential post-compromise staging signal
- **Actionable next steps:** Produced 7 specific remediation steps (isolate host, block IP/domain, forensic analysis, SMB session review, SIEM/EDR search, delivery vector review, credential audit) compared to the exercise's focus on victim identification only
- **Entropy analysis:** Quantified payload entropy at 7.97, providing an objective signal for encryption consistent with RAT command channels

---

### Where the assistant fell short

The assistant's extractor does not currently parse:

- **NBNS (NetBIOS Name Service):** Required to extract the Windows hostname (`DESKTOP-TEYQ2NR`) from broadcast frames
- **Kerberos:** Required to extract the Windows user account (`brolf`) from `CNameString` fields
- **ARP/DHCP:** Required to extract the MAC address (`00:19:d1:b2:4d:ad`)

These are critical for incident response (you need to know which physical machine to isolate and which user to notify). The human analyst retrieves all three in under 5 minutes using targeted Wireshark filters. The assistant cannot currently surface them because the extractor does not parse these protocol layers.

This represents the clearest gap between the GenAI and human approaches on this test case.

---

### Speed and workflow comparison

| Step | Human Analyst (Wireshark) | SOC Triage Assistant |
|---|---|---|
| Open and load pcap | ~30 seconds | ~5 seconds (upload) |
| Identify C2 traffic | Filter by IP, inspect manually (~5-10 min) | Automatic, in triage report |
| Identify RAT family | Recognize User-Agent string (~2-5 min) | Named in traffic summary |
| Find hostname | Apply `nbns` filter, inspect frame (~2 min) | Not available |
| Find user account | Apply `kerberos.CNameString` filter (~3 min) | Not available |
| Find full name | Use Find Packet, search string (~2 min) | Not available |
| Write incident summary | Manual writeup (~15-30 min) | Auto-generated in structured format |
| Determine disposition | Based on full analysis | Risk: High, Confidence: High in seconds |

For the threat identification portion of triage, the assistant is significantly faster. For victim attribution (the specific focus of this exercise), the human analyst with Wireshark is more capable due to the current extractor's limitations.

---

### Overall assessment

The SOC Triage Assistant correctly identified the core threat (NetSupport Manager RAT, C2 server, infection confirmed) and recommended the correct disposition (Escalate) with zero hallucinations. It surfaced indicators and context that go beyond what the exercise answer key covers, including evasion techniques, lateral movement signals, and specific remediation steps.

The primary gap is victim attribution: hostname, MAC address, and user account extraction requires NBNS and Kerberos parsing that is not yet implemented in the feature extractor. Adding these protocol layers to `extractor.py` would close the most significant difference between the GenAI and human analyst outputs on incident response tasks.

---

## Dependencies

| Package | Purpose |
|---|---|
| `anthropic` | Claude API client (tool use, structured output) |
| `streamlit` | Web UI |
| `scapy` | pcap parsing and network feature extraction |
| `requests` | HTTP calls to reputation APIs |
| `python-dotenv` | `.env` file loading |
