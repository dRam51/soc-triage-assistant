# SOC Triage Assistant

An triage tool for junior SOC analysts. Upload a flagged `.pcap` file, get an AI-generated triage report with risk rating and actionable indicators, then record your disposition - all in a browser UI.

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

## Dependencies

| Package | Purpose |
|---|---|
| `anthropic` | Claude API client (tool use, structured output) |
| `streamlit` | Web UI |
| `scapy` | pcap parsing and network feature extraction |
| `requests` | HTTP calls to reputation APIs |
| `python-dotenv` | `.env` file loading |
