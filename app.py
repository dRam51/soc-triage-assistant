"""
SOC Triage Assistant — Streamlit UI
Analyst workflow: upload pcap → AI triage report → review raw features → select disposition.
"""
import os
import tempfile

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from analyzer import analyze_pcap
from audit import log_analysis, log_disposition
from extractor import extract_features

# ── Page Config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SOC Triage Assistant",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Styles ────────────────────────────────────────────────────────────────────

st.markdown(
    """
    <style>
    .ai-banner {
        background: #fff3cd;
        border: 1px solid #ffc107;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 18px;
        font-weight: 600;
        color: #856404;
        font-size: 0.95em;
    }
    .risk-high  { color: #dc3545; font-weight: 700; font-size: 1.5em; }
    .risk-medium{ color: #fd7e14; font-weight: 700; font-size: 1.5em; }
    .risk-low   { color: #28a745; font-weight: 700; font-size: 1.5em; }
    .ind-high   { border-left: 4px solid #dc3545; padding: 6px 10px; margin: 6px 0; background: #fff5f5; border-radius: 0 4px 4px 0; }
    .ind-medium { border-left: 4px solid #fd7e14; padding: 6px 10px; margin: 6px 0; background: #fff8f0; border-radius: 0 4px 4px 0; }
    .ind-low    { border-left: 4px solid #28a745; padding: 6px 10px; margin: 6px 0; background: #f0fff4; border-radius: 0 4px 4px 0; }
    .disp-btn   { margin-top: 12px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Header ────────────────────────────────────────────────────────────────────

st.title("🛡 SOC Triage Assistant")
st.caption("LLM-augmented triage for flagged network packet captures")

st.markdown(
    '<div class="ai-banner">'
    "⚠️ <strong>AI-Generated Triage Assistance</strong> — "
    "All findings must be reviewed by the analyst before action. "
    "Do not use as the sole basis for escalation, blocking, or quarantine decisions."
    "</div>",
    unsafe_allow_html=True,
)

# ── File Upload ───────────────────────────────────────────────────────────────

uploaded_file = st.file_uploader(
    "Upload a .pcap or .pcapng file from your alert queue",
    type=["pcap", "pcapng"],
    help="Raw packet payloads are NOT sent to the AI — only derived metadata is analyzed.",
)

if uploaded_file is None:
    st.info("Upload a .pcap or .pcapng file above to begin triage.")
    with st.expander("About this tool"):
        st.markdown(
            """
**SOC Triage Assistant** accelerates initial alert triage by automatically extracting
structured network features and running them through Claude (Anthropic) to produce a
plain-language analysis report.

**Analyst workflow:**
1. Receive a flagged pcap from the alert queue
2. Upload it here — features are extracted locally
3. Review the AI-generated triage report and raw features side by side
4. Select a disposition: **Escalate / Investigate / Close**

**What the AI sees (structured metadata only):**
- Protocol distribution & connection summaries
- DNS query names
- HTTP request lines, Host headers, User-Agent strings
- TLS Server Name Indication (SNI) values
- Payload entropy & packet-size statistics
- Top talkers (IP addresses by packet count)

**What the AI never sees:** raw packet bytes, payload content, credentials.

**Optional enrichment:** Set `ABUSEIPDB_API_KEY` and/or `VIRUSTOTAL_API_KEY` in `.env`
to enable live reputation lookups during analysis.
"""
        )
    st.stop()

# ── Feature Extraction ────────────────────────────────────────────────────────

# Cache features per uploaded filename to avoid re-parsing on every rerun
file_key = uploaded_file.name + str(uploaded_file.size)
if st.session_state.get("_file_key") != file_key:
    st.session_state.clear()
    st.session_state["_file_key"] = file_key

if "features" not in st.session_state:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name
    try:
        with st.spinner("Extracting pcap features…"):
            st.session_state["features"] = extract_features(tmp_path)
            st.session_state["tmp_path"] = tmp_path
    except Exception as exc:
        os.unlink(tmp_path)
        st.error(f"Feature extraction failed: {exc}")
        st.stop()

features: dict = st.session_state["features"]

# ── View Toggle ───────────────────────────────────────────────────────────────

mode = st.radio(
    "View mode",
    ["🤖 AI-Augmented Analysis", "📊 Baseline (Features Only)"],
    horizontal=True,
)

st.divider()

# ── AI-Augmented Analysis ─────────────────────────────────────────────────────

if mode == "🤖 AI-Augmented Analysis":
    if "report" not in st.session_state:
        with st.spinner("Analyzing with Claude — reputation lookups may add a few seconds…"):
            report = analyze_pcap(features)
            st.session_state["report"] = report
            st.session_state["analysis_id"] = log_analysis(
                uploaded_file.name, features, report
            )

    report: dict = st.session_state["report"]

    if "error" in report and "traffic_summary" not in report:
        st.error(f"Analysis error: {report['error']}")
    else:
        # ── Summary + Risk ────────────────────────────────────────────────────
        col_summary, col_risk = st.columns([3, 1])

        with col_summary:
            st.subheader("Traffic Summary")
            st.write(report.get("traffic_summary", "—"))
            if report.get("insufficient_data"):
                st.warning(
                    f"**Insufficient Data:** {report.get('insufficient_data_reason', 'Features too sparse for payload analysis.')}"
                )

        with col_risk:
            risk = report.get("overall_risk", "Unknown")
            conf = report.get("confidence_level", "Unknown")
            risk_class = {"High": "risk-high", "Medium": "risk-medium", "Low": "risk-low"}.get(
                risk, ""
            )
            st.markdown("**Overall Risk**")
            st.markdown(f"<span class='{risk_class}'>{risk}</span>", unsafe_allow_html=True)
            st.markdown(f"**Confidence:** {conf}")

        st.divider()

        # ── Indicators ────────────────────────────────────────────────────────
        indicators: list = report.get("indicators", [])
        st.subheader(f"Flagged Indicators ({len(indicators)})")
        if indicators:
            for ind in indicators:
                sev = ind.get("severity", "Low")
                cls = {"High": "ind-high", "Medium": "ind-medium", "Low": "ind-low"}.get(
                    sev, "ind-low"
                )
                st.markdown(
                    f'<div class="{cls}">'
                    f'<strong>[{sev}]</strong> {ind["description"]}<br>'
                    f'<small><em>Evidence: {ind["evidence"]}</em></small>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("No suspicious indicators flagged.")

        st.divider()

        # ── Next Steps ────────────────────────────────────────────────────────
        next_steps: list = report.get("next_steps", [])
        if next_steps:
            st.subheader("Recommended Next Steps")
            for step in next_steps:
                st.markdown(f"- {step}")

        # ── Reputation Lookup Log ─────────────────────────────────────────────
        tool_calls: list = report.get("tool_calls", [])
        if tool_calls:
            with st.expander(f"Reputation Lookups ({len(tool_calls)} calls)"):
                for call in tool_calls:
                    st.markdown(f"**{call['tool']}** → `{list(call['input'].values())[0]}`")
                    st.json(call["output"])

# ── Raw Extracted Features (always shown) ─────────────────────────────────────

st.subheader("Extracted Features")
st.caption("Raw pcap metadata - use this to cross-reference AI findings.")

# ── Malware Port Hits (auto-detected C2 ports) ───────────────────────────────
malware_hits = features.get("known_malware_port_hits", [])
if malware_hits:
    with st.expander(f"⚠️ Known Malware Port Hits ({len(malware_hits)})", expanded=True):
        for hit in malware_hits:
            st.markdown(
                f"🔴 **{hit['malware_family']}** — port `{hit['dst_port']}` "
                f"(`{hit['src']}` → `{hit['dst']}`)\n\n"
                f"*{hit['description']}*"
            )

# ── Suspicious Downloads ──────────────────────────────────────────────────────
suspicious_dl = features.get("suspicious_downloads", [])
if suspicious_dl:
    with st.expander(f"⚠️ Suspicious Downloads ({len(suspicious_dl)})", expanded=True):
        for dl in suspicious_dl:
            st.markdown(
                f"🔴 `{dl.get('extension', '?')}` file via HTTP — "
                f"`{dl.get('request_line', '')}` | host: `{dl.get('host', '')}`"
            )

# ── Host Identity (MAC, Hostname, Windows Users) ──────────────────────────────
host_details = features.get("host_details", [])
windows_users = features.get("windows_users", [])

ldap_users = features.get("ldap_users", [])

if host_details or windows_users or ldap_users:
    with st.expander("Host Identity (MAC, Hostname, Windows Users)", expanded=True):
        if host_details:
            for host in host_details:
                parts = [f"`{host['ip']}`"]
                if host.get("mac_address"):
                    parts.append(f"MAC: `{host['mac_address']}`")
                if host.get("hostnames"):
                    parts.append(f"Hostname(s): **{', '.join(host['hostnames'])}**")
                st.markdown(" | ".join(parts))
        if windows_users:
            st.markdown(f"**Windows user account(s):** {', '.join(f'`{u}`' for u in windows_users)}")
        if ldap_users:
            for lu in ldap_users:
                display = lu.get("display_name") or lu.get("common_name") or ""
                sam = lu.get("sam_account_name") or ""
                given = lu.get("given_name") or ""
                sn = lu.get("surname") or ""
                full = display or (f"{given} {sn}".strip()) or sam
                st.markdown(
                    f"**LDAP full name:** `{full}`"
                    + (f" | sAMAccountName: `{sam}`" if sam else "")
                )

left, right = st.columns(2)

with left:
    st.metric("Total Packets", features.get("total_packets", 0))

    proto = features.get("protocol_distribution", {})
    if proto:
        with st.expander("Protocol Distribution", expanded=True):
            for p, c in sorted(proto.items(), key=lambda x: x[1], reverse=True):
                st.markdown(f"- **{p}**: {c:,}")

    conns = features.get("connections", [])
    if conns:
        with st.expander(f"Top Connections ({len(conns)})", expanded=True):
            for conn in conns[:15]:
                st.markdown(
                    f"- `{conn['src']}` → `{conn['dst']}` "
                    f"[{conn['proto']}] × {conn['packets']}"
                )

    talkers = features.get("top_talkers", {})
    if talkers:
        with st.expander("Top Talkers (packets)"):
            for ip, cnt in sorted(talkers.items(), key=lambda x: x[1], reverse=True):
                st.markdown(f"- `{ip}`: {cnt:,}")

    flags = features.get("tcp_flags_summary", {})
    if flags:
        with st.expander("TCP Flag Combinations"):
            for flag, cnt in sorted(flags.items(), key=lambda x: x[1], reverse=True):
                st.markdown(f"- `{flag}`: {cnt}")

    icmp = features.get("icmp_summary", {})
    if icmp:
        with st.expander("ICMP Summary"):
            for t, cnt in icmp.items():
                st.markdown(f"- {t}: {cnt}")

with right:
    dns = features.get("dns_queries", [])
    if dns:
        with st.expander(f"DNS Queries ({len(dns)})", expanded=True):
            for q in dns[:40]:
                st.markdown(f"- `{q}`")
    else:
        st.info("No DNS queries detected.")

    http = features.get("http_requests", [])
    if http:
        with st.expander(f"HTTP Requests ({len(http)})", expanded=True):
            for req in http[:25]:
                host = req.get("host", "")
                ua = req.get("user_agent", "")
                auth = req.get("authorization", "")
                st.markdown(
                    f"- `{req.get('request_line', '')}` "
                    + (f"| host: `{host}`" if host else "")
                    + (f"| UA: `{ua[:60]}`" if ua else "")
                    + (" | **[auth header present]**" if auth else "")
                )
    else:
        st.info("No cleartext HTTP requests detected.")

    sni = features.get("tls_sni", [])
    if sni:
        with st.expander(f"TLS SNI ({len(sni)})", expanded=True):
            for s in sni:
                st.markdown(f"- `{s}`")
    else:
        st.info("No TLS SNI values extracted.")

    stats = features.get("packet_size_stats", {})
    if stats:
        with st.expander("Packet Size Stats"):
            for k, v in stats.items():
                st.markdown(f"- **{k}**: {v:,}" if isinstance(v, int) else f"- **{k}**: {v}")

    entropy = features.get("payload_entropy", {})
    if entropy:
        with st.expander("Payload Entropy"):
            st.markdown(f"- **Entropy**: `{entropy.get('entropy', 'N/A')}`")
            st.caption(entropy.get("note", ""))

with st.expander("Full Features JSON"):
    st.json(features)

# ── Disposition ───────────────────────────────────────────────────────────────

st.divider()
st.subheader("Analyst Disposition")
st.caption("Select your triage decision. This will be audit-logged.")

analysis_id: str = st.session_state.get("analysis_id", "")

# Prevent re-logging if a disposition was already recorded this session
if "disposition_recorded" not in st.session_state:
    col_esc, col_inv, col_close = st.columns(3)

    with col_esc:
        if st.button("🔴  Escalate", use_container_width=True):
            if analysis_id:
                log_disposition(analysis_id, "Escalate")
            st.session_state["disposition_recorded"] = "Escalate"
            st.rerun()

    with col_inv:
        if st.button("🟡  Investigate", use_container_width=True):
            if analysis_id:
                log_disposition(analysis_id, "Investigate")
            st.session_state["disposition_recorded"] = "Investigate"
            st.rerun()

    with col_close:
        if st.button("🟢  Close", use_container_width=True):
            if analysis_id:
                log_disposition(analysis_id, "Close")
            st.session_state["disposition_recorded"] = "Close"
            st.rerun()

else:
    disp = st.session_state["disposition_recorded"]
    colors = {"Escalate": "error", "Investigate": "warning", "Close": "success"}
    getattr(st, colors.get(disp, "info"))(
        f"Disposition recorded: **{disp.upper()}** — audit log updated."
    )
    if st.button("Change disposition"):
        del st.session_state["disposition_recorded"]
        st.rerun()
