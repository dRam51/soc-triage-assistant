"""
Audit logging for SOC Triage Assistant.
Every analysis and disposition is appended to audit_log.jsonl as newline-delimited JSON.
Fields logged: event type, timestamp, pcap filename, extracted features, LLM report, disposition.
"""
import json
import datetime
from pathlib import Path

AUDIT_LOG_PATH = Path("audit_log.jsonl")


def log_analysis(pcap_filename: str, features: dict, report: dict) -> str:
    """
    Log a completed analysis event.
    Returns a unique analysis_id (timestamp-based) for linking disposition events.
    """
    analysis_id = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    entry = {
        "event": "analysis",
        "analysis_id": analysis_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "pcap_filename": pcap_filename,
        "features": features,
        "report": report,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return analysis_id


def log_disposition(analysis_id: str, disposition: str) -> None:
    """
    Log the analyst's disposition decision for a given analysis.
    disposition should be one of: "Escalate", "Investigate", "Close".
    """
    entry = {
        "event": "disposition",
        "analysis_id": analysis_id,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "disposition": disposition,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
