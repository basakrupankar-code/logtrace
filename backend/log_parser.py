"""
LogTrace AI — Log Parser & Pre-classifier
Parses raw log data, categorizes events, and builds attack timelines.
"""
import json
from collections import Counter, defaultdict
from datetime import datetime

# ──────────────────────────────────────────────
#  Threat classification rules (pre-Gemma pass)
# ──────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ATTACK_PHASE_MAP = {
    "port_scan": "Reconnaissance",
    "ssh_failed": "Brute Force",
    "ssh_success": "Initial Access",
    "shell_command": "Execution",
    "sudo_attempt": "Privilege Escalation",
    "sudo_success": "Privilege Escalation",
    "privilege_escalation": "Privilege Escalation",
    "file_access": "Discovery",
    "data_exfiltration": "Exfiltration",
    "web_shell": "Persistence",
    "persistence": "Persistence",
    "log_tampering": "Defense Evasion",
    "command_injection": "Execution",
    "web_access": "Normal Traffic",
}

MITRE_MAP = {
    "Reconnaissance": "TA0043",
    "Brute Force": "T1110",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Privilege Escalation": "TA0004",
    "Discovery": "TA0007",
    "Exfiltration": "TA0010",
    "Persistence": "TA0003",
    "Defense Evasion": "TA0005",
    "Normal Traffic": None,
}


def load_logs(filepath: str) -> list[dict]:
    """Load and return log entries from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        logs = json.load(f)
    # Ensure sorted by timestamp
    logs.sort(key=lambda e: e.get("timestamp", ""))
    return logs


def enrich_log(entry: dict) -> dict:
    """Add computed fields to a log entry."""
    event_type = entry.get("event_type", "unknown")
    
    # Any event type not in our explicit map defaults to Unclassified for AI analysis
    if event_type not in ATTACK_PHASE_MAP:
        entry["attack_phase"] = "Unclassified"
        entry["mitre_id"] = None
        entry["is_malicious"] = False
        if "severity" not in entry:
            entry["severity"] = "info"
        return entry

    entry["attack_phase"] = ATTACK_PHASE_MAP[event_type]
    entry["mitre_id"] = MITRE_MAP.get(entry["attack_phase"])
    entry["is_malicious"] = entry["attack_phase"] != "Normal Traffic"
    
    if "severity" not in entry:
        entry["severity"] = "medium" if entry["is_malicious"] else "info"
        
    return entry


def enrich_all(logs: list[dict]) -> list[dict]:
    """Enrich every log entry."""
    return [enrich_log(e) for e in logs]


def get_threat_summary(logs: list[dict]) -> dict:
    """Return counts by severity level."""
    counts = Counter(e.get("severity", "info") for e in logs)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total": len(logs),
        "malicious": sum(1 for e in logs if e.get("is_malicious")),
    }


def get_attacker_ips(logs: list[dict]) -> list[dict]:
    """Identify unique attacker IPs with event counts."""
    ip_events = defaultdict(list)
    for e in logs:
        if e.get("is_malicious"):
            ip_events[e["source_ip"]].append(e)

    attackers = []
    for ip, events in ip_events.items():
        severities = [ev["severity"] for ev in events]
        worst = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))
        attackers.append({
            "ip": ip,
            "event_count": len(events),
            "worst_severity": worst,
            "first_seen": events[0]["timestamp"],
            "last_seen": events[-1]["timestamp"],
            "phases": list(set(ev["attack_phase"] for ev in events)),
        })
    attackers.sort(key=lambda a: a["event_count"], reverse=True)
    return attackers


def build_timeline(logs: list[dict]) -> list[dict]:
    """Build a chronological attack timeline from malicious events."""
    timeline = []
    for e in logs:
        if not e.get("is_malicious"):
            continue
        timeline.append({
            "timestamp": e["timestamp"],
            "phase": e["attack_phase"],
            "severity": e["severity"],
            "message": e["message"],
            "source_ip": e["source_ip"],
            "user": e.get("user"),
            "mitre_id": e.get("mitre_id"),
            "event_type": e["event_type"],
        })
    return timeline


def get_phase_summary(logs: list[dict]) -> list[dict]:
    """Group events by MITRE ATT&CK phase."""
    phase_events = defaultdict(list)
    for e in logs:
        if e.get("is_malicious"):
            phase_events[e["attack_phase"]].append(e)

    # Order by first occurrence
    ordered_phases = []
    seen = set()
    for e in logs:
        phase = e.get("attack_phase")
        if phase and phase != "Normal Traffic" and phase not in seen:
            seen.add(phase)
            ordered_phases.append(phase)

    result = []
    for phase in ordered_phases:
        events = phase_events[phase]
        result.append({
            "phase": phase,
            "mitre_id": MITRE_MAP.get(phase),
            "count": len(events),
            "first_event": events[0]["timestamp"],
            "last_event": events[-1]["timestamp"],
            "severity": min(
                (ev["severity"] for ev in events),
                key=lambda s: SEVERITY_ORDER.get(s, 99),
            ),
        })
    return result
