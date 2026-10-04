"""
LogTrace AI — Gemma 4 Analyzer
Feeds structured log chunks to Gemma 4 via the google-genai SDK
for anomaly classification, timeline reconstruction, and triage reporting.
"""
import json
import os

# ──────────────────────────────────────────────
#  Gemma / Gemini client setup
# ──────────────────────────────────────────────
_client = None
MODEL = "gemma-4-26b-a4b-it"  # Gemma 4 MoE — 26B total / 4B active


def _get_client():
    """Lazy-init the genai client."""
    global _client
    if _client is None:
        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return None
        from google import genai
        _client = genai.Client(api_key=api_key)
    return _client


# ──────────────────────────────────────────────
#  Core analysis functions
# ──────────────────────────────────────────────

def analyze_logs(logs: list[dict]) -> dict:
    """
    Send enriched log data to Gemma 4 for comprehensive security analysis.
    Returns a structured analysis dict.
    """
    client = _get_client()
    if client is None:
        return _demo_analysis()

    malicious_logs = [
        {
            "ts": e["timestamp"],
            "src": e["source_ip"],
            "type": e["event_type"],
            "sev": e["severity"],
            "user": e.get("user"),
            "msg": e["message"],
        }
        for e in logs
        if e.get("is_malicious") or e.get("attack_phase") == "Unclassified"
    ]
    
    # Truncate to avoid context window limits on very large files
    if len(malicious_logs) > 500:
        malicious_logs = malicious_logs[-500:]

    log_summary = json.dumps(malicious_logs, indent=2)

    prompt = f"""You are an expert Tier-3 Incident Responder and Lead Forensic Analyst for LogTrace AI.

Your objective is to inspect raw, uploaded security log telemetry and produce a precise, evidence-grounded incident report.

OPERATIONAL CONSTRAINTS & ACCURACY RULES:
1. STRICT DATA GROUNDING:
   - Base all findings, metrics, and indicators STRICTLY on the log data provided below.
   - NEVER invent, simulate, or hallucinate IP addresses, hostnames, usernames, CVEs, or attack vectors that do not appear in the logs.
   - If an attack cannot be definitively confirmed, state that evidence is partial or inconclusive. Do not default to canned attack narratives (e.g., do not claim Tor exit nodes or CVE-2021-4034 unless explicitly visible in the logs).

2. THREAT ACTOR & ATTACK RECONSTRUCTION:
   - Identify the primary threat actor by analyzing anomalous frequency, failed auth spikes, unauthorized file access, or privilege escalation events.
   - Extract the earliest timestamp (first_seen) and latest timestamp (last_seen) specifically associated with that actor.
   - Trace the exact progression across kill-chain phases (e.g., Reconnaissance, Initial Access, Privilege Escalation, Discovery).

3. MITRE ATT&CK ALIGNMENT:
   - Accurately map observed log patterns to official MITRE ATT&CK tactics, technique IDs (e.g., T1110, T1078, T1068, T1087, T1003), and technique names.
   - For every mapped technique, provide exact event counts and specific evidence strings extracted from the logs.

4. DYNAMIC RISK SCORING:
   - Calculate a deterministic risk_score (integer between 0 and 100) based strictly on observed impact:
     * 0-39 (LOW): Routine informational traffic, isolated 404s, benign internal queries.
     * 40-69 (MEDIUM): Scattered failed logins, blocked inbound scans, intermittent policy violations.
     * 70-89 (HIGH): Coordinated brute force attempts, unauthorized access to sensitive configs (/etc/hosts, auth.log).
     * 90-100 (CRITICAL): Confirmed privilege escalation patterns, unauthorized root access, or active command execution.
   - Ensure the 'risk_level' strictly matches the 'risk_score'.

REQUIRED RESPONSE FORMAT:
Output MUST be a single, valid JSON object matching the exact schema below. Do NOT output markdown code blocks (no ```json fences), no preamble, and no postscript.

{{
  "incident_overview": {{
    "title": "Concise headline summarizing the primary incident",
    "risk_score": 0,
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
    "threat_assessment": "1-2 sentence executive assessment of compromise status"
  }},
  "executive_summary": "Comprehensive narrative detailing verified actions, targeted services, compromised accounts, and timeline.",
  "threat_actor": {{
    "primary_ip": "Source IP address causing the primary anomaly",
    "first_seen": "ISO-8601 timestamp string or original log timestamp",
    "last_seen": "ISO-8601 timestamp string or original log timestamp",
    "total_events": 0,
    "max_severity": "LOW | MEDIUM | HIGH | CRITICAL",
    "attack_phases": ["Phase 1", "Phase 2"]
  }},
  "mitre_mapping": [
    {{
      "tactic": "MITRE Tactic Name",
      "technique_id": "TXXXX",
      "technique_name": "Technique Name",
      "event_count": 0,
      "evidence": ["Sample log line or concise evidence snippet"]
    }}
  ],
  "iocs": {{
    "source_ips": ["List of suspicious external/internal source IPs"],
    "targeted_hosts": ["List of targeted destination IPs/hostnames"],
    "targeted_accounts": ["List of targeted usernames"],
    "accessed_paths": ["List of accessed file paths or endpoints"]
  }},
  "mitigations": [
    {{
      "priority": "Immediate | Short-term | Long-term",
      "action": "Concrete, actionable defensive remediation step"
    }}
  ]
}}

LOG DATA TO ANALYZE:
---
{log_summary}
---
"""

    try:
        interaction = client.interactions.create(
            model=MODEL,
            input=prompt,
            store=False,
        )
        text = interaction.output_text or ""
        text = text.strip()
        start_idx = text.find('{')
        end_idx = text.rfind('}')
        if start_idx != -1 and end_idx != -1:
            text = text[start_idx:end_idx+1]
        return json.loads(text)
    except json.JSONDecodeError:
        # If JSON parsing fails, return the raw text wrapped
        return {"executive_summary": text, "raw_response": True}
    except Exception as exc:
        return {"error": str(exc)}


def generate_triage_report(logs: list[dict]) -> str:
    """Generate a human-readable triage report using Gemma 4."""
    client = _get_client()
    if client is None:
        return _demo_report()

    malicious_logs = [e for e in logs if e.get("is_malicious") or e.get("attack_phase") == "Unclassified"]
    if len(malicious_logs) > 500:
        malicious_logs = malicious_logs[-500:]
        
    log_text = "\n".join(e.get("raw", e["message"]) for e in malicious_logs)

    prompt = f"""You are writing an executive incident triage report for a CISO.

Based on the raw security logs below, produce a professional report in Markdown with sections:
## Incident Summary
## Timeline of Events
## Impact Assessment
## Indicators of Compromise
## Immediate Actions Required
## Long-term Recommendations

RAW LOGS:
{log_text}"""

    try:
        interaction = client.interactions.create(
            model=MODEL,
            input=prompt,
            store=False,
        )
        return interaction.output_text or "Analysis unavailable."
    except Exception as exc:
        return f"Error generating report: {exc}"


# ──────────────────────────────────────────────
#  Demo / fallback (no API key)
# ──────────────────────────────────────────────

def _demo_analysis() -> dict:
    """Pre-computed analysis for demo mode."""
    return {
        "incident_overview": {
            "title": "Sophisticated Multi-Phase Attack on prod-web-01",
            "risk_score": 95,
            "risk_level": "CRITICAL",
            "threat_assessment": "Critical compromise of prod-web-01 via SSH brute force and pkexec privilege escalation."
        },
        "executive_summary": "A sophisticated multi-phase attack was detected against prod-web-01 (10.0.1.15) originating from 185.220.101.42 (known Tor exit node). The attacker performed reconnaissance via port scanning, followed by SSH brute force attacks against multiple accounts. After compromising the 'deploy' account, they exploited CVE-2021-4034 (pkexec) to gain root privileges. The attacker then dumped the shadow file, exfiltrated SSH keys and a database dump to an external C2 server, and established persistence via a PHP web shell and a malicious cron job.",
        "threat_actor": {
            "primary_ip": "185.220.101.42",
            "first_seen": "2026-10-04T02:00:15Z",
            "last_seen": "2026-10-04T03:28:42Z",
            "total_events": 28,
            "max_severity": "CRITICAL",
            "attack_phases": ["Reconnaissance", "Initial Access", "Privilege Escalation", "Discovery", "Exfiltration", "Persistence"]
        },
        "mitre_mapping": [
            {
                "tactic": "Reconnaissance",
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "event_count": 3,
                "evidence": ["Nmap scanning activity detected on ports 22, 80, 443"]
            },
            {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "event_count": 12,
                "evidence": ["Failed SSH login attempts for root, admin, deploy"]
            },
            {
                "tactic": "Privilege Escalation",
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "event_count": 1,
                "evidence": ["Successful execution of pkexec exploit (CVE-2021-4034)"]
            }
        ],
        "iocs": {
            "source_ips": ["185.220.101.42", "45.33.32.156"],
            "targeted_hosts": ["10.0.1.15 (prod-web-01)"],
            "targeted_accounts": ["deploy", "root", "sysadm1n"],
            "accessed_paths": ["/etc/shadow", "/tmp/.backup.sql", "/var/www/html/.system_health.php"]
        },
        "mitigations": [
            {
                "priority": "Immediate",
                "action": "Isolate prod-web-01 from the network and block 185.220.101.42 and 45.33.32.156 at the firewall."
            },
            {
                "priority": "Immediate",
                "action": "Disable backdoor account 'sysadm1n' and remove web shell /var/www/html/.system_health.php."
            },
            {
                "priority": "Short-term",
                "action": "Rotate all passwords and SSH keys, and patch pkexec (CVE-2021-4034)."
            },
            {
                "priority": "Long-term",
                "action": "Implement MFA for all SSH access and deploy fail2ban for brute-force protection."
            }
        ],
        "demo_mode": True
    }


def _demo_report() -> str:
    """Pre-computed triage report for demo mode."""
    return """## Incident Summary

A **critical** security incident was detected on **prod-web-01** (10.0.1.15) on October 4, 2026, spanning approximately 02:00–03:28 UTC. An external threat actor operating from **185.220.101.42** (a known Tor exit node) successfully compromised the server through SSH brute force, escalated privileges to root, exfiltrated sensitive data, and installed multiple persistence mechanisms.

## Timeline of Events

| Time (UTC) | Phase | Event |
|---|---|---|
| 02:00 | Reconnaissance | Port scanning detected (22, 80, 443, 3306, 5432, 8080) |
| 02:15–02:30 | Brute Force | 15+ SSH login attempts across root, admin, deploy, ubuntu |
| 02:47 | Initial Access | Successful SSH login as 'deploy' |
| 02:48 | Enumeration | System reconnaissance (whoami, /etc/passwd) |
| 02:48–02:49 | Privilege Escalation | Sudo denied → SUID search → pkexec exploit |
| 02:50 | Privilege Escalation | Root shell obtained via pkexec vulnerability |
| 02:52–02:55 | Data Access | /etc/shadow read, PostgreSQL database dumped |
| 02:57–02:58 | Exfiltration | Database + SSH keys sent to C2 (45.33.32.156) |
| 03:02–03:08 | Persistence | Backdoor user, crontab reverse shell, web shell |
| 03:10 | Defense Evasion | Auth logs truncated, bash history cleared |
| 03:15 | Web Exploitation | Command injection probes via web app |
| 03:25 | Disruption | iptables rule to block internal subnet |

## Impact Assessment

- **Confidentiality**: SEVERE — Production database and all SSH keys exfiltrated
- **Integrity**: HIGH — Backdoor accounts, web shell, and crontab entries installed
- **Availability**: MEDIUM — Network disruption attempted via iptables

## Indicators of Compromise

- `185.220.101.42` — Attacker source IP
- `45.33.32.156:8443` — C2 / exfiltration endpoint
- `45.33.32.156:4444` — Reverse shell callback
- `/var/www/html/.system_health.php` — PHP web shell
- `/tmp/.backup.sql` — Database dump staging
- `/tmp/.ssh_keys.tar.gz` — SSH key archive
- User `sysadm1n` — Backdoor account

## Immediate Actions Required

1. **Isolate** prod-web-01 from the network immediately
2. **Block** IPs 185.220.101.42 and 45.33.32.156 at all perimeter defenses
3. **Remove** backdoor user 'sysadm1n', malicious crontab, and web shell
4. **Reset** ALL credentials — SSH keys, database passwords, deploy account
5. **Preserve** forensic evidence before any remediation

## Long-term Recommendations

1. Enforce **multi-factor authentication** on all SSH access
2. Deploy **fail2ban** with aggressive thresholds for brute force mitigation
3. Implement **centralized, immutable logging** (ship to SIEM/WORM storage)
4. Patch **pkexec** (CVE-2021-4034) and audit all SUID binaries
5. Implement **egress filtering** to prevent unauthorized data transfers
6. Conduct a **full incident response** to check for lateral movement
"""


def chat_with_logs(query: str, logs: list[dict]) -> str:
    """Chat with the SOC logs using Gemma 4."""
    client = _get_client()
    if client is None:
        # Fallback responses for demo mode
        query_lower = query.lower()
        if "root" in query_lower:
            return "The attacker brute-forced the 'deploy' account, escalated to **root** via a pkexec vulnerability, dumped the shadow file, and executed commands to exfiltrate the database and SSH keys."
        elif "ip" in query_lower:
            return "The primary attacker IP is **185.220.101.42** (a known Tor exit node), and the C2 exfiltration server is **45.33.32.156**."
        elif "fix" in query_lower or "remediate" in query_lower:
            return "Immediate actions: Isolate prod-web-01, block 185.220.101.42 and 45.33.32.156, remove the 'sysadm1n' backdoor, delete `/var/www/html/.system_health.php`, and rotate all credentials."
        return "I am operating in DEMO mode without an API key, so my responses are limited. Based on the logs, there is a critical compromise involving SSH brute force and privilege escalation to root."

    # Build concise log context
    malicious_logs = [
        {"ts": e["timestamp"], "user": e.get("user", ""), "msg": e["message"]}
        for e in logs if e.get("is_malicious") or e.get("attack_phase") == "Unclassified"
    ]
    if len(malicious_logs) > 500:
        malicious_logs = malicious_logs[-500:]
        
    log_summary = json.dumps(malicious_logs, indent=2)

    prompt = f"""You are a brilliant SOC (Security Operations Center) AI assistant powered by Gemma 4.
You are helping a human security analyst investigate an active incident.

CONTEXT LOGS:
{log_summary}

ANALYST QUERY: {query}

Provide a concise, helpful, and technically accurate response based ONLY on the provided logs. Use markdown for formatting."""

    try:
        interaction = client.interactions.create(
            model=MODEL,
            input=prompt,
            store=False,
        )
        return interaction.output_text or "No response generated."
    except Exception as exc:
        return f"Error connecting to Gemma 4: {exc}"
