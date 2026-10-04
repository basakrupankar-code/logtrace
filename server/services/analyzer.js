const { GoogleGenAI } = require("@google/genai");

const MODEL = "gemini-2.5-pro";

let genaiClient = null;

function getClient() {
    if (genaiClient) return genaiClient;
    const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
    if (apiKey) {
        genaiClient = new GoogleGenAI({ apiKey });
        return genaiClient;
    }
    return null;
}

function demoReport() {
    return `
# Incident Triage Report (Demo Mode)

**Note:** This is a simulated report. To enable live Gemini analysis, set the \`GOOGLE_API_KEY\` environment variable.

## Incident Summary
A coordinated, multi-phase attack was executed against \`prod-web-01\` (10.0.1.15). The threat actor gained initial access via SSH brute force, escalated privileges using the \`pkexec\` vulnerability (CVE-2021-4034), and successfully exfiltrated production database dumps and SSH keys to an external C2 server. 

## Timeline of Events
* **02:00:15 UTC:** Port scanning (SYN scan) detected from 185.220.101.42.
* **02:15:33 UTC:** SSH brute force campaign initiated against \`root\`, \`admin\`, and \`deploy\`.
* **02:47:11 UTC:** Successful SSH login for user \`deploy\` from 185.220.101.42.
* **02:50:04 UTC:** Privilege escalation to \`root\` via pkexec exploit.
* **02:51:12 UTC:** Unauthorized access to \`/etc/shadow\`.
* **03:10:45 UTC:** Data exfiltration detected (\`/tmp/.backup.sql\` sent to 45.33.32.156).
* **03:28:42 UTC:** Log tampering (auth.log truncated) to evade detection.

## Impact Assessment
**CRITICAL.** The attacker achieved full root compromise and successfully exfiltrated sensitive data, including password hashes and production database contents.

## Indicators of Compromise
* **Source IPs:** \`185.220.101.42\` (Initial Access), \`45.33.32.156\` (C2/Exfiltration)
* **Compromised Accounts:** \`deploy\`, \`root\`
* **Backdoor Accounts:** \`sysadm1n\`
* **Malicious Files:** \`/var/www/html/.system_health.php\` (Web shell)

## Immediate Actions Required
1. **Isolate:** Immediately disconnect \`prod-web-01\` from the network.
2. **Block:** Block IPs \`185.220.101.42\` and \`45.33.32.156\` at the firewall.
3. **Revoke:** Delete the \`sysadm1n\` backdoor account and reset all passwords/SSH keys for \`deploy\` and \`root\`.

## Long-term Recommendations
1. Implement Multi-Factor Authentication (MFA) for all SSH access.
2. Ensure all systems are patched against known vulnerabilities (e.g., CVE-2021-4034).
3. Deploy network segmentation to limit lateral movement from web servers.
    `.trim();
}

function demoAnalysis() {
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
        "demo_mode": true
    };
}

async function analyzeLogs(logs) {
    const client = getClient();
    if (!client) {
        return demoAnalysis();
    }

    let maliciousLogs = logs.filter(e => e.is_malicious || e.attack_phase === "Unclassified");
    if (maliciousLogs.length > 500) {
        maliciousLogs = maliciousLogs.slice(-500);
    }
    
    const logSummary = JSON.stringify(maliciousLogs, null, 2);

    const prompt = `You are an expert Tier-3 Incident Responder and Lead Forensic Analyst for LogTrace AI.

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
Output MUST be a single, valid JSON object matching the exact schema below. Do NOT output markdown code blocks (no \`\`\`json fences), no preamble, and no postscript.

{
  "incident_overview": {
    "title": "Concise headline summarizing the primary incident",
    "risk_score": 0,
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
    "threat_assessment": "1-2 sentence executive assessment of compromise status"
  },
  "executive_summary": "Comprehensive narrative detailing verified actions, targeted services, compromised accounts, and timeline.",
  "threat_actor": {
    "primary_ip": "Source IP address causing the primary anomaly",
    "first_seen": "ISO-8601 timestamp string or original log timestamp",
    "last_seen": "ISO-8601 timestamp string or original log timestamp",
    "total_events": 0,
    "max_severity": "LOW | MEDIUM | HIGH | CRITICAL",
    "attack_phases": ["Phase 1", "Phase 2"]
  },
  "mitre_mapping": [
    {
      "tactic": "MITRE Tactic Name",
      "technique_id": "TXXXX",
      "technique_name": "Technique Name",
      "event_count": 0,
      "evidence": ["Sample log line or concise evidence snippet"]
    }
  ],
  "iocs": {
    "source_ips": ["List of suspicious external/internal source IPs"],
    "targeted_hosts": ["List of targeted destination IPs/hostnames"],
    "targeted_accounts": ["List of targeted usernames"],
    "accessed_paths": ["List of accessed file paths or endpoints"]
  },
  "mitigations": [
    {
      "priority": "Immediate | Short-term | Long-term",
      "action": "Concrete, actionable defensive remediation step"
    }
  ]
}

LOG DATA TO ANALYZE:
---
${logSummary}
---`;

    try {
        const response = await client.models.generateContent({
            model: MODEL,
            contents: prompt,
            config: {
                temperature: 0.2
            }
        });
        let text = response.text || "";
        text = text.trim();
        const startIdx = text.indexOf('{');
        const endIdx = text.lastIndexOf('}');
        if (startIdx !== -1 && endIdx !== -1) {
            text = text.substring(startIdx, endIdx + 1);
        }
        return JSON.parse(text);
    } catch (err) {
        console.error("AI Analysis Error:", err);
        return { error: err.message, executive_summary: "AI analysis failed." };
    }
}

async function generateTriageReport(logs) {
    const client = getClient();
    if (!client) {
        return demoReport();
    }

    let maliciousLogs = logs.filter(e => e.is_malicious || e.attack_phase === "Unclassified");
    if (maliciousLogs.length > 500) {
        maliciousLogs = maliciousLogs.slice(-500);
    }
    
    const logText = maliciousLogs.map(e => e.raw || e.message).join("\\n");

    const prompt = `You are writing an executive incident triage report for a CISO.

Based on the raw security logs below, produce a professional report in Markdown with sections:
## Incident Summary
## Timeline of Events
## Impact Assessment
## Indicators of Compromise
## Immediate Actions Required
## Long-term Recommendations

RAW LOGS:
${logText}`;

    try {
        const response = await client.models.generateContent({
            model: MODEL,
            contents: prompt,
            config: {
                temperature: 0.2
            }
        });
        return response.text || "Analysis unavailable.";
    } catch (err) {
        console.error("Report Generation Error:", err);
        return "Error generating report: " + err.message;
    }
}

module.exports = {
    analyzeLogs,
    generateTriageReport
};
