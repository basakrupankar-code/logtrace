const fs = require('fs');

const SEVERITY_ORDER = { "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4 };

const ATTACK_PHASE_MAP = {
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
};

const MITRE_MAP = {
    "Reconnaissance": "TA0043",
    "Brute Force": "T1110",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Privilege Escalation": "TA0004",
    "Discovery": "TA0007",
    "Exfiltration": "TA0010",
    "Persistence": "TA0003",
    "Defense Evasion": "TA0005",
    "Normal Traffic": null,
};

function loadLogs(filepath) {
    try {
        const data = fs.readFileSync(filepath, 'utf8');
        const logs = JSON.parse(data);
        logs.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
        return logs;
    } catch (e) {
        console.error("Error loading logs", e);
        return [];
    }
}

function enrichLog(entry) {
    let eventType = entry.event_type || "unknown";

    // Attempt to extract IP if it's missing or unknown
    if (!entry.source_ip || entry.source_ip === 'Unknown') {
        const textToSearch = entry.message || JSON.stringify(entry);
        const ipMatch = textToSearch.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (ipMatch) {
            entry.source_ip = ipMatch[0];
        }
    }

    // Attempt to extract timestamp if missing or 'now'
    if (!entry.timestamp || entry.timestamp.startsWith('2026-')) {
        const textToSearch = entry.message || JSON.stringify(entry);
        // Match common log date formats like "Oct 04 12:00:00" or ISO
        const timeMatch = textToSearch.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/);
        if (timeMatch) {
            entry.timestamp = timeMatch[0];
        }
    }

    let attackPhase = ATTACK_PHASE_MAP[eventType];

    // Heuristic parsing for unknown, raw, or csv logs
    if (!attackPhase || eventType === 'raw_text' || eventType === 'csv_log' || eventType === 'unknown') {
        const lowerText = (entry.message || JSON.stringify(entry)).toLowerCase();
        
        if (lowerText.includes("nmap") || lowerText.includes("scan") || lowerText.includes("recon")) {
            attackPhase = "Reconnaissance";
            entry.event_type = "port_scan";
        } else if (lowerText.includes("failed password") || lowerText.includes("brute") || lowerText.includes("invalid user") || lowerText.includes("fail") || lowerText.includes("denied")) {
            attackPhase = "Brute Force";
            entry.event_type = "ssh_failed";
        } else if (lowerText.includes("sql") || lowerText.includes("injection") || lowerText.includes("select ") || lowerText.includes("union ")) {
            attackPhase = "Execution";
            entry.event_type = "command_injection";
        } else if (lowerText.includes("sudo") || lowerText.includes("root") || lowerText.includes("pkexec")) {
            attackPhase = "Privilege Escalation";
            entry.event_type = "privilege_escalation";
        } else if (lowerText.includes("shadow") || lowerText.includes("passwd") || lowerText.includes("cat /etc")) {
            attackPhase = "Discovery";
            entry.event_type = "file_access";
        } else if (lowerText.includes("wget") || lowerText.includes("curl") || lowerText.includes("download") || lowerText.includes("exfiltrat")) {
            attackPhase = "Exfiltration";
            entry.event_type = "data_exfiltration";
        } else if (lowerText.includes("backdoor") || lowerText.includes("webshell") || lowerText.includes("cron")) {
            attackPhase = "Persistence";
            entry.event_type = "persistence";
        } else if (lowerText.includes("tamper") || lowerText.includes("clear") || lowerText.includes("rm -rf")) {
            attackPhase = "Defense Evasion";
            entry.event_type = "log_tampering";
        } else if (lowerText.includes("accepted password") || lowerText.includes("session opened") || lowerText.includes("login") || lowerText.includes("success")) {
            attackPhase = "Initial Access";
            entry.event_type = "ssh_success";
        } else {
            attackPhase = "Unclassified";
        }
    }

    entry.attack_phase = attackPhase;
    entry.mitre_id = MITRE_MAP[attackPhase] || null;
    entry.is_malicious = (attackPhase !== "Normal Traffic" && attackPhase !== "Unclassified");
    
    if (!entry.severity || entry.severity === "info") {
        entry.severity = entry.is_malicious ? "medium" : "info";
        if (attackPhase === "Privilege Escalation" || attackPhase === "Exfiltration" || attackPhase === "Persistence") {
            entry.severity = "high";
        }
    }
        
    return entry;
}

function enrichAll(logs) {
    return logs.map(enrichLog);
}

function getThreatSummary(logs) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let malicious = 0;
    
    logs.forEach(e => {
        const sev = e.severity || "info";
        if (counts[sev] !== undefined) {
            counts[sev]++;
        }
        if (e.is_malicious) {
            malicious++;
        }
    });

    return {
        ...counts,
        total: logs.length,
        malicious
    };
}

function getAttackerIps(logs) {
    const ipEvents = {};
    
    logs.forEach(e => {
        if (e.is_malicious) {
            if (!ipEvents[e.source_ip]) ipEvents[e.source_ip] = [];
            ipEvents[e.source_ip].push(e);
        }
    });

    const attackers = Object.entries(ipEvents).map(([ip, events]) => {
        const severities = events.map(ev => ev.severity);
        let worst = severities[0];
        let minVal = 99;
        
        severities.forEach(s => {
            const val = SEVERITY_ORDER[s] !== undefined ? SEVERITY_ORDER[s] : 99;
            if (val < minVal) {
                minVal = val;
                worst = s;
            }
        });
        
        const phasesSet = new Set(events.map(ev => ev.attack_phase));
        
        return {
            ip,
            event_count: events.length,
            worst_severity: worst,
            first_seen: events[0].timestamp,
            last_seen: events[events.length - 1].timestamp,
            phases: Array.from(phasesSet)
        };
    });

    attackers.sort((a, b) => b.event_count - a.event_count);
    return attackers;
}

function buildTimeline(logs) {
    const timeline = [];
    logs.forEach(e => {
        if (!e.is_malicious) return;
        timeline.push({
            timestamp: e.timestamp,
            phase: e.attack_phase,
            severity: e.severity,
            message: e.message,
            source_ip: e.source_ip,
            user: e.user,
            mitre_id: e.mitre_id,
            event_type: e.event_type
        });
    });
    return timeline;
}

function getPhaseSummary(logs) {
    const phaseEvents = {};
    logs.forEach(e => {
        if (e.is_malicious) {
            if (!phaseEvents[e.attack_phase]) phaseEvents[e.attack_phase] = [];
            phaseEvents[e.attack_phase].push(e);
        }
    });

    const orderedPhases = [];
    const seen = new Set();
    
    logs.forEach(e => {
        const phase = e.attack_phase;
        if (phase && phase !== "Normal Traffic" && !seen.has(phase)) {
            seen.add(phase);
            orderedPhases.push(phase);
        }
    });

    const result = [];
    orderedPhases.forEach(phase => {
        const events = phaseEvents[phase];
        if (!events) return;
        
        let worst = events[0].severity;
        let minVal = 99;
        events.forEach(ev => {
            const val = SEVERITY_ORDER[ev.severity] !== undefined ? SEVERITY_ORDER[ev.severity] : 99;
            if (val < minVal) {
                minVal = val;
                worst = ev.severity;
            }
        });

        result.push({
            phase,
            mitre_id: MITRE_MAP[phase] || null,
            count: events.length,
            first_event: events[0].timestamp,
            last_event: events[events.length - 1].timestamp,
            severity: worst
        });
    });
    
    return result;
}

module.exports = {
    loadLogs,
    enrichLog,
    enrichAll,
    getThreatSummary,
    getAttackerIps,
    buildTimeline,
    getPhaseSummary
};
