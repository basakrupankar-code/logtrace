/**
 * LogTrace AI — Dashboard JavaScript
 * Handles data fetching, rendering, and interactivity.
 */

// ════════════════════════════════════════════
//  Constants & State
// ════════════════════════════════════════════
const SEVERITY_COLORS = {
    critical: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', dot: 'bg-red-500', ring: '#ef4444' },
    high:     { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', dot: 'bg-orange-500', ring: '#f97316' },
    medium:   { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-500', ring: '#eab308' },
    low:      { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', dot: 'bg-green-500', ring: '#22c55e' },
    info:     { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', dot: 'bg-blue-500', ring: '#3b82f6' },
};

const SEVERITY_ICONS = {
    critical: '🔴',
    high:     '🟠',
    medium:   '🟡',
    low:      '🟢',
    info:     '🔵',
};

const PHASE_ICONS = {
    'Reconnaissance':       '🔍',
    'Brute Force':          '🔨',
    'Initial Access':       '🚪',
    'Execution':            '⚡',
    'Privilege Escalation': '⬆️',
    'Discovery':            '🗺️',
    'Exfiltration':         '📤',
    'Persistence':          '🔗',
    'Defense Evasion':      '🛡️',
};

let analysisData = null;
let currentTab = 'summary';

// ════════════════════════════════════════════
//  Init
// ════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    setInterval(updateClock, 1000);
    loadDashboard();
});

async function loadDashboard() {
    try {
        const [logs, summary, timeline, phases, attackers] = await Promise.all([
            fetchJSON('/api/logs'),
            fetchJSON('/api/summary'),
            fetchJSON('/api/timeline'),
            fetchJSON('/api/phases'),
            fetchJSON('/api/attackers'),
        ]);

        renderThreatCards(summary);
        renderLogFeed(logs);
        renderTimeline(phases, timeline);
        renderPhaseList(phases);
        renderAttackerProfile(attackers);
        document.getElementById('log-count').textContent = `${logs.length} events`;
    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

// ════════════════════════════════════════════
//  Data Fetching & Upload
// ════════════════════════════════════════════
async function fetchJSON(url, opts = {}) {
    const resp = await fetch(url, opts);
    if (!resp.ok) throw new Error(`${url}: ${resp.status}`);
    return resp.json();
}

async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    // Reset input so they can upload the same file again if needed
    event.target.value = '';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Upload failed');
        
        // Clear log feed and reload dashboard
        document.getElementById('log-feed').innerHTML = '';
        analysisData = null; // Clear cached frontend analysis
        
        // Ensure analysis placeholder is visible and tabs hidden
        document.getElementById('analysis-placeholder').classList.remove('hidden');
        document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
        
        // Reset risk ring
        renderRiskScore(0);
        
        // Load the new dashboard data
        await loadDashboard();
        
        // Send a system message to chat
        appendChatMessage('gemma', `<span class="text-green-400">Successfully loaded ${data.count} new log events from <strong>${file.name}</strong>. Ready for analysis.</span>`);
        
    } catch (err) {
        console.error('Upload error:', err);
        alert('Failed to upload logs: ' + err.message);
    }
}

// ════════════════════════════════════════════
//  Threat Summary Cards
// ════════════════════════════════════════════
function renderThreatCards(summary) {
    const container = document.getElementById('threat-cards');
    const cards = [
        { label: 'Critical', key: 'critical', sev: 'critical' },
        { label: 'High',     key: 'high',     sev: 'high' },
        { label: 'Medium',   key: 'medium',   sev: 'medium' },
        { label: 'Low',      key: 'low',      sev: 'low' },
        { label: 'Total',    key: 'total',     sev: 'info' },
    ];

    container.innerHTML = cards.map((c, i) => {
        const colors = SEVERITY_COLORS[c.sev];
        const count = summary[c.key] || 0;
        return `
            <div class="${colors.bg} border ${colors.border} rounded-xl p-4 flex flex-col items-center gap-1 animate-slide-up"
                 style="animation-delay: ${i * 80}ms">
                <span class="text-2xl font-bold ${colors.text}">${count}</span>
                <span class="text-[10px] uppercase tracking-wider text-gray-500">${c.label}</span>
            </div>
        `;
    }).join('');
}

// ════════════════════════════════════════════
//  Log Feed (left panel)
// ════════════════════════════════════════════
function renderLogFeed(logs) {
    const feed = document.getElementById('log-feed');
    feed.innerHTML = '';
    // Simulate real-time by adding entries with staggered delays
    logs.forEach((log, i) => {
        setTimeout(() => {
            const el = document.createElement('div');
            const colors = SEVERITY_COLORS[log.severity] || SEVERITY_COLORS.info;
            const time = log.timestamp.split('T')[1]?.replace('Z', '') || '';
            el.className = `px-2 py-1.5 rounded-md ${colors.bg} border ${colors.border} animate-fade-in cursor-pointer hover:brightness-125 transition-all`;
            el.innerHTML = `
                <div class="flex items-center gap-1.5">
                    <span class="w-1.5 h-1.5 rounded-full ${colors.dot} flex-shrink-0"></span>
                    <span class="text-gray-500">${time}</span>
                    <span class="${colors.text} font-medium truncate">${log.event_type.replace(/_/g, ' ')}</span>
                </div>
                <div class="text-gray-400 truncate mt-0.5 pl-3">${log.source_ip} → ${log.message.substring(0, 60)}…</div>
            `;
            el.title = log.raw || log.message;
            feed.appendChild(el);
            feed.scrollTop = feed.scrollHeight;
        }, i * 60); // 60ms stagger for animation effect
    });
}

// ════════════════════════════════════════════
//  Attack Timeline (center)
// ════════════════════════════════════════════
function renderTimeline(phases, events) {
    const container = document.getElementById('attack-timeline');

    // Horizontal phase flow
    const phaseHTML = phases.map((p, i) => {
        const colors = SEVERITY_COLORS[p.severity] || SEVERITY_COLORS.info;
        const icon = PHASE_ICONS[p.phase] || '❓';
        const isLast = i === phases.length - 1;
        return `
            <div class="flex items-center animate-fade-in" style="animation-delay: ${i * 120}ms">
                <div class="flex flex-col items-center gap-2 min-w-[120px]">
                    <div class="w-12 h-12 rounded-xl ${colors.bg} border ${colors.border} flex items-center justify-center text-xl
                                hover:scale-110 transition-transform cursor-default" title="${p.phase} — ${p.count} events">
                        ${icon}
                    </div>
                    <div class="text-center">
                        <div class="text-xs font-medium ${colors.text}">${p.phase}</div>
                        <div class="text-[10px] text-gray-500">${p.mitre_id || ''}</div>
                        <div class="text-[10px] text-gray-600">${p.count} events</div>
                    </div>
                </div>
                ${!isLast ? `
                    <div class="flex-shrink-0 w-10 h-px bg-gradient-to-r from-gray-600 to-gray-700 mx-1 relative">
                        <div class="absolute right-0 top-1/2 -translate-y-1/2 w-0 h-0 border-t-[3px] border-t-transparent border-b-[3px] border-b-transparent border-l-[5px] border-l-gray-600"></div>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');

    // Event detail list below the phase flow
    const criticalEvents = events.filter(e => e.severity === 'critical').slice(0, 8);
    const eventHTML = criticalEvents.map(e => {
        const colors = SEVERITY_COLORS[e.severity];
        const time = e.timestamp.split('T')[1]?.replace('Z', '') || '';
        return `
            <div class="flex items-start gap-3 py-2 border-b border-cyber-border/50 last:border-0">
                <span class="text-[10px] text-gray-500 font-mono w-14 flex-shrink-0 pt-0.5">${time}</span>
                <span class="w-1.5 h-1.5 rounded-full ${colors.dot} mt-1.5 flex-shrink-0"></span>
                <div class="min-w-0">
                    <span class="text-xs ${colors.text} font-medium">[${e.phase}]</span>
                    <span class="text-xs text-gray-300 ml-1">${e.message}</span>
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = `
        <div class="flex items-start overflow-x-auto pb-4 gap-0">${phaseHTML}</div>
        <div class="mt-4 border-t border-cyber-border pt-3">
            <div class="text-[10px] uppercase tracking-wider text-gray-500 mb-2">Critical Events</div>
            <div class="space-y-0">${eventHTML}</div>
        </div>
    `;
}

// ════════════════════════════════════════════
//  Kill Chain Phases (right panel)
// ════════════════════════════════════════════
function renderPhaseList(phases) {
    const container = document.getElementById('phase-list');
    container.innerHTML = phases.map(p => {
        const colors = SEVERITY_COLORS[p.severity] || SEVERITY_COLORS.info;
        const icon = PHASE_ICONS[p.phase] || '❓';
        return `
            <div class="${colors.bg} border ${colors.border} rounded-lg p-3 flex items-center gap-3 hover:brightness-125 transition-all cursor-default">
                <span class="text-lg">${icon}</span>
                <div class="flex-1 min-w-0">
                    <div class="text-xs font-medium text-white">${p.phase}</div>
                    <div class="text-[10px] text-gray-500">${p.mitre_id || 'N/A'} · ${p.count} events</div>
                </div>
                <span class="text-[10px] px-2 py-0.5 rounded-full ${colors.bg} ${colors.text} font-medium uppercase">${p.severity}</span>
            </div>
        `;
    }).join('');
}

// ════════════════════════════════════════════
//  Attacker Profile (right panel)
// ════════════════════════════════════════════
function renderAttackerProfile(attackers) {
    const container = document.getElementById('attacker-profile');
    if (!attackers.length) {
        container.innerHTML = '<p class="text-gray-500 text-xs">No attackers identified.</p>';
        return;
    }

    const primary = attackers[0];
    container.innerHTML = `
        <div class="flex items-center gap-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
            <div class="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center text-red-400">
                <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0"/>
                </svg>
            </div>
            <div>
                <div class="text-sm font-semibold text-red-400 font-mono">${primary.ip}</div>
                <div class="text-[10px] text-gray-500">Primary Threat Actor</div>
            </div>
        </div>
        <div class="grid grid-cols-2 gap-2 text-xs">
            <div class="bg-cyber-card rounded-lg p-2.5">
                <div class="text-gray-500 text-[10px]">Events</div>
                <div class="text-white font-semibold">${primary.event_count}</div>
            </div>
            <div class="bg-cyber-card rounded-lg p-2.5">
                <div class="text-gray-500 text-[10px]">Max Severity</div>
                <div class="${SEVERITY_COLORS[primary.worst_severity]?.text || 'text-white'} font-semibold capitalize">${primary.worst_severity}</div>
            </div>
            <div class="bg-cyber-card rounded-lg p-2.5">
                <div class="text-gray-500 text-[10px]">First Seen</div>
                <div class="text-white font-mono text-[11px]">${primary.first_seen.split('T')[1]?.replace('Z','')}</div>
            </div>
            <div class="bg-cyber-card rounded-lg p-2.5">
                <div class="text-gray-500 text-[10px]">Last Seen</div>
                <div class="text-white font-mono text-[11px]">${primary.last_seen.split('T')[1]?.replace('Z','')}</div>
            </div>
        </div>
        <div class="space-y-1">
            <div class="text-[10px] text-gray-500 uppercase tracking-wider">Attack Phases</div>
            <div class="flex flex-wrap gap-1">
                ${primary.phases.map(ph => `<span class="text-[10px] px-2 py-0.5 rounded-full bg-cyber-card border border-cyber-border text-gray-300">${ph}</span>`).join('')}
            </div>
        </div>
    `;
}

// ════════════════════════════════════════════
//  Gemma 4 Analysis
// ════════════════════════════════════════════
async function runAnalysis() {
    const btn = document.getElementById('analyze-btn');
    const placeholder = document.getElementById('analysis-placeholder');

    btn.disabled = true;
    btn.innerHTML = `
        <svg class="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
        </svg>
        Analyzing with Gemma 4…
    `;

    try {
        analysisData = await fetchJSON('/api/analyze', { method: 'POST' });
        placeholder.classList.add('hidden');
        renderAnalysisTabs(analysisData);
        renderRiskScore(analysisData.incident_overview?.risk_score || 0);
        switchTab('summary');
        
        // Refresh dashboard widgets with the updated classifications
        await loadDashboard();
    } catch (err) {
        btn.textContent = 'Retry Analysis';
        btn.disabled = false;
        console.error('Analysis error:', err);
    }
}

function renderAnalysisTabs(data) {
    // Summary
    document.getElementById('tab-summary').innerHTML = `
        <div class="space-y-4">
            ${data.demo_mode ? '<div class="text-[10px] px-3 py-1.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 inline-block mb-3">⚡ Demo Mode — Set GOOGLE_API_KEY for live Gemma 4 analysis</div>' : ''}
            <div>
                <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-2">Incident Overview</h3>
                <p class="text-sm text-gray-300 font-bold">${data.incident_overview?.title || 'Unknown Incident'}</p>
            </div>
            <div>
                <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-2">Threat Assessment</h3>
                <p class="text-sm font-semibold text-red-400">${data.incident_overview?.threat_assessment || 'N/A'}</p>
            </div>
            ${data.threat_actor ? `
            <div>
                <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-2">Threat Actor</h3>
                <div class="grid grid-cols-2 gap-2 text-xs">
                    <div class="bg-cyber-card rounded-lg p-2.5">
                        <div class="text-gray-500 text-[10px]">Primary IP</div>
                        <div class="text-orange-400 font-semibold">${data.threat_actor.primary_ip}</div>
                    </div>
                    <div class="bg-cyber-card rounded-lg p-2.5">
                        <div class="text-gray-500 text-[10px]">Max Severity</div>
                        <div class="text-red-400 font-semibold">${data.threat_actor.max_severity}</div>
                    </div>
                </div>
                <div class="mt-2 flex flex-wrap gap-1">
                    ${(data.threat_actor.attack_phases || []).map(p => `<span class="text-[10px] px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400">${p}</span>`).join('')}
                </div>
            </div>` : ''}
        </div>
    `;

    // Narrative / Executive Summary
    document.getElementById('tab-narrative').innerHTML = `
        <div>
            <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-3">Executive Summary</h3>
            <p class="text-sm text-gray-300 leading-relaxed whitespace-pre-line">${data.executive_summary || 'No summary available.'}</p>
        </div>
    `;

    // IOCs
    const iocs = [];
    if (data.iocs) {
        Object.entries(data.iocs).forEach(([key, arr]) => {
            if (Array.isArray(arr)) {
                arr.forEach(val => iocs.push(`${key.replace(/_/g, ' ').toUpperCase()}: ${val}`));
            }
        });
    }
    
    document.getElementById('tab-iocs').innerHTML = `
        <div>
            <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-3">Indicators of Compromise (${iocs.length})</h3>
            <div class="space-y-2">
                ${iocs.map(ioc => `
                    <div class="flex items-center gap-2 px-3 py-2 bg-cyber-card rounded-lg border border-cyber-border font-mono text-xs text-red-400">
                        <span class="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0"></span>
                        ${ioc}
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    // MITRE
    const techniques = data.mitre_mapping || [];
    document.getElementById('tab-mitre').innerHTML = `
        <div>
            <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-3">MITRE ATT&CK Techniques (${techniques.length})</h3>
            <div class="space-y-2">
                ${techniques.map(t => `
                    <div class="px-3 py-2.5 bg-cyber-card rounded-lg border border-cyber-border">
                        <div class="flex items-center gap-2">
                            <span class="text-[10px] px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 font-mono font-semibold">${t.technique_id}</span>
                            <span class="text-xs font-medium text-white">${t.technique_name}</span>
                        </div>
                        <p class="text-[11px] text-gray-400 mt-1">${t.tactic} - ${(t.evidence || []).join(', ')}</p>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    // Mitigation
    const steps = data.mitigations || [];
    document.getElementById('tab-mitigation').innerHTML = `
        <div>
            <h3 class="text-xs uppercase tracking-wider text-gray-500 mb-3">Remediation Steps (${steps.length})</h3>
            <div class="space-y-2">
                ${steps.map(s => `
                    <div class="flex items-start gap-2 px-3 py-2 bg-cyber-card rounded-lg border border-cyber-border text-xs text-gray-300">
                        <span class="mt-0.5">•</span>
                        <span><strong class="text-${(s.priority || '').toLowerCase() === 'immediate' ? 'red-400' : 'orange-400'}">[${s.priority ? s.priority.toUpperCase() : 'ACTION'}]</strong> ${s.action}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

function renderRiskScore(score) {
    const ring = document.getElementById('risk-ring');
    const label = document.getElementById('risk-label');
    const scoreEl = document.getElementById('risk-score');

    const circumference = 2 * Math.PI * 52; // ~326.73
    const offset = circumference - (score / 100) * circumference;

    // Determine color by score
    let color, labelText, labelClass;
    if (score >= 80) {
        color = '#ef4444'; labelText = 'CRITICAL'; labelClass = 'bg-red-500/10 text-red-400 border border-red-500/30';
    } else if (score >= 60) {
        color = '#f97316'; labelText = 'HIGH'; labelClass = 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
    } else if (score >= 40) {
        color = '#eab308'; labelText = 'MEDIUM'; labelClass = 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
    } else {
        color = '#22c55e'; labelText = 'LOW'; labelClass = 'bg-green-500/10 text-green-400 border border-green-500/30';
    }

    ring.style.stroke = color;
    ring.style.strokeDashoffset = offset;
    ring.style.filter = `drop-shadow(0 0 6px ${color}40)`;
    scoreEl.textContent = score;
    scoreEl.style.color = color;
    label.textContent = labelText;
    label.className = `text-xs font-medium px-3 py-1 rounded-full ${labelClass}`;
}

// ════════════════════════════════════════════
//  Tab Switching
// ════════════════════════════════════════════
function switchTab(tab) {
    if (!analysisData) return;
    currentTab = tab;

    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });

    // Show/hide content
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    const target = document.getElementById(`tab-${tab}`);
    if (target) target.classList.remove('hidden');
}

// ════════════════════════════════════════════
//  Triage Report
// ════════════════════════════════════════════
async function generateReport() {
    const btn = document.getElementById('report-btn');
    btn.disabled = true;
    btn.innerHTML = `
        <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
        </svg>
        Generating Report…
    `;

    try {
        const data = await fetchJSON('/api/report', { method: 'POST' });
        const content = document.getElementById('report-content');
        content.innerHTML = marked.parse(data.report || 'No report generated.');
        document.getElementById('report-modal').classList.remove('hidden');
    } catch (err) {
        console.error('Report error:', err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/>
            </svg>
            Generate Executive Report
        `;
    }
}

function closeReport() {
    document.getElementById('report-modal').classList.add('hidden');
}

// ════════════════════════════════════════════
//  Header Clock
// ════════════════════════════════════════════
function updateClock() {
    const el = document.getElementById('header-clock');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' UTC' + (now.getTimezoneOffset() > 0 ? '-' : '+') + String(Math.abs(now.getTimezoneOffset() / 60)).padStart(2, '0') + ':00';
}

// ════════════════════════════════════════════
//  API Status indicator
// ════════════════════════════════════════════
(function setApiStatus() {
    const el = document.getElementById('api-status');
    // Check if page was rendered with has_api_key
    const hasKey = document.body.innerHTML.includes('live analysis enabled') || false;
    // Simple heuristic: we'll check via a quick call
    el.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
        <span class="text-gray-400">Gemma 4 Ready</span>
    `;
    el.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border border-cyan-500/20 bg-cyan-500/5';
})();

// ════════════════════════════════════════════
//  ChatOps Widget
// ════════════════════════════════════════════
function toggleChat() {
    const panel = document.getElementById('chat-panel');
    panel.classList.toggle('hidden');
    if (!panel.classList.contains('hidden')) {
        document.getElementById('chat-input').focus();
    }
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const msg = input.value.trim();
    if (!msg) return;
    
    input.value = '';
    appendChatMessage('user', msg);
    
    // Add loading indicator
    const loadingId = 'loading-' + Date.now();
    appendChatMessage('gemma', '<span class="animate-pulse">Analyzing logs...</span>', loadingId);
    
    try {
        const resp = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: msg })
        });
        const data = await resp.json();
        
        // Remove loading and append real response
        document.getElementById(loadingId).remove();
        
        // Use marked.parse with minimal configuration to prevent styling conflicts
        const renderedHtml = marked.parse(data.response || 'No response.');
        appendChatMessage('gemma', renderedHtml);
    } catch (err) {
        console.error('Chat error:', err);
        document.getElementById(loadingId).remove();
        appendChatMessage('gemma', '<span class="text-red-400">Error communicating with Gemma.</span>');
    }
}

function appendChatMessage(role, htmlContent, id = null) {
    const container = document.getElementById('chat-messages');
    const el = document.createElement('div');
    if (id) el.id = id;
    
    if (role === 'user') {
        el.className = 'flex items-start gap-2 max-w-[85%] self-end flex-row-reverse';
        el.innerHTML = `
            <div class="w-6 h-6 rounded-md bg-blue-500/20 text-blue-400 flex items-center justify-center flex-shrink-0 text-xs mt-1 border border-blue-500/30">U</div>
            <div class="bg-blue-600/20 border border-blue-500/30 rounded-xl rounded-tr-none px-3 py-2 text-white text-sm shadow-sm">
                ${htmlContent}
            </div>
        `;
    } else {
        el.className = 'flex items-start gap-2 max-w-[95%]';
        el.innerHTML = `
            <div class="w-6 h-6 rounded-md bg-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs mt-1 border border-cyan-500/30">G</div>
            <div class="bg-cyber-card border border-cyber-border rounded-xl rounded-tl-none px-4 py-3 text-gray-300 shadow-sm prose prose-invert prose-sm max-w-none prose-p:leading-relaxed prose-a:text-cyan-400">
                ${htmlContent}
            </div>
        `;
    }
    
    container.appendChild(el);
    
    // Smooth scroll to bottom
    setTimeout(() => {
        container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
    }, 50);
}
