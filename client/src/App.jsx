import { useState, useEffect, useRef, useMemo } from 'react'
import axios from 'axios'
import { Activity, ShieldAlert, Cpu, Network, Upload, FileText, ServerCrash, AlertTriangle, ShieldCheck, Copy, Filter, CheckCircle2, Check, XCircle, Search, Clock, Flame, UploadCloud, Terminal, X, ChevronRight, Maximize2, Shield, Download, Crosshair, MapPin, Key } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

const getAdversaryRisk = (count) => {
  if (count >= 18) return { label: 'CRITICAL', color: 'rose' };
  if (count >= 12) return { label: 'HIGH', color: 'amber' };
  return { label: 'ELEVATED', color: 'blue' };
};

const isFailedEvent = (msg, phase) => {
  const text = (msg + " " + phase).toLowerCase();
  return text.includes('fail') || text.includes('invalid') || text.includes('error') || text.includes('brute') || text.includes('block');
};

const getEventColor = (phase) => {
  const text = (phase || '').toLowerCase();
  if (text.includes('brute') || text.includes('fail')) return 'rose';
  if (text.includes('initial access') || text.includes('access')) return 'amber';
  if (text.includes('dns') || text.includes('c2')) return 'purple';
  return 'cyan';
};

const getEventId = (e) => {
  let str = (e.timestamp || '') + (e.message || '');
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
};

const kpiVariants = {
  hidden: { opacity: 0, y: -8 },
  visible: (i) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.4 } })
};

const timelineVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { staggerChildren: 0.06 } }
};

const timelineItemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0 }
};

const detectCVE = (eventText, username) => {
  const text = eventText.toLowerCase();
  // Signature 1: Suspicious DNS/SSRF typical of Log4Shell or similar RCEs
  if (text.includes('suspicious-login.test') || text.includes('jndi:ldap')) {
    return {
      id: 'CVE-2021-44228',
      name: 'Log4Shell Remote Code Execution',
      cvss: 10.0,
      severity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
    };
  }
  // Signature 2: Specific targeted admin exploitation attempts
  if (text.includes('admin') && text.includes('failed')) {
    return {
      id: 'CVE-2023-38408',
      name: 'OpenSSH Forwarded ssh-agent RCE',
      cvss: 9.8,
      severity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    };
  }
  // Signature 3: Service account anomalous access (Privilege Escalation)
  if (username === 'svc_backup' && text.includes('successfully')) {
    return {
      id: 'CVE-2024-21626',
      name: 'runc Container Breakout',
      cvss: 8.6,
      severity: 'HIGH',
      vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
    };
  }
  return null;
};

// Find the newest timestamp across all ingested events
const getLatestTelemetryTime = (eventsList) => {
  if (!eventsList || eventsList.length === 0) return Date.now();
  return Math.max(...eventsList.map(e => new Date(e.timestamp).getTime()));
};

function App() {
  const [summary, setSummary] = useState(null)
  const [attackers, setAttackers] = useState([])
  const [timeline, setTimeline] = useState([])
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  
  const [timeRange, setTimeRange] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [copiedValue, setCopiedValue] = useState(null)
  const [expandedEventId, setExpandedEventId] = useState(null)
  const [selectedAdversaryIp, setSelectedAdversaryIp] = useState(null)
  const timelineRef = useRef(null)

  const loadDashboard = async () => {
    try {
      const [sumRes, atkRes, timeRes] = await Promise.all([
        axios.get('/api/summary'),
        axios.get('/api/attackers'),
        axios.get('/api/timeline')
      ])
      setSummary(sumRes.data)
      setAttackers(atkRes.data)
      setTimeline(timeRes.data)
    } catch (err) {
      console.error('Error loading dashboard', err)
    }
  }

  useEffect(() => {
    loadDashboard()
  }, [])

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    try {
      setLoading(true)
      await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      await loadDashboard()
      setAnalysis(null)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
      e.target.value = null
    }
  }

  const runAnalysis = async () => {
    try {
      setLoading(true)
      const res = await axios.post('/api/analyze')
      setTimeout(() => {
        setAnalysis(res.data)
        setLoading(false)
      }, 1200)
    } catch (err) {
      console.error(err)
      setLoading(false)
    }
  }

  const handleCopy = (val, e) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(val)
    setCopiedValue(val)
    setTimeout(() => setCopiedValue(null), 1500)
  }

  const renderMessageWithCopy = (msg) => {
    if (!msg) return null;
    const regex = /(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)|(\b(?:admin|root|guest|jbasak|analyst|svc_[a-zA-Z0-9_]+)\b)|(\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b)/g;
    const parts = msg.split(regex);
    return parts.map((part, i) => {
      if (!part) return null;
      let badgeColor = '';
      if (part.match(/\b(?:admin|root|guest|jbasak|analyst|svc_[a-zA-Z0-9_]+)\b/)) {
        badgeColor = 'text-cyan-300 bg-cyan-950/50 border-cyan-900/50 hover:bg-cyan-900/50';
      } else if (part.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b/)) {
        badgeColor = 'text-purple-300 bg-purple-950/50 border-purple-900/50 hover:bg-purple-900/50';
      } else if (part.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)) {
        badgeColor = 'text-amber-300 bg-amber-950/50 border-amber-900/50 hover:bg-amber-900/50';
      }
      
      if (badgeColor) {
        return (
          <motion.code 
            whileTap={{ scale: 0.9 }}
            key={i} 
            onClick={(e) => handleCopy(part, e)}
            className={`cursor-pointer px-1.5 py-0.5 rounded border font-mono text-[11px] transition-colors inline-flex items-center gap-1 mx-0.5 ${badgeColor}`}
            title="Click to copy"
          >
            {part}
            {copiedValue === part ? <Check className="w-2.5 h-2.5" /> : <Copy className="w-2.5 h-2.5 opacity-50" />}
          </motion.code>
        );
      }
      return <span key={i} className="text-slate-300">{part}</span>;
    });
  };

  const latestTime = useMemo(() => {
    return getLatestTelemetryTime(timeline);
  }, [timeline]);

  const filteredTimeline = useMemo(() => {
    return timeline.filter(t => {
      const search = searchQuery.toLowerCase();
      const matchesSearch = !search || (
        (t.message && t.message.toLowerCase().includes(search)) || 
        (t.phase && t.phase.toLowerCase().includes(search)) ||
        (t.source_ip && t.source_ip.toLowerCase().includes(search)) ||
        (t.user && t.user.toLowerCase().includes(search)) ||
        (t.event_type && t.event_type.toLowerCase().includes(search)) ||
        (isFailedEvent(t.message || '', t.phase || '') ? 'failed'.includes(search) : 'success'.includes(search))
      );

      const matchesAdversary = !selectedAdversaryIp || t.source_ip === selectedAdversaryIp;

      let matchesTime = true;
      if (timeRange !== 'ALL' && t.timestamp) {
        const eventTime = new Date(t.timestamp).getTime();
        const diff = latestTime - eventTime;
        if (timeRange === '24H') matchesTime = diff <= 24 * 60 * 60 * 1000;
        else if (timeRange === '7D') matchesTime = diff <= 7 * 24 * 60 * 60 * 1000;
      }

      return matchesSearch && matchesAdversary && matchesTime;
    }).slice(0, 100);
  }, [timeline, timeRange, searchQuery, selectedAdversaryIp, latestTime]);

  const getSeverityBreakdown = () => {
    let crit = 0, high = 0, med = 0, low = 0;
    filteredTimeline.forEach(t => {
      const cve = detectCVE(t.message || '', t.user || '');
      if (cve && cve.severity === 'CRITICAL') crit++;
      else if (cve && cve.severity === 'HIGH') high++;
      else if (isFailedEvent(t.message || '', t.phase || '')) high++;
      else if (getEventColor(t.phase) === 'amber') med++;
      else low++;
    });
    return { crit, high, med, low };
  };
  
  const { crit, high: highSev, med, low } = getSeverityBreakdown();
  const totalGraph = (crit + highSev + med + low) || 1;

  const criticalCount = attackers.filter(a => a.event_count >= 18).length;
  const highCount = attackers.filter(a => a.event_count >= 12 && a.event_count < 18).length;

  return (
    <div className="min-h-screen bg-[#0B0F17] font-sans text-slate-200 selection:bg-cyan-900/50">
      
      {/* Header & Action Bar */}
      <header className="flex h-16 border-b border-slate-800 px-6 bg-[#0B0F17]/95 items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-4">
          <div className="w-7 h-7 text-cyan-400 p-1.5 rounded-lg bg-cyan-950/50 border border-cyan-800/50 flex items-center justify-center relative">
            <ShieldAlert className="w-full h-full" />
            <div className="absolute -bottom-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-slate-900 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse" />
          </div>
          <div className="flex flex-col">
            <h1 className="text-lg font-bold tracking-wider text-slate-100 uppercase leading-tight">LogTrace</h1>
            <span className="text-[10px] tracking-widest text-slate-400 font-mono leading-tight">Advanced Threat Intelligence</span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Active Pill-Toggle Group */}
          <div className="flex items-center bg-slate-900/50 border border-slate-800 rounded-lg p-1">
            {['24H', '7D', 'ALL'].map((range) => (
              <button 
                key={range}
                onClick={() => setTimeRange(range)} 
                className={`px-3 py-1 text-[11px] font-semibold rounded-md transition-colors font-mono uppercase ${
                  timeRange === range 
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 shadow-sm' 
                    : 'text-slate-500 hover:text-slate-300 border border-transparent'
                }`}
              >
                {range === '24H' ? 'Last 24h' : range === '7D' ? '7 Days' : 'All'}
              </button>
            ))}
          </div>

          <label className="cursor-pointer px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/50 text-slate-200 hover:bg-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors">
            <UploadCloud className="w-3.5 h-3.5 text-slate-400" />
            Upload Telemetry
            <input type="file" className="hidden" onChange={handleFileUpload} accept=".json,.csv,.txt,.log" />
          </label>
          <button 
            onClick={runAnalysis} 
            disabled={loading} 
            className="relative overflow-hidden px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs shadow-lg shadow-cyan-950/50 flex items-center gap-1.5 transition-all disabled:opacity-80"
          >
            {loading && <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-300/30 to-transparent animate-[shimmer_1.5s_infinite]" />}
            {loading ? <Activity className="w-3.5 h-3.5 animate-spin relative z-10" /> : <Cpu className="w-3.5 h-3.5 relative z-10" />}
            <span className="relative z-10">{loading ? 'Scanning Telemetry...' : 'Run Forensic Engine'}</span>
          </button>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto pb-10">
        
        {/* KPI / Stat Grid */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 px-6 pt-5">
            <motion.div custom={0} variants={kpiVariants} initial="hidden" animate="visible" className="bg-[#111827]/80 backdrop-blur border border-slate-800/80 rounded-xl p-4">
              <div className="flex justify-between items-start">
                <span className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-slate-500" />
                  Total Events
                </span>
              </div>
              <div className="text-2xl font-bold font-mono tracking-tight text-slate-100 mt-1">
                {summary.total.toLocaleString()}
              </div>
              <div className="text-[10px] text-slate-500 mt-1 font-sans">100% telemetry baseline</div>
            </motion.div>

            <motion.div custom={1} variants={kpiVariants} initial="hidden" animate="visible" className="bg-[#111827]/80 backdrop-blur border border-slate-800/80 rounded-xl p-4 relative overflow-hidden">
              <div className="flex justify-between items-start relative z-10">
                <span className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                  <Flame className="w-3.5 h-3.5 text-slate-500" />
                  Malicious
                </span>
                {summary.total > 0 && (
                  <span className="bg-rose-950/50 text-rose-400 border border-rose-900/50 text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold">
                    {((summary.malicious / summary.total) * 100).toFixed(1)}% flagged rate
                  </span>
                )}
              </div>
              <div className="text-2xl font-bold font-mono tracking-tight text-rose-400 mt-1 relative z-10">
                {summary.malicious.toLocaleString()}
              </div>
            </motion.div>

            <motion.div custom={2} variants={kpiVariants} initial="hidden" animate="visible" className={`bg-[#111827]/80 backdrop-blur border rounded-xl p-4 transition-colors ${criticalCount > 0 ? 'border-rose-800/50 bg-rose-950/10' : 'border-slate-800/80'}`}>
              <div className="flex justify-between items-start">
                <span className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-slate-500" />
                  Critical Priority
                </span>
              </div>
              <div className={`text-2xl font-bold font-mono tracking-tight mt-1 ${criticalCount > 0 ? 'text-rose-500 animate-[pulse_2s_ease-in-out_infinite]' : 'text-slate-500'}`}>
                {criticalCount}
              </div>
              <div className="text-[10px] mt-1 font-sans text-slate-500">
                {criticalCount > 0 ? 'High-frequency adversary thresholds met' : 'No critical escalations'}
              </div>
            </motion.div>

            <motion.div custom={3} variants={kpiVariants} initial="hidden" animate="visible" className="bg-[#111827]/80 backdrop-blur border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between">
              <div className="flex justify-between items-start mb-3">
                <span className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-slate-500" />
                  Severity Distribution
                </span>
              </div>
              
              <div className="flex-1 flex flex-col justify-end">
                {/* Graph */}
                <div className="h-2 w-full bg-slate-900 rounded-full flex overflow-hidden border border-slate-800/80 shadow-inner mb-3">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${(crit / totalGraph) * 100}%` }} transition={{ duration: 1, ease: 'easeOut' }} className="bg-rose-500 hover:bg-rose-400 transition-colors cursor-help" title={`Critical: ${crit}`} />
                  <motion.div initial={{ width: 0 }} animate={{ width: `${(highSev / totalGraph) * 100}%` }} transition={{ duration: 1, ease: 'easeOut', delay: 0.1 }} className="bg-amber-500 hover:bg-amber-400 transition-colors cursor-help" title={`High: ${highSev}`} />
                  <motion.div initial={{ width: 0 }} animate={{ width: `${(med / totalGraph) * 100}%` }} transition={{ duration: 1, ease: 'easeOut', delay: 0.2 }} className="bg-cyan-500 hover:bg-cyan-400 transition-colors cursor-help" title={`Medium: ${med}`} />
                  <motion.div initial={{ width: 0 }} animate={{ width: `${(low / totalGraph) * 100}%` }} transition={{ duration: 1, ease: 'easeOut', delay: 0.3 }} className="bg-slate-600 hover:bg-slate-500 transition-colors cursor-help" title={`Low: ${low}`} />
                </div>
                
                {/* Legend */}
                <div className="flex items-center justify-between text-[9px] font-mono uppercase tracking-wider text-slate-500">
                  <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-[0_0_5px_rgba(244,63,94,0.5)]" /> <span className={crit > 0 ? 'text-rose-400 font-bold' : ''}>{crit}</span></div>
                  <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-amber-500 shadow-[0_0_5px_rgba(245,158,11,0.5)]" /> <span className={highSev > 0 ? 'text-amber-400 font-bold' : ''}>{highSev}</span></div>
                  <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-cyan-500 shadow-[0_0_5px_rgba(6,182,212,0.5)]" /> <span className={med > 0 ? 'text-cyan-400 font-bold' : ''}>{med}</span></div>
                  <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-slate-600" /> <span>{low}</span></div>
                </div>
              </div>
            </motion.div>
          </div>
        )}

        {/* Main Content Area */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 px-6 pt-6 relative">
          
          {/* Attack Timeline (65% -> col-span-8) */}
          <div className={`lg:col-span-8 bg-[#111827]/80 backdrop-blur border rounded-xl flex flex-col shadow-sm h-[700px] transition-all ${loading ? 'border-cyan-500/50 animate-[pulse_1.5s_ease-in-out_infinite]' : 'border-slate-800/80'}`}>
            <div className="relative p-4 border-b border-slate-800/80 flex justify-between items-center bg-slate-900/40 rounded-t-xl shrink-0 overflow-hidden">
              {loading && <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/10 to-transparent animate-[shimmer_1.5s_infinite] pointer-events-none" />}
              <h2 className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2 relative z-10">
                <Network className="w-4 h-4 text-slate-500" />
                Attack Timeline
              </h2>
              <div className="flex items-center bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 w-64 shadow-inner relative z-10">
                <Search className="w-3 h-3 text-slate-500 mr-2" />
                <input 
                  type="text" 
                  placeholder="Filter by tactic, user, IP..." 
                  className="bg-transparent border-none outline-none text-[11px] text-slate-200 w-full placeholder-slate-600 font-mono"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
            {selectedAdversaryIp && (
              <div className="bg-slate-900/60 border-b border-slate-800/80 p-2.5 px-4 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span className="text-slate-400">Filtered by Adversary:</span>
                  <span className="text-cyan-400 bg-cyan-950/50 border border-cyan-800/50 px-2 py-0.5 rounded font-semibold">[ {selectedAdversaryIp} ]</span>
                  <span className="text-slate-500 ml-1">({filteredTimeline.length} events)</span>
                </div>
                <button 
                  onClick={() => setSelectedAdversaryIp(null)} 
                  className="text-slate-400 hover:text-white flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded transition border border-slate-700 hover:border-slate-600"
                >
                  <X className="w-3 h-3" /> CLEAR FILTER
                </button>
              </div>
            )}
            
            <div ref={timelineRef} className="flex-1 relative border-l border-slate-800/80 ml-5 pl-6 space-y-3 overflow-y-auto pr-4 scrollbar-hide py-4">
              <motion.div 
                className="space-y-2.5"
                variants={timelineVariants}
                initial="hidden"
                animate="visible"
              >
                {filteredTimeline.map((t, i) => {
                  const failed = isFailedEvent(t.message || '', t.phase || '');
                  const colorType = getEventColor(t.phase);
                  const badgeClasses = {
                    rose: 'bg-rose-950/40 text-rose-300 border border-rose-800/40',
                    amber: 'bg-amber-950/40 text-amber-300 border border-amber-800/40',
                    cyan: 'bg-cyan-950/40 text-cyan-300 border border-cyan-800/40',
                    purple: 'bg-purple-950/40 text-purple-300 border border-purple-800/40'
                  }[colorType];
                  
                  const dotColor = {
                    rose: 'border-rose-500 bg-rose-950/80',
                    amber: 'border-amber-400 bg-amber-950/80',
                    cyan: 'border-cyan-400 bg-cyan-950/80',
                    purple: 'border-purple-400 bg-purple-950/80'
                  }[colorType];
                  
                  const haloColor = {
                    rose: 'bg-rose-500/30',
                    amber: 'bg-amber-500/30',
                    cyan: 'bg-cyan-500/30',
                    purple: 'bg-purple-500/30'
                  }[colorType];

                  const eventId = getEventId(t);
                  const isSelected = expandedEventId === eventId;
                  const cve = detectCVE(t.message || '', t.user || '');

                  // Simple MITRE ID and Risk mapping based on severity/color
                  const mitreId = colorType === 'rose' ? 'T1110.001 - Password Guessing' : colorType === 'amber' ? 'T1078 - Valid Accounts' : colorType === 'purple' ? 'T1071.001 - Web Protocols (C2)' : 'T1046 - Network Service Scanning';

                  return (
                    <motion.div 
                      key={i} 
                      variants={timelineItemVariants}
                      className="relative group hover:translate-x-1 transition-transform duration-150"
                    >
                      {/* Interactive Animated Node on rail */}
                      <div className={`absolute -left-[31px] top-4 w-2.5 h-2.5 rounded-full border-2 ${dotColor} z-10 group-hover:scale-125 transition-transform duration-300`}>
                        {isSelected && (
                          <div className={`absolute -inset-1.5 rounded-full ${haloColor} animate-ping pointer-events-none`} />
                        )}
                      </div>
                      
                      {/* Event Card */}
                      <div 
                        onClick={() => setExpandedEventId(isSelected ? null : eventId)}
                        className={`p-2.5 rounded-lg border transition-all duration-200 cursor-pointer select-none relative overflow-hidden flex flex-col gap-1.5 shadow-sm hover:shadow-[0_0_15px_rgba(6,182,212,0.15)] ${
                          isSelected 
                            ? 'ring-1 ring-cyan-500/60 bg-cyan-950/20 border-cyan-500/50 rounded-b-none border-b-transparent' 
                            : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/60'
                        }`}
                      >
                        <div className="flex items-center justify-between z-10 w-full pr-1">
                          <div className="flex items-center gap-2">
                            <span className={`${badgeClasses} text-[10px] px-2 py-0.5 rounded font-mono font-medium uppercase tracking-wide flex items-center gap-1.5`}>
                              {failed ? <XCircle className="w-3 h-3" /> : <CheckCircle2 className="w-3 h-3" />}
                              {t.phase}
                            </span>
                            {cve && (
                              <span className="bg-rose-950/60 text-rose-400 border border-rose-800/60 text-[9px] px-1.5 py-0.5 rounded font-mono font-bold tracking-wider shadow-[0_0_8px_rgba(244,63,94,0.15)] flex items-center gap-1">
                                <AlertTriangle className="w-2.5 h-2.5" />
                                {cve.id}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-1.5 font-mono text-slate-500 text-[10px] opacity-80">
                            <Clock className="w-3 h-3" />
                            {t.timestamp?.split('T')[1]?.replace('Z', ' UTC') || t.timestamp}
                          </div>
                        </div>
                        
                        <div className="text-[11px] leading-relaxed mt-0.5 z-10 font-sans pr-1">
                          {renderMessageWithCopy(t.message)}
                        </div>
                      </div>

                      {/* Expandable Forensic Accordion (Inline) */}
                      <AnimatePresence>
                        {isSelected && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: 0.3, ease: "easeInOut" }}
                            className={`overflow-hidden border border-t-0 border-cyan-500/50 bg-[#080d17] px-4 py-0 rounded-b-lg font-mono text-xs`}
                          >
                            <div className="py-4">
                              {/* MITRE & Risk Headers */}
                              <div className="mb-4">
                                <span className="text-slate-500 block text-[10px] uppercase tracking-wider mb-1 font-sans">MITRE Tactic & Technique</span>
                                <span className="text-slate-200 font-semibold flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 px-2.5 py-1 rounded w-fit">
                                  <Crosshair className="w-3.5 h-3.5 text-rose-400" /> {mitreId}
                                </span>
                              </div>

                              {/* CVE Intelligence */}
                              {cve && (
                                <div className="mb-4 border border-rose-900/50 bg-rose-950/20 rounded p-3">
                                  <div className="flex items-center gap-2 mb-2">
                                    <AlertTriangle className="w-4 h-4 text-rose-500" />
                                    <span className="text-rose-400 font-bold font-sans uppercase text-[11px] tracking-wider">Vulnerability Intelligence</span>
                                  </div>
                                  <div className="grid grid-cols-2 gap-3">
                                    <div>
                                      <span className="text-slate-500 block text-[10px] uppercase font-sans mb-0.5">CVE ID & Name</span>
                                      <span className="text-rose-300 font-semibold">{cve.id} - {cve.name}</span>
                                    </div>
                                    <div>
                                      <span className="text-slate-500 block text-[10px] uppercase font-sans mb-0.5">CVSS Score</span>
                                      <span className="text-rose-400 font-bold">{cve.cvss} ({cve.severity})</span>
                                    </div>
                                    <div className="col-span-2">
                                      <span className="text-slate-500 block text-[10px] uppercase font-sans mb-0.5">CVSS Vector</span>
                                      <span className="text-rose-300/80 font-mono text-[10px]">{cve.vector}</span>
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* Forensic Key-Value Grid */}
                              <div className="grid grid-cols-3 gap-4 mb-4 border-t border-slate-800/80 pt-4">
                                <div>
                                  <span className="text-slate-500 block text-[10px] mb-1 uppercase font-sans">Source IP</span> 
                                  <div className="flex items-center gap-2 text-amber-300">
                                    {t.source_ip || 'Unknown'} 
                                    {t.source_ip && (
                                      <button onClick={(e) => { e.stopPropagation(); setSelectedAdversaryIp(t.source_ip); timelineRef.current?.scrollTo({ top: 0, behavior: 'smooth' }); }} className="bg-slate-800 hover:bg-slate-700 p-1 rounded transition text-slate-400 hover:text-cyan-400" title="Pivot on IP">
                                        <Filter className="w-3 h-3" />
                                      </button>
                                    )}
                                  </div>
                                </div>
                                <div>
                                  <span className="text-slate-500 block text-[10px] mb-1 uppercase font-sans">Target Identity</span> 
                                  <span className="text-cyan-300 bg-cyan-950/30 px-1.5 py-0.5 rounded border border-cyan-900/50">{t.user || 'SYSTEM'}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 block text-[10px] mb-1 uppercase font-sans">Action / Result</span> 
                                  <span className={`${failed ? 'bg-rose-950/50 text-rose-400 border border-rose-900/50' : 'bg-emerald-950/50 text-emerald-400 border border-emerald-900/50'} px-1.5 py-0.5 rounded font-semibold`}>{failed ? 'FAILED (0xC000006A)' : 'AUTHENTICATED'}</span>
                                </div>
                                <div className="col-span-3">
                                  <span className="text-slate-500 block text-[10px] mb-1 uppercase font-sans">Target Resource</span> 
                                  <span className="text-slate-300">{t.event_type?.includes('network') ? 'Port 443/HTTPS' : t.event_type?.includes('ssh') ? 'Port 22/SSH' : 'Domain/Service'}</span>
                                </div>
                              </div>

                              {/* Raw Payload / Telemetry Block */}
                              <div className="mt-4">
                                <div className="flex items-center justify-between mb-1.5">
                                  <span className="text-slate-500 block text-[10px] uppercase font-sans">Raw Payload / Telemetry</span>
                                  <button 
                                    onClick={(e) => handleCopy(JSON.stringify(t, null, 2), e)}
                                    className="text-slate-400 hover:text-cyan-400 transition flex items-center gap-1 text-[10px] uppercase font-sans font-medium"
                                  >
                                    {copiedValue === JSON.stringify(t, null, 2) ? <><Check className="w-3 h-3 text-emerald-400" /> Copied</> : <><Copy className="w-3 h-3" /> Copy Raw Log</>}
                                  </button>
                                </div>
                                <div className="bg-[#070b12] border border-slate-800/80 p-2.5 rounded font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre">
                                  {JSON.stringify(t, null, 2)}
                                </div>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
                {filteredTimeline.length === 0 && (
                  <div className="text-center py-10 text-slate-500 font-mono text-[11px]">No events match the current filter.</div>
                )}
              </motion.div>
            </div>
          </div>

          {/* Top Adversaries (35% -> col-span-4) */}
          <div className="lg:col-span-4 flex flex-col gap-6 h-[700px]">
            <div className="rounded-xl bg-[#111827]/80 backdrop-blur border border-slate-800 flex flex-col shadow-sm flex-1 overflow-hidden">
              <div className="p-4 border-b border-slate-800/80 bg-slate-900/40 shrink-0">
                <div className="flex justify-between items-center">
                  <h2 className="text-[11px] font-semibold text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                    <Activity className="w-4 h-4 text-slate-500" />
                    Top Adversaries
                  </h2>
                  <span className="bg-slate-800/80 text-slate-300 text-[10px] px-2 py-0.5 rounded font-mono font-medium border border-slate-700">
                    {attackers.length} Detected
                  </span>
                </div>
              </div>
              
              <div className="p-4 space-y-2.5 overflow-y-auto flex-1 scrollbar-hide">
                {attackers.slice(0, 50).map((a, i) => {
                  const risk = getAdversaryRisk(a.event_count);
                  const bgColors = {
                    rose: 'bg-rose-500',
                    amber: 'bg-amber-500',
                    blue: 'bg-blue-500'
                  };
                  const badgeStyles = {
                    rose: 'bg-rose-950/60 text-rose-400 border-rose-800/80',
                    amber: 'bg-amber-950/60 text-amber-400 border-amber-800/80',
                    blue: 'bg-blue-950/60 text-blue-400 border-blue-800/80'
                  };

                  return (
                    <motion.div 
                      key={i} 
                      onClick={() => {
                        setSelectedAdversaryIp(selectedAdversaryIp === a.ip ? null : a.ip);
                        timelineRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
                      }}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.15, delay: Math.min(i * 0.05, 0.5) }}
                      className={`p-3 rounded-lg border transition group cursor-pointer flex items-center justify-between ${
                        selectedAdversaryIp === a.ip 
                          ? 'ring-1 ring-cyan-400 bg-cyan-950/30 border-cyan-400/50 shadow-[0_0_12px_rgba(34,211,238,0.15)]'
                          : 'bg-slate-900/40 border-slate-800/80 hover:border-cyan-500/60 hover:bg-slate-800/40'
                      }`}
                    >
                      <div className="flex items-center gap-3 w-full pr-3">
                        <div className="w-6 h-6 flex-shrink-0 flex items-center justify-center rounded bg-slate-800 text-[11px] font-mono text-slate-300 font-bold">
                          #{i + 1}
                        </div>
                        <div className="flex-1 overflow-hidden">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-slate-200 tracking-wide truncate">{a.ip}</span>
                            <motion.button 
                              whileTap={{ scale: 0.85 }}
                              onClick={(e) => handleCopy(a.ip, e)} 
                              className="text-slate-600 hover:text-slate-300 transition-colors opacity-0 group-hover:opacity-100" 
                              title="Copy IP"
                            >
                              {copiedValue === a.ip ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </motion.button>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-[10px] text-slate-400 font-mono w-8">{a.event_count}</span>
                            <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden relative">
                              <motion.div 
                                initial={{ width: 0 }} 
                                animate={{ width: `${Math.min(100, (a.event_count / (summary?.malicious || 1)) * 100)}%` }}
                                transition={{ duration: 0.7, ease: "easeOut" }}
                                className={`absolute left-0 top-0 h-full rounded-full ${bgColors[risk.color]} shadow-[0_0_8px_currentColor]`}
                              />
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className={`flex-shrink-0 border ${badgeStyles[risk.color]} text-[10px] font-mono px-2 py-0.5 rounded font-semibold`}>
                        {risk.label}
                      </div>
                    </motion.div>
                  );
                })}
                {attackers.length === 0 && (
                  <div className="text-center py-8 text-slate-500 font-mono text-[11px]">No active adversaries.</div>
                )}
              </div>
            </div>

            {/* Forensic Engine Report */}
            <AnimatePresence>
              {analysis && (
                <motion.div 
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="rounded-xl bg-[#111827]/80 backdrop-blur border border-cyan-800/50 flex flex-col shadow-[0_0_15px_rgba(34,211,238,0.05)] shrink-0 overflow-hidden"
                >
                  <div className="p-3 border-b border-slate-800/50 bg-slate-900/40">
                    <h2 className="text-[11px] font-semibold text-cyan-400 tracking-wider uppercase font-mono flex items-center gap-2">
                      <Cpu className="w-3.5 h-3.5" />
                      Forensic Engine Report
                    </h2>
                  </div>
                  <div className="p-4 space-y-3">
                    <p className="text-[11px] text-slate-300 leading-relaxed bg-slate-900/50 p-2.5 rounded border border-slate-800/50 font-sans">
                      {analysis.executive_summary}
                    </p>
                    {analysis.mitigations && analysis.mitigations.length > 0 && (
                      <div className="space-y-1.5">
                        {analysis.mitigations.slice(0, 2).map((m, i) => (
                          <div key={i} className="flex gap-2 text-[11px] p-2 bg-slate-900/30 rounded border border-slate-800/30">
                            <div className={`w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0 ${m.priority.toLowerCase().includes('immediate') ? 'bg-rose-400' : 'bg-amber-400'}`} />
                            <span className="text-slate-300">{m.action}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </main>

    </div>
  )
}

export default App
