# LogTrace — Real-Time Incident Response & SOC Triage Visualizer

**Powered by Gemma 4 Open Source AI**

LogTrace is an interactive, high-density security operations triage desk that analyzes server logs, classifies anomalous behavior, reconstructs attacker timelines, and generates executive incident triage reports — all wrapped in a professional, enterprise-grade dark UI and powered by Google's Gemma 4 model.

![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![React](https://img.shields.io/badge/React-18-blue)
![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-06B6D4)
![Gemma](https://img.shields.io/badge/Gemma_4-AI-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Enterprise SOC Interface** — A high-density, CrowdStrike/Datadog-inspired dark theme with glassmorphism, precise data alignment, and Framer Motion micro-interactions.
- **Framer Motion Micro-Interactions** — Features staggered component entry, interactive bouncing metric cards, animated adversary volume bars, scaling pulse nodes on the timeline rail, and a continuous radar sweep beam during active forensics.
- **Expandable Forensic Accordions (Inline)** — Click any timeline row to toggle an inline `<AnimatePresence>` animated accordion detailing MITRE mappings, exact payloads with CRT-scanline effects, and immediate action buttons.
- **Dynamic Threat Calibration** — Adversaries are automatically tiered (Critical: 18+ events, High: 12-17 events) with dynamic top-level KPIs.
- **Omni-Search & Pivot Filtering** — Real-time fuzzy filtering across tactics, IPs, usernames, raw payloads, and outcomes, plus one-click "pivot" searches from timeline cards.
- **Click-to-Copy Entity Extraction** — Usernames, IPs, and domains are parsed into distinct code badges. Click any badge to instantly copy the IOC to your clipboard.
- **Gemma 4 Forensic Analysis** — AI-powered anomaly classification, executive summaries, and mitigation steps.
- **Dynamic Log Uploads** — Upload `.json`, `.csv`, `.log`, or `.txt` files directly via the header for instant processing.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| AI Model | Gemma 4 (via @google/genai SDK) |
| Backend | Node.js + Express (MERN Stack) |
| Frontend | React + Vite + Tailwind CSS + Lucide React + Framer Motion |
| Sample Data | Simulated attack traffic (SSH brute force, privilege escalation, exfiltration) |

## Quick Start

### 1. Clone & Install

```bash
git clone <your-repo-url>
cd logtrace-ai

# Install backend dependencies
cd server
npm install

# Install frontend dependencies
cd ../client
npm install
```

### 2. (Optional) Set API Key

For live Gemma 4 analysis, set your Google AI API key:

```bash
# In the server directory, create a .env file
cd server
echo GOOGLE_API_KEY=your_key_here > .env
```

> Without an API key, LogTrace AI runs in **Demo Mode** with pre-computed analysis results.

### 3. Run

Open two terminal windows:

**Terminal 1 (Backend):**
```bash
cd server
npm run dev
```

**Terminal 2 (Frontend):**
```bash
cd client
npm run dev
```

Open **http://localhost:5173** (or the port specified by Vite) in your browser.

## Project Structure

```
logtrace-ai/
├── server/                 # Node.js + Express backend
│   ├── server.js           # Express application & API routes
│   ├── package.json        # Backend dependencies
│   ├── .env                # API key (create this)
│   ├── models/             # Mongoose schemas
│   └── services/
│       ├── logParser.js    # Log parsing, enrichment, timeline builder
│       └── analyzer.js     # Gemma 4 AI analysis & triage reports
├── client/                 # React frontend
│   ├── src/
│   │   ├── App.jsx         # Main Interactive SOC Dashboard
│   │   ├── index.css       # Tailwind CSS & custom cyber-theme variables
│   │   └── main.jsx        # React entry point
│   ├── package.json        # Frontend dependencies
│   └── vite.config.js      # Vite config with API proxy
└── data/
    └── sample_logs.json    # Simulated attack traffic dataset
```

## Sample Attack Scenario

The included dataset simulates a realistic multi-phase attack mapped against MITRE ATT&CK:

1. **Reconnaissance** — Port scanning from a Tor exit node
2. **Brute Force** — 15+ SSH login attempts across multiple usernames
3. **Initial Access** — Successful login with compromised credentials
4. **Privilege Escalation** — pkexec exploit to gain root access
5. **Data Exfiltration** — Database dump and SSH keys sent to C2 server
6. **Persistence** — Backdoor user, crontab reverse shell, PHP web shell
7. **Defense Evasion** — Log tampering and history clearing

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/summary` | Aggregated threat severity counts & rates |
| GET | `/api/timeline` | Enriched attack timeline events |
| GET | `/api/attackers` | Identified adversary IPs, volumes, and severities |
| POST | `/api/upload` | Process a new `.json`, `.csv`, `.log`, or `.txt` file |
| POST | `/api/analyze` | Trigger the Gemma 4 Forensic Engine |

## License

MIT
