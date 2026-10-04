require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Log = require('./models/Log');
const Report = require('./models/Report');
const { parse } = require('csv-parse/sync'); // we might need csv-parse if we process CSVs on the fly, but we can do a naive string split for now

const {
    loadLogs,
    enrichAll,
    getThreatSummary,
    getAttackerIps,
    buildTimeline,
    getPhaseSummary
} = require('./services/logParser');
const { analyzeLogs, generateTriageReport } = require('./services/analyzer');

const app = express();
app.use(cors());
app.use(express.json());

// Set up MongoDB (optional, if provided in .env, otherwise skip)
if (process.env.MONGODB_URI) {
    mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    }).then(() => console.log('MongoDB connected'))
      .catch(err => console.error('MongoDB connection error:', err));
}

// Multer for uploads (store in memory for on-the-fly analysis)
const upload = multer({ storage: multer.memoryStorage() });

// Load sample logs on startup
const DATA_PATH = path.join(__dirname, '..', 'data', 'sample_logs.json');
let globalLogs = [];
if (fs.existsSync(DATA_PATH)) {
    globalLogs = enrichAll(loadLogs(DATA_PATH));
}

let analysisCache = null;
let reportCache = null;

// ──────────────────────────────────────────────
//  API routes
// ──────────────────────────────────────────────

app.get('/api/logs', (req, res) => {
    res.json(globalLogs);
});

app.get('/api/summary', (req, res) => {
    res.json(getThreatSummary(globalLogs));
});

app.get('/api/attackers', (req, res) => {
    res.json(getAttackerIps(globalLogs));
});

app.get('/api/timeline', (req, res) => {
    res.json(buildTimeline(globalLogs));
});

app.get('/api/phases', (req, res) => {
    res.json(getPhaseSummary(globalLogs));
});

app.post('/api/analyze', async (req, res) => {
    if (!analysisCache) {
        analysisCache = await analyzeLogs(globalLogs);
        if (process.env.MONGODB_URI && analysisCache && !analysisCache.error) {
            try {
                await Report.create(analysisCache);
                console.log("Analysis report saved to MongoDB");
            } catch (err) {
                console.error("Failed to save report to MongoDB", err);
            }
        }
    }
    res.json(analysisCache);
});

app.post('/api/report', async (req, res) => {
    if (!reportCache) {
        reportCache = await generateTriageReport(globalLogs);
    }
    res.json({ report: reportCache });
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
    }

    const filename = req.file.originalname;
    const content = req.file.buffer.toString('utf8');
    const rawLogs = [];
    const now = new Date().toISOString();

    try {
        if (filename.endsWith('.json')) {
            const parsed = JSON.parse(content);
            if (Array.isArray(parsed)) {
                rawLogs.push(...parsed);
            }
        } else if (filename.endsWith('.ipynb')) {
            const notebook = JSON.parse(content);
            (notebook.cells || []).forEach(cell => {
                if (['code', 'markdown'].includes(cell.cell_type)) {
                    const source = Array.isArray(cell.source) ? cell.source.join('') : cell.source;
                    if (source && source.trim()) {
                        rawLogs.push({
                            timestamp: now,
                            source_ip: 'Jupyter',
                            event_type: `notebook_${cell.cell_type}`,
                            message: source.trim()
                        });
                    }
                }
            });
        } else if (filename.endsWith('.csv')) {
            // Naive CSV parse for now (assuming header row exists)
            const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
            if (lines.length > 1) {
                const headers = lines[0].split(',').map(h => h.trim());
                for (let i = 1; i < lines.length; i++) {
                    const values = lines[i].split(',').map(v => v.trim());
                    const row = {};
                    headers.forEach((h, idx) => { row[h] = values[idx]; });
                    
                    rawLogs.push({
                        timestamp: row.timestamp || row.time || row.date || now,
                        source_ip: row.source_ip || row.ip || 'Unknown',
                        event_type: row.event_type || row.type || 'csv_log',
                        message: row.message || row.msg || row.log || lines[i]
                    });
                }
            }
        } else {
            // Text logs
            const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
            lines.forEach(line => {
                rawLogs.push({
                    timestamp: now,
                    source_ip: 'Unknown',
                    event_type: 'raw_text',
                    message: line
                });
            });
        }

        globalLogs = enrichAll(rawLogs);
        
        if (process.env.MONGODB_URI && globalLogs.length > 0) {
            try {
                await Log.insertMany(globalLogs);
                console.log(`Saved ${globalLogs.length} logs to MongoDB`);
            } catch (err) {
                console.error("Failed to save logs to MongoDB", err);
            }
        }

        analysisCache = null;
        reportCache = null;

        res.json({ message: `Successfully loaded ${globalLogs.length} events from ${filename}` });
    } catch (err) {
        console.error("Upload parse error:", err);
        res.status(400).json({ error: 'Failed to parse file: ' + err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`LogTrace AI Backend running on port ${PORT}`);
});
