"""
LogTrace AI — Flask Application
Real-Time Incident Response & SOC Triage Visualizer
Powered by Gemma 4
"""
import os
import json

from flask import Flask, jsonify, render_template, request
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

from backend.log_parser import (
    load_logs,
    enrich_all,
    get_threat_summary,
    get_attacker_ips,
    build_timeline,
    get_phase_summary,
)
from backend.analyzer import analyze_logs, generate_triage_report

load_dotenv()

app = Flask(__name__)

# ──────────────────────────────────────────────
#  Load & enrich sample data at startup
# ──────────────────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "sample_logs.json")
LOGS = enrich_all(load_logs(DATA_PATH))

# Cache for analysis results
_analysis_cache: dict | None = None
_report_cache: str | None = None


# ──────────────────────────────────────────────
#  Page routes
# ──────────────────────────────────────────────
@app.route("/")
def dashboard():
    """Serve the main dashboard."""
    has_api_key = bool(
        os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    )
    return render_template("index.html", has_api_key=has_api_key)


# ──────────────────────────────────────────────
#  API routes
# ──────────────────────────────────────────────
@app.route("/api/logs")
def api_logs():
    """Return all enriched log entries."""
    return jsonify(LOGS)


@app.route("/api/summary")
def api_summary():
    """Return threat summary counts."""
    return jsonify(get_threat_summary(LOGS))


@app.route("/api/attackers")
def api_attackers():
    """Return identified attacker IPs."""
    return jsonify(get_attacker_ips(LOGS))


@app.route("/api/timeline")
def api_timeline():
    """Return the attack timeline."""
    return jsonify(build_timeline(LOGS))


@app.route("/api/phases")
def api_phases():
    """Return attack phases (MITRE ATT&CK)."""
    return jsonify(get_phase_summary(LOGS))


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Trigger Gemma 4 analysis (cached)."""
    global _analysis_cache
    if _analysis_cache is None:
        _analysis_cache = analyze_logs(LOGS)
    return jsonify(_analysis_cache)


@app.route("/api/report", methods=["POST"])
def api_report():
    """Generate triage report via Gemma 4 (cached)."""
    global _report_cache
    if _report_cache is None:
        _report_cache = generate_triage_report(LOGS)
    return jsonify({"report": _report_cache})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Handle log file uploads (JSON, CSV, IPYNB, or raw text) for dynamic analysis."""
    global LOGS, _analysis_cache, _report_cache
    
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    try:
        content = file.read().decode("utf-8")
        import datetime
        import csv
        raw_logs = []
        
        if file.filename.endswith(".json"):
            raw_logs = json.loads(content)
        elif file.filename.endswith(".ipynb"):
            notebook = json.loads(content)
            for cell in notebook.get("cells", []):
                if cell.get("cell_type") in ["code", "markdown"]:
                    source = "".join(cell.get("source", []))
                    if source.strip():
                        raw_logs.append({
                            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                            "source_ip": "Jupyter",
                            "event_type": f"notebook_{cell.get('cell_type')}",
                            "message": source.strip()
                        })
        elif file.filename.endswith(".csv"):
            reader = csv.DictReader(content.splitlines())
            for row in reader:
                msg = row.get("message", row.get("msg", row.get("log", str(row))))
                ts = row.get("timestamp", row.get("time", row.get("date", datetime.datetime.utcnow().isoformat() + "Z")))
                ip = row.get("source_ip", row.get("ip", "Unknown"))
                evt = row.get("event_type", row.get("type", "csv_log"))
                raw_logs.append({
                    "timestamp": ts,
                    "source_ip": ip,
                    "event_type": evt,
                    "message": msg
                })
        else:
            # Basic parsing for raw text logs (each line is an event)
            for line in content.splitlines():
                if not line.strip(): continue
                raw_logs.append({
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "source_ip": "Unknown",
                    "event_type": "custom_log",
                    "message": line.strip()
                })
                
        LOGS = enrich_all(raw_logs)
        _analysis_cache = None
        _report_cache = None
        return jsonify({"message": f"Successfully loaded {len(LOGS)} logs", "count": len(LOGS)})
    except Exception as e:
        return jsonify({"error": f"Failed to parse file: {str(e)}"}), 500


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Handle ChatOps queries to Gemma 4."""
    data = request.json or {}
    query = data.get("query", "")
    if not query:
        return jsonify({"response": "Empty query."}), 400
    
    from backend.analyzer import chat_with_logs
    response = chat_with_logs(query, LOGS)
    return jsonify({"response": response})


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("\n+----------------------------------------------+")
    print("|        LogTrace AI -- SOC Triage Desk        |")
    print("|      Powered by Gemma 4 Open Source AI       |")
    print("+----------------------------------------------+\n")

    has_key = bool(
        os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    )
    if has_key:
        print("[OK]  Gemma API key detected -- live analysis enabled")
    else:
        print("[!!]  No API key found -- running in DEMO mode")
        print("      Set GOOGLE_API_KEY in .env or environment to enable live analysis\n")

    print(f"[i]  Loaded {len(LOGS)} log entries from sample data")
    print("[*]  Dashboard: http://127.0.0.1:5000\n")

    app.run(debug=True, port=5000)
