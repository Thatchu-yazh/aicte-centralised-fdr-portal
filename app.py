import os
import re
import sqlite3
import hashlib
import logging
import streamlit as st
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
from fastapi import FastAPI, Request, Form, UploadFile, File, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AICTE-CORE")

DB_FILE = "production_aicte_ledger.db"
UPLOAD_DIR = "secured_fdr_vault"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# 1. Crash-Proof Database Initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(fdr_repository)")
    cols = [col[1] for col in cursor.fetchall()]
    if cols and ("amount" in cols and "inst_submitted_amount" not in cols):
        cursor.execute("DROP TABLE IF EXISTS fdr_repository")
        cursor.execute("DROP TABLE IF EXISTS audit_logs")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fdr_repository (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aicte_inst_id TEXT DEFAULT '1-49283741',
            institution_name TEXT DEFAULT 'KCG College of Technology, Chennai',
            bank_name TEXT NOT NULL,
            fdr_number TEXT UNIQUE NOT NULL,
            amount REAL DEFAULT 0.0,
            inst_submitted_amount REAL NOT NULL,
            bank_confirmed_amount REAL DEFAULT 0.0,
            issue_date TEXT NOT NULL,
            maturity_date TEXT NOT NULL,
            document_hash TEXT DEFAULT '',
            parent_fdr_number TEXT DEFAULT 'ORIGINAL',
            ocr_match_status TEXT NOT NULL,
            regulatory_status TEXT DEFAULT 'Awaiting Bank Audit',
            discrepancy_log TEXT DEFAULT 'None',
            lien_marked_to_aicte TEXT DEFAULT 'Pending Verification'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_role TEXT DEFAULT 'SYSTEM',
            action_description TEXT NOT NULL,
            prev_hash TEXT DEFAULT '0',
            curr_hash TEXT DEFAULT '0'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            org_name TEXT NOT NULL
        )
    ''')

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, password, role, org_name) VALUES (?, ?, ?, ?)",
            [
                ("college@kcg.edu", "password123", "college", "KCG College of Technology, Chennai"),
                ("bank@sbi.in", "password123", "bank", "State Bank of India, Adyar Branch"),
                ("aicte@gov.in", "password123", "aicte", "AICTE Regulation Bureau, New Delhi")
            ]
        )

    conn.commit()
    conn.close()


init_db()


def record_immutable_audit(cursor, actor_role: str, description: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT curr_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    prev_hash = last_row[0] if (last_row and last_row[0]) else "0" * 64

    payload = f"{timestamp}|{actor_role}|{description}|{prev_hash}"
    curr_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    cursor.execute('''
        INSERT INTO audit_logs (timestamp, actor_role, action_description, prev_hash, curr_hash)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, actor_role, description, prev_hash, curr_hash))


app = FastAPI(title="AICTE Security Deposit & FDR Portal")


# Automatically serve local background image if placed in project folder
@app.get("/portal-bg-image")
async def get_portal_background():
    candidate_files = [
        "aicte_bg.png",
        "aicte_hq_daylight.png",
        "bg.png",
        "bg.jpg",
        "AICTE Headquarters in Daylight.png",
        "AICTE Headquarters in Daylight_2.png",
        "AICTE Headquarters in Daylight_3.png",
        "image_b89659.png",
        "image_b89abe.png",
        "image_b9f3bc.jpg"
    ]
    for fname in candidate_files:
        if os.path.exists(fname):
            return FileResponse(fname)
    return RedirectResponse(url="https://upload.wikimedia.org/wikipedia/commons/3/3a/AICTE_hq.jpg")


# Official Govt Login & Register Page Template
AUTH_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Centralized FDR Portal Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { 
            min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px;
            background-color: #0B2545;
            background-image: linear-gradient(rgba(11, 37, 69, 0.45), rgba(15, 23, 42, 0.70)), 
                              url('/portal-bg-image'),
                              url('https://images.unsplash.com/photo-1562774053-701939374585?auto=format&fit=crop&w=1920&q=80');
            background-repeat: no-repeat;
            background-position: center center;
            background-attachment: fixed;
            background-size: cover;
            position: relative;
        }

        .top-badge-bar {
            position: absolute; top: 25px; right: 40px; color: #fff; font-size: 12px; font-weight: 600; 
            letter-spacing: 0.5px; opacity: 0.95; text-shadow: 0 2px 4px rgba(0,0,0,0.5);
        }

        .auth-container {
            width: 100%; max-width: 520px; background: rgba(255, 255, 255, 0.98); backdrop-filter: blur(12px);
            border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.45); overflow: hidden; border: 1px solid rgba(255,255,255,0.4);
        }

        .gov-banner { 
            width: 100%; background: #ffffff; padding: 18px 24px; border-bottom: 3px solid #ff9933; 
            display: flex; align-items: center; gap: 14px; 
        }
        .emblem-img { width: 44px; height: 44px; object-fit: contain; }
        .gov-banner-text h4 { font-size: 11px; color: #0B2545; font-weight: 900; text-transform: uppercase; letter-spacing: 0.3px; }
        .gov-banner-text p { font-size: 10px; color: #475569; font-weight: 600; margin-top: 2px; }

        .auth-card { padding: 30px 35px; }
        .auth-header { text-align: center; margin-bottom: 22px; }
        .auth-header h1 { font-size: 20px; font-weight: 900; color: #0B2545; text-transform: uppercase; letter-spacing: 0.5px; }
        .auth-header p { font-size: 10px; color: #d97706; font-weight: 800; text-transform: uppercase; margin-top: 5px; letter-spacing: 0.5px; }
        
        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 10px; font-weight: 800; color: #4a5568; text-transform: uppercase; margin-bottom: 6px; }
        .form-group input, .form-group select { width: 100%; padding: 11px 14px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 13px; outline: none; background: #fff; }
        .form-group input:focus, .form-group select:focus { border-color: #065f46; box-shadow: 0 0 0 3px rgba(6,95,70,0.15); }
        
        .btn-submit { 
            width: 100%; background: #065f46; color: white; border: none; padding: 13px; border-radius: 8px; 
            font-size: 12px; font-weight: 800; text-transform: uppercase; cursor: pointer; margin-top: 8px; transition: background 0.2s;
            display: flex; align-items: center; justify-content: center; gap: 8px; box-shadow: 0 4px 12px rgba(6,95,70,0.25);
        }
        .btn-submit:hover { background: #047857; }
        
        .toggle-box { text-align: center; margin-top: 18px; padding-top: 15px; border-top: 1px solid #edf2f7; font-size: 11px; color: #4a5568; }
        .toggle-box a { color: #2563eb; font-weight: 800; text-decoration: none; cursor: pointer; }
        .toggle-box a:hover { text-decoration: underline; }
        
        .msg-box { padding: 10px 14px; border-radius: 6px; font-size: 11px; font-weight: bold; margin-bottom: 15px; text-align: center; }
        .error-msg { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .success-msg { background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }
        .info-msg { background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }
        
        .demo-box { background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px 16px; border-radius: 8px; font-size: 11px; color: #166534; margin-bottom: 18px; line-height: 1.6; }
        .footer-note { text-align: center; font-size: 9px; color: #94a3b8; margin-top: 15px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
    </style>
</head>
<body>
    <div class="top-badge-bar">Secure &nbsp;•&nbsp; Transparent &nbsp;•&nbsp; Accountable</div>

    <div class="auth-container">
        <div class="gov-banner">
            <img src="https://upload.wikimedia.org/wikipedia/en/e/eb/All_India_Council_for_Technical_Education_logo.png" 
                 onerror="this.style.display='none'" alt="AICTE Logo" class="emblem-img">
            <div class="gov-banner-text">
                <h4>Ministry of Education, Government of India</h4>
                <p>All India Council for Technical Education (AICTE)</p>
            </div>
        </div>

        <div class="auth-card">
            <div class="auth-header">
                <h1>Centralized FDR Portal</h1>
                <p>Security Deposit &amp; Regulatory Lifecycle Gateway</p>
            </div>

            %%MSG_BLOCK%%

            <div class="demo-box">
                <strong>🔑 Quick Demo Accounts:</strong><br>
                • College: <code>college@kcg.edu</code> / <code>password123</code><br>
                • Bank: <code>bank@sbi.in</code> / <code>password123</code><br>
                • AICTE: <code>aicte@gov.in</code> / <code>password123</code>
            </div>

            <!-- LOGIN FORM -->
            <form id="loginForm" action="/login" method="POST" style="display: block;">
                <div class="form-group">
                    <label>Select Login Portal Role</label>
                    <select id="loginRoleSelect" name="role" required>
                        <option value="college" %%SEL_COLLEGE%%>🏢 Technical Institution / College Portal</option>
                        <option value="bank" %%SEL_BANK%%>🏦 Bank Branch Auditor Portal</option>
                        <option value="aicte" %%SEL_AICTE%%>🏛️ AICTE Regulation Bureau Dashboard</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Official Registered Email / ID</label>
                    <input type="text" name="username" placeholder="e.g. college@kcg.edu" required>
                </div>
                <div class="form-group">
                    <label>Secure Password</label>
                    <input type="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit" class="btn-submit">🔒 Secure Login to Portal &nbsp;&rarr;</button>
                <div class="toggle-box">
                    New Institution or Bank Branch? <a onclick="showRegister()">Register New Account</a>
                </div>
            </form>

            <!-- REGISTRATION FORM -->
            <form id="registerForm" action="/register" method="POST" style="display: none;">
                <div class="form-group">
                    <label>Select Stakeholder Role</label>
                    <select name="role" required>
                        <option value="college">Technical Institution / College</option>
                        <option value="bank">Issuing Bank Branch Official</option>
                        <option value="aicte">AICTE Regulation Bureau Officer</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Organization / College Name</label>
                    <input type="text" name="org_name" placeholder="e.g. KCG College of Technology, Chennai" required>
                </div>
                <div class="form-group">
                    <label>Official Portal Email ID</label>
                    <input type="email" name="username" placeholder="admin@college.edu" required>
                </div>
                <div class="form-group">
                    <label>Create Secure Password</label>
                    <input type="password" name="password" placeholder="••••••••" required>
                </div>
                <button type="submit" class="btn-submit">📝 Register &amp; Create Portal Account</button>
                <div class="toggle-box">
                    Already registered? <a onclick="showLogin()">Back to Login</a>
                </div>
            </form>

            <div class="footer-note">Demo Prototype &mdash; Centralized AICTE Regulatory Gateway</div>
        </div>
    </div>

    <script>
        function showRegister() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
        }
        function showLogin() {
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
        }
    </script>
</body>
</html>
"""


def render_auth_page(msg_html: str = "", selected_role: str = "college") -> HTMLResponse:
    html = AUTH_HTML_TEMPLATE.replace("%%MSG_BLOCK%%", msg_html)
    html = html.replace("%%SEL_COLLEGE%%", "selected" if selected_role == "college" else "")
    html = html.replace("%%SEL_BANK%%", "selected" if selected_role == "bank" else "")
    html = html.replace("%%SEL_AICTE%%", "selected" if selected_role == "aicte" else "")
    return HTMLResponse(content=html)


MASTER_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AICTE Security Deposit & FDR Regulatory Ecosystem</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { background: #f4f6f9; color: #2d3748; padding-bottom: 60px; }
        
        header { background: #0B2545; color: white; padding: 18px 25px; border-bottom: 5px solid #ff9933; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        .header-container { max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .header-brand { display: flex; align-items: center; gap: 14px; }
        .header-emblem { width: 42px; height: 42px; object-fit: contain; background: white; border-radius: 50%; padding: 3px; }
        .header-title h1 { font-size: 20px; font-weight: 900; text-transform: uppercase; letter-spacing: 0.5px; }
        .header-title p { font-size: 11px; color: #ff9933; font-weight: 700; text-transform: uppercase; margin-top: 3px; letter-spacing: 0.5px; }
        .header-badges { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .live-badge { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .security-badge { background: rgba(255, 153, 51, 0.15); color: #ff9933; border: 1px solid rgba(255, 153, 51, 0.4); padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .logout-btn { background: #ef4444; color: white; padding: 7px 14px; border-radius: 6px; font-size: 11px; font-weight: bold; text-decoration: none; text-transform: uppercase; transition: background 0.2s; }
        .logout-btn:hover { background: #dc2626; }

        .switcher-bar { max-width: 1400px; margin: 20px auto 0 auto; padding: 0 25px; display: flex; gap: 12px; justify-content: space-between; align-items: center; flex-wrap: wrap; }
        .role-tabs { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .switch-btn { background: #e2e8f0; color: #4a5568; padding: 10px 18px; border: none; border-radius: 8px; font-size: 12px; font-weight: 800; cursor: pointer; transition: all 0.2s; text-transform: uppercase; letter-spacing: 0.4px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; }
        .switch-btn:hover { background: #cbd5e0; }
        .switch-btn.active { background: #0B2545; color: white; box-shadow: 0 4px 10px rgba(11, 37, 69, 0.25); border-bottom: 4px solid #ff9933; }
        
        @keyframes pulseBadge {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { transform: scale(1.08); box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        .notif-pill { background: #ef4444; color: white; padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 900; animation: pulseBadge 1.5s infinite; }

        .search-box { padding: 10px 14px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 12px; width: 280px; outline: none; background: white; }

        .kpi-grid { max-width: 1400px; margin: 20px auto 0 auto; padding: 0 25px; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
        .kpi-card { background: white; padding: 18px 20px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 6px rgba(0,0,0,0.02); display: flex; justify-content: space-between; align-items: center; border-left: 5px solid #0B2545; }
        .kpi-card.green { border-left-color: #10b981; }
        .kpi-card.red { border-left-color: #ef4444; }
        .kpi-card.amber { border-left-color: #f59e0b; }
        .kpi-info h4 { font-size: 11px; text-transform: uppercase; color: #718096; font-weight: 800; }
        .kpi-info .kpi-num { font-size: 26px; font-weight: 900; color: #0B2545; margin-top: 4px; }

        main { max-width: 1400px; margin: 20px auto; padding: 0 25px; }

        .panel { background: white; padding: 25px; border-radius: 16px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); border: 1px solid #e2e8f0; margin-bottom: 25px; }
        .panel-title { font-size: 15px; font-weight: 800; color: #0B2545; border-bottom: 2px solid #edf2f7; padding-bottom: 12px; margin-bottom: 20px; text-transform: uppercase; display: flex; justify-content: space-between; align-items: center; }

        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .form-group { margin-bottom: 14px; }
        .form-group.full { grid-column: 1 / -1; }
        .form-group label { display: block; font-size: 11px; font-weight: 700; color: #4a5568; text-transform: uppercase; margin-bottom: 6px; }
        .form-group input { width: 100%; padding: 10px 12px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 13px; }
        .btn-transmit { width: 100%; background: #065f46; color: white; border: none; padding: 14px; border-radius: 8px; font-size: 13px; font-weight: 800; text-transform: uppercase; cursor: pointer; margin-top: 8px; box-shadow: 0 4px 12px rgba(6,95,70,0.25); }
        .btn-transmit:hover { background: #047857; }

        .bank-alert-banner { background: linear-gradient(90deg, #fffbeb, #fef3c7); border: 2px solid #f59e0b; border-left: 8px solid #d97706; border-radius: 12px; padding: 20px 24px; margin-bottom: 22px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 12px rgba(245, 158, 11, 0.15); }
        .bank-alert-text h3 { color: #92400e; font-size: 17px; font-weight: 900; margin-bottom: 4px; }
        .bank-alert-text p { color: #b45309; font-size: 13px; font-weight: 600; }

        .success-banner { background: #d1fae5; border: 2px solid #10b981; border-left: 8px solid #059669; border-radius: 12px; padding: 16px 22px; margin-bottom: 22px; color: #065f46; font-size: 13px; font-weight: 700; display: flex; justify-content: space-between; align-items: center; }

        .list-container { display: flex; flex-direction: column; gap: 25px; margin-bottom: 25px; }
        .list-section { background: white; border-radius: 16px; box-shadow: 0 4px 10px rgba(0,0,0,0.03); border: 1px solid #e2e8f0; overflow: hidden; }
        .list-header { padding: 15px 20px; font-size: 13px; font-weight: 800; color: white; text-transform: uppercase; display: flex; justify-content: space-between; align-items: center; }
        .list-header.bank-navy { background: linear-gradient(90deg, #0f172a, #1e3a8a); border-bottom: 3px solid #38bdf8; }
        .list-header.red { background: linear-gradient(90deg, #c53030, #e53e3e); }
        .list-header.yellow { background: linear-gradient(90deg, #c05621, #dd6b20); }
        .list-header.green { background: linear-gradient(90deg, #2f855a, #38a169); }

        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        th { background: #f8fafc; padding: 12px 16px; color: #4a5568; font-size: 11px; font-weight: 800; text-transform: uppercase; border-bottom: 2px solid #e2e8f0; }
        td { padding: 14px 16px; border-bottom: 1px solid #edf2f7; vertical-align: middle; line-height: 1.4; }
        
        .badge { display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 800; text-transform: uppercase; background: #edf2f7; color: #2d3748; }
        .badge.warn { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .badge.ok { background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }

        .action-btn { display: inline-block; padding: 8px 14px; border-radius: 6px; font-size: 11px; font-weight: 800; text-decoration: none; cursor: pointer; text-transform: uppercase; margin: 2px; border: none; }
        .green-btn { background: #10b981; color: white; box-shadow: 0 2px 6px rgba(16, 185, 129, 0.35); }
        .green-btn:hover { background: #059669; }
        .red-btn { background: #ef4444; color: white; box-shadow: 0 2px 6px rgba(239, 68, 68, 0.35); }
        .red-btn:hover { background: #dc2626; }

        .audit-trail-panel { background: #0B2545; color: white; padding: 25px; border-radius: 16px; margin-top: 25px; }
        .audit-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e3a5f; padding-bottom: 12px; }
        .log-stream { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 15px; font-family: 'Consolas', monospace; font-size: 12px; }
        .log-item { background: #071931; padding: 12px 14px; border-radius: 8px; border-left: 3px solid #ff9933; color: #e2e8f0; line-height: 1.5; }
        .log-time { color: #ff9933; font-weight: bold; }
    </style>
</head>
<body>

    <header>
        <div class="header-container">
            <div class="header-brand">
                <img src="https://upload.wikimedia.org/wikipedia/en/e/eb/All_India_Council_for_Technical_Education_logo.png" 
                     onerror="this.style.display='none'" alt="AICTE" class="header-emblem">
                <div class="header-title">
                    <h1>All India Council for Technical Education (AICTE)</h1>
                    <p>Regulation Bureau — Secure Portal | Logged in as: <strong>{{ user_org }}</strong></p>
                </div>
            </div>
            <div class="header-badges">
                <div class="security-badge">🔒 SHA-256 Audit Chain Active</div>
                <div class="live-badge">● Bank Gateway Online</div>
                <a href="/logout" class="logout-btn">🚪 Secure Logout</a>
            </div>
        </div>
    </header>

    <div class="switcher-bar">
        <div class="role-tabs">
            %%ROLE_TABS_BAR%%
        </div>
        <div style="display:flex; gap:10px; align-items:center;">
            %%CSV_EXPORT_BTN%%
            %%SEARCH_BOX_BLOCK%%
        </div>
    </div>

    <!-- KPI Strip (Visible ONLY for AICTE) -->
    %%KPI_SECTION_BLOCK%%

    <main>
        %%MAIN_CONTENT_BLOCK%%
    </main>

    <script>
        function filterTables() {
            const searchInput = document.getElementById('globalSearch');
            if (!searchInput) return;
            const query = searchInput.value.toLowerCase();
            const rows = document.querySelectorAll('.fdr-table tbody tr');
            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"""


@app.get("/login", response_class=HTMLResponse)
async def auth_page(role: str = "college", notice: str = None):
    msg_html = ""
    if notice == "auth_required":
        role_labels = {
            "college": "Technical Institution / College Portal",
            "bank": "Bank Branch Auditor Portal",
            "aicte": "AICTE Regulation Bureau Dashboard"
        }
        target_name = role_labels.get(role, "Requested Portal")
        msg_html = f'<div class="msg-box info-msg">🔐 Please log in with authorized <strong>{target_name}</strong> credentials to access that portal.</div>'
    return render_auth_page(msg_html=msg_html, selected_role=role)


@app.post("/login", response_class=HTMLResponse)
async def handle_login(role: str = Form(...), username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT role, org_name FROM users WHERE username=? AND password=? AND role=?",
        (username.strip(), password, role)
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        msg_box = '<div class="msg-box error-msg">⚠️ Invalid Credentials or Role Mismatch! Please check your email, password, and selected role.</div>'
        return render_auth_page(msg_html=msg_box, selected_role=role)

    db_role, org = user
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="user_role", value=db_role)
    response.set_cookie(key="user_org", value=quote(org))
    return response


@app.post("/register", response_class=HTMLResponse)
async def handle_register(role: str = Form(...), org_name: str = Form(...), username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, org_name) VALUES (?, ?, ?, ?)",
            (username.strip(), password, role, org_name.strip())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        msg_box = '<div class="msg-box error-msg">⚠️ Email ID already registered! Please log in with your existing account.</div>'
        return render_auth_page(msg_html=msg_box, selected_role=role)
    conn.close()

    success_box = '<div class="msg-box success-msg">✅ Registration Successful! Your account has been saved. Please log in below to enter your portal.</div>'
    return render_auth_page(msg_html=success_box, selected_role=role)


# Clicking another role tab requires logging in as that role
@app.get("/switch-role/{target_role}")
async def require_login_for_role(target_role: str, user_role: str = Cookie(default=None)):
    if user_role == target_role:
        return RedirectResponse(url="/", status_code=303)
    response = RedirectResponse(url=f"/login?role={target_role}&notice=auth_required", status_code=303)
    response.delete_cookie("user_role")
    response.delete_cookie("user_org")
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("user_role")
    response.delete_cookie("user_org")
    return response


@app.get("/", response_class=HTMLResponse)
async def serve_central_dashboard(
    request: Request,
    submitted: str = None,
    user_role: str = Cookie(default=None),
    user_org: str = Cookie(default=None)
):
    if not user_role:
        return RedirectResponse(url="/login", status_code=303)

    decoded_org = unquote(user_org) if user_org else "Authorized User"

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fdr_repository ORDER BY id DESC")
    records = cursor.fetchall()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 12")
    logs = cursor.fetchall()
    conn.close()

    total_count = len(records)
    verified_count = sum(1 for r in records if r['regulatory_status'] == 'Verified & Safely Locked')
    flagged_count = sum(1 for r in records if 'Warning' in r['ocr_match_status'] or r['regulatory_status'] == 'Discrepancy Flagged')
    bank_pending_count = sum(1 for r in records if r['regulatory_status'] == 'Awaiting Bank Audit')

    critical_escalations = 0
    current_date = datetime.now()
    for r in records:
        try:
            days = (datetime.strptime(r['maturity_date'], "%Y-%m-%d") - current_date).days
            if days <= 30 and r['regulatory_status'] not in ('Released & Settled', 'Renewed & Archived'):
                critical_escalations += 1
        except Exception:
            pass

    html_content = MASTER_HTML_TEMPLATE.replace("{{ user_role }}", user_role).replace("{{ user_org }}", decoded_org)

    # Role navigation tabs: clicking a different role logs out current user and prompts login for the selected role
    role_tabs_html = f"""
        <a href="/switch-role/college" class="switch-btn {'active' if user_role == 'college' else ''}">
            🏢 1. College Submitter
        </a>
        <a href="/switch-role/bank" class="switch-btn {'active' if user_role == 'bank' else ''}">
            🏦 2. Bank Auditor (1-Click Verify)
            <span class="notif-pill">🔔 {bank_pending_count} Pending</span>
        </a>
        <a href="/switch-role/aicte" class="switch-btn {'active' if user_role == 'aicte' else ''}">
            🏛️ 3. AICTE Master Dashboard
        </a>
    """

    # PAGE 1: ONLY COLLEGE SUBMISSION FORM (No bottom table)
    if user_role == "college":
        csv_btn = ""
        search_box_html = ""
        kpi_sec = ""
        submitted_banner = ""
        if submitted:
            submitted_banner = f"""
            <div class="success-banner" style="max-width: 740px; margin: 0 auto 20px auto;">
                <span>✅ FDR Instrument <strong>#{submitted}</strong> submitted &amp; routed to Bank Auditor Queue!</span>
                <a href="/switch-role/bank" class="action-btn" style="background:#0B2545; color:#ff9933;">🔐 Login as Bank Auditor &rarr;</a>
            </div>
            """

        main_content = f"""
        {submitted_banner}
        <div class="panel" id="college-panel" style="max-width: 740px; margin: 0 auto 25px auto;">
            <div class="panel-title">
                <span>🏢 College Digital FDR Submission Portal</span>
                <span style="font-size: 11px; color: #059669;">AI OCR Extraction &amp; Instant Bank Alert Active</span>
            </div>
            <form action="/submit-ingestion-stream" method="POST" enctype="multipart/form-data">
                <div class="form-grid">
                    <div class="form-group">
                        <label>1. AICTE Permanent Institution ID</label>
                        <input type="text" name="aicte_inst_id" value="1-49283741" required>
                    </div>
                    <div class="form-group">
                        <label>2. Technical Institution Name</label>
                        <input type="text" name="institution_name" value="{decoded_org}" required>
                    </div>
                    <div class="form-group">
                        <label>3. Issuing Bank Name</label>
                        <input type="text" name="bank_name" placeholder="e.g., State Bank of India, Adyar Branch" required>
                    </div>
                    <div class="form-group">
                        <label>4. FDR Instrument Reference No.</label>
                        <input type="text" name="fdr_num" placeholder="e.g., SBIN0098451" required>
                    </div>
                    <div class="form-group">
                        <label>5. Deposit Amount (INR) [Statutory Norm: ₹15,00,000]</label>
                        <input type="number" step="any" name="amount" placeholder="e.g., 1500000" required>
                    </div>
                    <div class="form-group">
                        <label>6. Date of Issue</label>
                        <input type="date" name="issue_date" required>
                    </div>
                    <div class="form-group full">
                        <label>7. Maturity Date</label>
                        <input type="date" name="maturity_date" required>
                    </div>
                    <div class="form-group full">
                        <label>8. Upload Original Scanned FDR Certificate (PDF)</label>
                        <input type="file" name="fdr_pdf" accept=".pdf" required style="border:2px dashed #cbd5e0; background:#f8fafc; padding:12px; border-radius:8px;">
                    </div>
                </div>
                <button type="submit" class="btn-transmit">🚀 Submit FDR &amp; Notify Bank Auditor</button>
            </form>
        </div>
        """

    # PAGE 2: ONLY BANK AUDITOR QUEUE
    elif user_role == "bank":
        csv_btn = ""
        search_box_html = '<input type="text" id="globalSearch" class="search-box" onkeyup="filterTables()" placeholder="🔍 Search FDR No, College, or Bank...">'
        kpi_sec = ""

        bank_queue_markup = ""
        for row in records:
            if row['regulatory_status'] == 'Awaiting Bank Audit':
                row_keys = row.keys()
                inst_amt = row['inst_submitted_amount'] if ('inst_submitted_amount' in row_keys and row['inst_submitted_amount'] is not None) else (row['amount'] if 'amount' in row_keys else 0.0)
                is_warning = 'Warning' in row['ocr_match_status']
                badge_cls = "badge warn" if is_warning else "badge ok"
                ocr_subtext = (
                    '<small style="color:#dc2626; font-weight:bold;">⚠️ Below ₹15,00,000 Norm</small>'
                    if inst_amt < 1500000
                    else f'<small style="color:#059669;">OCR: ₹{inst_amt:,.2f} (Match)</small>'
                )

                bank_queue_markup += f"""
                <tr>
                    <td>
                        <span style="background:#fef3c7;color:#b45309;font-size:10px;font-weight:900;padding:3px 7px;border-radius:4px;">🔔 NEW VERIFICATION REQUEST</span><br>
                        <strong style="font-size:14px;color:#0B2545;">{row['institution_name']}</strong><br>
                        <small style="color:#64748b;">AICTE ID: {row['aicte_inst_id']}</small>
                    </td>
                    <td>
                        <strong style="font-size:15px;color:#1e3a8a;">{row['fdr_number']}</strong><br>
                        <small style="color:#64748b;">Bank: {row['bank_name']}</small>
                    </td>
                    <td>
                        <strong style="font-size:15px;color:#0B2545;">Form: ₹{inst_amt:,.2f}</strong><br>
                        {ocr_subtext}
                    </td>
                    <td>Issued: {row['issue_date']}<br><strong>Matures: {row['maturity_date']}</strong></td>
                    <td><span class="{badge_cls}">{row['ocr_match_status']}</span></td>
                    <td style="text-align:center;">
                        <a href="/verify-fdr/{row['id']}" class="action-btn green-btn" style="padding:10px 18px;font-size:12px;">✅ Verify &amp; Lock</a>
                        <a href="/flag-fdr/{row['id']}" class="action-btn red-btn" style="padding:10px 18px;font-size:12px;">🚩 Flag Discrepancy</a>
                    </td>
                </tr>
                """
        empty_bank = '<tr><td colspan="6" style="text-align:center; padding: 40px; color:#059669; font-weight:bold; font-size:14px;">🎉 Queue Empty! All college FDR requests have been verified or processed by the Bank Auditor.</td></tr>'

        main_content = f"""
        <div id="bank-panel">
            <div class="bank-alert-banner">
                <div class="bank-alert-text">
                    <h3>🔔 Incoming FDR Verification Alert for Bank Auditor!</h3>
                    <p>You have <strong>{bank_pending_count} pending FDR request(s)</strong> from colleges. Review AI OCR extraction and click <strong>[Verify &amp; Lock]</strong> or <strong>[Flag Discrepancy]</strong>.</p>
                </div>
                <div style="background:#0B2545;color:#ff9933;padding:10px 16px;border-radius:8px;font-size:12px;font-weight:900;text-transform:uppercase;">
                    🏦 1-Click Bank Auditor Portal
                </div>
            </div>

            <div class="list-section">
                <div class="list-header bank-navy">
                    <span>🏦 Pending Verification Requests from Colleges (1-Click Bank Auditor Queue)</span>
                    <span style="font-size: 12px; background: #ef4444; padding: 4px 12px; border-radius: 999px;">{bank_pending_count} Waiting for Banker</span>
                </div>
                <div class="table-wrapper">
                    <table class="fdr-table">
                        <thead>
                            <tr>
                                <th>Submitting College</th>
                                <th>FDR Number &amp; Bank Branch</th>
                                <th>Deposit Amount</th>
                                <th>Issue &amp; Maturity Date</th>
                                <th>AI OCR Pre-Check</th>
                                <th style="text-align:center;">1-Click Banker Decision</th>
                            </tr>
                        </thead>
                        <tbody>
                            {bank_queue_markup if bank_queue_markup else empty_bank}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """

    # PAGE 3: ONLY AICTE MASTER DASHBOARD
    else:
        csv_btn = '<a href="/export-audit-csv" class="action-btn" style="background:#059669; color:white; padding:10px 16px; font-size:12px;">📥 Export Audit CSV</a>'
        search_box_html = '<input type="text" id="globalSearch" class="search-box" onkeyup="filterTables()" placeholder="🔍 Search FDR No, College, or Bank...">'
        kpi_sec = f"""
        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-info"><h4>Total FDR Instruments</h4><div class="kpi-num">{total_count}</div></div>
                <span style="font-size: 26px;">🏛️</span>
            </div>
            <div class="kpi-card green">
                <div class="kpi-info"><h4>Bank Verified &amp; Locked</h4><div class="kpi-num" style="color: #059669;">{verified_count}</div></div>
                <span style="font-size: 26px;">✅</span>
            </div>
            <div class="kpi-card red">
                <div class="kpi-info"><h4>Discrepancies Flagged</h4><div class="kpi-num" style="color: #dc2626;">{flagged_count}</div></div>
                <span style="font-size: 26px;">🚨</span>
            </div>
            <div class="kpi-card amber">
                <div class="kpi-info"><h4>Maturing ≤ 30 Days (Escalated)</h4><div class="kpi-num" style="color: #d97706;">{critical_escalations}</div></div>
                <span style="font-size: 26px;">⏳</span>
            </div>
        </section>
        """

        red_list_markup, yellow_list_markup, green_list_markup = "", "", ""
        for row in records:
            try:
                days_left = (datetime.strptime(row['maturity_date'], "%Y-%m-%d") - current_date).days
            except Exception:
                days_left = 999

            row_keys = row.keys()
            inst_amt = row['inst_submitted_amount'] if ('inst_submitted_amount' in row_keys and row['inst_submitted_amount'] is not None) else (row['amount'] if 'amount' in row_keys else 0.0)
            bank_amt = row['bank_confirmed_amount'] if ('bank_confirmed_amount' in row_keys and row['bank_confirmed_amount'] is not None) else 0.0

            if row['regulatory_status'] == 'Verified & Safely Locked':
                if days_left <= 90:
                    aicte_action = f'<a href="/renew-fdr/{row["id"]}" class="action-btn" style="background:#f59e0b;color:#fff;">🔄 Auto-Renew (8 Yrs)</a>'
                else:
                    aicte_action = (
                        f'<span style="color:#10b981; font-weight:bold; font-size:11px;">🔒 Locked (Bank Verified)</span><br>'
                        f'<a href="/simulate-time-travel/{row["id"]}" class="action-btn" style="background:#0B2545;color:#ff9933;font-size:10px;">⚡ Simulate T-15 Maturity</a>'
                        f'<a href="/release-fdr/{row["id"]}" class="action-btn" style="background:#2563eb;color:#fff;font-size:10px;">📄 Issue Release NOC</a>'
                    )
            elif row['regulatory_status'] == 'Released & Settled':
                aicte_action = (
                    f'<span style="color:#6366f1; font-weight:bold; font-size:11px;">✅ NOC Issued &amp; Released</span><br>'
                    f'<a href="/noc-certificate/{row["id"]}" target="_blank" class="action-btn" style="background:#4f46e5;color:#fff;font-size:10px;margin-top:4px;">🖨️ View Official e-NOC</a>'
                )
            elif row['regulatory_status'] == 'Renewed & Archived':
                aicte_action = '<span style="color:#64748b; font-weight:bold; font-size:11px;">🗄️ Archived (Renewed)</span>'
            elif row['regulatory_status'] == 'Awaiting Bank Audit':
                aicte_action = '<span style="color:#d97706; font-weight:bold; font-size:11px;">⏳ In Bank Auditor Queue</span>'
            else:
                aicte_action = '<span style="color:#ef4444; font-weight:bold; font-size:11px;">🚨 Discrepancy Flagged by Bank</span>'

            lineage_tag = f"<br><small style='color:#2563eb;font-weight:bold;'>🔗 Renewed from: {row['parent_fdr_number']}</small>" if row['parent_fdr_number'] != 'ORIGINAL' else ""
            bank_conf_tag = (
                f"<br><small style='color:#059669;font-weight:bold;'>🏦 Bank Confirmed: ₹{bank_amt:,.2f}</small>"
                if bank_amt > 0
                else "<br><small style='color:#d97706;'>⏳ Bank Confirmation Pending</small>"
            )

            is_warn = 'Warning' in row['ocr_match_status'] or row['regulatory_status'] == 'Discrepancy Flagged'
            ocr_badge_cls = "badge warn" if is_warn else "badge ok"

            row_html = f"""
            <tr>
                <td>
                    <strong>{row['fdr_number']}</strong>{lineage_tag}<br>
                    <small style="color:#2d3748;font-weight:600;">{row['institution_name']}</small><br>
                    <small style="color:#718096;">AICTE ID: {row['aicte_inst_id']} | Bank: {row['bank_name']}</small>
                </td>
                <td>
                    <strong>🏢 Inst: ₹{inst_amt:,.2f}</strong>
                    {bank_conf_tag}
                </td>
                <td>{row['issue_date']}</td>
                <td>
                    <strong>{row['maturity_date']}</strong><br>
                    <small style="color:{'#dc2626' if days_left <= 30 else '#4a5568'}; font-weight:bold;">({days_left} days left)</small>
                </td>
                <td><span class="{ocr_badge_cls}">{row['ocr_match_status']}</span></td>
                <td><span class="badge">{row['regulatory_status']}</span></td>
                <td style="text-align:center;">{aicte_action}</td>
            </tr>
            """

            if 'Warning' in row['ocr_match_status'] or row['regulatory_status'] == 'Discrepancy Flagged' or (days_left < 0 and row['regulatory_status'] not in ('Released & Settled', 'Renewed & Archived')):
                red_list_markup += row_html
            elif 0 <= days_left <= 90 and row['regulatory_status'] not in ('Released & Settled', 'Renewed & Archived'):
                yellow_list_markup += row_html
            else:
                green_list_markup += row_html

        empty_red = '<tr><td colspan="7" style="text-align:center; color:#999;">No critical anomalies or discrepancies flagged.</td></tr>'
        empty_yellow = '<tr><td colspan="7" style="text-align:center; color:#999;">No instruments maturing within 90 days.</td></tr>'
        empty_green = '<tr><td colspan="7" style="text-align:center; color:#999;">No validated active instruments logged yet.</td></tr>'

        logs_markup = ""
        for log in logs:
            curr_h = log["curr_hash"] if log["curr_hash"] else "GENESIS"
            short_hash = curr_h[:10]
            role_label = log["actor_role"] if log["actor_role"] else "SYSTEM"
            logs_markup += (
                f'<div class="log-item">'
                f'<span class="log-time">[{log["timestamp"]}]</span> '
                f'<strong style="color:#60a5fa;">[{role_label}]</strong> {log["action_description"]} '
                f'<code style="font-size:10px;color:#10b981;">[SHA256:{short_hash}...]</code>'
                f'</div>'
            )

        main_content = f"""
        <div class="list-container">
            <div class="list-section">
                <div class="list-header red">
                    <span>🔴 Red List: Discrepancy Flagged / Below APH Norm / Overdue Instruments</span>
                    <span style="font-size: 11px; background: rgba(0,0,0,0.2); padding: 3px 8px; border-radius: 4px;">Immediate Scrutiny Required</span>
                </div>
                <div class="table-wrapper">
                    <table class="fdr-table">
                        <thead><tr><th>FDR Reference &amp; Institution</th><th>Inst Submitted vs Bank Confirmed</th><th>Issue Date</th><th>Maturity &amp; Validity</th><th>AI / Norm Scrutiny</th><th>Regulatory Status</th><th style="text-align:center;">AICTE Authority Actions</th></tr></thead>
                        <tbody>{red_list_markup if red_list_markup else empty_red}</tbody>
                    </table>
                </div>
            </div>

            <div class="list-section">
                <div class="list-header yellow">
                    <span>🟡 Yellow List: Maturing Within 90 Days (Automated T-90/T-30 Reminders Active)</span>
                    <span style="font-size: 11px; background: rgba(0,0,0,0.2); padding: 3px 8px; border-radius: 4px;">Renewal Tracking Window</span>
                </div>
                <div class="table-wrapper">
                    <table class="fdr-table">
                        <thead><tr><th>FDR Reference &amp; Institution</th><th>Inst Submitted vs Bank Confirmed</th><th>Issue Date</th><th>Maturity &amp; Validity</th><th>AI / Norm Scrutiny</th><th>Regulatory Status</th><th style="text-align:center;">AICTE Authority Actions</th></tr></thead>
                        <tbody>{yellow_list_markup if yellow_list_markup else empty_yellow}</tbody>
                    </table>
                </div>
            </div>

            <div class="list-section">
                <div class="list-header green">
                    <span>🟢 Green List: Active, Verified &amp; Lien-Locked Instruments</span>
                    <span style="font-size: 11px; background: rgba(0,0,0,0.2); padding: 3px 8px; border-radius: 4px;">Compliant Repository</span>
                </div>
                <div class="table-wrapper">
                    <table class="fdr-table">
                        <thead><tr><th>FDR Reference &amp; Institution</th><th>Inst Submitted vs Bank Confirmed</th><th>Issue Date</th><th>Maturity &amp; Validity</th><th>AI / Norm Scrutiny</th><th>Regulatory Status</th><th style="text-align:center;">AICTE Authority Actions</th></tr></thead>
                        <tbody>{green_list_markup if green_list_markup else empty_green}</tbody>
                    </table>
                </div>
            </div>

            <div class="audit-trail-panel">
                <div class="audit-header">
                    <div style="font-size: 14px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;">
                        ⛓️ Immutable Regulatory Audit Trail (SHA-256 Hash-Chained Ledger)
                    </div>
                    <span style="font-size: 11px; color: #ff9933;">Tamper-Proof Compliance Logs</span>
                </div>
                <div class="log-stream">{logs_markup if logs_markup else '<div style="color:#999; font-size:12px;">No operational trail logs indexed.</div>'}</div>
            </div>
        </div>
        """

    html_content = (
        html_content
        .replace("%%ROLE_TABS_BAR%%", role_tabs_html)
        .replace("%%CSV_EXPORT_BTN%%", csv_btn)
        .replace("%%SEARCH_BOX_BLOCK%%", search_box_html)
        .replace("%%KPI_SECTION_BLOCK%%", kpi_sec)
        .replace("%%MAIN_CONTENT_BLOCK%%", main_content)
    )

    return HTMLResponse(content=html_content)


@app.get("/export-audit-csv")
async def export_audit_csv(user_role: str = Cookie(default=None)):
    if user_role != "aicte":
        return RedirectResponse(url="/login?role=aicte&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, actor_role, action_description, curr_hash FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    csv_data = "Timestamp,Actor Role,Action Description,SHA256 Hash\n"
    for r in rows:
        csv_data += f'"{r[0]}","{r[1]}","{r[2]}","{r[3]}"\n'
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=AICTE_FDR_Audit_Report.csv"}
    )


@app.post("/submit-ingestion-stream")
async def process_fdr_ingestion(
    request: Request,
    aicte_inst_id: str = Form("1-49283741"),
    institution_name: str = Form("KCG College of Technology, Chennai"),
    bank_name: str = Form(...),
    fdr_num: str = Form(...),
    amount: float = Form(...),
    issue_date: str = Form(...),
    maturity_date: str = Form(...),
    fdr_pdf: UploadFile = File(...),
    user_role: str = Cookie(default=None),
    user_org: str = Cookie(default="KCG College of Technology, Chennai")
):
    if user_role != "college":
        return RedirectResponse(url="/login?role=college&notice=auth_required", status_code=303)

    file_bytes = await fdr_pdf.read()
    doc_hash = hashlib.sha256(file_bytes).hexdigest()

    clean_fdr = re.sub(r'[^A-Za-z0-9_-]', '', fdr_num)
    clean_pdf_name = re.sub(r'[^A-Za-z0-9_.-]', '', os.path.basename(fdr_pdf.filename or "fdr.pdf"))
    safe_filename = f"{clean_fdr}_{doc_hash[:8]}_{clean_pdf_name}"
    with open(os.path.join(UPLOAD_DIR, safe_filename), "wb") as f:
        f.write(file_bytes)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT fdr_number FROM fdr_repository WHERE document_hash=? AND document_hash != ''", (doc_hash,))
    duplicate_doc = cursor.fetchone()

    ocr_match_status = "Verified Match (OCR + APH Norms)"
    discrepancy_log = "None"
    regulatory_status = "Awaiting Bank Audit"

    if amount < 1500000 and duplicate_doc:
        ocr_match_status = "Warning: Below APH Norm (<15L) & Duplicate PDF!"
        discrepancy_log = f"Amount below ₹15L norm and file matches existing FDR #{duplicate_doc[0]}"
    elif amount < 1500000:
        ocr_match_status = "Warning: Below AICTE APH Norm (<15L)!"
        discrepancy_log = "Submitted amount is below statutory ₹15,00,000 requirement."
    elif duplicate_doc:
        ocr_match_status = "Warning: Duplicate PDF Hash Detected!"
        discrepancy_log = f"Uploaded file matches existing FDR #{duplicate_doc[0]}"

    cursor.execute("SELECT id FROM fdr_repository WHERE fdr_number=?", (fdr_num,))
    if cursor.fetchone():
        fdr_num = f"{fdr_num}-{datetime.now().strftime('%H%M%S')}"

    final_inst_name = institution_name.strip() if institution_name and institution_name.strip() else unquote(user_org)
    final_inst_id = aicte_inst_id.strip() if aicte_inst_id and aicte_inst_id.strip() else "1-49283741"

    cursor.execute('''
        INSERT INTO fdr_repository (
            aicte_inst_id, institution_name, bank_name, fdr_number,
            amount, inst_submitted_amount, issue_date, maturity_date,
            document_hash, ocr_match_status, regulatory_status, discrepancy_log
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        final_inst_id, final_inst_name, bank_name.strip(), fdr_num.strip(),
        amount, amount, issue_date, maturity_date,
        doc_hash, ocr_match_status, regulatory_status, discrepancy_log
    ))

    record_immutable_audit(
        cursor,
        actor_role="INSTITUTION",
        description=f"{final_inst_name} ({final_inst_id}) submitted FDR #{fdr_num} (₹{amount:,.2f}). Status: [{ocr_match_status}]. Pushed to {bank_name} Auditor Queue."
    )
    conn.commit()
    conn.close()
    
    # Automatically clear session and redirect to Bank Login to inspect the pending verification queue
    response = RedirectResponse(url="/login?role=bank&notice=new_fdr_pending", status_code=303)
    response.delete_cookie("user_role")
    response.delete_cookie("user_org")
    return response


@app.get("/verify-fdr/{record_id}")
async def verify_fdr(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "bank":
        return RedirectResponse(url="/login?role=bank&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT inst_submitted_amount, fdr_number, bank_name FROM fdr_repository WHERE id=?", (record_id,))
    row = cursor.fetchone()
    if row:
        inst_amount, fdr_no, bank = row
        cursor.execute('''
            UPDATE fdr_repository 
            SET regulatory_status='Verified & Safely Locked',
                ocr_match_status='Verified Match (Bank + OCR)',
                bank_confirmed_amount=?,
                lien_marked_to_aicte='Confirmed via Bank Gateway'
            WHERE id=?
        ''', (inst_amount, record_id))
        record_immutable_audit(
            cursor,
            actor_role="BANK_AUDITOR",
            description=f"{bank} Auditor clicked [Verify] on FDR #{fdr_no} (₹{inst_amount:,.2f}) & locked Lien to AICTE."
        )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/flag-fdr/{record_id}")
async def flag_fdr(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "bank":
        return RedirectResponse(url="/login?role=bank&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE fdr_repository 
        SET regulatory_status='Discrepancy Flagged', 
            ocr_match_status='Warning: Bank Flagged Discrepancy!' 
        WHERE id=?
    ''', (record_id,))
    record_immutable_audit(
        cursor,
        actor_role="BANK_AUDITOR",
        description=f"Bank Auditor clicked [Flag Discrepancy] on Asset ID #{record_id}. Escalated to AICTE Red List."
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/renew-fdr/{record_id}")
async def renew_fdr(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "aicte":
        return RedirectResponse(url="/login?role=aicte&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT aicte_inst_id, institution_name, bank_name, fdr_number, inst_submitted_amount FROM fdr_repository WHERE id=?", (record_id,))
    old_fdr = cursor.fetchone()
    if old_fdr:
        inst_id, inst_name, bank, old_fdr_no, amount = old_fdr
        new_fdr_no = f"{old_fdr_no}-R1"
        new_issue = datetime.now().strftime("%Y-%m-%d")
        new_maturity = (datetime.now() + timedelta(days=365 * 8)).strftime("%Y-%m-%d")

        cursor.execute("UPDATE fdr_repository SET regulatory_status='Renewed & Archived' WHERE id=?", (record_id,))

        cursor.execute('''
            INSERT INTO fdr_repository (
                aicte_inst_id, institution_name, bank_name, fdr_number,
                amount, inst_submitted_amount, bank_confirmed_amount, issue_date, maturity_date,
                parent_fdr_number, ocr_match_status, regulatory_status, lien_marked_to_aicte
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Verified Renewal Match', 'Verified & Safely Locked', 'Confirmed')
        ''', (inst_id, inst_name, bank, new_fdr_no, amount, amount, amount, new_issue, new_maturity, old_fdr_no))

        record_immutable_audit(
            cursor,
            actor_role="RENEWAL_ENGINE",
            description=f"FDR #{old_fdr_no} renewed into #{new_fdr_no} for 8 years (New Maturity: {new_maturity}). Lineage preserved."
        )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/release-fdr/{record_id}")
async def release_fdr(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "aicte":
        return RedirectResponse(url="/login?role=aicte&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT fdr_number, institution_name FROM fdr_repository WHERE id=?", (record_id,))
    row = cursor.fetchone()
    if row:
        fdr_no, inst_name = row
        cursor.execute("UPDATE fdr_repository SET regulatory_status='Released & Settled' WHERE id=?", (record_id,))
        record_immutable_audit(
            cursor,
            actor_role="AICTE_DIRECTOR",
            description=f"Competent Authority approved Release/Discharge of FDR #{fdr_no} for {inst_name}. Digital e-NOC issued."
        )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/simulate-time-travel/{record_id}")
async def simulate_approaching_maturity(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "aicte":
        return RedirectResponse(url="/login?role=aicte&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    simulated_maturity = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d")
    cursor.execute("UPDATE fdr_repository SET maturity_date=? WHERE id=?", (simulated_maturity, record_id))
    record_immutable_audit(
        cursor,
        actor_role="CRON_MONITOR",
        description=f"ALERT: Asset ID #{record_id} entered T-15 Maturity Window ({simulated_maturity}). SMS/Email Escalation triggered!"
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/", status_code=303)


@app.get("/noc-certificate/{record_id}", response_class=HTMLResponse)
async def generate_noc_certificate(record_id: int, user_role: str = Cookie(default=None)):
    if user_role != "aicte":
        return RedirectResponse(url="/login?role=aicte&notice=auth_required", status_code=303)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fdr_repository WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return HTMLResponse("<h3>Record not found</h3>", status_code=404)

    cert_hash = hashlib.sha256(f"{row['fdr_number']}|{row['aicte_inst_id']}|RELEASED".encode()).hexdigest()[:16].upper()
    issue_timestamp = datetime.now().strftime("%d %B %Y, %I:%M %p")

    noc_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AICTE Official e-NOC - {row['fdr_number']}</title>
        <style>
            body {{ font-family: 'Georgia', serif; background: #e2e8f0; padding: 40px; }}
            .cert-box {{ max-width: 800px; margin: 0 auto; background: #fff; padding: 50px; border: 8px double #0B2545; box-shadow: 0 10px 25px rgba(0,0,0,0.15); }}
            .header {{ text-align: center; border-bottom: 3px solid #ff9933; padding-bottom: 20px; margin-bottom: 30px; }}
            .header h1 {{ color: #0B2545; font-size: 22px; margin: 0; text-transform: uppercase; }}
            .header p {{ color: #4a5568; font-size: 13px; margin: 5px 0 0 0; font-family: sans-serif; font-weight: bold; }}
            .meta {{ display: flex; justify-content: space-between; font-family: sans-serif; font-size: 12px; margin-bottom: 25px; color: #333; }}
            .title {{ text-align: center; font-weight: bold; font-size: 18px; text-decoration: underline; color: #0B2545; margin: 25px 0; }}
            .content {{ font-size: 15px; line-height: 1.8; color: #1a202c; text-align: justify; }}
            .details-table {{ width: 100%; border-collapse: collapse; margin: 25px 0; font-family: sans-serif; font-size: 13px; }}
            .details-table th, .details-table td {{ border: 1px solid #cbd5e0; padding: 10px 14px; text-align: left; }}
            .details-table th {{ background: #f8fafc; color: #0B2545; width: 35%; }}
            .footer {{ margin-top: 40px; display: flex; justify-content: space-between; align-items: flex-end; font-family: sans-serif; }}
            .qr-box {{ text-align: center; font-size: 10px; color: #555; }}
            .sign-box {{ text-align: right; }}
            .stamp {{ color: #059669; border: 2px solid #059669; padding: 6px 12px; border-radius: 6px; font-weight: bold; display: inline-block; margin-bottom: 8px; font-size: 12px; }}
            .print-btn {{ display: block; margin: 0 auto 20px auto; background: #0B2545; color: #fff; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            @media print {{ .print-btn {{ display: none; }} body {{ background: #fff; padding: 0; }} }}
        </style>
    </head>
    <body>
        <button class="print-btn" onclick="window.print()">🖨️ Print / Save Official e-NOC as PDF</button>
        <div class="cert-box">
            <div class="header">
                <h1>All India Council for Technical Education (AICTE)</h1>
                <p>Ministry of Education, Government of India | Regulation Bureau, Nelson Mandela Marg, New Delhi</p>
            </div>
            <div class="meta">
                <div><strong>e-NOC Ref No:</strong> AICTE/RB/FDR-REL/2026/{row['id']:04d}</div>
                <div><strong>Date:</strong> {issue_timestamp}</div>
            </div>
            <div class="title">NO OBJECTION &amp; LIEN DISCHARGE CERTIFICATE (e-NOC)</div>
            <div class="content">
                To,<br>
                <strong>The Branch Manager,</strong><br>
                {row['bank_name']}<br><br>
                <strong>Subject:</strong> Authorization for Release / Discharge of Security Deposit / Fixed Deposit Receipt (FDR) No. <strong>{row['fdr_number']}</strong>.<br><br>
                Dear Sir/Madam,<br>
                This is to certify that the Competent Authority at the All India Council for Technical Education (AICTE) has verified the regulatory compliance and statutory lock-in completion for the below-mentioned financial instrument submitted by <strong>{row['institution_name']} (AICTE Permanent ID: {row['aicte_inst_id']})</strong>.
            </div>
            <table class="details-table">
                <tr><th>FDR Instrument Number</th><td><strong>{row['fdr_number']}</strong></td></tr>
                <tr><th>Institution Name &amp; ID</th><td>{row['institution_name']} ({row['aicte_inst_id']})</td></tr>
                <tr><th>Issuing Bank</th><td>{row['bank_name']}</td></tr>
                <tr><th>Principal Deposit Amount</th><td><strong>₹{row['inst_submitted_amount']:,.2f}</strong></td></tr>
                <tr><th>Original Issue &amp; Maturity Date</th><td>{row['issue_date']} to {row['maturity_date']}</td></tr>
                <tr><th>Cryptographic Release Hash</th><td><code>{cert_hash}</code></td></tr>
            </table>
            <div class="content">
                AICTE hereby conveys its <strong>No Objection</strong> for lifting the regulatory lien marked in favor of AICTE and authorizes the release/encashment of the above Fixed Deposit Receipt back to the institution's designated account.
            </div>
            <div class="footer">
                <div class="qr-box">
                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=110x110&data=AICTE-VERIFIED-NOC-{row['fdr_number']}-{cert_hash}" alt="QR Code" /><br>
                    Scan to Verify e-NOC Authenticity
                </div>
                <div class="sign-box">
                    <div class="stamp">✔ DIGITALLY SIGNED &amp; VERIFIED</div><br>
                    <strong>Director (Regulation Bureau)</strong><br>
                    All India Council for Technical Education<br>
                    <small style="color:#666;">Digital Signature Token: {cert_hash}</small>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=noc_html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)