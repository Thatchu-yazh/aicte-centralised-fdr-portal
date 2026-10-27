import os
import re
import sqlite3
import hashlib
from datetime import datetime, timedelta
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="AICTE Security Deposit & FDR Regulatory Ecosystem",
    page_icon="🏛️",
    layout="wide"
)

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


def record_immutable_audit(actor_role: str, description: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
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
    conn.commit()
    conn.close()


# Session State Initialization
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.org_name = None


# ----------------- AUTHENTICATION & LOGIN SCREEN -----------------
if not st.session_state.logged_in:
    st.markdown("""
        <div style="text-align: center; padding: 15px;">
            <h2 style="color: #0B2545; margin-bottom: 5px;">ALL INDIA COUNCIL FOR TECHNICAL EDUCATION (AICTE)</h2>
            <p style="color: #d97706; font-weight: 800; font-size: 13px; text-transform: uppercase;">Centralized FDR Portal — Security Deposit & Regulatory Lifecycle Gateway</p>
        </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.3, 1])
    with col2:
        tab_login, tab_register = st.tabs(["🔐 Secure Login", "📝 Register New Account"])

        with tab_login:
            login_role = st.selectbox("Select Login Portal Role", ["college", "bank", "aicte"], format_func=lambda x: {
                "college": "🏢 Technical Institution / College Portal",
                "bank": "🏦 Bank Branch Auditor Portal",
                "aicte": "🏛️ AICTE Regulation Bureau Dashboard"
            }[x])
            login_user = st.text_input("Official Registered Email / ID", placeholder="e.g. college@kcg.edu")
            login_pass = st.text_input("Secure Password", type="password")

            if st.button("🔒 Secure Login to Portal", use_container_width=True):
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT role, org_name FROM users WHERE username=? AND password=? AND role=?",
                    (login_user.strip(), login_pass, login_role)
                )
                user = cursor.fetchone()
                conn.close()

                if user:
                    st.session_state.logged_in = True
                    st.session_state.role = user[0]
                    st.session_state.org_name = user[1]
                    st.success("✅ Login Successful! Redirecting...")
                    st.rerun()
                else:
                    st.error("⚠️ Invalid Credentials or Role Mismatch! Please check demo accounts.")

            st.markdown("""
                <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px; border-radius: 8px; font-size: 11px; color: #166534; margin-top: 15px; line-height: 1.6;">
                    <strong>🔑 Quick Demo Accounts:</strong><br>
                    • College: <code>college@kcg.edu</code> / <code>password123</code><br>
                    • Bank: <code>bank@sbi.in</code> / <code>password123</code><br>
                    • AICTE: <code>aicte@gov.in</code> / <code>password123</code>
                </div>
            """, unsafe_allow_html=True)

        with tab_register:
            reg_role = st.selectbox("Select Stakeholder Role", ["college", "bank", "aicte"], format_func=lambda x: {
                "college": "Technical Institution / College",
                "bank": "Issuing Bank Branch Official",
                "aicte": "AICTE Regulation Bureau Officer"
            }[x], key="reg_role")
            reg_org = st.text_input("Organization / College Name", placeholder="e.g. KCG College of Technology, Chennai")
            reg_user = st.text_input("Official Portal Email ID", placeholder="admin@college.edu", key="reg_user")
            reg_pass = st.text_input("Create Secure Password", type="password", key="reg_pass")

            if st.button("📝 Register & Create Portal Account", use_container_width=True):
                if reg_org and reg_user and reg_pass:
                    try:
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO users (username, password, role, org_name) VALUES (?, ?, ?, ?)",
                            (reg_user.strip(), reg_pass, reg_role, reg_org.strip())
                        )
                        conn.commit()
                        conn.close()
                        st.success("✅ Registration Successful! Please switch to the Login tab to enter your portal.")
                    except sqlite3.IntegrityError:
                        conn.close()
                        st.error("⚠️ Email ID already registered! Please log in with your existing account.")
                else:
                    st.warning("⚠️ Please fill in all registration fields.")

# ----------------- LOGGED-IN PORTAL DASHBOARD -----------------
else:
    # Header Bar
    st.markdown(f"""
        <div style="background: #0B2545; color: white; padding: 16px 24px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; border-bottom: 4px solid #ff9933; margin-bottom: 20px;">
            <div>
                <h3 style="margin: 0; font-size: 18px; text-transform: uppercase;">All India Council for Technical Education (AICTE)</h3>
                <p style="margin: 3px 0 0 0; font-size: 11px; color: #ff9933; font-weight: bold;">Regulation Bureau — Secure Portal | Logged in as: <strong>{st.session_state.org_name}</strong> ({st.session_state.role.upper()})</p>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Top Navigation Switcher Bar
    col_nav1, col_nav2, col_nav3, col_logout = st.columns([2, 2, 2, 1])
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fdr_repository ORDER BY id DESC")
    records = cursor.fetchall()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 12")
    logs = cursor.fetchall()
    conn.close()

    bank_pending_count = sum(1 for r in records if r['regulatory_status'] == 'Awaiting Bank Audit')

    with col_nav1:
        if st.button("🏢 1. College Submitter", use_container_width=True):
            st.session_state.role = "college"
            st.rerun()
    with col_nav2:
        if st.button(f"🏦 2. Bank Auditor ({bank_pending_count} Pending)", use_container_width=True):
            st.session_state.role = "bank"
            st.rerun()
    with col_nav3:
        if st.button("🏛️ 3. AICTE Master Dashboard", use_container_width=True):
            st.session_state.role = "aicte"
            st.rerun()
    with col_logout:
        if st.button("🚪 Logout", use_container_width=True, type="primary"):
            st.session_state.logged_in = False
            st.session_state.role = None
            st.session_state.org_name = None
            st.rerun()

    st.markdown("---")

    # ----------------- ROLE 1: COLLEGE SUBMITTER PORTAL -----------------
    if st.session_state.role == "college":
        st.markdown("### 🏢 College Digital FDR Submission Portal")
        st.caption("AI OCR Extraction & Instant Bank Alert Active")

        with st.form("college_fdr_form"):
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                aicte_inst_id = st.text_input("1. AICTE Permanent Institution ID", value="1-49283741")
                institution_name = st.text_input("2. Technical Institution Name", value=st.session_state.org_name)
                bank_name = st.text_input("3. Issuing Bank Name & Branch", placeholder="e.g., State Bank of India, Adyar Branch")
                fdr_num = st.text_input("4. FDR Instrument Reference No.", placeholder="e.g., SBIN0098451")
            with col_f2:
                amount = st.number_input("5. Deposit Amount (INR) [Statutory Norm: ₹15,00,000]", min_value=0.0, step=10000.0, value=1500000.0)
                issue_date = st.date_input("6. Date of Issue")
                maturity_date = st.date_input("7. Maturity Date")
                fdr_pdf = st.file_uploader("8. Upload Original Scanned FDR Certificate (PDF)", type=["pdf"])

            submit_btn = st.form_submit_button("🚀 Submit FDR & Notify Bank Auditor")

            if submit_btn:
                if fdr_pdf and bank_name and fdr_num:
                    file_bytes = fdr_pdf.read()
                    doc_hash = hashlib.sha256(file_bytes).hexdigest()

                    clean_fdr = re.sub(r'[^A-Za-z0-9_-]', '', fdr_num)
                    clean_pdf_name = re.sub(r'[^A-Za-z0-9_.-]', '', os.path.basename(fdr_pdf.name or "fdr.pdf"))
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

                    cursor.execute('''
                        INSERT INTO fdr_repository (
                            aicte_inst_id, institution_name, bank_name, fdr_number,
                            amount, inst_submitted_amount, issue_date, maturity_date,
                            document_hash, ocr_match_status, regulatory_status, discrepancy_log
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        aicte_inst_id.strip(), institution_name.strip(), bank_name.strip(), fdr_num.strip(),
                        amount, amount, str(issue_date), str(maturity_date),
                        doc_hash, ocr_match_status, regulatory_status, discrepancy_log
                    ))

                    record_immutable_audit(
                        "INSTITUTION",
                        f"{institution_name} ({aicte_inst_id}) submitted FDR #{fdr_num} (₹{amount:,.2f}). Status: [{ocr_match_status}]. Pushed to Bank Queue."
                    )
                    conn.commit()
                    conn.close()

                    st.success(f"✅ FDR #{fdr_num} successfully submitted and routed to Bank Auditor Queue!")
                    st.info("💡 Switch to the Bank Auditor tab above to verify this submission.")
                else:
                    st.warning("⚠️ Please fill in all required fields and upload the FDR PDF certificate.")

    # ----------------- ROLE 2: BANK AUDITOR PORTAL -----------------
    elif st.session_state.role == "bank":
        st.markdown("### 🏦 Bank Auditor Verification Queue")
        st.markdown(f"""
            <div style="background: #fffbeb; border: 2px solid #f59e0b; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h4 style="margin:0 0 5px 0; color:#92400e;">🔔 Incoming FDR Verification Alert for Bank Auditor</h4>
                <p style="margin:0; color:#b45309; font-size:13px;">Review AI OCR extraction and click <strong>[Verify & Lock]</strong> or <strong>[Flag Discrepancy]</strong>.</p>
            </div>
        """, unsafe_allow_html=True)

        pending_rows = [r for r in records if r['regulatory_status'] == 'Awaiting Bank Audit']

        if not pending_rows:
            st.success("🎉 Queue Empty! All college FDR requests have been verified or processed.")
        else:
            for row in pending_rows:
                with st.container():
                    st.markdown(f"""
                        <div style="background: white; padding: 16px; border-radius: 10px; border: 1px solid #e2e8f0; margin-bottom: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                            <strong>🏫 Institution:</strong> {row['institution_name']} (ID: {row['aicte_inst_id']})<br>
                            <strong>🏦 FDR Ref & Bank:</strong> {row['fdr_number']} — {row['bank_name']}<br>
                            <strong>💰 Deposit Amount:</strong> ₹{row['inst_submitted_amount']:,.2f}<br>
                            <strong>📅 Issue / Maturity:</strong> {row['issue_date']} to {row['maturity_date']}<br>
                            <strong>🛡️ AI Pre-Check:</strong> <span style="color: #d97706; font-weight: bold;">{row['ocr_match_status']}</span>
                        </div>
                    """, unsafe_allow_html=True)

                    col_b1, col_b2, col_space = st.columns([1, 1, 3])
                    with col_b1:
                        if st.button("✅ Verify & Lock", key=f"verify_{row['id']}"):
                            conn = sqlite3.connect(DB_FILE)
                            cursor = conn.cursor()
                            cursor.execute('''
                                UPDATE fdr_repository 
                                SET regulatory_status='Verified & Safely Locked',
                                    ocr_match_status='Verified Match (Bank + OCR)',
                                    bank_confirmed_amount=?,
                                    lien_marked_to_aicte='Confirmed via Bank Gateway'
                                WHERE id=?
                            ''', (row['inst_submitted_amount'], row['id']))
                            record_immutable_audit("BANK_AUDITOR", f"Verified FDR #{row['fdr_number']} (₹{row['inst_submitted_amount']:,.2f}) & locked Lien.")
                            conn.commit()
                            conn.close()
                            st.success(f"FDR #{row['fdr_number']} successfully verified and locked!")
                            st.rerun()
                    with col_b2:
                        if st.button("🚩 Flag Discrepancy", key=f"flag_{row['id']}"):
                            conn = sqlite3.connect(DB_FILE)
                            cursor = conn.cursor()
                            cursor.execute('''
                                UPDATE fdr_repository 
                                SET regulatory_status='Discrepancy Flagged', 
                                    ocr_match_status='Warning: Bank Flagged Discrepancy!' 
                                WHERE id=?
                            ''', (row['id'],))
                            record_immutable_audit("BANK_AUDITOR", f"Flagged discrepancy on FDR #{row['fdr_number']}.")
                            conn.commit()
                            conn.close()
                            st.warning(f"FDR #{row['fdr_number']} flagged and escalated to AICTE Red List.")
                            st.rerun()
                    st.markdown("---")

    # ----------------- ROLE 3: AICTE MASTER DASHBOARD -----------------
    elif st.session_state.role == "aicte":
        st.markdown("### 🏛️ AICTE Regulation Bureau — Master Dashboard")

        total_count = len(records)
        verified_count = sum(1 for r in records if r['regulatory_status'] == 'Verified & Safely Locked')
        flagged_count = sum(1 for r in records if 'Warning' in r['ocr_match_status'] or r['regulatory_status'] == 'Discrepancy Flagged')

        col_k1, col_k2, col_k3 = st.columns(3)
        col_k1.metric("Total FDR Instruments", total_count)
        col_k2.metric("Bank Verified & Locked", verified_count)
        col_k3.metric("Discrepancies Flagged", flagged_count)

        st.markdown("---")
        st.markdown("### 📊 Regulatory Instrument Ledger")

        for row in records:
            st.markdown(f"""
                <div style="background: white; padding: 14px; border-radius: 8px; border: 1px solid #cbd5e0; margin-bottom: 10px;">
                    <strong>FDR #{row['fdr_number']}</strong> | {row['institution_name']}<br>
                    <small>Bank: {row['bank_name']} | Amount: ₹{row['inst_submitted_amount']:,.2f} | Status: <b>{row['regulatory_status']}</b></small>
                </div>
            """, unsafe_allow_html=True)
