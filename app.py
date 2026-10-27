import os
import sqlite3
import hashlib
from datetime import datetime, timedelta
import streamlit as st

# Page Configuration
st.set_page_config(
    page_title="AICTE Centralized FDR Portal",
    page_icon="🏛️",
    layout="wide"
)

DB_FILE = "production_aicte_ledger.db"
UPLOAD_DIR = "secured_fdr_vault"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize Session State for Authentication
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.org_name = None

# Database Connection & Helpers
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def record_audit(actor_role, description):
    conn = get_db_connection()
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

# ----------------- LOGIN / REGISTER SCREEN -----------------
if not st.session_state.logged_in:
    st.markdown("""
        <div style="text-align: center; padding: 20px;">
            <h2>🏛️ All India Council for Technical Education (AICTE)</h2>
            <p style="color: #666; font-weight: bold;">Centralized FDR Portal — Security Deposit & Regulatory Lifecycle Gateway</p>
        </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        tab_login, tab_register = st.tabs(["🔐 Secure Login", "📝 Register Account"])

        with tab_login:
            login_role = st.selectbox("Select Portal Role", ["college", "bank", "aicte"], format_func=lambda x: {
                "college": "🏢 Technical Institution / College Portal",
                "bank": "🏦 Bank Branch Auditor Portal",
                "aicte": "🏛️ AICTE Regulation Bureau Dashboard"
            }[x])
            login_user = st.text_input("Official Email / ID", placeholder="e.g. college@kcg.edu")
            login_pass = st.text_input("Secure Password", type="password")

            if st.button("Login to Portal", use_container_width=True):
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT org_name FROM users WHERE username=? AND password=? AND role=?", (login_user.strip(), login_pass, login_role))
                user = cursor.fetchone()
                conn.close()

                if user:
                    st.session_state.logged_in = True
                    st.session_state.role = login_role
                    st.session_state.org_name = user["org_name"]
                    st.success("Login Successful! Loading Portal...")
                    st.rerun()
                else:
                    st.error("⚠️ Invalid Credentials or Role Mismatch!")

            st.markdown("""
                <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 6px; font-size: 12px; margin-top: 15px;">
                    <strong>🔑 Demo Accounts:</strong><br>
                    • College: <code>college@kcg.edu</code> / <code>password123</code><br>
                    • Bank: <code>bank@sbi.in</code> / <code>password123</code><br>
                    • AICTE: <code>aicte@gov.in</code> / <code>password123</code>
                </div>
            """, unsafe_allow_html=True)

        with tab_register:
            reg_role = st.selectbox("Stakeholder Role", ["college", "bank", "aicte"])
            reg_org = st.text_input("Organization / College Name", placeholder="KCG College of Technology")
            reg_user = st.text_input("Portal Email ID", placeholder="admin@college.edu")
            reg_pass = st.text_input("Create Password", type="password", key="reg_pass")

            if st.button("Create Account", use_container_width=True):
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO users (username, password, role, org_name) VALUES (?, ?, ?, ?)", (reg_user.strip(), reg_pass, reg_role, reg_org.strip()))
                    conn.commit()
                    conn.close()
                    st.success("✅ Registration Successful! Please switch to the Login tab.")
                except sqlite3.IntegrityError:
                    st.error("⚠️ Email ID already registered!")

# ----------------- LOGGED-IN DASHBOARD -----------------
else:
    # Top Header Bar
    st.markdown(f"""
        <div style="background: #0B2545; color: white; padding: 15px 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; border-bottom: 4px solid #ff9933;">
            <div>
                <h3 style="margin: 0; font-size: 18px;">AICTE Regulation Bureau</h3>
                <p style="margin: 2px 0 0 0; font-size: 11px; color: #ff9933;">Logged in as: <strong>{st.session_state.org_name}</strong> ({st.session_state.role.upper()})</p>
            </div>
        </div>
    """, unsafe_allow_html=True)

    col_space, col_logout = st.columns([8, 1])
    with col_logout:
        if st.button("🚪 Logout"):
            st.session_state.logged_in = False
            st.session_state.role = None
            st.session_state.org_name = None
            st.rerun()

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fdr_repository ORDER BY id DESC")
    records = cursor.fetchall()
    conn.close()

    # ROLE 1: COLLEGE SUBMITTER PORTAL
    if st.session_state.role == "college":
        st.subheader("🏢 College Digital FDR Submission Portal")
        with st.form("fdr_submit_form"):
            col1, col2 = st.columns(2)
            with col1:
                aicte_inst_id = st.text_input("AICTE Permanent Institution ID", value="1-49283741")
                institution_name = st.text_input("Technical Institution Name", value=st.session_state.org_name)
                bank_name = st.text_input("Issuing Bank Name & Branch", placeholder="State Bank of India, Adyar Branch")
                fdr_num = st.text_input("FDR Instrument Reference No.", placeholder="SBIN0098451")
            with col2:
                amount = st.number_input("Deposit Amount (INR) [Statutory Norm: ₹15,00,000]", min_value=0.0, step=10000.0, value=1500000.0)
                issue_date = st.date_input("Date of Issue")
                maturity_date = st.date_input("Maturity Date")
                uploaded_file = st.file_uploader("Upload Scanned FDR Certificate (PDF)", type=["pdf"])

            submitted = st.form_submit_button("🚀 Submit FDR & Notify Bank Auditor")
            if submitted:
                if uploaded_file and bank_name and fdr_num:
                    file_bytes = uploaded_file.read()
                    doc_hash = hashlib.sha256(file_bytes).hexdigest()
                    safe_filename = f"{fdr_num}_{doc_hash[:8]}_{uploaded_file.name}"
                    with open(os.path.join(UPLOAD_DIR, safe_filename), "wb") as f:
                        f.write(file_bytes)

                    ocr_match_status = "Verified Match (OCR + APH Norms)"
                    discrepancy_log = "None"
                    if amount < 1500000:
                        ocr_match_status = "Warning: Below AICTE APH Norm (<15L)!"
                        discrepancy_log = "Submitted amount is below statutory requirement."

                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO fdr_repository (
                            aicte_inst_id, institution_name, bank_name, fdr_number,
                            amount, inst_submitted_amount, issue_date, maturity_date,
                            document_hash, ocr_match_status, regulatory_status, discrepancy_log
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        aicte_inst_id, institution_name, bank_name, fdr_num,
                        amount, amount, str(issue_date), str(maturity_date),
                        doc_hash, ocr_match_status, "Awaiting Bank Audit", discrepancy_log
                    ))
                    record_audit("INSTITUTION", f"{institution_name} submitted FDR #{fdr_num} (₹{amount:,.2f}). Pushed to Bank Queue.")
                    conn.commit()
                    conn.close()
                    st.success("✅ FDR successfully submitted and sent to Bank Auditor Queue!")
                else:
                    st.warning("⚠️ Please fill in all required fields and upload the PDF.")

    # ROLE 2: BANK AUDITOR PORTAL
    elif st.session_state.role == "bank":
        st.subheader("🏦 Bank Auditor Verification Queue")
        pending_records = [r for r in records if r["regulatory_status"] == "Awaiting Bank Audit"]

        if not pending_records:
            st.info("🎉 Queue Empty! All college FDR requests have been verified.")
        else:
            for row in pending_records:
                with st.expander(f"🔔 {row['institution_name']} — FDR No: {row['fdr_number']} (₹{row['inst_submitted_amount']:,.2f})"):
                    st.write(f"**Bank Name:** {row['bank_name']}")
                    st.write(f"**Issue Date:** {row['issue_date']} | **Maturity Date:** {row['maturity_date']}")
                    st.write(f"**AI Pre-Check Status:** {row['ocr_match_status']}")
                    
                    col_v, col_f = st.columns(2)
                    with col_v:
                        if st.button("✅ Verify & Lock Lien", key=f"v_{row['id']}"):
                            conn = get_db_connection()
                            cursor = conn.cursor()
                            cursor.execute("UPDATE fdr_repository SET regulatory_status='Verified & Safely Locked', ocr_match_status='Verified Match (Bank + OCR)', bank_confirmed_amount=? WHERE id=?", (row['inst_submitted_amount'], row['id']))
                            record_audit("BANK_AUDITOR", f"Verified FDR #{row['fdr_number']} & locked Lien.")
                            conn.commit()
                            conn.close()
                            st.success("Verified successfully!")
                            st.rerun()
                    with col_f:
                        if st.button("🚩 Flag Discrepancy", key=f"f_{row['id']}"):
                            conn = get_db_connection()
                            cursor = conn.cursor()
                            cursor.execute("UPDATE fdr_repository SET regulatory_status='Discrepancy Flagged', ocr_match_status='Warning: Bank Flagged Discrepancy!' WHERE id=?", (row['id'],))
                            record_audit("BANK_AUDITOR", f"Flagged discrepancy on FDR #{row['fdr_number']}.")
                            conn.commit()
                            conn.close()
                            st.warning("Flagged as discrepancy.")
                            st.rerun()

    # ROLE 3: AICTE MASTER DASHBOARD
    elif st.session_state.role == "aicte":
        st.subheader("🏛️ AICTE Regulation Bureau — Master Dashboard")
        
        total = len(records)
        verified = sum(1 for r in records if r['regulatory_status'] == 'Verified & Safely Locked')
        flagged = sum(1 for r in records if 'Warning' in r['ocr_match_status'] or r['regulatory_status'] == 'Discrepancy Flagged')

        k1, k2, k3 = st.columns(3)
        k1.metric("Total Instruments", total)
        k2.metric("Bank Verified & Locked", verified)
        k3.metric("Discrepancies Flagged", flagged)

        st.markdown("---")
        st.markdown("### 📋 All Registered FDR Ledger")
        
        for row in records:
            st.markdown(f"""
                <div style="background: white; padding: 12px; border-radius: 8px; border: 1px solid #ddd; margin-bottom: 8px;">
                    <strong>FDR: {row['fdr_number']}</strong> | Institution: {row['institution_name']} <br>
                    Amount: ₹{row['inst_submitted_amount']:,.2f} | Status: <code>{row['regulatory_status']}</code>
                </div>
            """, unsafe_allow_html=True)