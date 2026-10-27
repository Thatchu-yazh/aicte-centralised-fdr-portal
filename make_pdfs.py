def create_minimal_pdf(filename, title, bank, fdr_no, college, amount, issue_dt, mat_dt):
    content = f"""BT
/F1 16 Tf
50 750 Td
({title}) Tj
/F1 12 Tf
0 -35 Td
(Issuing Bank: {bank}) Tj
0 -22 Td
(FDR Instrument Reference No: {fdr_no}) Tj
0 -22 Td
(Institution Name: {college}) Tj
0 -22 Td
(Principal Deposit Amount: INR {amount}) Tj
0 -22 Td
(Issue Date: {issue_dt}   |   Maturity Date: {mat_dt}) Tj
0 -22 Td
(Lien Status: Jointly Held / Hypothecated to AICTE, New Delhi) Tj
ET"""
    
    stream_bytes = content.encode('latin-1')
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >> endobj\n"
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n"
        + f"5 0 obj << /Length {len(stream_bytes)} >> stream\n".encode('latin-1')
        + stream_bytes
        + b"\nendstream endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000229 00000 n \n0000000297 00000 n \n"
        b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n"
        + f"{350 + len(stream_bytes)}\n%%EOF".encode('latin-1')
    )
    with open(filename, "wb") as f:
        f.write(pdf_bytes)
    print(f"✅ Created: {filename}")

# 1. Generate genuine_fdr.pdf (Matches Test 1 & used again in Test 2 to trigger Duplicate Hash Fraud)
create_minimal_pdf(
    filename="genuine_fdr.pdf",
    title="OFFICIAL FIXED DEPOSIT RECEIPT (FDR) - AICTE SECURITY DEPOSIT",
    bank="State Bank of India, Adyar Branch",
    fdr_no="SBIN0098451",
    college="KCG College of Technology, Chennai (ID: 1-49283741)",
    amount="15,00,000.00",
    issue_dt="2026-10-01",
    mat_dt="2034-10-01"
)

# 2. Generate sample2.pdf (Matches Test 3 with a unique SHA-256 fingerprint)
create_minimal_pdf(
    filename="sample2.pdf",
    title="FIXED DEPOSIT RECEIPT - BELOW NORM TEST DOCUMENT",
    bank="Indian Bank, Guindy Branch",
    fdr_no="IDIB0044219",
    college="Vellore Metro Polytechnic (ID: 1-33445566)",
    amount="5,00,000.00",
    issue_dt="2026-09-01",
    mat_dt="2034-09-01"
)