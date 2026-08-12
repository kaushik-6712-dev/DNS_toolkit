import os
import re
import hashlib
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import requests
import whois
import dns.resolver
import dns.message
import dns.rdatatype
import dkim
import extract_msg
import olefile
from email import message_from_bytes

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///scan_history.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'enterprise-sec-token-2026')

db = SQLAlchemy(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per minute"],
    storage_uri="memory://"
)

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    report_json = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

with app.app_context():
    db.create_all()

VT_API_KEY = os.getenv('VT_API_KEY', '')

def analyze_domain_layman(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Email Protection (SPF & DMARC)
    spf_pass = False
    dmarc_pass = False
    try:
        txt_records = [str(r) for r in resolver.resolve(domain, "TXT")]
        spf_pass = any("v=spf1" in r for r in txt_records)
    except Exception:
        pass

    try:
        dmarc_records = [str(r) for r in resolver.resolve(f"_dmarc.{domain}", "TXT")]
        dmarc_pass = any("v=DMARC1" in r for r in dmarc_records)
    except Exception:
        pass

    # 2. Website Tamper Lock (DNSSEC)
    dnssec_pass = False
    try:
        q = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        resp = dns.query.udp(q, "8.8.8.8", timeout=3.0)
        dnssec_pass = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in resp.answer)
    except Exception:
        pass

    # 3. Domain Age & Registration
    days_old = None
    is_new = False
    registrar = "Unknown"
    try:
        w = whois.whois(domain)
        registrar = w.registrar or "Unknown"
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if creation_date:
            days_old = (datetime.now() - creation_date.replace(tzinfo=None)).days
            if days_old < 30:
                is_new = True
    except Exception:
        pass

    # 4. Global Malware & Phishing Blacklist (VirusTotal)
    vt_hits = 0
    if VT_API_KEY:
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": VT_API_KEY}, timeout=4)
            if resp.status_code == 200:
                vt_hits = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        except Exception:
            pass

    # Risk Score Calculation (0 to 100)
    score = 0
    if is_new: score += 35
    if vt_hits > 0: score += 40
    if not spf_pass: score += 10
    if not dmarc_pass: score += 10
    if not dnssec_pass: score += 5

    severity = "HIGH RISK" if score >= 60 else "MEDIUM CAUTION" if score >= 30 else "SAFE"

    return {
        "domain": domain,
        "score": score,
        "severity": severity,
        "summary": "High risk! This website shows clear signs commonly associated with phishing or scam pages." if score >= 60 
                   else "Proceed with caution. Some security controls are missing." if score >= 30 
                   else "This domain is properly configured and shows no obvious security red flags.",
        "checks": [
            {
                "title": "Email Identity Lock (SPF & DMARC)",
                "status": "PROTECTED" if (spf_pass and dmarc_pass) else "UNPROTECTED",
                "is_good": spf_pass and dmarc_pass,
                "meaning": "Prevents scammers from sending fake emails pretending to come from this domain name."
            },
            {
                "title": "Website Identity Lock (DNSSEC)",
                "status": "SECURE" if dnssec_pass else "NOT LOCKED",
                "is_good": dnssec_pass,
                "meaning": "Stops hackers from secretly redirecting visitors to a malicious copy of this website."
            },
            {
                "title": "Domain Age & Trust",
                "status": f"{days_old} Days Old" if days_old is not None else "Age Unknown",
                "is_good": not is_new,
                "meaning": "Scam websites are typically created very recently (under 30 days old) and discarded quickly."
            },
            {
                "title": "Global Malware & Blacklist Check",
                "status": f"{vt_hits} Security Warnings" if vt_hits > 0 else "Clean Record",
                "is_good": vt_hits == 0,
                "meaning": "Cross-checks over 70 security databases to see if this address has been reported for fraud."
            }
        ]
    }

def inspect_ole_and_macros(attachment_bytes):
    has_ole = olefile.isOleFile(attachment_bytes)
    has_vba = False
    if has_ole:
        try:
            ole = olefile.OleFileIO(attachment_bytes)
            has_vba = ole.exists('VBA') or ole.exists('Macros') or ole.exists('_VBA_PROJECT')
            ole.close()
        except Exception:
            pass
    return has_ole, has_vba

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze/domain', methods=['POST'])
@limiter.limit("20 per minute")
def analyze_domain():
    data = request.json or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "Target domain is required"}), 400

    report = analyze_domain_layman(domain)

    record = ScanRecord(target=domain, scan_type="domain", risk_score=report["score"], severity=report["severity"], report_json=report)
    db.session.add(record)
    db.session.commit()

    return jsonify(report)

@app.route('/api/analyze/email', methods=['POST'])
@limiter.limit("20 per minute")
def analyze_email():
    file_obj = request.files.get("file")
    if not file_obj:
        return jsonify({"error": "No file uploaded"}), 400

    filename = file_obj.filename.lower()
    content = file_obj.read()
    
    score = 0
    attachments_info = []
    dkim_valid = False
    sender_domain = ""

    try:
        if filename.endswith(".msg"):
            msg = extract_msg.Message(content)
            raw_headers = str(msg.header)
            for att in msg.attachments:
                att_bytes = att.data
                sha256 = hashlib.sha256(att_bytes).hexdigest()
                has_ole, has_vba = inspect_ole_and_macros(att_bytes)
                is_dangerous = any(att.longFilename.lower().endswith(ext) for ext in ['.exe', '.iso', '.vbs', '.js', '.xlsm']) or has_vba
                attachments_info.append({
                    "filename": att.longFilename, "size_kb": round(len(att_bytes)/1024, 1),
                    "sha256": sha256, "is_dangerous": is_dangerous, "has_vba": has_vba
                })
                if is_dangerous: score += 40

        elif filename.endswith(".eml"):
            msg = message_from_bytes(content)
            raw_headers = "".join([f"{k}: {v}\n" for k, v in msg.items()])
            try:
                dkim_valid = dkim.verify(content)
            except Exception:
                dkim_valid = False
                
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart' or not part.get_filename():
                    continue
                att_bytes = part.get_payload(decode=True) or b''
                fname = part.get_filename()
                sha256 = hashlib.sha256(att_bytes).hexdigest()
                has_ole, has_vba = inspect_ole_and_macros(att_bytes)
                is_dangerous = any(fname.lower().endswith(ext) for ext in ['.exe', '.iso', '.vbs', '.js', '.xlsm']) or has_vba
                attachments_info.append({
                    "filename": fname, "size_kb": round(len(att_bytes)/1024, 1),
                    "sha256": sha256, "is_dangerous": is_dangerous, "has_vba": has_vba
                })
                if is_dangerous: score += 40

        match = re.search(r'From:.*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw_headers)
        if match:
            sender_domain = match.group(1).strip()

        if not dkim_valid: score += 20

        severity = "HIGH RISK" if score >= 60 else "MEDIUM CAUTION" if score >= 30 else "SAFE"

        report = {
            "sender_domain": sender_domain or "Unknown Sender",
            "dkim_valid": dkim_valid,
            "attachments": attachments_info,
            "score": score,
            "severity": severity,
            "summary": "Dangerous file extensions or hidden script macros were found in this email." if score >= 60
                       else "This email has unverified signatures or minor security concerns." if score >= 30
                       else "No obvious malicious code or dangerous attachments detected."
        }

        record = ScanRecord(target=sender_domain or filename, scan_type="email", risk_score=score, severity=severity, report_json=report)
        db.session.add(record)
        db.session.commit()

        return jsonify(report)

    except Exception as e:
        return jsonify({"error": f"Email parsing failed: {str(e)}"}), 500

@app.route('/api/history', methods=['GET'])
def scan_history():
    records = ScanRecord.query.order_by(ScanRecord.created_at.desc()).limit(10).all()
    history = [{
        "id": r.id, "target": r.target, "type": r.scan_type,
        "score": r.risk_score, "severity": r.severity, "date": r.created_at.strftime("%Y-%m-%d %H:%M")
    } for r in records]
    return jsonify(history)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)