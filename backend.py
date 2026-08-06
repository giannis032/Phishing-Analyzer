import os
import re
import json
import ssl
import socket
import whois
import io
import requests
import tldextract
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from dotenv import load_dotenv
from groq import Groq

# ReportLab για παραγωγή PDF
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

app = Flask(__name__)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

# --- 1. SSL CERTIFICATE CHECKER ---
def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (exp_date - datetime.utcnow()).days
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer_dict.get('organizationName', 'Unknown Issuer')
                return {
                    "valid": True,
                    "issuer": issuer_name,
                    "days_until_expiration": days_left,
                    "expires_on": exp_date.strftime('%Y-%m-%d')
                }
    except Exception as e:
        return {"valid": False, "error": "Δεν εντοπίστηκε έγκυρο πιστοποιητικό SSL (HTTPS)"}

# --- 2. WHOIS / DOMAIN AGE CHECKER ---
def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return {
                "created_at": creation_date.strftime('%Y-%m-%d'),
                "age_days": age_days,
                "is_new": age_days < 30
            }
    except Exception:
        pass
    return {"error": "Αδυναμία ανάκτησης δεδομένων WHOIS"}

# --- 3. VIRUSTOTAL CHECKER ---
def check_virustotal_domain(domain):
    if not VT_API_KEY or VT_API_KEY == "το_vt_κλειδι_σου":
        return None

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as e:
        print(f"VirusTotal Error: {e}")
    return None

# --- ANALYZE URL LOGIC ---
def analyze_url_logic(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    risk_score = 0
    warnings = []
    
    # 1. Heuristics
    ip_pattern = r"^(http|https)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if re.match(ip_pattern, url):
        risk_score += 40
        warnings.append("Το URL χρησιμοποιεί απευθείας διεύθυνση IP αντί για domain.")
        
    if "@" in url:
        risk_score += 30
        warnings.append("Το URL περιέχει το σύμβολο '@'.")
        
    if len(url) > 75:
        risk_score += 20
        warnings.append("Το URL είναι ασυνήθιστα μεγάλο σε μήκος.")

    # 2. SSL Check
    ssl_info = check_ssl_certificate(domain)
    if not ssl_info.get("valid"):
        risk_score += 20
        warnings.append("⚠️ Έλλειψη ή σφάλμα στο πιστοποιητικό SSL (HTTPS).")

    # 3. Domain Age Check
    whois_info = check_domain_age(domain)
    if whois_info.get("is_new"):
        risk_score += 35
        warnings.append(f"🚨 Πρόσφατα καταχωρημένο Domain! Ηλικία: μόλις {whois_info['age_days']} ημέρες.")

    # 4. VirusTotal Check
    vt_stats = check_virustotal_domain(domain)
    if vt_stats:
        malicious_count = vt_stats.get("malicious", 0)
        if malicious_count > 0:
            risk_score += 50
            warnings.append(f"⚠️ Το VirusTotal εντόπισε {malicious_count} engines που το καταγράφουν ως κακόβουλο.")

    return {
        "domain": domain,
        "risk_score": min(risk_score, 100),
        "warnings": warnings,
        "ssl_info": ssl_info,
        "whois_info": whois_info,
        "virustotal_data": vt_stats
    }

def analyze_email_with_groq(email_text):
    if not groq_client:
        return {"error": "Δεν έχει οριστεί GROQ_API_KEY στο .env"}

    system_prompt = """
    Είσαι ένας εξειδικευμένος αναλυτής Cybersecurity & Phishing. 
    Σου δίνεται το κείμενο ενός email. Ανάλυσέ το για ενδείξεις Phishing / Social Engineering.
    
    Απάντησε ΑΠΟΚΛΕΙΣΤΙΚΑ σε έγκυρη μορφή JSON με την εξής δομή:
    {
      "is_phishing": true,
      "risk_score": 85,
      "urgency_detected": true,
      "red_flags": ["σημείο 1", "σημείο 2"],
      "summary": "Σύντομη επεξήγηση στα Ελληνικά"
    }
    """

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Κείμενο Email προς ανάλυση:\n\n{email_text}"}
            ],
            temperature=0.2
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": f"Groq Error: {str(e)}"}

# --- PDF GENERATOR HELPER ---
def generate_pdf_bytes(title, data_dict):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#1E293B'))
    story.append(Paragraph(f"<b>SOC Shield Report: {title}</b>", title_style))
    story.append(Paragraph(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 15))

    # Table Data
    table_data = [["Metric / Field", "Value"]]
    for key, val in data_dict.items():
        if isinstance(val, list):
            val_str = ", ".join(val) if val else "None"
        else:
            val_str = str(val)
        table_data.append([str(key), val_str])

    t = Table(table_data, colWidths=[150, 350])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
    ]))
    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer

# --- ENDPOINTS ---
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "running"}), 200

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing url"}), 400
    return jsonify(analyze_url_logic(data['url'])), 200

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    data = request.get_json()
    if not data or 'email_text' not in data:
        return jsonify({"error": "Missing email_text"}), 400
    return jsonify(analyze_email_with_groq(data['email_text'])), 200

@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf():
    req_data = request.get_json()
    title = req_data.get("title", "Security Audit")
    content = req_data.get("data", {})
    
    pdf_buffer = generate_pdf_bytes(title, content)
    return send_file(
        pdf_buffer, 
        mimetype='application/pdf', 
        as_attachment=True, 
        download_name='SOC_Shield_Report.pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)