import streamlit as st
import requests

BACKEND_URL = "http://127.0.0.1:5000/api"

# Ρύθμιση Σελίδας
st.set_page_config(
    page_title="Sentinel Security Platform",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Sentinel Platform")
    st.caption("Cybersecurity & Threat Intelligence")
    st.divider()
    
    # Ελεγχος Backend status με native streamlit status
    try:
        health_resp = requests.get(f"{BACKEND_URL}/health", timeout=2)
        if health_resp.status_code == 200:
            st.success("API Status: Online", icon="✅")
        else:
            st.warning("API Status: Degraded", icon="⚠️")
    except:
        st.error("API Status: Offline", icon="❌")
        
    st.divider()
    st.markdown("**Τεχνικές Προδιαγραφές:**")
    st.markdown("- Whois & SSL Protocol Check")
    st.markdown("- VirusTotal Threat Intelligence")
    st.markdown("- Groq Llama-3.3 LLM Engine")

# ---------------------------------------------------------
# MAIN INTERFACE
# ---------------------------------------------------------
st.title("Αναλυτής Απειλών Ασφαλείας")
st.write("Πλατφόρμα ελέγχου επικινδυνότητας για URLs και κείμενα Email με παραγωγή αναφορών PDF.")

tab1, tab2 = st.tabs(["🔗 Έλεγχος URL", "📧 Έλεγχος Email (AI)"])

# =========================================================
# TAB 1: URL ANALYSIS
# =========================================================
with tab1:
    with st.container(border=True):
        st.subheader("Εισαγωγή Στοιχείων")
        url_input = st.text_input("Διεύθυνση URL:", placeholder="https://example.com/login")
        analyze_btn = st.button("Έλεγχος Συνδέσμου", type="primary")

    if analyze_btn:
        if url_input:
            with st.spinner("Εκτέλεση ελέγχων SSL, WHOIS και VirusTotal..."):
                try:
                    res = requests.post(f"{BACKEND_URL}/analyze-url", json={"url": url_input})
                    if res.status_code == 200:
                        st.session_state['url_res'] = res.json()
                    else:
                        st.error("Σφάλμα από το Backend API.")
                except Exception as e:
                    st.error(f"Αδυναμία σύνδεσης με το API: {e}")
        else:
            st.warning("Παρακαλώ συμπληρώστε το πεδίο URL.")

    # Εμφάνιση Αποτελεσμάτων
    if 'url_res' in st.session_state:
        data = st.session_state['url_res']
        risk = data['risk_score']
        ssl_info = data.get("ssl_info", {})
        whois_info = data.get("whois_info", {})

        st.divider()
        st.subheader("Αποτελέσματα Αξιολόγησης")

        # Βασικά Metrics σε 3 Στήλες
        col1, col2, col3 = st.columns(3)
        with col1:
            with st.container(border=True):
                st.metric(label="Domain", value=data['domain'])
        with col2:
            with st.container(border=True):
                st.metric(label="Score Επικινδυνότητας", value=f"{risk}/100")
        with col3:
            with st.container(border=True):
                st.metric(label="Ηλικία Domain", value=f"{whois_info.get('age_days', 'N/A')} ημέρες")

        # Μπάρα προόδου
        st.progress(risk / 100)

        # Λεπτομέρειες σε 2 Containers
        c1, c2 = st.columns(2)
        with c1:
            with st.container(border=True):
                st.markdown("### 🔒 Πιστοποιητικό SSL")
                if ssl_info.get("valid"):
                    st.success(f"Έγκυρο Πιστοποιητικό ({ssl_info.get('issuer')})")
                    st.write(f"**Ημέρες μέχρι τη λήξη:** {ssl_info.get('days_until_expiration')}")
                else:
                    st.error(ssl_info.get("error", "Μη έγκυρο SSL"))

        with c2:
            with st.container(border=True):
                st.markdown("### ⚠️ Ευρήματα Ασφαλείας")
                if data.get("warnings"):
                    for w in data["warnings"]:
                        st.write(f"- {w}")
                else:
                    st.info("Δεν εντοπίστηκαν ύποπτες ενδείξεις.")

        # Εξαγωγή PDF
        st.divider()
        pdf_res = requests.post(f"{BACKEND_URL}/generate-pdf", json={
            "title": f"Security Report - {data['domain']}",
            "data": {
                "Domain": data['domain'],
                "Risk Score": f"{data['risk_score']}/100",
                "Warnings": data.get('warnings', []),
                "SSL Valid": ssl_info.get('valid'),
                "Domain Age": f"{whois_info.get('age_days', 'N/A')} Days"
            }
        })
        if pdf_res.status_code == 200:
            st.download_button(
                label="📥 Λήψη Αναφοράς PDF",
                data=pdf_res.content,
                file_name=f"Report_{data['domain']}.pdf",
                mime="application/pdf"
            )

# =========================================================
# TAB 2: EMAIL ANALYSIS
# =========================================================
with tab2:
    with st.container(border=True):
        st.subheader("Εισαγωγή Κειμένου Email")
        email_text = st.text_area("Περιεχόμενο Email:", height=150, placeholder="Επικολλήστε το κείμενο εδώ...")
        email_btn = st.button("Ανάλυση Email με AI", type="primary")

    if email_btn:
        if email_text:
            with st.spinner("Ανάλυση κειμένου από το Groq AI..."):
                try:
                    res = requests.post(f"{BACKEND_URL}/analyze-email", json={"email_text": email_text})
                    if res.status_code == 200:
                        st.session_state['email_res'] = res.json()
                    else:
                        st.error("Σφάλμα από το Backend API.")
                except Exception as e:
                    st.error(f"Αδυναμία σύνδεσης με το API: {e}")
        else:
            st.warning("Παρακαλώ εισάγετε κείμενο email.")

    if 'email_res' in st.session_state:
        e_data = st.session_state['email_res']
        if "error" not in e_data:
            st.divider()
            st.subheader("Αποτελέσματα Ανάλυσης AI")

            score = e_data.get('risk_score', 0)
            
            with st.container(border=True):
                st.metric(label="Πιθανότητα Phishing", value=f"{score}%")
                st.progress(score / 100)
                st.markdown("---")
                st.markdown("**Σύνοψη Αξιολόγησης:**")
                st.write(e_data.get('summary', ''))

            if e_data.get("red_flags"):
                with st.container(border=True):
                    st.markdown("**🚩 Ύποπτα Σημεία (Red Flags):**")
                    for rf in e_data["red_flags"]:
                        st.write(f"• {rf}")

            st.divider()
            pdf_res = requests.post(f"{BACKEND_URL}/generate-pdf", json={
                "title": "Email Phishing Analysis Report",
                "data": {
                    "Risk Score": f"{score}%",
                    "Summary": e_data.get('summary'),
                    "Red Flags": e_data.get('red_flags', [])
                }
            })
            if pdf_res.status_code == 200:
                st.download_button(
                    label="📥 Λήψη Αναφοράς PDF",
                    data=pdf_res.content,
                    file_name="Report_Email.pdf",
                    mime="application/pdf"
                )