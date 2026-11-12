import re
import html
from datetime import datetime

import requests
import streamlit as st

BACKEND_URL = "http://127.0.0.1:5000/api"
TIMEOUT = 30          # δευτερόλεπτα για κάθε κλήση στο backend
MAX_EMAIL_LINKS = 5   # πόσους συνδέσμους από ένα email ελέγχουμε το πολύ
MAX_HISTORY = 8

st.set_page_config(
    page_title="Sentinel Security Platform",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------
# STYLE
# ---------------------------------------------------------
st.markdown(
    """
<style>
.verdict{display:flex;align-items:center;gap:1.1rem;padding:1.1rem 1.4rem;
  border-radius:12px;border-left:6px solid;margin:.4rem 0 1.2rem}
.verdict-safe{background:rgba(22,163,74,.12);border-color:#16a34a}
.verdict-warn{background:rgba(234,179,8,.15);border-color:#eab308}
.verdict-danger{background:rgba(220,38,38,.13);border-color:#dc2626}
.verdict-icon{font-size:2.4rem;line-height:1}
.verdict-label{font-weight:700;font-size:1.3rem}
.verdict-title{font-family:monospace;opacity:.85;word-break:break-all}
.verdict-sub{font-size:.88rem;opacity:.7;margin-top:.15rem}
.verdict-score{margin-left:auto;font-size:2.2rem;font-weight:800;white-space:nowrap}
.verdict-score span{font-size:.95rem;opacity:.55;font-weight:500}
.legend-dot{display:inline-block;width:.7rem;height:.7rem;border-radius:50%;margin-right:.4rem}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
LEVELS = {
    "safe": {
        "icon": "✅",
        "label": "Χαμηλός κίνδυνος",
        "advice": [
            "Δεν βρέθηκαν σοβαρές ενδείξεις, αλλά παραμείνετε προσεκτικοί.",
            "Βεβαιωθείτε ότι το domain είναι ακριβώς αυτό που περιμένετε "
            "(π.χ. `paypal.com` και όχι `paypa1.com`).",
        ],
    },
    "warn": {
        "icon": "⚠️",
        "label": "Ύποπτο",
        "advice": [
            "Μην εισάγετε κωδικούς ή στοιχεία κάρτας μέσω αυτού του συνδέσμου/μηνύματος.",
            "Ανοίξτε τον ιστότοπο πληκτρολογώντας μόνοι σας τη διεύθυνση, όχι από τον σύνδεσμο.",
            "Αν ο αποστολέας είναι γνωστός, επιβεβαιώστε μαζί του από άλλο κανάλι (π.χ. τηλέφωνο).",
        ],
    },
    "danger": {
        "icon": "🚨",
        "label": "Υψηλός κίνδυνος",
        "advice": [
            "Μην ανοίξετε τον σύνδεσμο και μην απαντήσετε στο μήνυμα.",
            "Αν έχετε ήδη δώσει στοιχεία, αλλάξτε αμέσως κωδικούς και ενημερώστε την τράπεζά σας.",
            "Αναφέρετε το μήνυμα ως phishing στον πάροχο email σας ή στο τμήμα IT.",
        ],
    },
}


def level_key(score: int) -> str:
    if score >= 70:
        return "danger"
    if score >= 35:
        return "warn"
    return "safe"


def to_score(value) -> int:
    try:
        return max(0, min(100, int(float(value))))
    except (TypeError, ValueError):
        return 0


def render_verdict(score: int, title: str, subtitle: str = ""):
    key = level_key(score)
    lvl = LEVELS[key]
    st.markdown(
        f'<div class="verdict verdict-{key}">'
        f'<div class="verdict-icon">{lvl["icon"]}</div>'
        f"<div>"
        f'<div class="verdict-label">{lvl["label"]}</div>'
        f'<div class="verdict-title">{html.escape(title)}</div>'
        f'<div class="verdict-sub">{html.escape(subtitle)}</div>'
        f"</div>"
        f'<div class="verdict-score">{score}<span>/100</span></div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def render_advice(score: int):
    with st.container(border=True):
        st.markdown("#### 🧭 Τι να κάνετε")
        for tip in LEVELS[level_key(score)]["advice"]:
            st.markdown(f"- {tip}")


@st.cache_data(ttl=10, show_spinner=False)
def backend_online() -> bool:
    try:
        return requests.get(f"{BACKEND_URL}/health", timeout=2).status_code == 200
    except requests.RequestException:
        return False


def api_post(endpoint: str, payload: dict):
    """Επιστρέφει (data, error). Ακριβώς ένα από τα δύο είναι None."""
    try:
        res = requests.post(f"{BACKEND_URL}/{endpoint}", json=payload, timeout=TIMEOUT)
    except requests.Timeout:
        return None, "Ο έλεγχος άργησε πολύ να απαντήσει. Δοκιμάστε ξανά σε λίγο."
    except requests.ConnectionError:
        return None, "Δεν υπάρχει σύνδεση με το backend. Βεβαιωθείτε ότι τρέχει το Flask API (port 5000)."
    except requests.RequestException as e:
        return None, f"Απρόσμενο σφάλμα δικτύου: {e}"

    if res.status_code != 200:
        return None, f"Το backend απάντησε με σφάλμα (HTTP {res.status_code})."
    try:
        data = res.json()
    except ValueError:
        return None, "Το backend επέστρεψε μη έγκυρη απάντηση."
    if isinstance(data, dict) and data.get("error"):
        return None, str(data["error"])
    return data, None


@st.cache_data(ttl=600, show_spinner=False)
def fetch_pdf(title: str, data: dict):
    try:
        res = requests.post(
            f"{BACKEND_URL}/generate-pdf",
            json={"title": title, "data": data},
            timeout=TIMEOUT,
        )
        if res.status_code == 200:
            return res.content
    except requests.RequestException:
        pass
    return None


def normalize_url(raw: str) -> str:
    url = raw.strip()
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    seen, out = set(), []
    for m in URL_RE.findall(text or ""):
        url = normalize_url(m.rstrip(".,;:!?»"))
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def add_history(kind: str, label: str, score: int, payload: dict):
    hist = st.session_state.setdefault("history", [])
    hist.insert(0, {
        "kind": kind,
        "label": label,
        "score": score,
        "time": datetime.now().strftime("%H:%M"),
        "payload": payload,
    })
    del hist[MAX_HISTORY:]


# ---------------- callbacks ----------------
def set_url_example(url: str):
    st.session_state.url_input = url


def clear_url():
    st.session_state.url_input = ""
    st.session_state.pop("url_res", None)


def set_email_example():
    st.session_state.email_input = EXAMPLE_EMAIL


def clear_email():
    st.session_state.email_input = ""
    st.session_state.pop("email_res", None)


def restore_history(i: int):
    item = st.session_state.history[i]
    if item["kind"] == "url":
        st.session_state.url_res = item["payload"]
    else:
        st.session_state.email_res = item["payload"]


EXAMPLE_EMAIL = (
    "Αγαπητέ πελάτη,\n\n"
    "Εντοπίσαμε ασυνήθιστη δραστηριότητα στον λογαριασμό σας. Για λόγους ασφαλείας, "
    "ο λογαριασμός θα ΑΠΕΝΕΡΓΟΠΟΙΗΘΕΙ εντός 24 ωρών αν δεν επιβεβαιώσετε τα στοιχεία σας.\n\n"
    "Επιβεβαιώστε άμεσα εδώ: http://192.168.4.21/secure-login/verify?id=88213\n\n"
    "Με εκτίμηση,\nΤμήμα Ασφαλείας"
)

online = backend_online()

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Sentinel Platform")
    st.caption("Cybersecurity & Threat Intelligence")

    status_col, refresh_col = st.columns([4, 1])
    with status_col:
        if online:
            st.success("API Online", icon="✅")
        else:
            st.error("API Offline", icon="❌")
    with refresh_col:
        if st.button("↻", help="Επανέλεγχος σύνδεσης"):
            backend_online.clear()
            st.rerun()

    st.divider()
    st.markdown("**Κλίμακα κινδύνου**")
    st.markdown(
        '<span class="legend-dot" style="background:#16a34a"></span>0–34 · Χαμηλός<br>'
        '<span class="legend-dot" style="background:#eab308"></span>35–69 · Ύποπτο<br>'
        '<span class="legend-dot" style="background:#dc2626"></span>70–100 · Υψηλός',
        unsafe_allow_html=True,
    )

    history_slot = st.container()

    st.divider()
    with st.expander("ℹ️ Πώς λειτουργεί"):
        st.markdown(
            "- **URL:** έλεγχος SSL, ηλικίας domain (WHOIS), VirusTotal και ύποπτων μοτίβων.\n"
            "- **Email:** ανάλυση κειμένου από AI (Groq · Llama 3.3) και αυτόματος έλεγχος "
            "των συνδέσμων που περιέχει.\n"
            "- Τα αποτελέσματα είναι ενδεικτικά, όχι εγγύηση ασφάλειας."
        )

# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------
st.title("Αναλυτής Απειλών Ασφαλείας")
st.write("Ελέγξτε αν ένας σύνδεσμος ή ένα email είναι ασφαλές πριν κάνετε κλικ.")

if not online:
    st.error(
        "**Το backend δεν είναι διαθέσιμο.** Ξεκινήστε το με `python app.py` "
        "και πατήστε ↻ στο πλάι.",
        icon="🔌",
    )

tab_url, tab_email = st.tabs(["🔗 Έλεγχος URL", "📧 Έλεγχος Email (AI)"])

# =========================================================
# TAB 1: URL
# =========================================================
with tab_url:
    with st.form("url_form", border=True):
        st.text_input(
            "Επικολλήστε τον σύνδεσμο που θέλετε να ελέγξετε",
            key="url_input",
            placeholder="π.χ. https://example.com/login ή απλά example.com",
        )
        url_submit = st.form_submit_button(
            "🔍 Έλεγχος συνδέσμου", type="primary", disabled=not online
        )

    ex1, ex2, ex3, _ = st.columns([1.3, 1.5, 1, 3])
    ex1.button("Παράδειγμα: google.com", on_click=set_url_example,
               args=("https://www.google.com",), use_container_width=True)
    ex2.button("Παράδειγμα: ύποπτο IP link", on_click=set_url_example,
               args=("http://192.168.4.21/secure-login/verify",), use_container_width=True)
    ex3.button("🧹 Καθαρισμός", on_click=clear_url, use_container_width=True)

    if url_submit:
        raw = st.session_state.get("url_input", "")
        if not raw.strip():
            st.warning("Συμπληρώστε έναν σύνδεσμο για έλεγχο.", icon="✏️")
        else:
            url = normalize_url(raw)
            if url != raw.strip():
                st.caption(f"Προστέθηκε αυτόματα το πρωτόκολλο: `{url}`")
            with st.spinner("Έλεγχος SSL, WHOIS και VirusTotal… (έως ~10 δευτερόλεπτα)"):
                data, err = api_post("analyze-url", {"url": url})
            if err:
                st.error(err, icon="❌")
            else:
                data["_url"] = url
                st.session_state.url_res = data
                add_history("url", data.get("domain", url), to_score(data.get("risk_score")), data)

    if "url_res" in st.session_state:
        data = st.session_state.url_res
        risk = to_score(data.get("risk_score"))
        domain = data.get("domain", "—")
        ssl_info = data.get("ssl_info") or {}
        whois_info = data.get("whois_info") or {}
        vt = data.get("virustotal_data") or None
        warnings = data.get("warnings") or []

        st.divider()
        render_verdict(risk, data.get("_url", domain), f"Domain: {domain}")

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Βαθμός κινδύνου", f"{risk}/100")
        with m2:
            age = whois_info.get("age_days")
            st.metric(
                "Ηλικία domain",
                f"{age} ημέρες" if age is not None else "Άγνωστη",
                help="Domains νεότερα των 30 ημερών είναι συχνό σημάδι phishing.",
            )
        with m3:
            st.metric("Πιστοποιητικό SSL", "✔ Έγκυρο" if ssl_info.get("valid") else "✘ Μη έγκυρο")
        with m4:
            if vt:
                total = sum(v for v in vt.values() if isinstance(v, (int, float)))
                flagged = vt.get("malicious", 0) + vt.get("suspicious", 0)
                st.metric("VirusTotal", f"{flagged}/{total}",
                          help="Engines που το χαρακτήρισαν κακόβουλο ή ύποπτο / σύνολο engines.")
            else:
                st.metric("VirusTotal", "Μη διαθέσιμο")

        left, right = st.columns([3, 2])
        with left:
            with st.container(border=True):
                st.markdown(f"#### 🔎 Ευρήματα ({len(warnings)})")
                if warnings:
                    for w in warnings:
                        st.warning(w)
                else:
                    st.success("Δεν εντοπίστηκαν ύποπτες ενδείξεις.", icon="👍")
        with right:
            render_advice(risk)

        with st.expander("🔬 Τεχνικές λεπτομέρειες"):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("**🔒 SSL**")
                if ssl_info.get("valid"):
                    st.write(f"Εκδότης: **{ssl_info.get('issuer', '—')}**")
                    st.write(f"Λήγει: **{ssl_info.get('expires_on', '—')}** "
                             f"({ssl_info.get('days_until_expiration', '—')} ημέρες)")
                else:
                    st.write(ssl_info.get("error", "Μη έγκυρο SSL"))
            with c2:
                st.markdown("**📅 WHOIS**")
                if whois_info.get("created_at"):
                    st.write(f"Καταχώρηση: **{whois_info['created_at']}**")
                    st.write(f"Ηλικία: **{whois_info.get('age_days')}** ημέρες")
                else:
                    st.write(whois_info.get("error", "Δεν υπάρχουν δεδομένα"))
            with c3:
                st.markdown("**🦠 VirusTotal**")
                if vt:
                    for k, label in [("malicious", "Κακόβουλο"), ("suspicious", "Ύποπτο"),
                                     ("harmless", "Ασφαλές"), ("undetected", "Χωρίς εντοπισμό")]:
                        st.write(f"{label}: **{vt.get(k, 0)}**")
                    st.markdown(f"[Άνοιγμα στο VirusTotal ↗](https://www.virustotal.com/gui/domain/{domain})")
                else:
                    st.write("Δεν υπάρχουν δεδομένα (λείπει API key ή όριο κλήσεων).")
            st.markdown("**Πλήρης απάντηση API**")
            st.json({k: v for k, v in data.items() if not k.startswith("_")}, expanded=False)

        pdf = fetch_pdf(
            f"Security Report - {domain}",
            {
                "URL": data.get("_url", domain),
                "Domain": domain,
                "Risk Score": f"{risk}/100",
                "Verdict": LEVELS[level_key(risk)]["label"],
                "Warnings": warnings,
                "SSL Valid": ssl_info.get("valid"),
                "Domain Age": f"{whois_info.get('age_days', 'N/A')} Days",
                "VirusTotal": str(vt) if vt else "N/A",
            },
        )
        b1, b2, _ = st.columns([1, 1, 3])
        with b1:
            if pdf:
                st.download_button("📥 Λήψη αναφοράς PDF", data=pdf,
                                   file_name=f"Report_{domain}.pdf", mime="application/pdf",
                                   use_container_width=True)
            else:
                st.caption("Η αναφορά PDF δεν είναι διαθέσιμη αυτή τη στιγμή.")
        with b2:
            st.button("🔄 Νέος έλεγχος", on_click=clear_url, key="new_url",
                      use_container_width=True)

# =========================================================
# TAB 2: EMAIL
# =========================================================
with tab_email:
    with st.form("email_form", border=True):
        st.text_area(
            "Επικολλήστε το κείμενο του email (μαζί με αποστολέα και θέμα, αν τα έχετε)",
            key="email_input",
            height=200,
            placeholder="Από: support@bank-secure.com\nΘέμα: Επείγον – Επιβεβαίωση λογαριασμού\n\nΑγαπητέ πελάτη…",
        )
        scan_links = st.checkbox(
            "Έλεγχος και των συνδέσμων του email (SSL, WHOIS, VirusTotal)",
            value=True,
            help=f"Ελέγχονται έως {MAX_EMAIL_LINKS} σύνδεσμοι. Κάθε σύνδεσμος παίρνει μερικά δευτερόλεπτα.",
        )
        email_submit = st.form_submit_button(
            "🤖 Ανάλυση email", type="primary", disabled=not online
        )

    e1, e2, _ = st.columns([1.4, 1, 4.5])
    e1.button("Παράδειγμα phishing email", on_click=set_email_example, use_container_width=True)
    e2.button("🧹 Καθαρισμός", on_click=clear_email, key="clear_email",
              use_container_width=True)

    if email_submit:
        text = st.session_state.get("email_input", "")
        if not text.strip():
            st.warning("Επικολλήστε πρώτα το κείμενο του email.", icon="✏️")
        else:
            with st.status("Ανάλυση email…", expanded=True) as status:
                st.write("🤖 Ανάλυση κειμένου από το AI…")
                ai, ai_err = api_post("analyze-email", {"email_text": text})

                links = []
                urls = extract_urls(text) if scan_links else []
                if urls:
                    shown = urls[:MAX_EMAIL_LINKS]
                    st.write(f"🔗 Βρέθηκαν {len(urls)} σύνδεσμοι — έλεγχος {len(shown)}…")
                    bar = st.progress(0.0)
                    for i, u in enumerate(shown, start=1):
                        res, err = api_post("analyze-url", {"url": u})
                        links.append({"url": u, "result": res, "error": err})
                        bar.progress(i / len(shown))
                elif scan_links:
                    st.write("🔗 Δεν βρέθηκαν σύνδεσμοι στο κείμενο.")

                if ai_err and not links:
                    status.update(label="Η ανάλυση απέτυχε", state="error")
                else:
                    status.update(label="Η ανάλυση ολοκληρώθηκε", state="complete", expanded=False)

            if ai_err and not links:
                st.error(ai_err, icon="❌")
            else:
                payload = {"ai": ai, "ai_error": ai_err, "links": links,
                           "skipped": max(0, len(urls) - MAX_EMAIL_LINKS)}
                st.session_state.email_res = payload
                first_line = text.strip().splitlines()[0]
                ai_score = to_score((ai or {}).get("risk_score"))
                link_max = max((to_score(l["result"].get("risk_score"))
                                for l in links if l["result"]), default=0)
                add_history("email", first_line, max(ai_score, link_max), payload)

    if "email_res" in st.session_state:
        res = st.session_state.email_res
        ai = res.get("ai") or {}
        links = res.get("links", [])
        ai_score = to_score(ai.get("risk_score"))
        link_scores = [to_score(l["result"].get("risk_score")) for l in links if l["result"]]
        worst_link = max(link_scores, default=0)
        overall = max(ai_score, worst_link)
        dangerous_links = sum(1 for s in link_scores if s >= 35)

        st.divider()
        sub = f"AI: {ai_score}/100" if not res.get("ai_error") else "AI: μη διαθέσιμο"
        if links:
            sub += f" · Χειρότερος σύνδεσμος: {worst_link}/100"
        render_verdict(overall, "Ανάλυση email", sub)

        if res.get("ai_error"):
            st.warning(f"Η ανάλυση AI απέτυχε: {res['ai_error']}. "
                       "Εμφανίζονται μόνο τα αποτελέσματα των συνδέσμων.", icon="🤖")

        m1, m2, m3 = st.columns(3)
        m1.metric("Πιθανότητα phishing (AI)",
                  f"{ai_score}%" if not res.get("ai_error") else "—")
        m2.metric("Πίεση / επείγων τόνος",
                  "Ναι" if ai.get("urgency_detected") else "Όχι",
                  help="Οι επιτιθέμενοι συχνά δημιουργούν αίσθηση βιασύνης για να μη σκεφτείτε.")
        m3.metric("Ύποπτοι σύνδεσμοι",
                  f"{dangerous_links}/{len(links)}" if links else "—")

        left, right = st.columns([3, 2])
        with left:
            if ai.get("summary"):
                with st.container(border=True):
                    st.markdown("#### 📝 Σύνοψη")
                    st.write(ai["summary"])
            flags = ai.get("red_flags") or []
            with st.container(border=True):
                st.markdown(f"#### 🚩 Ύποπτα σημεία ({len(flags)})")
                if flags:
                    for rf in flags:
                        st.markdown(f"- {rf}")
                elif not res.get("ai_error"):
                    st.success("Το AI δεν εντόπισε ύποπτα σημεία στο κείμενο.", icon="👍")
        with right:
            render_advice(overall)

        if links:
            with st.container(border=True):
                st.markdown("#### 🔗 Σύνδεσμοι στο email")
                for l in links:
                    r = l["result"]
                    if not r:
                        st.markdown(f"❔ `{l['url']}` — {l['error']}")
                        continue
                    s = to_score(r.get("risk_score"))
                    icon = LEVELS[level_key(s)]["icon"]
                    with st.expander(f"{icon} {r.get('domain', l['url'])} · {s}/100"):
                        st.code(l["url"], language=None)
                        ws = r.get("warnings") or []
                        if ws:
                            for w in ws:
                                st.markdown(f"- {w}")
                        else:
                            st.write("Δεν εντοπίστηκαν ύποπτες ενδείξεις.")
                if res.get("skipped"):
                    st.caption(f"Δεν ελέγχθηκαν άλλοι {res['skipped']} σύνδεσμοι "
                               f"(όριο {MAX_EMAIL_LINKS}).")

        pdf_data = {
            "Overall Risk": f"{overall}/100",
            "Verdict": LEVELS[level_key(overall)]["label"],
            "AI Phishing Probability": f"{ai_score}%" if not res.get("ai_error") else "N/A",
            "Urgency Detected": bool(ai.get("urgency_detected")),
            "Summary": ai.get("summary", "N/A"),
            "Red Flags": ai.get("red_flags", []),
        }
        if links:
            pdf_data["Links"] = [
                f"{l['url']} ({to_score(l['result'].get('risk_score'))}/100)" if l["result"]
                else f"{l['url']} (error)"
                for l in links
            ]
        pdf = fetch_pdf("Email Phishing Analysis Report", pdf_data)

        b1, b2, _ = st.columns([1, 1, 3])
        with b1:
            if pdf:
                st.download_button("📥 Λήψη αναφοράς PDF", data=pdf, file_name="Report_Email.pdf",
                                   mime="application/pdf", use_container_width=True)
            else:
                st.caption("Η αναφορά PDF δεν είναι διαθέσιμη αυτή τη στιγμή.")
        with b2:
            st.button("🔄 Νέος έλεγχος", on_click=clear_email, key="new_email",
                      use_container_width=True)

# ---------------------------------------------------------
# SIDEBAR HISTORY (σχεδιάζεται τελευταίο ώστε να δείχνει και τον τελευταίο έλεγχο)
# ---------------------------------------------------------
with history_slot:
    history = st.session_state.get("history", [])
    if history:
        st.divider()
        st.markdown("**🕘 Πρόσφατοι έλεγχοι**")
        for i, item in enumerate(history):
            icon = LEVELS[level_key(item["score"])]["icon"]
            kind_icon = "🔗" if item["kind"] == "url" else "📧"
            label = item["label"] if len(item["label"]) <= 28 else item["label"][:27] + "…"
            st.button(
                f"{icon} {kind_icon} {label} · {item['score']}",
                key=f"hist_{i}",
                help=f"{item['time']} · Πατήστε για να ξαναδείτε το αποτέλεσμα",
                on_click=restore_history,
                args=(i,),
                use_container_width=True,
            )