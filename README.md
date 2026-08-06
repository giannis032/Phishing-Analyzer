# 🛡️ Sentinel - AI Phishing & Threat Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Backend-Flask-000000?style=flat-square&logo=flask)
![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-FF4B4B?style=flat-square&logo=streamlit)
![Groq](https://img.shields.io/badge/AI-Groq%20Llama--3.3-f34f29?style=flat-square)
![VirusTotal](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20v3-3B82F6?style=flat-square)

Sentinel is an end-to-end Threat Intelligence Platform that combines **Cybersecurity Heuristics**, **LLM Reasoning (AI)**, and **Threat Intelligence APIs** to inspect suspicious URLs and detect Phishing / Social Engineering attempts in email content.

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10 or higher
* Git
* API Keys for [Groq Console](https://console.groq.com/) and [VirusTotal Portal](https://www.virustotal.com/)

---

## 1. Repository Setup & Environment

```bash
# Clone the repository
git clone [https://github.com/your-username/phishing-analyzer.git](https://github.com/your-username/phishing-analyzer.git)
cd phishing-analyzer

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate
```
## 2. Install Dependencies
```bash
pip install flask streamlit requests tldextract python-dotenv groq python-whois reportlab
```
## 3. Configure Environment Variables (.env)
Create a .env file in the root directory:
```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GROQ_API_KEY=your_groq_api_key_here
```
## 4. Running the Application
Open two terminal instances (ensuring venv is active in both):

Terminal 1 (Backend REST API):
```bash
python backend.py
```
Terminal 2 (Frontend Dashboard):
```bash
streamlit run frontend.py
```
---

## 📡 REST API Endpoints

| Method | Endpoint | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/health` | Backend API health check | `N/A` |
| **POST** | `/api/analyze-url` | Scans URL (Heuristics, SSL, WHOIS, VirusTotal) | `{"url": "https://..."}` |
| **POST** | `/api/analyze-email` | Analyzes email text using Groq LLM | `{"email_text": "..."}` |
| **POST** | `/api/generate-pdf` | Generates downloadable PDF Security Report | `{"title": "...", "data": {...}}` |

---

## 🌟 Key Features

* **🔗 URL Threat Analysis:**
  * **Domain Age Verification (WHOIS):** Identifies recently registered domains (high-risk indicators).
  * **SSL/TLS Certificate Inspection:** Validates HTTPS certificates and tracks expiration timelines.
  * **VirusTotal v3 Integration:** Cross-references domain reputation across dozens of antivirus engines.
  * **Static Heuristics:** Detects IP-based URLs, obfuscation symbols (`@`), and suspicious URL lengths.

* **📧 Email Social Engineering Analysis (AI):**
  * **Groq Llama-3.3-70b LLM:** Natural Language Processing (NLP) tailored for social engineering detection.
  * **Urgency & Threat Detection:** Automatically flags artificial time-pressure tactics.
  * **Structured Red Flags:** Extracts specific risk indicators into structured JSON format.

* **📄 Automated Audit Reporting:**
  * Generates and exports downloadable PDF technical reports (via ReportLab) for every analysis performed.

---

## 🛠️ Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend API** | Python 3.10+, Flask | Data processing, routing, and RESTful endpoints |
| **Frontend UI** | Streamlit | Responsive SOC Dashboard, metrics, and containers |
| **Artificial Intelligence** | Groq API (`llama-3.3-70b-versatile`) | NLP Email & Social Engineering reasoning |
| **Threat Intel APIs** | VirusTotal v3 API, PyWHOIS, SSL/Socket | Domain age, reputation, and certificate scanning |
| **PDF Generation** | ReportLab | Automated Security Audit Report generation |

---

## 📐 System Architecture

```text
┌─────────────────┐       HTTP Requests       ┌──────────────────┐
│  Streamlit UI   │ ────────────────────────> │   Flask REST API │
│  (frontend.py)  │ <──────────────────────── │   (backend.py)   │
└─────────────────┘       JSON Responses      └────────┬─────────┘
                                                       │
         ┌──────────────────────┬──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼                      ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Groq Llama-3.3   │  │ VirusTotal v3    │  │ WHOIS Protocol   │  │ ReportLab Engine │
│ (Social Eng AI)  │  │ (Domain Reputation)│ │ (Domain Age)     │  │ (PDF Generation) │
└──────────────────┘  └──────────────────┘  └──────────────────┘  └──────────────────┘

```
---

