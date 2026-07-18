# AI-Powered Phishing Website Detection System

A full-stack phishing detection system combining a **Python AI scanner** (`app.py`) with a **React + Node.js web application**.

---

https://website-detector-1.onrender.com/

## 📁 Project Structure

```
AD-web-detect/
├── app.py                  ← Python CLI scanner (ML-based, 4-phase analysis)
├── package.json            ← Root scripts to run both servers
│
├── backend/
│   ├── server.js           ← Node.js Express API (16 engines, 10 vuln signatures)
│   └── package.json
│
└── frontend/
    ├── index.html          ← SEO-optimized HTML entry
    ├── package.json
    ├── vite.config.js      ← Vite (proxies /api → backend:5000)
    ├── postcss.config.js
    ├── tailwind.config.js
    └── src/
        ├── main.jsx        ← React entry point
        ├── App.jsx         ← Full UI (Login, Dashboard, Results)
        ├── App.css
        └── index.css       ← Complete design system
```

---

## 🚀 Quick Start

### Option A — Web App (React + Node.js)

**Step 1: Install dependencies**
```bash
cd backend && npm install
cd ../frontend && npm install
```

**Step 2: Start backend (port 5000)**
```bash
cd backend
node server.js
```

**Step 3: Start frontend (port 5173)**
```bash
cd frontend
npm run dev
```

**Step 4: Open browser**
```
http://localhost:5173
```
Login: `dhruv` / `dhrparg@37`

---

### Option B — Python CLI Scanner

```bash
pip install requests beautifulsoup4 scikit-learn numpy python-whois
python app.py
```

---

## 🛡️ Detection Features

### Web App (Node.js Backend)
| ID | Vulnerability | Severity | CVSS |
|---|---|---|---|
| VLN-001 | No HTTPS / Unencrypted HTTP | HIGH | 7.5 |
| VLN-002 | Phishing Keywords in URL | MEDIUM | 5.9 |
| VLN-003 | @ Symbol URL Authority Bypass | CRITICAL | 9.1 |
| VLN-004 | Excessive URL Length | LOW | 3.1 |
| VLN-005 | High-Risk TLD (.xyz, .top, etc.) | HIGH | 6.8 |
| VLN-006 | Raw IP Address in URL | HIGH | 7.2 |
| VLN-007 | Double Slash Redirect | MEDIUM | 5.3 |
| VLN-008 | Brand Spoofing in Subdomain | CRITICAL | 8.7 |
| VLN-009 | URL Encoding Obfuscation | MEDIUM | 5.0 |
| VLN-010 | Homograph / Typosquat Attack | HIGH | 7.0 |

### Python Scanner (app.py)
- **Phase 1**: URL & Lexical Analysis (entropy, punycode, typosquatting)
- **Phase 2**: Content & Heuristic Analysis (forms, credentials, JS obfuscation)
- **Phase 3**: Behavioral & Infrastructure (SSL, WHOIS, redirects)
- **Phase 4**: AI/ML Analysis (Naive Bayes + optional LLM)

---

## 🔐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/login` | Authenticate user |
| POST | `/api/check` | Scan a URL for phishing |
| GET | `/api/health` | Server health check |

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite, Vanilla CSS |
| Backend | Node.js, Express |
| Python | scikit-learn, BeautifulSoup, Requests, WHOIS |
| Styling | Custom glassmorphism design system |
