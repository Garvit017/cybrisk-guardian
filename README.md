# 🛡️ CybRisk Guardian

**AI-Powered Cybersecurity Platform** — Protect yourself from phishing, scams, fake jobs & social engineering.

---

## 📁 Project Structure

```
cybrisk-guardian/
├── backend/
│   ├── main.py           ← FastAPI backend (all routes + mock AI)
│   ├── requirements.txt  ← Python dependencies
│   └── cybrisk.db        ← SQLite DB (auto-created on first run)
└── frontend/
    ├── index.html         ← Home page
    ├── css/style.css      ← Cyberpunk dark theme
    └── pages/
        ├── analyzer.html  ← Scam Analyzer module
        ├── training.html  ← Training Simulator module
        └── damage.html    ← Damage Control module
```

---

## ⚙️ Setup & Running

### 1. Backend (FastAPI)

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --port 8000
```

Backend will be live at: **http://localhost:8000**

API Docs (auto-generated): **http://localhost:8000/docs**

---

### 2. Frontend

Open the frontend folder and just open `index.html` in any browser.

**Option A — Simple (just open file):**
```
Double-click: frontend/index.html
```

**Option B — Using Python HTTP server (recommended):**
```bash
cd frontend
python -m http.server 5500
# Then open: http://localhost:5500
```

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| 🔍 Scam Analyzer | Paste suspicious messages → AI risk score + red flags |
| 🎯 Training Simulator | Test yourself against phishing/scam scenarios |
| 🚨 Damage Control | Get step-by-step recovery plan after being scammed |

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze a suspicious message |
| GET | `/api/training/scenario?type=...` | Get a training scenario |
| POST | `/api/training/submit` | Submit training answer |
| POST | `/api/damage-control` | Get damage control plan |
| GET | `/api/stats` | Get platform statistics |

---

## 🛠️ Tech Stack

- **Frontend:** HTML5 + CSS3 + Vanilla JavaScript
- **Backend:** Python + FastAPI
- **Database:** SQLite (auto-initialized)
- **AI:** Rule-based mock AI (keyword + pattern analysis)
- **Fonts:** Orbitron, Rajdhani, Share Tech Mono

---

## 📞 Emergency Helplines (India)

- **Cyber Crime Helpline:** 1930
- **Cyber Crime Portal:** cybercrime.gov.in
- **RBI Banking Ombudsman:** 14448
- **National Consumer Helpline:** 1800-11-4000
