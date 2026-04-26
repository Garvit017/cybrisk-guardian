from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import json
import random
import re
from datetime import datetime
from typing import Optional

app = FastAPI(title="CybRisk Guardian API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Database Setup ───────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("cybrisk.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scam_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            red_flags TEXT,
            recommendations TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS training_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_type TEXT,
            scenario TEXT,
            user_answer TEXT,
            correct INTEGER,
            vulnerability_score INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS damage_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT,
            description TEXT,
            action_plan TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ─── Models ───────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    message: str

class TrainingAnswerRequest(BaseModel):
    scenario_id: int
    scenario_type: str
    scenario_text: str
    user_answer: str  # "legit" or "scam"
    correct_answer: str

class DamageControlRequest(BaseModel):
    incident_type: str
    description: str

# ─── Mock AI: Scam Analyzer ──────────────────────────────────────
SCAM_KEYWORDS = [
    "urgent", "immediately", "verify your account", "click here", "winner",
    "prize", "lottery", "otp", "bank account", "suspend", "suspended",
    "confirm your details", "limited time", "act now", "free gift",
    "congratulations", "you have been selected", "password", "login",
    "unusual activity", "security alert", "claim your", "wire transfer",
    "western union", "gift card", "bitcoin", "nigerian prince",
    "inheritance", "kyc", "aadhar", "pan card", "cvv", "expiry"
]

SAFE_INDICATORS = [
    "unsubscribe", "privacy policy", "terms of service", "official website",
    "no action required", "your subscription", "receipt", "order confirmed"
]

SUSPICIOUS_PATTERNS = [
    r"http[s]?://bit\.ly",
    r"http[s]?://tinyurl",
    r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"\b(whatsapp|telegram)\b.*\b(send|transfer|share)\b",
    r"\b\d{6}\b.*\b(otp|code|pin)\b",
    r"(bank|account|wallet).*\b(details|number|info)\b",
]

def analyze_scam(message: str):
    msg_lower = message.lower()
    red_flags = []
    score = 0

    # Check keywords
    found_keywords = [kw for kw in SCAM_KEYWORDS if kw in msg_lower]
    for kw in found_keywords:
        red_flags.append(f"Suspicious keyword detected: \"{kw}\"")
        score += 8

    # Check patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, msg_lower):
            red_flags.append(f"Suspicious pattern: matches known scam format")
            score += 15

    # Check safe indicators
    safe_count = sum(1 for s in SAFE_INDICATORS if s in msg_lower)
    score = max(0, score - safe_count * 10)

    # Urgency language
    if any(word in msg_lower for word in ["urgent", "immediately", "asap", "right now", "act now"]):
        red_flags.append("Urgency pressure tactic detected — scammers create panic to rush decisions")
        score += 12

    # Reward bait
    if any(word in msg_lower for word in ["winner", "prize", "lottery", "free", "reward", "gift"]):
        red_flags.append("Reward baiting detected — 'too good to be true' offers are a classic scam pattern")
        score += 10

    # Sensitive info requests
    if any(word in msg_lower for word in ["password", "otp", "cvv", "pin", "aadhar", "pan"]):
        red_flags.append("Request for sensitive credentials — legitimate organizations NEVER ask for these via message")
        score += 20

    # Clamp score
    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
        recommendations = [
            "Do NOT click any links in this message",
            "Do NOT share any personal information",
            "Block and report the sender immediately",
            "Warn others in your contact list about this scam",
            "If already clicked, change passwords immediately and run antivirus"
        ]
    elif score >= 40:
        risk_level = "MEDIUM"
        recommendations = [
            "Treat this message with caution",
            "Verify the sender through official channels before responding",
            "Do not provide any sensitive information",
            "Check the official website directly instead of clicking links"
        ]
    else:
        risk_level = "LOW"
        recommendations = [
            "This message appears relatively safe",
            "Still exercise caution with any links",
            "Verify sender identity if unsure"
        ]

    if not red_flags:
        red_flags = ["No major red flags detected — but always stay cautious"]

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "recommendations": recommendations
    }

# ─── Mock AI: Training Scenarios ─────────────────────────────────
SCENARIOS = {
    "phishing_email": [
        {
            "text": "Subject: URGENT - Your SBI account will be suspended!\n\nDear Customer,\n\nWe have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your details immediately.\n\nClick here to verify: http://sbi-secure-login.xyz/verify\n\nProvide your ATM PIN and OTP sent to your registered number.\n\nRegards,\nSBI Security Team",
            "answer": "scam",
            "explanation": "Real banks NEVER ask for your ATM PIN or OTP via email. The domain 'sbi-secure-login.xyz' is not an official SBI domain."
        },
        {
            "text": "Subject: Your Amazon order #408-2938741 has shipped\n\nHi there,\n\nYour order has been shipped and will arrive by Thursday.\nTracking number: IN123456789\n\nView your order: https://www.amazon.in/orders\n\nThank you for shopping with Amazon.\nAmazon Customer Service",
            "answer": "legit",
            "explanation": "This is a standard shipping confirmation. It directs to the official amazon.in domain, has a real order number, and asks for nothing sensitive."
        },
        {
            "text": "Subject: Congratulations! You've won ₹50,00,000 in Google Lucky Draw\n\nDear User,\n\nYour email was randomly selected in our annual lucky draw. To claim your prize of ₹50 Lakhs, send us your full name, bank account number, and IFSC code.\n\nContact: lucky-google-india@gmail.com\nClaim within 48 hours or forfeit your prize!",
            "answer": "scam",
            "explanation": "Google does not run lottery draws. No legitimate prize requires your bank details upfront. The email uses a Gmail address, not an official @google.com domain."
        }
    ],
    "fake_job": [
        {
            "text": "WORK FROM HOME OPPORTUNITY!\n\nEarn ₹50,000/month by liking YouTube videos and sharing on WhatsApp! No experience needed. Just pay a registration fee of ₹999 to get started. Guaranteed income daily. WhatsApp us NOW: +91-9876543210",
            "answer": "scam",
            "explanation": "Legitimate jobs never require you to pay a registration fee. 'Earn money by liking videos' is a well-known scam model with no real income."
        },
        {
            "text": "Infosys is hiring Software Engineer Interns for Summer 2025. Apply through our official careers portal at infosys.com/careers. No application fee required. Shortlisted candidates will be contacted via official @infosys.com email only.",
            "answer": "legit",
            "explanation": "This follows all hallmarks of a genuine job posting: official website, no fees, clear contact channel, and a recognizable company."
        }
    ],
    "scam_message": [
        {
            "text": "Hi, I'm a customs officer at Delhi airport. A parcel in your name contains illegal items. To avoid arrest, pay ₹15,000 fine to this UPI ID immediately: customs_fine@ybl. Do not contact police.",
            "answer": "scam",
            "explanation": "Government officials never contact you via WhatsApp for fines. The instruction 'do not contact police' is a major red flag — it's designed to isolate and panic you."
        },
        {
            "text": "Your Jio bill of ₹649 for March is due. Pay by 31st March to avoid service interruption. Visit myjio.com or use the MyJio app to pay. For help call 198.",
            "answer": "legit",
            "explanation": "This is a standard billing reminder. It points to official Jio channels, includes the official helpline, and doesn't ask for sensitive info via message."
        }
    ]
}

def get_training_scenario(scenario_type: str):
    scenarios = SCENARIOS.get(scenario_type, SCENARIOS["phishing_email"])
    scenario = random.choice(scenarios)
    return scenario

# ─── Mock AI: Damage Control ─────────────────────────────────────
DAMAGE_PLANS = {
    "shared_password": {
        "title": "Password Compromised",
        "steps": [
            "🔴 IMMEDIATELY change the compromised password on all platforms",
            "🔴 Enable Two-Factor Authentication (2FA) on all important accounts",
            "🔴 Check login history in account settings for unauthorized access",
            "🟡 Change passwords on accounts that used the SAME password",
            "🟡 Scan your device with a trusted antivirus tool",
            "🟡 Check if your email is on haveibeenpwned.com",
            "🟢 Set up a password manager (Bitwarden, 1Password) for future",
            "🟢 Monitor your email for unusual activity for next 30 days"
        ]
    },
    "shared_bank_details": {
        "title": "Bank Details Compromised",
        "steps": [
            "🔴 Call your bank's helpline IMMEDIATELY (SBI: 1800-11-2211, HDFC: 1800-202-6161)",
            "🔴 Request your card to be blocked/frozen right now",
            "🔴 Request a new card and account number if possible",
            "🔴 File a complaint on cybercrime.gov.in or call 1930",
            "🟡 Review your last 30 days of transactions for unauthorized charges",
            "🟡 Dispute any fraudulent transactions with your bank in writing",
            "🟡 File an FIR at your local police station for documentation",
            "🟢 Set up SMS/email alerts for ALL transactions",
            "🟢 Never share OTP, CVV, or PIN even with bank officials on call"
        ]
    },
    "clicked_phishing_link": {
        "title": "Clicked a Phishing Link",
        "steps": [
            "🔴 Disconnect your device from the internet immediately",
            "🔴 Do NOT enter any credentials on that page",
            "🔴 Run a full antivirus/malware scan right now",
            "🟡 Change passwords of accounts you were logged into at the time",
            "🟡 Check browser extensions — remove any you didn't install",
            "🟡 Clear browser cache and cookies",
            "🟡 Report the phishing URL to Google Safe Browsing: safebrowsing.google.com",
            "🟢 Enable 2FA on important accounts",
            "🟢 Update your browser and operating system to latest version"
        ]
    },
    "shared_otp": {
        "title": "OTP Shared with Scammer",
        "steps": [
            "🔴 Call your bank / service provider IMMEDIATELY to report",
            "🔴 Check if any transactions or changes were made using your account",
            "🔴 File a complaint at cybercrime.gov.in or call 1930 (Cyber Crime Helpline)",
            "🟡 Change your account password and phone number PIN",
            "🟡 Enable 2FA via authenticator app instead of SMS",
            "🟡 Block the scammer's number and report on your telecom portal",
            "🟢 Remember: NEVER share OTP with ANYONE — not even bank officials",
            "🟢 Screenshot all communication for police complaint evidence"
        ]
    },
    "fake_job_scam": {
        "title": "Fell for a Fake Job Scam",
        "steps": [
            "🔴 Stop all communication with the scammer immediately",
            "🔴 If money was paid, contact your bank to initiate a chargeback",
            "🔴 File a complaint at cybercrime.gov.in and your local police",
            "🟡 If personal documents were shared, monitor for identity fraud",
            "🟡 Alert your contacts so they don't fall for the same scam",
            "🟡 Report the job posting on the platform it appeared (LinkedIn, Naukri, etc.)",
            "🟢 Verify future job offers through official company websites only",
            "🟢 Legitimate employers never ask for registration fees"
        ]
    }
}

# ─── API Routes ───────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "CybRisk Guardian API is running 🛡️"}

@app.post("/api/analyze")
def analyze_message(req: AnalyzeRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    result = analyze_scam(req.message)

    conn = get_db()
    conn.execute(
        "INSERT INTO scam_analyses (message, risk_score, risk_level, red_flags, recommendations) VALUES (?, ?, ?, ?, ?)",
        (req.message, result["risk_score"], result["risk_level"],
         json.dumps(result["red_flags"]), json.dumps(result["recommendations"]))
    )
    conn.commit()
    conn.close()

    return result

@app.get("/api/training/scenario")
def get_scenario(type: str = "phishing_email"):
    valid_types = ["phishing_email", "fake_job", "scam_message"]
    if type not in valid_types:
        type = "phishing_email"
    scenario = get_training_scenario(type)
    return {
        "scenario_type": type,
        "text": scenario["text"],
        "correct_answer": scenario["answer"],
        "explanation": scenario["explanation"]
    }

@app.post("/api/training/submit")
def submit_training(req: TrainingAnswerRequest):
    is_correct = req.user_answer == req.correct_answer
    vulnerability_score = 0 if is_correct else random.randint(30, 70)

    conn = get_db()
    conn.execute(
        "INSERT INTO training_sessions (scenario_type, scenario, user_answer, correct, vulnerability_score) VALUES (?, ?, ?, ?, ?)",
        (req.scenario_type, req.scenario_text, req.user_answer, int(is_correct), vulnerability_score)
    )
    conn.commit()

    # Calculate overall vulnerability score
    rows = conn.execute("SELECT correct FROM training_sessions").fetchall()
    conn.close()

    total = len(rows)
    correct = sum(1 for r in rows if r["correct"])
    accuracy = int((correct / total) * 100) if total > 0 else 0
    vuln_score = 100 - accuracy

    return {
        "correct": is_correct,
        "vulnerability_score": vuln_score,
        "accuracy": accuracy,
        "total_attempts": total,
        "message": "✅ Correct! You identified this successfully." if is_correct else "❌ Incorrect. Scammers counted on you missing that."
    }

@app.post("/api/damage-control")
def damage_control(req: DamageControlRequest):
    plan = DAMAGE_PLANS.get(req.incident_type, {
        "title": "General Cyber Incident",
        "steps": [
            "🔴 Stop all interaction with the suspected scammer immediately",
            "🔴 File a complaint at cybercrime.gov.in or call 1930",
            "🟡 Document everything: screenshots, messages, transaction IDs",
            "🟡 Inform your bank if financial information was involved",
            "🟢 Talk to a trusted person or cybersecurity professional",
        ]
    })

    conn = get_db()
    conn.execute(
        "INSERT INTO damage_reports (incident_type, description, action_plan) VALUES (?, ?, ?)",
        (req.incident_type, req.description, json.dumps(plan["steps"]))
    )
    conn.commit()
    conn.close()

    return {
        "title": plan["title"],
        "steps": plan["steps"],
        "helplines": {
            "Cyber Crime Helpline": "1930",
            "Cyber Crime Portal": "cybercrime.gov.in",
            "RBI Banking Ombudsman": "14448",
            "National Consumer Helpline": "1800-11-4000"
        }
    }

@app.get("/api/stats")
def get_stats():
    conn = get_db()
    analyses = conn.execute("SELECT COUNT(*) as c FROM scam_analyses").fetchone()["c"]
    high_risk = conn.execute("SELECT COUNT(*) as c FROM scam_analyses WHERE risk_level='HIGH'").fetchone()["c"]
    trainings = conn.execute("SELECT COUNT(*) as c FROM training_sessions").fetchone()["c"]
    correct = conn.execute("SELECT COUNT(*) as c FROM training_sessions WHERE correct=1").fetchone()["c"]
    damage = conn.execute("SELECT COUNT(*) as c FROM damage_reports").fetchone()["c"]
    conn.close()

    accuracy = int((correct / trainings) * 100) if trainings > 0 else 0

    return {
        "total_analyses": analyses,
        "high_risk_detected": high_risk,
        "training_sessions": trainings,
        "training_accuracy": accuracy,
        "damage_reports": damage
    }
