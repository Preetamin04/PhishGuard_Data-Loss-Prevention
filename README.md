# PhishGuard — Email Security Analyser
Rule-Based Phishing Detection + Data Loss Prevention (DLP)
No AI. No external APIs. Pure deterministic rule-based logic — readable, explainable, and auditable.

# Project Structure
PhishGuard/
├── main.py                    ← Entry point (run this)
├── requirements.txt
├── sample_emails/             ← Incoming emails to scan for phishing
├── outgoing_drafts/           ← Outgoing emails to scan for data leakage
└── utils/
    ├── email_parser.py        ← Parses .eml + runs phishing detectors
    ├── risk_engine.py         ← Converts indicators → risk score + severity
    ├── dlp_engine.py          ← Scans outgoing email for sensitive data
    └── report.py              ← Terminal output / formatting

# How to Run

```bash
# Install dependency (optional)
pip install textblob

# Scan both incoming + outgoing (default)
python main.py --mode both

# Scan only incoming emails (phishing detection)
python main.py --mode incoming

# Scan only outgoing emails (DLP)
python main.py --mode outgoing

# Scan a specific .eml file
python main.py --email "folder_name\file.eml"
OR
python main.py --email "raw_path_string"
```

# Feature 1 — Phishing Detection (Incoming)
Scans every `.eml` in `sample_emails/` (applies these rule checks):

| Rule | Description | Weight |
| Urgency Language | Words like "urgent", "act now", "account suspended" | 1 |
| Suspicious URL | IP addresses, mismatched domains, obfuscated subdomains | 2 |
| Brand Spoofing | Mentions PayPal/Google/Amazon but sends from unrelated domain | 2 |
| Sender Name Mismatch | Display name claims to be a brand but email domain differs | 2 |
| Free Email Brand Abuse | Brand name in Gmail/Hotmail address | 2 |
| Advance Fee Scam | "inheritance", "next of kin", "Benin Republic" patterns | 3 |
| Crypto Bait | Bitcoin giveaway, airdrop, wallet transfer keywords | 3 |
| Phishing Template Match | Known DHL, Tax Refund, Password Reset patterns | 3 |
| HTML Form in Email | `<form>`, `<input>` tags inside email body | 3 |
| Language Score | Persuasion/manipulation vocabulary | 1 |
| SPF/DKIM Failure | Email authentication header fails | +2 each |
| Attachment Risk | .exe=4, .zip=3, .pdf=2, etc. | variable |


Severity Thresholds:
| Score | Level |
| ≥ 10 | 🔴 CRITICAL |
| ≥ 5 | 🟠 HIGH |
| ≥ 2 | 🟡 MEDIUM |
| ≥ 1 | 🟢 LOW |
| 0 | ✅ SAFE |

Also performs (cross-email batch analysis) to detect coordinated campaigns (repeated subjects, reused URLs, same sender across multiple emails).

# Feature 2 — Data Loss Prevention / DLP (Outgoing)
Scans every `.eml` in `outgoing_drafts/` (sensitive data before it leaves):

| Pattern Detected | Example |
| PAN Card | `ABCDE1234F` |
| Aadhaar Number | `2345 6789 0123` |
| Credit/Debit Card (Luhn-validated) | `4111111111111111` |
| Password / Secret in plaintext | `password=MyPass123` |
| IFSC Code | `HDFC0001234` |
| Sensitive Filename | `HR_Data.xlsx`, `Employee_Payroll.csv` |
| Bulk Data Attachment | CSV/XLSX with >10 rows |

Actions:
- 🚫 **BLOCKED** — If CRITICAL data (PAN, Aadhaar, Card, Password) is found
- ⚠️  **WARNING** — If HIGH-severity patterns found (bulk files, IFSC, etc.)
- ✅ **CLEARED** — No violations found

# Design Philosophy
- No AI / ML — Every decision is a readable `if-else` or regex rule
- Explainable — Every flag tells you exactly *what* was found and *why*
- Extensible — Add new rules to `email_parser.py` or `dlp_engine.py`
- India-aware — PAN, Aadhaar, IFSC, RuPay cards natively supported
