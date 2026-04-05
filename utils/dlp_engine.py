'''
Detects:
  • Indian PAN card numbers
  • Aadhaar card numbers
  • Credit / debit card numbers (Luhn-validated)
  • Passwords / secrets in plain text
  • Sensitive file attachments (HR data, employee data, payroll, etc.)
  • Bulk data indicators (many rows of tabular data)
'''

import re
import os
from email import policy
from email.parser import BytesParser

PATTERNS = {
    # Indian PAN: 5 letters, 4 digits, 1 letter  e.g. ABCDE1234F
    "PAN Card":
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),

    # Aadhaar: 12 digits, often written as XXXX XXXX XXXX
    "Aadhaar Number":
        re.compile(r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b"),

    # Credit/debit cards: 13-19 digits (Visa, MC, Amex, Discover, RuPay)
    "Credit/Debit Card": re.compile(
        r"\b(?:"
        r"4[0-9]{12}(?:[0-9]{3})?"                    # Visa
        r"|"
        r"(?:6[0-9]{15}|8[0-9]{15}|508[0-9]{13})"     # RuPay 
        r")\b"),

    "Password/Secret":
        re.compile(r"(?i)(password|passwd|secret|api[_\-]?key|auth[_\-]?token)\s*[=:]\s*\S{6,}"),

    "IFSC Code":
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),

    "Bank Account Number":
        re.compile(r"\b\d{9,18}\b"),
}

SENSITIVE_FILENAME_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"hr.?data",
        r"employee.?data",
        r"payroll",
        r"salary",
        r"personal.?details",
        r"customer.?list",
        r"client.?data",
        r"database.?export",
        r"confidential",
        r"internal.?only",
        r"restricted",
        r"pii",           # Personally Identifiable Information
        r"aadhar",
        r"pan.?card",
        r"passport",
    ]
]

BULK_DATA_EXTENSIONS = {".xlsx", ".xls", ".csv", ".db", ".sql", ".json", ".xml"}

# Minimum hits before flagging "bulk data"
BULK_ROW_THRESHOLD = 10

# Helpers
def _luhn_check(number: str) -> bool:
    '''Credit card no. detection'''
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def _get_text_body(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            ct  = part.get_content_type()
            cd  = str(part.get("Content-Disposition", ""))
            if ct in ("text/plain", "text/html") and "attachment" not in cd:
                parts.append(part.get_payload(decode=True).decode(errors="ignore"))
        return "\n".join(parts)
    return msg.get_payload(decode=True).decode(errors="ignore")

'''Return list of DLP violations found in attachment metadata.'''
def _scan_attachments(msg):
    violations = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        fname = part.get_filename() or ""
        ext   = os.path.splitext(fname)[1].lower()

        # Name-based detection
        for pat in SENSITIVE_FILENAME_PATTERNS:
            if pat.search(fname):
                violations.append({
                    "type":    "Sensitive Filename",
                    "detail":  f"'{fname}' matches sensitive data pattern",
                    "severity":"HIGH",
                })
                break

        # Extension — bulk data carrier
        if ext in BULK_DATA_EXTENSIONS:
            try:
                content = part.get_payload(decode=True).decode(errors="ignore")
                lines   = [l for l in content.split("\n") if l.strip()]
                if len(lines) > BULK_ROW_THRESHOLD:
                    violations.append({
                        "type":    "Bulk Data Attachment",
                        "detail":  f"'{fname}' contains {len(lines)} rows of data",
                        "severity":"HIGH",
                    })
            except Exception:
                pass
    return violations

def _classify_severity(pattern_type: str) -> str:
    critical = {"PAN Card", "Aadhaar Number", "Credit/Debit Card", "Password/Secret"}
    return "CRITICAL" if pattern_type in critical else "HIGH"

# Public API
def scan_outgoing(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body       = _get_text_body(msg)
    violations = []

    # Pattern scanning
    for ptype, regex in PATTERNS.items():
        matches = regex.findall(body)
        if not matches:
            continue

        # Extra validation for credit cards
        if ptype == "Credit/Debit Card":
            matches = [m for m in matches if _luhn_check(m)]

        # Bank account numbers are noisy — only flag if clearly high count
        if ptype == "Bank Account Number" and len(matches) < 3:
            continue

        if matches:
            violations.append({
                "type":    ptype,
                "detail":  f"{len(matches)} instance(s) found: {matches[:3]}{'...' if len(matches) > 3 else ''}",
                "severity": _classify_severity(ptype),
            })

    # Attachment scanning
    violations.extend(_scan_attachments(msg))

    # Result 
    dlp_blocked = any(v["severity"] == "CRITICAL" for v in violations)
    return {
        "from":        msg.get("From", ""),
        "to":          msg.get("To",   ""),
        "subject":     msg.get("Subject", ""),
        "violations":  violations,
        "dlp_blocked": dlp_blocked,
    }
