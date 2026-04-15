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

# ==============================
# Regex Patterns for DLP
# ==============================
PATTERNS = {
    # Indian PAN: 5 letters, 4 digits, 1 letter  e.g. ABCDE1234F
    "PAN Card":
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),

    # Aadhaar: 12 digits, often written as XXXX XXXX XXXX
    "Aadhaar Number":
        re.compile(r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b"),

    # Credit/debit cards: Visa, Mastercard, American Express, RuPay, Discover, UnionPay
    "Credit/Debit Card": re.compile(
        r"\b(?:"
        r"(?:4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # Visa
        r"|"
        r"(?:5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # Mastercard
        r"|"
        r"(?:2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # Mastercard (new range)
        r"|"
        r"(?:3[47]\d{2}[- ]?\d{6}[- ]?\d{5})"  # American Express
        r"|"
        r"(?:508\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # RuPay
        r"|"
        r"(?:6\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # RuPay/Discover variants
        r"|"
        r"(?:62\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})"  # UnionPay
        r")\b"
    ),

    # Passwords and Secrets in plain text
    "Password/Secret":
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token|"
            r"access[_\-]?token|private[_\-]?key)\s*[=:]\s*\S{6,}"
        ),

    # IFSC Code
    "IFSC Code":
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),

    # Bank Account Number (9–18 digits)
    "Bank Account Number":
        re.compile(r"\b\d{9,18}\b(?!\d)"),
}

# Sensitive Attachment Names
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

# Extensions considered as bulk data carriers
BULK_DATA_EXTENSIONS = {".xlsx", ".xls", ".csv", ".db", ".sql", ".json", ".xml"}

# Minimum hits before flagging "bulk data"
BULK_ROW_THRESHOLD = 10

# Helper Functions
def _luhn_check(number: str) -> bool:
    '''Credit card number detection using the Luhn Algorithm.'''
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


def _normalize_number(number: str) -> str:
    '''Remove spaces and hyphens from detected numbers.'''
    return re.sub(r"[^\d]", "", number)


def _mask_sensitive_data(value: str, visible: int = 4) -> str:
    '''Mask sensitive data except the last few digits.'''
    clean_value = _normalize_number(value)
    if len(clean_value) <= visible:
        return clean_value
    return "X" * (len(clean_value) - visible) + clean_value[-visible:]


def _get_text_body(msg) -> str:
    '''Extract text body from email message.'''
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct in ("text/plain", "text/html") and "attachment" not in cd:
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(errors="ignore"))
        return "\n".join(parts)

    payload = msg.get_payload(decode=True)
    return payload.decode(errors="ignore") if payload else ""


def _scan_attachments(msg):
    '''Return list of DLP violations found in attachment metadata.'''
    violations = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        fname = part.get_filename() or ""
        ext = os.path.splitext(fname)[1].lower()

        # Name-based detection
        for pat in SENSITIVE_FILENAME_PATTERNS:
            if pat.search(fname):
                violations.append({
                    "type": "Sensitive Filename",
                    "detail": f"'{fname}' matches sensitive data pattern",
                    "severity": "HIGH",
                })
                break

        # Extension-based bulk data detection
        if ext in BULK_DATA_EXTENSIONS:
            try:
                content_bytes = part.get_payload(decode=True)
                if not content_bytes:
                    continue
                content = content_bytes.decode(errors="ignore")
                lines = [l for l in content.split("\n") if l.strip()]
                if len(lines) > BULK_ROW_THRESHOLD:
                    violations.append({
                        "type": "Bulk Data Attachment",
                        "detail": f"'{fname}' contains {len(lines)} rows of data",
                        "severity": "HIGH",
                    })
            except Exception:
                pass

    return violations

def _classify_severity(pattern_type: str) -> str:
    '''Classify severity based on detected data type.'''
    critical = {"PAN Card", "Aadhaar Number", "Credit/Debit Card", "Password/Secret"}
    return "CRITICAL" if pattern_type in critical else "HIGH"

# Public API
def scan_outgoing(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = _get_text_body(msg)
    violations = []

    # Pattern scanning
    for ptype, regex in PATTERNS.items():
        raw_matches = regex.findall(body)
        if not raw_matches:
            continue

        # Ensure matches are handled correctly even if tuples are returned
        matches = []
        for m in raw_matches:
            if isinstance(m, tuple):
                matches.append("".join(m))
            else:
                matches.append(m)

        # Extra validation for credit cards
        if ptype == "Credit/Debit Card":
            validated = []
            for m in matches:
                clean = _normalize_number(m)
                if _luhn_check(clean):
                    validated.append(_mask_sensitive_data(clean))
            matches = validated

        # Mask sensitive numeric identifiers
        elif ptype in {"Aadhaar Number", "Bank Account Number"}:
            matches = [_mask_sensitive_data(m) for m in matches]

        # Bank account numbers are noisy — only flag if clearly high count
        if ptype == "Bank Account Number" and len(matches) < 3:
            continue

        if matches:
            violations.append({
                "type": ptype,
                "detail": f"{len(matches)} instance(s) found: {matches[:3]}{'...' if len(matches) > 3 else ''}",
                "severity": _classify_severity(ptype),
            })

    # Attachment scanning
    violations.extend(_scan_attachments(msg))

    # Result
    dlp_blocked = any(v["severity"] == "CRITICAL" for v in violations)
    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "violations": violations,
        "dlp_blocked": dlp_blocked,
    }