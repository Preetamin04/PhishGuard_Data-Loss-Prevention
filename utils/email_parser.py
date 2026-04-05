import re
import os
from email import policy
from email.parser import BytesParser

URGENCY_WORDS = [
    "urgent", "immediately", "verify now", "action required",
    "account suspended", "click now", "limited time", "respond now",
    "your account will be closed", "act fast", "final notice"
]

SCAM_KEYWORDS = [
    "my late husband", "inherit", "executor", "financial firm",
    "claim the deposit", "benin republic", "i offer you",
    "trusted person", "only daughter", "transfer to your custody",
    "investment purposes", "next of kin", "bank of africa"
]

CRYPTO_KEYWORDS = [
    "digital currency", "crypto", "blockchain", "token", "wallet",
    "airdropped", "airdrop", "transferred to you", "crypto prize",
    "bitcoin", "ethereum", "claim your crypto", "we will send"
]

LANGUAGE_SCORE_WORDS = [
    "trust", "confidential", "important", "secure", "privacy",
    "verify", "confirm", "click", "login", "reset", "reply",
    "prize", "winner", "locked", "suspended", "legal action",
    "friend", "partner", "only you", "last chance"
]

POSITIVE_WORDS = {
    "congratulations", "winner", "prize", "reward", "free", "gift",
    "lucky", "selected", "bonus", "offer", "earn", "claim"
}
NEGATIVE_WORDS = {
    "suspended", "blocked", "terminated", "locked", "expired",
    "unauthorized", "illegal", "violation", "penalty", "arrest", "fraud"
}

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "linkedin": "linkedin.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "apple": "apple.com",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "aol.com", "outlook.com",
    "icloud.com", "protonmail.com", "live.com", "mail.com", "zoho.com",
    "yandex.com", "gmx.com"
}

ATTACHMENT_RISK = {
    ".exe": 4, ".scr": 4, ".vbs": 4, ".js": 4, ".jar": 4, ".msi": 4,
    ".bat": 4, ".cmd": 4, ".wsf": 4, ".com": 4, ".cpl": 4,
    ".zip": 3, ".7z": 3, ".rar": 3, ".html": 3, ".htm": 3,
    ".docm": 3, ".xlsm": 3, ".pptm": 3, ".rtf": 2, ".pdf": 2,
    ".doc": 1, ".xls": 1, ".ppt": 1,
}

PHISHING_TEMPLATES = {
    "DHL Delivery Scam":      [r"dhl", r"parcel.{0,30}held", r"delivery.{0,30}fee"],
    "Tax Refund Scam":        [r"tax refund", r"irs", r"income tax.{0,20}return"],
    "Crypto Giveaway":        [r"bitcoin.{0,30}giveaway", r"double your (crypto|btc)", r"elon.{0,15}send"],
    "Password Reset Phish":   [r"reset your password", r"verify your account", r"confirm.{0,20}identity"],
    "Advance Fee (419) Scam": [r"million (dollars|usd)", r"bank transfer.{0,30}fee", r"claim your (inheritance|funds)"],
}

BANNED_DOMAINS    = {"fakesite.com", "phishlink.ru", "malware-dl.xyz"}
BANNED_KEYWORDS   = {"reset wallet", "update token", "your prize"}
BANNED_EXTENSIONS = {".iso", ".svg"}

# Helper extractors
def _get_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if (part.get_content_type() == "text/plain"
                    and "attachment" not in str(part.get("Content-Disposition", ""))):
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""

def _extract_urls(text: str):
    return re.findall(r"https?://[^\s<>\"']+", text)

def _parse_auth(msg) -> dict:
    results = {"spf": "not_found", "dkim": "not_found"}
    header  = msg.get("Authentication-Results", "")
    for proto in ("spf", "dkim"):
        m = re.search(rf"{proto}=(pass|fail|neutral|none)", header, re.I)
        if m:
            results[proto] = m.group(1).lower()
    return results

def _detect_attachments(msg):
    names, suspicious, score = [], [], 0
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            fname = part.get_filename()
            if fname:
                names.append(fname)
                ext = os.path.splitext(fname)[1].lower()
                w   = ATTACHMENT_RISK.get(ext, 0)
                if w:
                    suspicious.append(f"{fname} [risk={w}]")
                    score += w
    return names, suspicious, score

def _detect_html_forms(msg):
    tags = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_type() == "text/html":
            html = part.get_payload(decode=True).decode(errors="ignore").lower()
            for tag in ("<form", "<input", "<button"):
                if tag in html:
                    tags.append(tag + ">")
    return tags

# Indicator detectors
def _urgency(body: str):
    body_l = body.lower()
    return [w for w in URGENCY_WORDS if w in body_l]

def _suspicious_urls(urls, from_domain: str):
    found = []
    for url in urls:
        m = re.search(r"https?://([^/]+)", url)
        if not m:
            continue
        domain = m.group(1)
        if re.match(r"(\d{1,3}\.){3}\d{1,3}", domain):
            found.append(f"IP address URL: {url}")
        if domain.count(".") > 3:
            found.append(f"Obfuscated subdomain: {domain}")
        if from_domain and from_domain not in domain:
            found.append(f"Domain mismatch — sender:{from_domain} / link:{domain}")
    return found

def _brand_spoofing(sender: str, body: str):
    found = []
    sl, bl = sender.lower(), body.lower()
    for brand, legit in KNOWN_BRANDS.items():
        if (brand in sl or brand in bl) and legit not in sl:
            found.append(f"Brand spoofing: '{brand}' via non-official sender")
    return found

def _advance_fee_scam(body: str):
    bl = body.lower()
    return [kw for kw in SCAM_KEYWORDS if kw in bl]

def _crypto_bait(subject: str, body: str, from_domain: str):
    text = f"{subject} {body}".lower()
    hits = [kw for kw in CRYPTO_KEYWORDS if kw in text]
    trusted = {"linkedin.com", "indeed.com", "glassdoor.com"}
    return hits if hits and not any(t in from_domain for t in trusted) else []

def _language_score(body: str):
    bl = body.lower()
    return [kw for kw in LANGUAGE_SCORE_WORDS if kw in bl]

def _sentiment_score(body: str):
    """Simple rule-based sentiment — no external library needed."""
    words = set(body.lower().split())
    pos = words & POSITIVE_WORDS
    neg = words & NEGATIVE_WORDS
    result = []
    if pos:
        result.append(f"High-reward language: {', '.join(list(pos)[:3])}")
    if neg:
        result.append(f"Fear/threat language: {', '.join(list(neg)[:3])}")
    return result

def _sender_name_mismatch(from_field: str):
    m = re.match(r"(.+?)\s*<(.+?)>", from_field)
    if not m:
        return []
    name   = m.group(1).strip().lower()
    domain = m.group(2).split("@")[-1].lower().strip(">")
    return [
        f"Name spoofing: '{name}' via {domain}"
        for brand, legit in KNOWN_BRANDS.items()
        if brand in name and legit not in domain
    ]

def _free_email_brand_abuse(from_field: str):
    m = re.match(r".*<(.+?)>", from_field)
    if not m:
        return []
    email  = m.group(1).strip().lower()
    domain = email.split("@")[-1]
    return [
        f"Brand '{brand}' claimed from free-email domain: {domain}"
        for brand in KNOWN_BRANDS
        if brand in email and domain in FREE_EMAIL_DOMAINS
    ]

def _user_rules(body: str, urls, attachments):
    found = []
    bl = body.lower()
    for kw in BANNED_KEYWORDS:
        if kw.lower() in bl:
            found.append(f"Banned keyword: '{kw}'")
    for domain in BANNED_DOMAINS:
        for url in urls:
            if domain in url.lower():
                found.append(f"Banned domain in URL: '{domain}'")
    for fname in attachments:
        ext = os.path.splitext(fname)[1].lower()
        if ext in BANNED_EXTENSIONS:
            found.append(f"Banned attachment type '{ext}': {fname}")
    return found

def _template_match(body: str):
    hits = []
    for name, patterns in PHISHING_TEMPLATES.items():
        if any(re.search(p, body, re.I) for p in patterns):
            hits.append(f"Matched known template: {name}")
    return hits

# Public API
def parse_eml_file(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    from_field  = msg.get("From", "")
    from_domain = (from_field.split("@")[-1].strip(">").lower()
                   if "@" in from_field else "")
    body        = _get_body(msg)
    urls        = _extract_urls(body)

    attachments, suspicious_att, att_score = _detect_attachments(msg)
    html_forms  = _detect_html_forms(msg)
    auth        = _parse_auth(msg)

    indicators = {
        "urgency_language":       _urgency(body),
        "suspicious_url":         _suspicious_urls(urls, from_domain),
        "brand_spoofing":         _brand_spoofing(from_field, body),
        "advance_fee_scam":       _advance_fee_scam(body),
        "crypto_bait":            _crypto_bait(msg.get("Subject", ""), body, from_domain),
        "sender_name_mismatch":   _sender_name_mismatch(from_field),
        "language_scoring":       _language_score(body),
        "sentiment_score":        _sentiment_score(body),
        "free_email_brand_abuse": _free_email_brand_abuse(from_field),
        "user_defined_rules":     _user_rules(body, urls, attachments),
        "phishing_template_match":_template_match(body),
        "html_form_detector":     html_forms,
    }
    return {
        "from":                 from_field,
        "from_domain":          from_domain,
        "to":                   msg.get("To", ""),
        "subject":              msg.get("Subject", ""),
        "date":                 msg.get("Date", ""),
        "body":                 body,
        "urls":                 urls,
        "attachments":          attachments,
        "suspicious_attachments": suspicious_att,
        "attachment_score":     att_score,
        "auth_results":         auth,
        "html_form_usage":      html_forms,
        "indicators":           indicators,
    }
