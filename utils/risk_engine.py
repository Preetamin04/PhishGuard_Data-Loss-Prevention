'''Converts raw phishing indicators into a risk score + severity label.'''

INDICATOR_WEIGHTS = {
    "urgency_language":        1,
    "suspicious_url":          2,
    "brand_spoofing":          2,
    "advance_fee_scam":        3,
    "crypto_bait":             3,
    "sender_name_mismatch":    2,
    "language_scoring":        1,
    "sentiment_score":         1,
    "free_email_brand_abuse":  2,
    "user_defined_rules":      2,
    "phishing_template_match": 3,
    "html_form_detector":      3,
}

SEVERITY_LABEL = {
    "CRITICAL": 10,
    "HIGH":      5,
    "MEDIUM":    2,
    "LOW":       1,
    "SAFE":      0,
}
'''
    Returns (total_score, severity_string).
    indicators      – dict of {key: list}  (non-empty list = triggered)
    attachment_score– pre-computed sum from ATTACHMENT_RISK weights
    auth_results    – {"spf": "pass|fail", "dkim": "pass|fail"}
    '''
def calculate_risk(indicators: dict, attachment_score: int, auth_results: dict):
    score = 0
    for key, val in indicators.items():
        if isinstance(val, list) and val:
            score += INDICATOR_WEIGHTS.get(key, 1)

    score += attachment_score

    if auth_results.get("spf")  == "fail":
        score += 2
    if auth_results.get("dkim") == "fail":
        score += 2

    # Map score to severity
    for label, threshold in SEVERITY_LABEL.items():
        if score >= threshold:
            return score, label
    return 0, "SAFE"
