from datetime import datetime

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "SAFE":     "✅",
}
DLP_ICON = {
    "CRITICAL": "🚫",
    "HIGH":     "⚠️ ",
}


def print_banner():
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    print("""
╔══════════════════════════════════════════════════════════╗
║        PhishGuard — Email Security Analyser              ║
║        Rule-Based Phishing Detection + DLP               ║
╚══════════════════════════════════════════════════════════╝""")
    print(f"  Scan started : {now}\n")

def print_incoming_report(records, patterns):
    safe_count  = sum(1 for r in records if r["severity"] == "SAFE")
    risky_count = len(records) - safe_count

    print(f"\n  Scanned {len(records)} email(s) — "
          f"{risky_count} suspicious, {safe_count} clean.\n")

    # Batch patterns first
    if patterns:
        _print_patterns(patterns)

    # Per-email detail
    for rec in sorted(records, key=lambda r: r["risk_score"], reverse=True):
        _print_email_block(rec)

def _print_patterns(patterns):
    has_any = any(patterns[k] for k in patterns)
    if not has_any:
        return
    print("─" * 60)
    print("CROSS-EMAIL PATTERN ANALYSIS")
    print("─" * 60)
    for label, data in (
        ("Repeated Subjects", patterns["repeated_subjects"]),
        ("Reused URLs",       patterns["reused_urls"]),
        ("Common Senders",    patterns["common_senders"]),
    ):
        if data:
            print(f"\n  ⚠️  {label}:")
            for item, count in data.items():
                short = (item[:72] + "…") if len(item) > 75 else item
                print(f"      • {short!r}  ×{count}")


def _print_email_block(rec):
    icon = SEVERITY_ICON.get(rec["severity"], "❓")
    print("\n" + "─" * 60)
    print(f"  {icon}  [{rec['severity']}]  {rec['filename']}")
    print("─" * 60)
    print(f"  From    : {rec['from']}")
    print(f"  To      : {rec['to']}")
    print(f"  Subject : {rec['subject']}")
    print(f"  Date    : {rec['date']}")
    print(f"  Score   : {rec['risk_score']}")

    auth = rec.get("auth_results", {})
    if auth:
        spf_icon  = "✅" if auth.get("spf")  == "pass" else "❌"
        dkim_icon = "✅" if auth.get("dkim") == "pass" else "❌"
        print(f"  Auth    : SPF {spf_icon} {auth.get('spf','?')}  |  "
              f"DKIM {dkim_icon} {auth.get('dkim','?')}")

    indicators = rec.get("indicators", {})
    active = {k: v for k, v in indicators.items() if isinstance(v, list) and v}
    if active:
        print("\n  Indicators triggered:")
        for key, hits in active.items():
            label = key.replace("_", " ").title()
            print(f"    • {label}")
            for h in hits[:3]:
                print(f"        ↳ {h}")
            if len(hits) > 3:
                print(f"        ↳ … and {len(hits)-3} more")

    if rec.get("suspicious_attachments"):
        print("\n  ⚠️  Suspicious Attachments:")
        for a in rec["suspicious_attachments"]:
            print(f"      • {a}")

    if rec["severity"] == "SAFE":
        print("\nNo phishing indicators detected.")

def print_outgoing_report(records):
    blocked = sum(1 for r in records if r["dlp_blocked"])
    print(f"\n  Scanned {len(records)} outgoing email(s) — "
          f"{blocked} BLOCKED, {len(records)-blocked} cleared.\n")

    for rec in records:
        _print_dlp_block(rec)

def _print_dlp_block(rec):
    status = "🚫 BLOCKED" if rec["dlp_blocked"] else "✅ CLEARED"
    print("\n" + "─" * 60)
    print(f"  {status}  {rec['filename']}")
    print("─" * 60)
    print(f"  From    : {rec['from']}")
    print(f"  To      : {rec['to']}")
    print(f"  Subject : {rec['subject']}")

    if not rec["violations"]:
        print("\n  No sensitive data detected. Safe to send.")
        return

    print("\n  DLP Violations detected:")
    for v in rec["violations"]:
        icon = DLP_ICON.get(v["severity"], "⚠️ ")
        print(f"\n    {icon} [{v['severity']}]  {v['type']}")
        print(f"        {v['detail']}")

    if rec["dlp_blocked"]:
        print("\n  🚫  This email is BLOCKED from sending.")
        print("      Remove or redact all sensitive data before re-sending.")
    else:
        print("\n  ⚠️   This email has warnings. Review before sending.")
