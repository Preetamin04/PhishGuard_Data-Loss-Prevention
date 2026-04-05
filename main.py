'''
PhishGuard - Rule-Based Phishing Detection & Data Loss Prevention

Analyzes INCOMING emails for phishing threats and OUTGOING emails
for sensitive data leakage - using  rule-based logic.

Usage:
    python main.py --mode incoming          # scan sample_emails/
    python main.py --mode outgoing          # scan outgoing_drafts/
    python main.py --mode both              # scan all
    python main.py --email "folder_naem\file.eml" # scan a single file
'''

import os
import sys
import argparse
from collections import Counter

from utils.email_parser  import parse_eml_file
from utils.risk_engine   import calculate_risk, SEVERITY_LABEL
from utils.dlp_engine    import scan_outgoing
from utils.report        import print_banner, print_incoming_report, print_outgoing_report

# Incoming: Phishing Detection
def scan_incoming(directory="sample_emails"):
    files = [f for f in os.listdir(directory) if f.endswith(".eml")]
    if not files:
        print(f"[!] No .eml files found in '{directory}'.")
        return []

    records = []
    for fname in files:
        path = os.path.join(directory, fname)
        parsed = parse_eml_file(path)
        parsed["filename"] = fname
        score, severity = calculate_risk(
            parsed["indicators"],
            parsed.get("attachment_score", 0),
            parsed.get("auth_results", {})
        )
        parsed["risk_score"] = score
        parsed["severity"]   = severity
        records.append(parsed)
    return records

'''Detect cross-email patterns (same subject / URL / sender reuse).'''
def batch_pattern_analysis(records):
    subjects = [r["subject"] for r in records]
    urls     = [u for r in records for u in r["urls"]]
    senders  = [r["from"]    for r in records]

    patterns = {
        "repeated_subjects": {s: c for s, c in Counter(subjects).items() if c > 1},
        "reused_urls":       {u: c for u, c in Counter(urls).items()     if c > 1},
        "common_senders":    {s: c for s, c in Counter(senders).items()  if c > 1},
    }
    return patterns

# CLI entry point
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="PhishGuard – Email Security Analyser")
    parser.add_argument("--mode",  choices=["incoming", "outgoing", "both"], default="both")
    parser.add_argument("--email", help="Scan a single .eml file")
    args = parser.parse_args()

    # Single-file mode
    if args.email:
        if not os.path.isfile(args.email):
            print(f"[ERROR] File not found: {args.email}")
            sys.exit(1)
        parsed = parse_eml_file(args.email)
        parsed["filename"] = os.path.basename(args.email)
        score, severity = calculate_risk(
            parsed["indicators"],
            parsed.get("attachment_score", 0),
            parsed.get("auth_results", {})
        )
        parsed["risk_score"] = score
        parsed["severity"]   = severity
        print_incoming_report([parsed], {})
        return

    # Batch incoming mode 
    if args.mode in ("incoming", "both"):
        print("\n" + "═"*60)
        print("  📥  INCOMING MAIL — PHISHING DETECTION")
        print("═"*60)
        records  = scan_incoming("sample_emails")
        patterns = batch_pattern_analysis(records)
        print_incoming_report(records, patterns)

    # Outgoing / DLP mode 
    if args.mode in ("outgoing", "both"):
        print("\n" + "═"*60)
        print("  📤  OUTGOING MAIL — DATA LOSS PREVENTION (DLP)")
        print("═"*60)
        outgoing_dir = "outgoing_drafts"
        if not os.path.isdir(outgoing_dir):
            print(f"[!] No '{outgoing_dir}/' folder found. Skipping DLP scan.")
            return
        files = [f for f in os.listdir(outgoing_dir) if f.endswith(".eml")]
        if not files:
            print("[!] No outgoing .eml drafts to scan.")
            return
        dlp_records = []
        for fname in files:
            path   = os.path.join(outgoing_dir, fname)
            result = scan_outgoing(path)
            result["filename"] = fname
            dlp_records.append(result)
        print_outgoing_report(dlp_records)

    print("\n" + "═"*60)
    print("PhishGuard scan complete.")
    print("═"*60 + "\n")

if __name__ == "__main__":
    main()
