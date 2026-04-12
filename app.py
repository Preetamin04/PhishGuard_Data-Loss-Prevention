import os
import streamlit as st
from collections import Counter
from utils.email_parser import parse_eml_file
from utils.risk_engine   import calculate_risk
from utils.dlp_engine    import scan_outgoing

# PAGE CONFIG 

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
)

# MINIMAL CUSTOM CSS 

st.markdown("""
<style>
/* severity badges */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
}
.badge-CRITICAL { background:#3d0a0f; color:#ff4c6a; border:1px solid #ff4c6a; }
.badge-HIGH     { background:#3d2600; color:#ff9f1c; border:1px solid #ff9f1c; }
.badge-MEDIUM   { background:#3d3200; color:#ffd700; border:1px solid #ffd700; }
.badge-LOW      { background:#003d1a; color:#00e57a; border:1px solid #00e57a; }
.badge-SAFE     { background:#003d1a; color:#00e57a; border:1px solid #00e57a; }

.badge-BLOCKED  { background:#3d0a0f; color:#ff4c6a; border:1px solid #ff4c6a; }
.badge-CLEARED  { background:#003d1a; color:#00e57a; border:1px solid #00e57a; }
</style>
""", unsafe_allow_html=True)

# HELPERS 

SEVERITY_COLOR = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "SAFE":     "✅",
}

DLP_SEVERITY_COLOR = {
    "CRITICAL": "🔴",
    "HIGH":     "🟡",
}


def severity_badge(sev: str) -> str:
    return f'<span class="badge badge-{sev}">{sev}</span>'


def scan_incoming(folder="sample_emails"):
    files = [f for f in os.listdir(folder) if f.endswith(".eml")]
    records = []
    for fname in files:
        parsed = parse_eml_file(os.path.join(folder, fname))
        parsed["filename"] = fname
        score, severity = calculate_risk(
            parsed["indicators"],
            parsed.get("attachment_score", 0),
            parsed.get("auth_results", {}),
        )
        parsed["risk_score"] = score
        parsed["severity"]   = severity
        records.append(parsed)
    records.sort(key=lambda r: r["risk_score"], reverse=True)
    return records


def batch_patterns(records):
    subjects = [r["subject"] for r in records]
    urls     = [u for r in records for u in r["urls"]]
    senders  = [r["from"]    for r in records]
    return {
        "Repeated Subjects": {s: c for s, c in Counter(subjects).items() if c > 1},
        "Reused URLs":        {u: c for u, c in Counter(urls).items()     if c > 1},
        "Common Senders":     {s: c for s, c in Counter(senders).items()  if c > 1},
    }


def scan_outgoing_folder(folder="outgoing_drafts"):
    if not os.path.isdir(folder):
        return []
    files = [f for f in os.listdir(folder) if f.endswith(".eml")]
    results = []
    for fname in files:
        r = scan_outgoing(os.path.join(folder, fname))
        r["filename"] = fname
        results.append(r)
    return results


# SIDEBAR 
with st.sidebar:
    st.markdown("## 🛡️ PhishGuard")
    st.caption("Rule-Based Email Security Analyser")
    st.divider()

    mode = st.radio(
        "Select Scan Mode",
        ["📥 Phishing Detection", "📤 Data Loss Prevention"],
        index=0,
    )
    st.divider()

    run_scan = st.button("▶ Run Scan", use_container_width=True, type="primary")

    st.divider()
    st.caption("**Folders scanned:**")
    st.code("sample_emails/     ← incoming\noutgoing_drafts/   ← outgoing")
    st.caption("Add your own `.eml` files to these folders and re-run the scan.")


# ── MAIN ─────────────────────────────────────────────────────────────────────

st.title("🛡️ PhishGuard — Email Security Analyser")
st.caption("Rule-based phishing detection + data loss prevention · No AI · No internet required")
st.divider()

# TAB 1 — INCOMING PHISHING DETECTION
if mode == "📥 Phishing Detection":

    st.subheader("📥 Incoming Mail — Phishing Detection")

    if run_scan:
        with st.spinner("Scanning sample_emails/ folder..."):
            records  = scan_incoming("sample_emails")
            patterns = batch_patterns(records)

        # ── Stats ────────────────────────────────────────────────────────
        critical = sum(1 for r in records if r["severity"] == "CRITICAL")
        high     = sum(1 for r in records if r["severity"] == "HIGH")
        safe     = sum(1 for r in records if r["severity"] == "SAFE")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔴 Critical",     critical)
        c2.metric("🟠 High Risk",    high)
        c3.metric("✅ Safe",          safe)
        c4.metric("📧 Total Scanned", len(records))

        st.divider()

        # ── Campaign Pattern Analysis ─────────────────────────────────────
        st.subheader("🔍 Campaign Pattern Analysis")
        has_pattern = any(patterns[k] for k in patterns)
        if not has_pattern:
            st.success("✅ No repeated subjects, reused URLs, or common senders detected.")
        else:
            for label, data in patterns.items():
                if data:
                    st.warning(f"⚠️ **{label}**")
                    for item, count in data.items():
                        st.write(f"&nbsp;&nbsp;• `{item[:80]}` — appears **{count}×**")

        st.divider()

        # ── Per-Email Results ─────────────────────────────────────────────
        st.subheader(f"📋 Scan Results — {len(records)} Email(s)")

        for rec in records:
            icon = SEVERITY_COLOR.get(rec["severity"], "❓")
            with st.expander(
                f"{icon}  [{rec['severity']}]  {rec['filename']}  —  Score: {rec['risk_score']}",
                expanded=(rec["severity"] in ("CRITICAL", "HIGH")),
            ):
                # Metadata
                col_a, col_b = st.columns(2)
                with col_a:
                    st.write(f"**From:** {rec['from']}")
                    st.write(f"**To:** {rec['to']}")
                with col_b:
                    st.write(f"**Subject:** {rec['subject']}")
                    st.write(f"**Date:** {rec['date']}")

                # Auth
                auth = rec.get("auth_results", {})
                spf_ok  = auth.get("spf",  "") == "pass"
                dkim_ok = auth.get("dkim", "") == "pass"
                st.write(
                    f"**SPF:** {'✅ pass' if spf_ok  else '❌ ' + auth.get('spf',  'not found')}  &nbsp;|&nbsp;  "
                    f"**DKIM:** {'✅ pass' if dkim_ok else '❌ ' + auth.get('dkim', 'not found')}",
                    unsafe_allow_html=True,
                )

                st.divider()

                if rec["severity"] == "SAFE":
                    st.success("✅ No phishing indicators detected. Email appears legitimate.")
                else:
                    indicators = rec.get("indicators", {})
                    active = {k: v for k, v in indicators.items() if isinstance(v, list) and v}

                    if active:
                        st.write("**Indicators triggered:**")
                        for key, hits in active.items():
                            label = key.replace("_", " ").title()
                            with st.container():
                                st.markdown(f"&nbsp;&nbsp;⚡ **{label}**")
                                for h in hits[:4]:
                                    st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`{h}`")
                                if len(hits) > 4:
                                    st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_… and {len(hits)-4} more_")

                if rec.get("suspicious_attachments"):
                    st.warning("⚠️ Suspicious Attachments:")
                    for a in rec["suspicious_attachments"]:
                        st.write(f"  • `{a}`")

    else:
        st.info("👈 Click **▶ Run Scan** in the sidebar to start scanning emails.")


# TAB 2 — OUTGOING DLP
elif mode == "📤 Data Loss Prevention":

    st.subheader("📤 Outgoing Mail — Data Loss Prevention (DLP)")

    if run_scan:
        with st.spinner("Scanning outgoing_drafts/ folder..."):
            dlp_records = scan_outgoing_folder("outgoing_drafts")

        if not dlp_records:
            st.warning("No .eml files found in `outgoing_drafts/` folder.")
        else:
            blocked = sum(1 for r in dlp_records if r["dlp_blocked"])
            cleared = len(dlp_records) - blocked

            c1, c2, c3 = st.columns(3)
            c1.metric("🚫 Blocked",      blocked)
            c2.metric("✅ Cleared",       cleared)
            c3.metric("📧 Total Scanned", len(dlp_records))

            st.divider()
            st.subheader(f"📋 DLP Scan Results — {len(dlp_records)} Email(s)")

            for rec in dlp_records:
                status_icon = "🚫" if rec["dlp_blocked"] else "✅"
                status_txt  = "BLOCKED" if rec["dlp_blocked"] else "CLEARED"

                with st.expander(
                    f"{status_icon}  [{status_txt}]  {rec['filename']}  —  {len(rec['violations'])} violation(s)",
                    expanded=rec["dlp_blocked"],
                ):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**From:** {rec['from']}")
                        st.write(f"**To:** {rec['to']}")
                    with col_b:
                        st.write(f"**Subject:** {rec['subject']}")

                    st.divider()

                    if not rec["violations"]:
                        st.success("✅ No sensitive data detected. Safe to send.")
                    else:
                        for v in rec["violations"]:
                            icon = "🔴" if v["severity"] == "CRITICAL" else "🟡"
                            if v["severity"] == "CRITICAL":
                                st.error(f"{icon} **[{v['severity']}]  {v['type']}**\n\n{v['detail']}")
                            else:
                                st.warning(f"{icon} **[{v['severity']}]  {v['type']}**\n\n{v['detail']}")

                        if rec["dlp_blocked"]:
                            st.error("🚫 **This email is BLOCKED.** Remove or redact all sensitive data before sending.")
    else:
        st.info("👈 Click **▶ Run Scan** in the sidebar to start scanning outgoing emails.")
