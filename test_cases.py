"""
test_cases.py: labelled samples for Sangyan.

All messages are synthetic. Phone numbers, UPI handles and look-alike domains are made up.

label:   "scam"   -> should score high
         "benign" -> should score low and trigger no impersonation / SEBI alerts
         "edge"   -> known tricky cases; used to see how the engine behaves, not pass/fail on score
expect:  typosquat  (bool)  any domain flagged as impersonation
         min_flags / max_flags  linguistic flag count
         sebi       substring that must appear in a SEBI alert status (needs DB seeded as noted)
"""

TEST_CASES = [
    # ======================= SCAMS =======================
    {"id": "S01", "label": "scam", "name": "SEBI ID stolen (your preset)",
     "needs_db": "INA200098765 registered to a firm other than 'Pro Traders VIP India'",
     "text": """🚨 VIP Stock Tips Channel! 🚨
Recover old losses today! Guaranteed 50% weekly returns on Options Trading.
Registered under SEBI Reg ID: INA200098765 (Managed by 'Pro Traders VIP India').
To join our secret group, pay the VIP membership fee to UPI ID: insider_tips@okaxis or Call 9876543210.
100% loss-free, guaranteed upper circuit stock tips!""",
     "expect": {"min_flags": 4, "sebi": "IDENTITY FRAUD"}},

    {"id": "S02", "label": "scam", "name": "Fake SEBI ID (not in registry)",
     "needs_db": "INA999999999 must NOT exist in sebi_registry",
     "text": """Get SEBI registered advice from 'Alpha Wealth Advisors', Reg No INA999999999.
Guaranteed 40% monthly returns. Pay Rs 4,999 joining fee to alphawealth@ybl to unlock our premium group.""",
     "expect": {"min_flags": 3, "sebi": "FAKE"}},

    {"id": "S03", "label": "scam", "name": "KYC phishing, leet-speak clone (your example)",
     "text": """Urgent: SEBI KYC verification required for your demat account.
Please log in immediately to verify your details: http://zer0dha-secure-login.net/login
Failure to update will freeze your trading account within 24 hours.""",
     "expect": {"typosquat": True, "min_flags": 5}},

    {"id": "S04", "label": "scam", "name": "Subdomain trick (brand.com.evil.xyz)",
     "text": """Your Zerodha account is locked. Unlock now: https://zerodha.com.account-unlock.xyz/auth
Act now, this is your final warning.""",
     "expect": {"typosquat": True, "min_flags": 2}},

    {"id": "S05", "label": "scam", "name": "Groww KYC expiry",
     "text": "Groww KYC expired! Update within 12 hours or your account will be blocked: http://groww-kyc-update.in/verify",
     "expect": {"typosquat": True, "min_flags": 3}},

    {"id": "S06", "label": "scam", "name": "Bare look-alike domain, no scam words",
     "text": "Dear customer, your Angel One refund is pending. Claim at angelone-support.top",
     "expect": {"typosquat": True}},

    {"id": "S07", "label": "scam", "name": "ICICI Direct PAN update",
     "text": "ICICI Direct: PAN update mandatory. Login at https://icicidirect-login.net immediately or trading will be suspended.",
     "expect": {"typosquat": True, "min_flags": 2}},

    {"id": "S08", "label": "scam", "name": "Regulator-named domain",
     "text": "SEBI notice: verify your demat details now at http://sebi-kyc-verify.in or your account will be frozen.",
     "expect": {"typosquat": True, "min_flags": 3}},

    {"id": "S09", "label": "scam", "name": "Hinglish tips group",
     "text": """Bhai pakka profit! Sure shot calls, 100% guaranteed. Paisa double in 1 month.
Join our Telegram group, joining fee 2999, UPI pe bhejo: tradeking@paytm""",
     "expect": {"min_flags": 4}},

    {"id": "S10", "label": "scam", "name": "Hindi account-closure + KYC",
     "text": "आपका खाता बंद हो जाएगा। तुरंत केवाईसी अपडेट करें। 100% गारंटी के साथ मुनाफा पाएं।",
     "expect": {"min_flags": 2}},

    {"id": "S11", "label": "scam", "name": "OTP + remote access (bank impersonation)",
     "text": "Dear customer, your bank account will be suspended today. To avoid this, share your OTP and install AnyDesk so our executive can help.",
     "expect": {"min_flags": 3}},

    {"id": "S12", "label": "scam", "name": "Income-tax refund phishing",
     "text": "Income Tax Dept: refund of Rs 18,540 approved. Verify your bank details at http://incometax-refund-claim.top within 24 hours.",
     "expect": {"min_flags": 3}},

    {"id": "S13", "label": "scam", "name": "Fake trading app (APK)",
     "text": "Download our official trading app TradePro.apk. 300% returns guaranteed in 7 days. No risk. Limited slots.",
     "expect": {"min_flags": 3}},

    {"id": "S14", "label": "scam", "name": "Cyber-cell / arrest threat",
     "text": "This is Cyber Cell. A case has been filed against your Aadhaar. Arrest warrant issued. Pay the penalty immediately to avoid arrest.",
     "expect": {"min_flags": 3}},

    {"id": "S15", "label": "scam", "name": "Obfuscated text",
     "text": "G u a r a n t e e d  p r o f i t every week! Rec0ver your l0sses with our VIP g r o u p. Zer0 risk.",
     "expect": {"min_flags": 3}},

    {"id": "S16", "label": "scam", "name": "Pre-IPO / insider tips",
     "text": "Pre-IPO allotment guaranteed! Insider tips from operator-driven calls. Zero risk. Pay advance fee to book your slot.",
     "expect": {"min_flags": 3}},

    {"id": "S17", "label": "scam", "name": "Part-time job advance-fee",
     "text": "Earn Rs 5000 daily from home! Part-time job, just like YouTube videos. Pay registration fee Rs 999 to start. Join our WhatsApp group.",
     "expect": {"min_flags": 2}},

    # ======================= BENIGN =======================
    {"id": "B01", "label": "benign", "name": "OTP safety notice",
     "text": "Your OTP is 482913. Do not share this OTP with anyone. Never share it, even with bank staff.",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B02", "label": "benign", "name": "Market news",
     "text": "Nifty closed 0.6% higher today led by banking stocks. Read the weekly outlook at https://example.com/outlook",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B03", "label": "benign", "name": "Genuine broker link (subdomain)",
     "text": "Zerodha: your KYC is verified. Open https://kite.zerodha.com to start trading.",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B04", "label": "benign", "name": "Delivery update",
     "text": "Your order will be delivered within 24 hours. Track it at amazon.in/orders",
     "expect": {"typosquat": False, "max_flags": 1}},

    {"id": "B05", "label": "benign", "name": "SEBI investor awareness",
     "text": "Investor awareness: check an adviser's registration at https://www.sebi.gov.in before investing. Be careful with unsolicited tips.",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B06", "label": "benign", "name": "Friend chat",
     "text": "Bro are we still meeting at 6? I'll book the table at the cafe near the metro.",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B07", "label": "benign", "name": "Bank debit alert",
     "text": "HDFC Bank: Rs 2,500 debited from A/c XX1234 on 03-Oct. If this was not you, call the number on the back of your card. Never share OTP.",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B08", "label": "benign", "name": "Hindi market news",
     "text": "आज बाजार में तेजी रही। निफ्टी 0.6% ऊपर बंद हुआ।",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B09", "label": "benign", "name": "Genuine broker console link",
     "text": "View your holdings at https://console.zerodha.com/portfolio",
     "expect": {"typosquat": False, "max_flags": 0}},

    {"id": "B10", "label": "benign", "name": "News sites",
     "text": "Read more at https://www.moneycontrol.com/news and https://economictimes.indiatimes.com",
     "expect": {"typosquat": False, "max_flags": 0}},

    # ======================= EDGE CASES =======================
    {"id": "E01", "label": "edge", "name": "Educational warning (quotes scam phrases)",
     "note": "Warning text repeats scam wording; may false-positive. Good candidate for the LLM gray-zone step.",
     "text": "SEBI warns: nobody can offer guaranteed returns in the stock market. Avoid tipsters promising 100% safe profits.",
     "expect": {"typosquat": False}},

    {"id": "E02", "label": "edge", "name": "Genuine KYC prompt from broker",
     "note": "Should score low: a single mild KYC flag at most, no impersonation.",
     "text": "Complete your KYC update in the Zerodha app to continue trading. Help: https://zerodha.com/support",
     "expect": {"typosquat": False, "max_flags": 1}},

    {"id": "E03", "label": "edge", "name": "Fan site with brand name",
     "note": "Brand in a non-official domain; the engine will flag it (conservative by design).",
     "text": "I wrote a review of Zerodha vs Groww at https://zerodha-vs-groww-review.blog",
     "expect": {}},

    {"id": "E04", "label": "edge", "name": "Scam with no links, phone only",
     "note": "Only language rules can catch this; combined with DB/phone history in threat_intel.",
     "text": "Sir your demat account has a problem. Call me urgently on 9123456780 to fix it, otherwise it will be blocked.",
     "expect": {"min_flags": 1}},
]


# ---------------------------------------------------------
# Runner
# ---------------------------------------------------------
def _noisy_or(ps):
    out = 1.0
    for p in ps:
        out *= 1 - max(0.0, min(1.0, p))
    return 1 - out


def run_tests(scan_linguistic_red_flags, inspect_urls_and_domains_enhanced,
              verify_sebi_registry_sqlite=None, verbose=True):
    """
    Pass your three engine functions. verify_sebi_registry_sqlite is optional: if given,
    S01/S02 SEBI checks run too (they need the DB seeded as described in 'needs_db').
    """
    rows, failures = [], 0
    for case in TEST_CASES:
        text, exp = case["text"], case["expect"]
        flags = scan_linguistic_red_flags(text)
        domains = inspect_urls_and_domains_enhanced(text)
        sebi = verify_sebi_registry_sqlite(text) if verify_sebi_registry_sqlite else []

        typo = any(d["is_typosquat"] for d in domains)
        sebi_bad = [a for a in sebi if "VERIFIED" not in a["status"]]

        # approximate fused score (same idea as threat_intel.assess, without DB / LLM)
        signals = [f.get("severity", 15) / 100 for f in flags]
        signals += [0.8] if typo else []
        signals += [0.9] if sebi_bad else []
        score = round(_noisy_or(signals) * 100)

        problems = []
        if "typosquat" in exp and typo != exp["typosquat"]:
            problems.append(f"typosquat={typo}, expected {exp['typosquat']}")
        if "min_flags" in exp and len(flags) < exp["min_flags"]:
            problems.append(f"{len(flags)} flags, expected >= {exp['min_flags']}")
        if "max_flags" in exp and len(flags) > exp["max_flags"]:
            problems.append(f"{len(flags)} flags, expected <= {exp['max_flags']}")
        if "sebi" in exp and verify_sebi_registry_sqlite:
            if not any(exp["sebi"] in a["status"] for a in sebi):
                problems.append(f"no SEBI alert containing '{exp['sebi']}'")
        if case["label"] == "scam" and score < 60 and not ("sebi" in exp and not verify_sebi_registry_sqlite):
            problems.append(f"score {score} < 60 for a scam")
        if case["label"] == "benign" and score >= 30:
            problems.append(f"score {score} >= 30 for a benign message")

        failures += bool(problems)
        rows.append((case["id"], case["label"], case["name"], score, len(flags), typo, problems))

    if verbose:
        print(f"{'ID':<4} {'label':<7} {'score':>5} {'flags':>5} {'clone':>5}  result")
        for cid, label, name, score, nflags, typo, problems in rows:
            status = "PASS" if not problems else "FAIL: " + "; ".join(problems)
            print(f"{cid:<4} {label:<7} {score:>5} {nflags:>5} {str(typo):>5}  {name} -> {status}")
        print(f"\n{len(rows) - failures}/{len(rows)} passed")
    return rows


if __name__ == "__main__":
    # Change this import to wherever your engine functions live
    from app import (scan_linguistic_red_flags, inspect_urls_and_domains_enhanced,
                     verify_sebi_registry_sqlite)
    run_tests(scan_linguistic_red_flags, inspect_urls_and_domains_enhanced, verify_sebi_registry_sqlite)
