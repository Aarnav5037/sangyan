import streamlit as st
import re
import pandas as pd
from urllib.parse import urlparse
import datetime
import sqlite3
import datetime
import math
import re
from urllib.parse import urlparse
from fuzzywuzzy import fuzz
import whois
import db_engine
# At the top of app.py
from db_engine import (
    DB_FILE,
    init_db,
    record_threat_event,
    check_blacklist
)

# 1. Fuzzy Matching Library
try:
    from rapidfuzz import fuzz
except ImportError:
    st.error("Please install rapidfuzz: `pip install rapidfuzz`")

# 2. WHOIS Library (with graceful fallback for offline/demo reliability)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

init_db()

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="Sangyan - Advanced Scam Detection Engine",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------
# Embedded SEBI/NSDL Public Registry (Mock Database)
# ---------------------------------------------------------
SEBI_REGISTRY_DB = {
    "INA000001234": {"firm_name": "Zerodha Broking Limited", "category": "Investment Adviser", "status": "Active"},
    "INZ000031633": {"firm_name": "Zerodha Broking Ltd", "category": "Stock Broker", "status": "Active"},
    "INA000012345": {"firm_name": "Nextbillion Technology Private Limited (Groww)", "category": "Investment Adviser", "status": "Active"},
    "INA200098765": {"firm_name": "ABC Wealth Management Pvt Ltd", "category": "Research Analyst", "status": "Active"},
    "INH000000001": {"firm_name": "Motilal Oswal Financial Services Ltd", "category": "Research Analyst", "status": "Active"},
    "INP000006789": {"firm_name": "Angel One Limited", "category": "Portfolio Manager", "status": "Active"}
}

LEGITIMATE_DOMAINS = [
    "zerodha.com", "groww.in", "angelone.in", "upstox.com", 
    "icicidirect.com", "sebi.gov.in", "scores.sebi.gov.in", "nsdl.co.in"
]

import os
import io
import streamlit as st
from google import genai
from google.genai import types
from gtts import gTTS

# Language Code Mapping for gTTS

SUPPORTED_LANGUAGES={
    "Hindi (हिन्दी)": {"code": "hi", "name": "Hindi"},
    "Tamil (தமிழ்)": {"code": "ta", "name": "Tamil"},
    "Telugu (తెలుగు)": {"code": "te", "name": "Telugu"},
    "Marathi (मराठी)": {"code": "mr", "name": "Marathi"},
    "Bengali (বাংলা)": {"code": "bn", "name": "Bengali"},
    "Gujarati (ગુજરાતી)": {"code": "gu", "name": "Gujarati"},
    "Kannada (ಕನ್ನಡ)": {"code": "kn", "name": "Kannada"},
    "Malayalam (മലയാളം)": {"code": "ml", "name": "Malayalam"},
    "English": {"code": "en", "name": "English"}
}

import streamlit as st
import datetime
from google import genai
from google.genai import types
import os
import io
import streamlit as st
from google import genai
from google.genai import types
from gtts import gTTS

MODEL_ID = "gemini-3.6-flash"  # Using Gemini 2.5 Flash engine

LANGUAGE_MAP = {
    "Hindi (हिन्दी)": {"code": "hi", "name": "Hindi"},
    "Tamil (தமிழ்)": {"code": "ta", "name": "Tamil"},
    "Telugu (తెలుగు)": {"code": "te", "name": "Telugu"},
    "Marathi (मराठी)": {"code": "mr", "name": "Marathi"},
    "Bengali (বাংলা)": {"code": "bn", "name": "Bengali"},
    "Gujarati (ગુજરાતી)": {"code": "gu", "name": "Gujarati"},
    "Kannada (ಕನ್ನಡ)": {"code": "kn", "name": "Kannada"},
    "Malayalam (മലയാളം)": {"code": "ml", "name": "Malayalam"},
    "English": {"code": "en", "name": "English"}
}

import os
import io
import time
import tempfile
import streamlit as st
from google import genai
from google.genai import types


MODEL_ID = "gemini-3.5-flash-lite"
GEMINI_API_KEY=st.secrets.get("GEMINI_API_KEY", None)
gemini_api_key=st.secrets.get("GEMINI_API_KEY", None)
api_key=st.secrets.get("GEMINI_API_KEY", None)
def analyze_multimodal_with_gemini(
    uploaded_file,
    text_prompt: str,
    context_json: dict,
    target_language_label: str,
    api_key: str = None
):
    effective_api_key = api_key or os.environ.get("GEMINI_API_KEY") or st.secrets.get("GEMINI_API_KEY", None)
    
    if not effective_api_key:
        return "⚠️ Please enter a valid input", None, ""

    lang_info = LANGUAGE_MAP.get(target_language_label, LANGUAGE_MAP["Hindi (हिन्दी)"])
    target_lang_name = lang_info["name"]
    target_lang_code = lang_info["code"]

    client = genai.Client(api_key=effective_api_key)
    file_ref = None
    tmp_path = None

    try:
        contents = []

        # Handle uploaded video/audio/image via disk buffer & Files API
        if uploaded_file is not None:
            suffix = os.path.splitext(uploaded_file.name)[1]
            
            # Write to disk buffer to prevent RAM memory spikes and Axios disconnects
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
                tmp_file.write(uploaded_file.getbuffer())
                tmp_path = tmp_file.name

            # For Videos and Large Audio, use client.files.upload
            if uploaded_file.type.startswith("video/") or uploaded_file.type.startswith("audio/"):
                st.info("📤 Uploading media...")
                file_ref = client.files.upload(file=tmp_path)

                # Wait for video processing if necessary
                if uploaded_file.type.startswith("video/"):
                    with st.spinner("⏳ Processing video frames..."):
                        while file_ref.state.name == "PROCESSING":
                            time.sleep(2)
                            file_ref = client.files.get(name=file_ref.name)
                        
                        if file_ref.state.name == "FAILED":
                            raise ValueError("Failed to process video file.")
                
                contents.append(file_ref)
            
            # For small images, pass bytes directly
            else:
                with open(tmp_path, "rb") as f:
                    img_bytes = f.read()
                media_part = types.Part.from_bytes(data=img_bytes, mime_type=uploaded_file.type)
                contents.append(media_part)

        system_instruction = """
        You are an AI Investor Protection & Fraud Resilience Assistant built for SEBI/NSDL Sangyan Hackathon.
        MANDATORY GUARDRAILS:
        1. NEVER provide stock tips, buy/sell/hold recommendations, price predictions, or financial advice.
        2. Focus strictly on safety, fraud detection, regulatory awareness, and user protection.
        3. Explain risks in simple, empathetic, plain language suitable for a first-time investor.
        """

        prompt_text = f"""
        User Query / Description:
        \"\"\"{text_prompt if text_prompt else 'Analyze the attached media file for potential financial scam/fraud indicators.'}\"\"\"

        Pre-computed Algorithmic Verification Context:
        {context_json}

        Tasks:
        1. Analyze the attached media file (image/audio/video) for regulatory violations (guaranteed returns, fake SEBI IDs, cloned logos).
        2. Provide a detailed risk report in English (Sections: Verdict & Risk Level, Evidence Found in Media, SEBI Rule Explained, Safe Next Steps).
        3. At the VERY END of your response, add a section tagged exactly as `===REGIONAL_SCRIPT===` containing a 2-sentence safety warning summary written ENTIRELY in {target_lang_name} native script.
        """
        contents.append(prompt_text)

        # Call Gemini 2.5 Flash
        response = client.models.generate_content(
            model=MODEL_ID,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2,
            )
        )

        full_output = response.text

        # Parse output and regional script
        if "===REGIONAL_SCRIPT===" in full_output:
            english_report, regional_script = full_output.split("===REGIONAL_SCRIPT===")
            regional_script = regional_script.strip()
        else:
            english_report = full_output
            regional_script = "सावधान! यह संदेश उच्च जोखिम वाला हो सकता है। किसी भी अनजान व्यक्ति को पैसे ट्रांसफर न करें।"

        # Synthesize audio
        audio_fp = io.BytesIO()
        tts = gTTS(text=regional_script, lang=target_lang_code, slow=False)
        tts.write_to_fp(audio_fp)
        audio_fp.seek(0)

        return english_report.strip(), audio_fp, regional_script

    except Exception as e:
        return f"❌ **Error processing media**: {str(e)}", None, ""

    finally:
        # Cleanup temporary file from local disk
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        # Cleanup uploaded file from Gemini storage
        if file_ref:
            try:
                client.files.delete(name=file_ref.name)
            except Exception:
                pass    
# ---------------------------------------------------------
# Formal Complaint Template Generator
# ---------------------------------------------------------
def generate_raw_complaint_dossier(
    complainant_name: str,
    contact_number: str,
    email_id: str,
    incident_date: str,
    entity_name: str,
    financial_loss: float,
    extracted_entities: dict,
    risk_score: int
) -> str:
    """Generates a structured formal grievance draft for SCORES / Cyber Crime Cell."""
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    evidence_summary = []
    for category, values in extracted_entities.items():
        if values:
            if isinstance(values, list):
                if isinstance(values[0], dict):
                    vals_str = ", ".join([v.get("id", str(v)) for v in values])
                else:
                    vals_str = ", ".join(values)
            else:
                vals_str = str(values)
            evidence_summary.append(f"  - {category}: {vals_str}")

    evidence_text = "\n".join(evidence_summary) if evidence_summary else "  - None automatically extracted."

    complaint_text = f"""
================================================================================
FORMAL COMPLAINT & INCIDENT DOSSIER FOR INVESTOR PROTECTION / CYBER CRIME CELL
Generated via Sangyan Investor Resilience System | Date: {timestamp}
================================================================================

1. COMPLAINANT DETAILS
-----------------------
Full Name: {complainant_name if complainant_name else '[Not Provided]'}
Contact Phone: {contact_number if contact_number else '[Not Provided]'}
Email Address: {email_id if email_id else '[Not Provided]'}

2. INCIDENT OVERVIEW
--------------------
Date of Incident / Initial Contact: {incident_date}
Name of Impersonated Entity / Channel: {entity_name if entity_name else 'Unidentified / Telegram / WhatsApp Channel'}
Reported Financial Loss (INR): Rs. {financial_loss:,.2f}
Automated Risk Score Assessed: {risk_score}/100

3. DETECTED EVIDENCE & DIGITAL ARTIFACTS
----------------------------------------
{evidence_text}

4. COMPLAINT STATEMENT & FACTUAL NARRATIVE
------------------------------------------
To,
The Grievance Redressal Officer / Cyber Crime Cell / SEBI SCORES Portal,

I am filing this formal complaint regarding an alleged fraudulent financial scheme / unauthorized stock advisory channel operating under the name '{entity_name if entity_name else "Unknown Operator"}'.

On or around {incident_date}, I was targeted by/encountered promotional messages promising returns and/or posing as SEBI-registered intermediaries. Upon technical verification, the following regulatory violations and deceptive vectors were identified:

1. Deceptive / Unsolicited Tip Signals: Messages offered guaranteed/unrealistic returns, violating SEBI (Investment Advisers) Regulations.
2. Unverified / Misused Registration Details: Digital handles failed official cross-verification or referenced unverified payment endpoints.
3. Financial Demands: Solicitations were directed to non-registered UPI/Bank accounts.

I request the portal/authorities to:
a) Block and investigate the associated phone numbers, UPI handles, and Telegram/WhatsApp channels listed in the evidence.
b) Issue an administrative hold/investigation on the receiving financial accounts.
c) Direct the entity/intermediary to initiate appropriate restitution if funds were transferred.

DECLARATION:
I hereby declare that the information provided above is true and accurate to the best of my knowledge based on recorded digital communications.

Signature / Name: {complainant_name if complainant_name else '[Complainant Name]'}
Date: {datetime.date.today().strftime('%d-%m-%Y')}
================================================================================
"""
    return complaint_text.strip()


# ---------------------------------------------------------
# Gemini API Formal Draft Enhancer
# ---------------------------------------------------------
def enhance_complaint_with_gemini(raw_complaint: str, api_key: str = None) -> str:
    """Uses Gemini 1.5 Flash to polish the complaint into legal, objective language."""
    if not api_key:
        return raw_complaint

    try:
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
        Refine the following draft complaint so it is written in clear, objective, and formal legal language suitable for submission to SEBI SCORES 2.0 or the National Cyber Crime Reporting Portal (1930).
        
        Rules:
        1. Maintain all factual data (names, dates, loss amount, UPI IDs, phone numbers, SEBI numbers).
        2. Remove any emotional language and replace it with precise, factual legal phrasing.
        3. Keep the output clean, professional, and directly usable.

        Draft to Refine:
        {raw_complaint}
        """

        response = client.models.generate_content(
            model=MODEL_ID,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1)
        )
        return response.text
    except Exception:
        return raw_complaint  # Fallback to raw draft on error


# ---------------------------------------------------------
# Grievance & Complaint Assistant (redesigned)
# ---------------------------------------------------------
# Drop-in replacement. Same function name and signature.
# Still uses your generate_raw_complaint_dossier() and enhance_complaint_with_gemini().
# Imports needed:
import datetime
import hashlib
import html
import re

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PHONE_RE = re.compile(r"^(?:\+?91)?[6-9]\d{9}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

# Placeholders double as the demo values used by "Fill example" and Tab-to-fill
PH = {
    "gv_name": "e.g., Rajesh Kumar",
    "gv_phone": "e.g., +91 9876543210",
    "gv_email": "e.g., rajesh@example.com",
    "gv_entity": "e.g., VIP Trading Signals Telegram",
}
EXAMPLE = {k: re.sub(r"^e\.g\.,?\s*", "", v) for k, v in PH.items()}

PORTALS = {
    "cyber": {
        "title": "National Cyber Crime Portal and 1930 helpline",
        "url": "https://cybercrime.gov.in",
        "blurb": "Main route for online financial fraud, UPI scams and phishing links.",
        "steps": [
            "If money was sent, call **1930** right away. Faster reporting improves the chance of holding the funds.",
            "File the detailed report at cybercrime.gov.in under financial fraud.",
            "Attach this dossier and your evidence, and note the acknowledgement number.",
        ],
    },
    "scores": {
        "title": "SEBI SCORES 2.0",
        "url": "https://scores.sebi.gov.in",
        "blurb": "Best when a SEBI-registered intermediary is involved or a SEBI registration number is being misused. "
                 "Check on the portal whether your case category is accepted.",
        "steps": [
            "Create an account or log in on scores.sebi.gov.in.",
            "Choose the entity and category that best match your case.",
            "Paste the complaint text, attach evidence, and save the registration number.",
        ],
    },
    "nsdl": {
        "title": "NSDL investor grievance",
        "url": "https://nsdl.co.in",
        "blurb": "For demat-account or depository-related disputes.",
        "steps": [
            "Use this only if your demat account or a depository participant is involved.",
            "Find the investor grievance section on nsdl.co.in and submit the complaint with evidence.",
        ],
    },
}

CHECKLIST = [
    "Screenshots of the message, profile or channel",
    "Transaction IDs / UTR numbers and bank statement (if money was sent)",
    "Phone numbers, UPI IDs and links involved",
    "This complaint draft",
]


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def _inject_css():
    st.markdown(
        """
        <style>
        .gv-paper { border:1px solid rgba(128,128,128,.35); border-radius:10px;
                    background:rgba(128,128,128,.06); padding:1.1rem 1.3rem; }
        .gv-meta  { display:flex; justify-content:space-between; flex-wrap:wrap; gap:.5rem;
                    font-size:.8rem; opacity:.75; border-bottom:1px solid rgba(128,128,128,.3);
                    padding-bottom:.5rem; margin-bottom:.8rem; }
        .gv-body  { white-space:pre-wrap; font-family:Georgia,'Times New Roman',serif;
                    line-height:1.65; font-size:.95rem; max-height:430px; overflow:auto; }
        .gv-pill  { display:inline-block; padding:.15rem .6rem; border-radius:999px;
                    font-size:.78rem; font-weight:600; color:#fff; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _risk_band(score: int):
    if score >= 60:
        return "High risk", "#d64545"
    if score >= 30:
        return "Medium risk", "#e08a1e"
    return "Low risk", "#2e9e5b"


def _detected_entity(payload: dict) -> str:
    """Best guess of the scammer / impersonated entity from the engine output."""
    for a in payload.get("sebi_audit", []):
        claimed = a.get("claimed_entity", "")
        if "VERIFIED" not in a.get("status", "") and claimed and not claimed.startswith("Unspecified"):
            return claimed
    for d in payload.get("domain_audit", []):
        if d.get("is_typosquat"):
            brand = d.get("impersonated_brand")
            return f"Fake {brand.title()} website ({d['domain']})" if brand else f"Fake website ({d['domain']})"
    return ""


def _recommend(payload: dict, loss: float) -> list:
    """Order the filing routes by relevance to this case."""
    order = []
    if loss > 0:
        order.append("cyber")                      # time-sensitive when money has left the account
    if any("VERIFIED" not in a.get("status", "") for a in payload.get("sebi_audit", [])):
        order.append("scores")
    if "cyber" not in order:
        order.append("cyber")
    if "scores" not in order:
        order.append("scores")
    order.append("nsdl")
    return order


def _evidence(payload: dict):
    sebi = pd.DataFrame([{
        "SEBI ID": a.get("id"), "Status": a.get("status"), "Official name": a.get("official_name"),
        "Claimed entity": a.get("claimed_entity"), "Details": a.get("reason"),
    } for a in payload.get("sebi_audit", [])])
    dom = pd.DataFrame([{
        "Domain": d.get("domain"), "Impersonation": "Yes" if d.get("is_typosquat") else "No",
        "Age (days)": d.get("domain_age_days"), "Flags": "; ".join(d.get("flags", [])),
    } for d in payload.get("domain_audit", [])])
    ling = pd.DataFrame([{
        "Phrase": f.get("trigger_phrase"), "Why it is a red flag": f.get("description"),
    } for f in payload.get("linguistic_flags", [])])
    return sebi, dom, ling


def _indicator_list(payload: dict) -> list:
    items = [a["id"] for a in payload.get("sebi_audit", []) if a.get("id")]
    items += [d["domain"] for d in payload.get("domain_audit", []) if d.get("domain")]
    return items


def _build_html(ref: str, meta: dict, text: str) -> str:
    """Standalone, print-ready HTML (open it and press Ctrl+P to save as PDF)."""
    esc = html.escape
    sebi, dom, ling = _evidence(meta["payload"])

    def table(title, df):
        if df.empty:
            return ""
        head = "".join(f"<th>{esc(str(c))}</th>" for c in df.columns)
        rows = "".join("<tr>" + "".join(f"<td>{esc(str(v))}</td>" for v in r) + "</tr>"
                       for r in df.itertuples(index=False))
        return f"<h3>{esc(title)}</h3><table><tr>{head}</tr>{rows}</table>"

    label, color = _risk_band(meta["risk"])
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Complaint {esc(ref)}</title>
<style>
 body{{font-family:Georgia,'Times New Roman',serif;max-width:800px;margin:2rem auto;padding:0 1rem;color:#111;line-height:1.6}}
 h1{{font-size:1.4rem;margin-bottom:.2rem}} .meta{{color:#555;font-size:.9rem;border-bottom:1px solid #ccc;padding-bottom:.6rem;margin-bottom:1rem}}
 .pill{{background:{color};color:#fff;border-radius:999px;padding:.1rem .6rem;font-size:.8rem}}
 pre{{white-space:pre-wrap;font-family:inherit}} table{{border-collapse:collapse;width:100%;font-size:.85rem;margin:.5rem 0 1.2rem}}
 th,td{{border:1px solid #bbb;padding:.35rem .5rem;text-align:left;vertical-align:top}} th{{background:#f0f0f0}}
 .note{{font-size:.8rem;color:#666;margin-top:2rem}}
 @media print{{body{{margin:0}}}}
</style></head><body>
<h1>Complaint Dossier</h1>
<div class="meta">Reference: <b>{esc(ref)}</b> &nbsp;|&nbsp; Date: {esc(meta['date'])} &nbsp;|&nbsp;
Automated risk assessment: <span class="pill">{esc(label)} ({meta['risk']}/100)</span></div>
<pre>{esc(text)}</pre>
<h2>Annexure: Evidence summary</h2>
{table("SEBI registration checks", sebi)}{table("Domains", dom)}{table("Language red flags", ling)}
<p class="note">Generated by Sangyan. This draft is an aid, not legal advice. Please verify every detail before filing.</p>
</body></html>"""


def _fill_example():
    st.session_state.update(EXAMPLE)


def _use_detected(value: str):
    st.session_state["gv_entity"] = value


def _sync_edit():
    st.session_state["gv_dossier"] = st.session_state["gv_edit"]


def _tab_to_fill(enabled: bool):
    """
    Demo helper: pressing Tab in an EMPTY field inside the form fills it with its placeholder
    example (a second Tab moves on). Streamlit has no native feature for this, so a small script
    attaches one listener to the parent page. It only works inside st.form fields.
    """
    components.html(
        f"""
        <script>
        const doc = window.parent.document;
        doc.__sangyanTabFill = {str(enabled).lower()};
        if (!doc.__sangyanTabInstalled) {{
          doc.__sangyanTabInstalled = true;
          doc.addEventListener('keydown', function (e) {{
            if (!doc.__sangyanTabFill || e.key !== 'Tab' || e.shiftKey) return;
            const el = doc.activeElement;
            if (!el || !['INPUT', 'TEXTAREA'].includes(el.tagName)) return;
            if (!el.closest('[data-testid="stForm"]')) return;
            if (el.value !== '' || !el.placeholder) return;
            const text = el.placeholder.replace(/^e\\.g\\.,?\\s*/i, '');
            const proto = el.tagName === 'INPUT' ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
            Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, text);
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            e.preventDefault();
          }}, true);
        }}
        </script>
        """,
        height=0,
    )


# ---------------------------------------------------------
# Main tab
# ---------------------------------------------------------
def render_grievance_redressal_tab(extracted_payload: dict, risk_score: int, api_key: str = None):
    """Renders the Grievance & Complaint Dossier Generation UI."""
    ss = st.session_state
    _inject_css()

    st.subheader("📝 Grievance and complaint assistant")
    st.caption("Generate a ready-to-file complaint dossier for SCORES 2.0, NSDL or the 1930 Cyber Crime portal.")

    detected = _detected_entity(extracted_payload)
    col_form, col_out = st.columns([5, 6], gap="large")

    # ---------------- Step 1: form ----------------
    with col_form:
        st.markdown("##### 👤 Step 1: Your details")

        demo = st.toggle(
            "Demo mode: press Tab in an empty box to fill its example",
            key="gv_demo",
            help="For demos only. The examples are fake details; don't file a real complaint with them.",
        )
        b1, b2 = st.columns(2)
        b1.button("Fill example details", on_click=_fill_example, use_container_width=True)
        if detected:
            b2.button("Use detected entity", on_click=_use_detected, args=(detected,),
                      help=detected, use_container_width=True)

        with st.form("gv_form"):
            name = st.text_input("Full name *", key="gv_name", placeholder=PH["gv_name"])
            c1, c2 = st.columns(2)
            phone = c1.text_input("Mobile number *", key="gv_phone", placeholder=PH["gv_phone"])
            email = c2.text_input("Email", key="gv_email", placeholder=PH["gv_email"])
            c3, c4 = st.columns(2)
            incident_date = c3.date_input("Date of incident", value=datetime.date.today(),
                                          max_value=datetime.date.today(), key="gv_date")
            loss = c4.number_input("Amount lost (₹)", min_value=0.0, step=500.0, key="gv_loss")
            entity = st.text_input("Scam group / impersonated entity", key="gv_entity",
                                   placeholder=PH["gv_entity"])
            submitted = st.form_submit_button("📄 Generate complaint", type="primary",
                                              use_container_width=True)

        _tab_to_fill(demo)

        if submitted:
            errors = []
            if len(name.strip()) < 3:
                errors.append("Enter your full name.")
            if not PHONE_RE.match(re.sub(r"[\s-]", "", phone)):
                errors.append("Enter a valid 10-digit Indian mobile number.")
            if email.strip() and not EMAIL_RE.match(email.strip()):
                errors.append("That email address doesn't look right.")

            if errors:
                for e in errors:
                    st.error(e)
            else:
                raw_draft = generate_raw_complaint_dossier(
                    complainant_name=name,
                    contact_number=phone,
                    email_id=email,
                    incident_date=incident_date.strftime("%d-%m-%Y"),
                    entity_name=entity,
                    financial_loss=loss,
                    extracted_entities=extracted_payload,
                    risk_score=risk_score,
                )
                final_draft = raw_draft
                if api_key:
                    with st.spinner("Polishing the draft..."):
                        final_draft = enhance_complaint_with_gemini(raw_draft, api_key)

                today = datetime.date.today()
                tag = hashlib.sha1(f"{name}{phone}{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:4].upper()
                ss["gv_dossier"] = final_draft
                ss["gv_edit"] = final_draft
                ss["gv_ref"] = f"SGY-{today:%Y%m%d}-{tag}"
                ss["gv_meta"] = {
                    "date": today.strftime("%d-%m-%Y"), "loss": loss, "risk": risk_score,
                    "entity": entity, "payload": extracted_payload,
                }

    # ---------------- Step 2: output ----------------
    with col_out:
        st.markdown("##### 📄 Step 2: Your complaint dossier")

        if "gv_dossier" not in ss:
            st.info("👈 Fill in your details and click **Generate complaint**. "
                    "Your draft, evidence summary and filing guide will appear here.")
            return

        meta, ref = ss["gv_meta"], ss["gv_ref"]
        text = ss["gv_dossier"]
        label, color = _risk_band(meta["risk"])
        sebi_df, dom_df, ling_df = _evidence(meta["payload"])

        m1, m2, m3 = st.columns(3)
        m1.metric("Risk score", f"{meta['risk']}/100")
        m2.metric("Amount lost", f"₹{meta['loss']:,.0f}")
        m3.metric("Evidence items", len(sebi_df) + len(dom_df) + len(ling_df))

        t_view, t_evid, t_edit, t_file = st.tabs(["📄 Complaint", "🔎 Evidence", "✏️ Edit", "🚀 How to file"])

        with t_view:
            st.markdown(
                f"""<div class="gv-paper">
                      <div class="gv-meta"><span>Ref: <b>{html.escape(ref)}</b></span>
                      <span>{html.escape(meta['date'])}</span>
                      <span class="gv-pill" style="background:{color}">{label}</span></div>
                      <div class="gv-body">{html.escape(text)}</div></div>""",
                unsafe_allow_html=True,
            )
            st.caption("This draft is an aid, not legal advice. Check every detail before filing.")

        with t_evid:
            st.caption("Attached as an annexure in the printable version.")
            for title, df in (("SEBI registration checks", sebi_df), ("Domains", dom_df), ("Language red flags", ling_df)):
                if not df.empty:
                    st.markdown(f"**{title}**")
                    st.dataframe(df, use_container_width=True, hide_index=True)
            if sebi_df.empty and dom_df.empty and ling_df.empty:
                st.info("No automated evidence was captured for this complaint.")

        with t_edit:
            ss.setdefault("gv_edit", text)
            st.text_area("Edit the draft. Downloads use this version.", key="gv_edit",
                         height=340, on_change=_sync_edit)

        with t_file:
            st.markdown("**Before you file, gather:**")
            for i, item in enumerate(CHECKLIST):
                st.checkbox(item, key=f"gv_chk_{i}")
            indicators = _indicator_list(meta["payload"])
            if indicators:
                st.markdown("**Indicators to paste into the forms:**")
                st.code("\n".join(indicators), language=None)

            st.markdown("---")
            for rank, key in enumerate(_recommend(meta["payload"], meta["loss"])):
                p = PORTALS[key]
                with st.container(border=True):
                    st.markdown(f"**{p['title']}**" + ("  ·  ✅ Recommended first" if rank == 0 else ""))
                    st.caption(p["blurb"])
                    st.markdown("\n".join(f"{n}. {s}" for n, s in enumerate(p["steps"], 1)))
                    st.link_button(f"Open {p['url'].replace('https://', '')}", p["url"])

        d1, d2 = st.columns(2)
        d1.download_button("📥 Download (.txt)", data=ss["gv_dossier"], file_name=f"{ref}.txt",
                           mime="text/plain", use_container_width=True)
        d2.download_button("🖨️ Printable (.html)", data=_build_html(ref, meta, ss["gv_dossier"]),
                           file_name=f"{ref}.html", mime="text/html", use_container_width=True,
                           help="Open the file and press Ctrl+P to save it as a PDF")
        
def analyze_and_synthesize_regional(user_text: str, context_json: dict, target_language_label: str, api_key: str = None):
    """
    1. Calls Gemini to generate an English detailed report AND a short regional summary script.
    2. Uses gTTS to convert the regional summary script into audio bytes.
    """
    effective_api_key = api_key or os.environ.get("GEMINI_API_KEY") or st.secrets.get("GEMINI_API_KEY", None)
    
    if not effective_api_key:
        return "⚠️ Please provide a valid Gemini API Key.", None, ""

    lang_info = LANGUAGE_MAP.get(target_language_label, LANGUAGE_MAP["Hindi (हिन्दी)"])
    target_lang_name = lang_info["name"]
    target_lang_code = lang_info["code"]

    try:
        client = genai.Client(api_key=effective_api_key)

        system_instruction = """
        You are an AI Investor Protection & Fraud Resilience Assistant for the SEBI/NSDL Sangyan Hackathon.
        NEVER give stock recommendations, price targets, or financial advice.
        Focus strictly on safety, fraud detection, and regulatory awareness in plain language.
        """

        prompt = f"""
        User Message to Analyze:
        \"\"\"{user_text}\"\"\"

        Algorithmic Verification Data:
        {context_json}

        Task:
        1. Provide a detailed risk assessment report in English (with sections: Verdict, Fraud Indicators, SEBI Rule Explained, Safe Next Steps).
        2. At the VERY END of your response, add a section exactly tagged as `===REGIONAL_SCRIPT===` containing a 2-sentence safety warning summary written ENTIRELY in {target_lang_name} native script (e.g., if Hindi, use Devanagari script; if Tamil, use Tamil script).
        """

        response = client.models.generate_content(
            model=MODEL_ID,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2,
            ),
        )

        full_output = response.text

        # Parse the English report and the Regional Script
        if "===REGIONAL_SCRIPT===" in full_output:
            english_report, regional_script = full_output.split("===REGIONAL_SCRIPT===")
            regional_script = regional_script.strip()
        else:
            english_report = full_output
            regional_script = "सावधान! यह संदेश उच्च जोखिम वाला हो सकता है। किसी भी अनजान व्यक्ति को पैसे ट्रांसफर न करें।"

        # Synthesize Speech from the Regional Script
        audio_fp = io.BytesIO()
        tts = gTTS(text=regional_script, lang=target_lang_code, slow=False)
        tts.write_to_fp(audio_fp)
        audio_fp.seek(0)

        return english_report.strip(), audio_fp, regional_script

    except Exception as e:
        return f"❌ Error: {str(e)}", None, ""
    
def generate_regional_summary(risk_score: int, sebi_alerts: list, lang_code: str) -> str:
    """Generates a concise vernacular summary text tailored for audio playback."""
    
    # 1. Base Hindi Template
    if lang_code == "hi":
        if risk_score > 50:
            text = f"सावधान! यह संदेश उच्च जोखिम वाला है। इसका जोखिम स्कोर {risk_score} प्रतिशत है। "
            if sebi_alerts:
                text += "इसमें फर्जी या अनधिकृत सेबी पंजीकरण संख्या का उपयोग किया गया है। "
            text += "किसी भी अज्ञात व्यक्ति को पैसे ट्रांसफर न करें और बिना जांच के शेयर बाजार के टिप्स पर भरोसा न करें।"
        else:
            text = f"चेतावनी का स्तर कम है। इसका जोखिम स्कोर {risk_score} प्रतिशत है। फिर भी, अपनी वित्तीय सुरक्षा का ध्यान रखें।"
            
    # 2. Base Tamil Template
    elif lang_code == "ta":
        if risk_score > 50:
            text = f"எச்சரிக்கை! இந்த செய்தி அதிக ஆபத்து கொண்டது. ஆபத்து மதிப்பெண் {risk_score} சதவீதம். "
            text += "தெரியாத நபர்களுக்கு பணம் அனுப்ப வேண்டாம்."
        else:
            text = f"ஆபத்து குறைவு. மதிப்பெண் {risk_score} சதவீதம்."
            
    # 3. Default English Fallback for other regional selections
    else:
        if risk_score > 50:
            text = f"Warning! This message is classified as High Risk with a score of {risk_score} out of 100. "
            if sebi_alerts:
                text += "Suspicious or mismatched SEBI registration details detected. "
            text += "Do not transfer money or act on guaranteed stock tip claims."
        else:
            text = f"Low risk detected with a score of {risk_score} out of 100. Always verify financial advice before investing."
            
    return text


def render_regional_audio_player(risk_score: int, sebi_alerts: list):
    """Renders the UI layout and audio stream in Streamlit."""
    st.subheader("🔊 Vernacular Audio Alert (Bharat-First Accessibility)")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        selected_lang_label = st.selectbox(
            "Select Audio Language:",
            list(SUPPORTED_LANGUAGES.keys()),
            index=0 # Default to Hindi
        )
        lang_code = SUPPORTED_LANGUAGES[selected_lang_label]
        
    # Generate text script based on language
    audio_text = generate_regional_summary(risk_score, sebi_alerts, lang_code)
    
    with col2:
        st.caption("Script Preview:")
        st.info(f'"{audio_text}"')
        
    if st.button("▶️ Generate & Play Audio Alert"):
        with st.spinner("Synthesizing regional voice output..."):
            try:
                # Synthesize TTS in memory using BytesIO (No disk write latency)
                audio_bytes = io.BytesIO()
                tts = gTTS(text=audio_text, lang=lang_code, slow=False)
                tts.write_to_fp(audio_bytes)
                audio_bytes.seek(0)
                
                # Render Streamlit Audio Player
                st.audio(audio_bytes, format="audio/mp3")
                st.success(f"Audio generated successfully in {selected_lang_label}!")
            except Exception as e:
                st.error(f"Failed to generate audio: {e}")
                
# ---------------------------------------------------------
# Module 1: SQLite-Backed SEBI Registry Verification
# ---------------------------------------------------------
import re
import sqlite3
from fuzzywuzzy import fuzz

ILLEGAL_PROMISES = [
    "guaranteed", "50%", "100%", "loss-free", "upper circuit", 
    "secret group", "vip", "daily return", "fixed profit", "recover loss"
]

def extract_claimed_entity(text: str) -> str:
    """
    Dynamically extracts quoted entity names or channel prefixes 
    from arbitrary user text (e.g. 'Managed by XYZ', 'Group: ABC').
    """
    # 1. Extract explicitly quoted names (e.g., 'Pro Traders VIP India' or "Alpha Signals")
    quoted = re.findall(r"['\"]([^'\"]+)['\"]", text)
    if quoted:
        return quoted[0].strip()
    
    # 2. Extract names following keywords like "Managed by", "Channel", "Group", "Admin"
    prefix_match = re.search(
        r"(?:managed by|channel|group|traders|advisory|team|admin|by)\s+([A-Za-z0-9\s]{3,30})", 
        text, 
        re.IGNORECASE
    )
    if prefix_match:
        return prefix_match.group(1).strip()
        
    return "Unspecified Sender / Unknown Group"


def verify_sebi_registry_sqlite(text: str) -> list:
    init_db()
    text_lower = text.lower()
    
    # 1. Flexible regex pattern for SEBI registration IDs
    sebi_pattern = r"\b(?:INA|INH|INZ|INM|INR|INP|IN-DB)[/\- ]?[0-9]{7,10}\b"
    raw_matches = re.findall(sebi_pattern, text, flags=re.IGNORECASE)
    found_ids = list(set([re.sub(r"[/\- ]", "", m).upper() for m in raw_matches]))

    # 2. Dynamically parse claimed entity name from input text
    claimed_entity = extract_claimed_entity(text)

    alerts = []
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for sebi_id_upper in found_ids:
        cursor.execute(
            "SELECT firm_name, category, validity_status FROM sebi_registry WHERE sebi_id = ?",
            (sebi_id_upper,)
        )
        record = cursor.fetchone()

        if record:
            official_name, category, status = record
            
            # Compute token similarity against official entity in DB
            token_score = fuzz.token_set_ratio(official_name.lower(), text_lower)
            
            # Dynamically pull matching illegal terms from the text
            found_illegal_terms = [kw for kw in ILLEGAL_PROMISES if kw in text_lower]

            if token_score < 40:
                # Case A: SEBI ID belongs to Official Firm A, but Text claims Entity B (or no match)
                if claimed_entity != "Unspecified Sender / Unknown Group":
                    reason_msg = (
                        f"SEBI Registration ID '{sebi_id_upper}' is officially registered to '{official_name}', "
                        f"but is being claimed by '{claimed_entity}'. Stolen or misused credentials detected."
                    )
                else:
                    reason_msg = (
                        f"SEBI Registration ID '{sebi_id_upper}' belongs to official entity '{official_name}', "
                        f"but this entity name is absent from the communication text."
                    )
                
                record_threat_event(
                    indicator=sebi_id_upper,
                    indicator_type="SEBI_MISUSE",
                    threat_score=90,
                    reason=reason_msg
                )

                alerts.append({
                    "id": sebi_id_upper,
                    "official_name": official_name,
                    "claimed_entity": claimed_entity,
                    "status": "🚨 IDENTITY FRAUD / STOLEN SEBI ID",
                    "reason": reason_msg,
                    "action": "Flagged & Added to Threat DB"
                })

            elif found_illegal_terms:
                # Case B: Entity matches, but communication contains regulatory violations
                terms_formatted = ", ".join([f"'{t}'" for t in found_illegal_terms])
                reason_msg = (
                    f"Message claims association with valid SEBI entity '{official_name}' ({sebi_id_upper}), "
                    f"but violates SEBI regulations by including prohibited claims: {terms_formatted}."
                )

                record_threat_event(
                    indicator=sebi_id_upper,
                    indicator_type="SEBI_MISUSE",
                    threat_score=85,
                    reason=reason_msg
                )

                alerts.append({
                    "id": sebi_id_upper,
                    "official_name": official_name,
                    "claimed_entity": claimed_entity,
                    "status": "🚨 REGULATORY VIOLATION ALERT",
                    "reason": reason_msg,
                    "action": "Flagged & Added to Threat DB"
                })

            else:
                alerts.append({
                    "id": sebi_id_upper,
                    "official_name": official_name,
                    "claimed_entity": official_name,
                    "status": "✅ VERIFIED REGISTRATION",
                    "reason": f"Registration number verified for official entity '{official_name}' ({category}).",
                    "action": "Verified"
                })
        else:
            # Case C: SEBI ID does not exist in registry database
            reason_msg = f"Registration ID '{sebi_id_upper}' was not found in official SEBI/NSDL registries."
            
            record_threat_event(
                indicator=sebi_id_upper,
                indicator_type="SEBI_MISUSE",
                threat_score=95,
                reason=reason_msg
            )

            alerts.append({
                "id": sebi_id_upper,
                "official_name": "Unregistered / Unknown Entity",
                "claimed_entity": claimed_entity,
                "status": "⚠️ FAKE SEBI ID",
                "reason": reason_msg,
                "action": "Flagged & Added to Threat DB"
            })

    conn.close()
    return alerts

# ---------------------------------------------------------
# Helper: Calculate Shannon Entropy (Detects Random Subdomains)
# ---------------------------------------------------------
def calculate_entropy(string: str) -> float:
    """Higher entropy (> 4.0) indicates randomly generated domain names or subdomains."""
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return - sum([p * math.log(p) / math.log(2) for p in prob])


# ---------------------------------------------------------
# Domain inspection patch: brand-impersonation detection
# ---------------------------------------------------------
# Drop-in replacement for Module 2. Same function name, same return keys.
# Added (optional) keys per domain: "impersonated_brand", "threat_score" is unchanged.
# Needs the same imports you already have: re, math, datetime, urlparse, fuzz, whois
# plus your existing: init_db, check_blacklist, record_threat_event, LEGITIMATE_DOMAINS,
# calculate_entropy.

# Extra allow-listed domains (kept separate so your LEGITIMATE_DOMAINS stays untouched)
EXTRA_LEGIT_DOMAINS = ["kite.zerodha.com", "nseindia.com", "bseindia.com", "upstox.com",
                       "kotaksecurities.com", "cdslindia.com"]

# Brands we protect, derived from your list + a few extras
EXTRA_BRANDS = ["upstox", "kotak", "cdsl", "fyers", "sharekhan", "paytm", "phonepe"]
GENERIC_LABELS = {"scores", "www", "kite", "console"}

PHISHING_WORDS = {"secure", "login", "signin", "verify", "verification", "kyc", "update",
                  "account", "support", "official", "alert", "otp", "auth", "portal",
                  "customer", "care", "refund", "reward"}

MULTI_PART_TLDS = {"co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "com.au", "co.uk"}

# Look-alike characters: digits and symbols often swapped for letters
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                       "@": "a", "$": "s"})


def _protected_brands() -> set:
    brands = {d.split(".")[0] for d in LEGITIMATE_DOMAINS} - GENERIC_LABELS
    return brands | set(EXTRA_BRANDS)


def _is_legit(domain: str) -> bool:
    """True for allow-listed domains and their genuine subdomains, and for gov.in sites."""
    if domain.endswith(".gov.in") or domain.endswith(".nic.in"):
        return True
    return any(domain == d or domain.endswith("." + d)
               for d in list(LEGITIMATE_DOMAINS) + EXTRA_LEGIT_DOMAINS)


def _label_tokens(domain: str) -> list:
    """Split a domain into word tokens, dropping the TLD (handles .co.in etc.)."""
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        parts = parts[:-2]
    else:
        parts = parts[:-1]
    tokens = []
    for p in parts:
        tokens.extend(t for t in re.split(r"[-_]", p) if t)
    return tokens


def _variants(token: str) -> set:
    """Normalised spellings of a token (undo digit/symbol substitutions)."""
    base = token.lower().translate(_LEET)
    base = base.replace("rn", "m").replace("vv", "w")
    # '1' is ambiguous: could be 'l' or 'i'
    return {base.replace("1", "l"), base.replace("1", "i")}


def detect_brand_impersonation(domain: str) -> dict:
    """
    Detects domains that embed or mimic a protected brand, e.g.
    'zer0dha-secure-login.net', 'zerodha.com.verify-now.xyz', 'groww-kyc.in'.
    Returns {"brand", "tokens_hit", "used_substitution", "phishing_words"} or {}.
    """
    if _is_legit(domain):
        return {}

    tokens = _label_tokens(domain)
    brands = _protected_brands()

    for token in tokens:
        for variant in _variants(token):
            for brand in brands:
                n = len(brand)
                if n <= 4:
                    hit = variant == brand                               # short brands: exact token only
                elif n == 5:
                    hit = brand in variant                               # avoids 'grow' vs 'groww'
                else:
                    hit = brand in variant or fuzz.ratio(variant, brand) >= 80   # typos like 'zerodah'
                if hit:
                    return {
                        "brand": brand,
                        "tokens_hit": token,
                        "used_substitution": variant != token.lower(),
                        "phishing_words": sorted({t.lower() for t in tokens} & PHISHING_WORDS),
                    }
    return {}


# ---------------------------------------------------------
# Module 2: Enhanced Domain Inspection & Persistent Threat Engine
# ---------------------------------------------------------
# (LEGITIMATE_DOMAINS is your existing list; keep it defined above this function.)


def inspect_urls_and_domains_enhanced(text: str) -> list:
    init_db()
    url_pattern = r"https?://[^\s/$.?#].[^\s]*|\b[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,6}\b"
    extracted_urls = re.findall(url_pattern, text)

    domain_reports = []

    for raw_url in set(extracted_urls):
        if "@" in raw_url:  # Filter out UPI handles
            continue

        parsed_url = urlparse(raw_url if raw_url.startswith("http") else f"http://{raw_url}")
        domain = parsed_url.netloc or parsed_url.path
        domain = domain.split(":")[0].lower().replace("www.", "")

        if not domain or "." not in domain:
            continue

        flags = []
        threat_score = 0
        impersonated_brand = None

        # Step 1: Local growing blacklist (unchanged)
        blacklist_check = check_blacklist(domain)
        if blacklist_check["is_blacklisted"]:
            flags.append(
                f"🚨 KNOWN THREAT DB MATCH: Previously flagged {blacklist_check['hit_count']} time(s). "
                f"Reason: {blacklist_check['reason']}"
            )
            threat_score += 50

        # Step 2a: Whole-string clone detection (unchanged)
        is_typosquat = False
        for legit in ([] if _is_legit(domain) else LEGITIMATE_DOMAINS):   # genuine domains are never "clones"
            similarity = fuzz.ratio(domain, legit)
            if 70 <= similarity < 100:
                is_typosquat = True
                impersonated_brand = legit.split(".")[0]
                flags.append(f"Cloned Domain Warning: '{domain}' is {similarity}% visually similar to legitimate portal '{legit}'.")
                threat_score += 40

        # Step 2b (NEW): Brand embedded or mimicked inside a longer domain
        if not is_typosquat:
            imp = detect_brand_impersonation(domain)
            if imp:
                is_typosquat = True            # keeps the existing UI/score logic working
                impersonated_brand = imp["brand"]
                flags.append(
                    f"Brand Impersonation: '{domain}' imitates '{imp['brand']}' "
                    f"(token '{imp['tokens_hit']}') but is not an official domain."
                )
                threat_score += 40
                if imp["used_substitution"]:
                    flags.append("Look-alike characters used (e.g. 0 for o) to disguise the brand name.")
                    threat_score += 10
                if imp["phishing_words"]:
                    flags.append("Credential-phishing wording in domain: " + ", ".join(imp["phishing_words"]) + ".")
                    threat_score += 15

        # Step 3: Entropy (unchanged)
        domain_entropy = calculate_entropy(domain)
        if domain_entropy > 3.8 and not is_typosquat:
            flags.append(f"Suspicious URL Structure: High randomness entropy score ({domain_entropy:.2f}).")
            threat_score += 20

        # Step 4: WHOIS age (timezone-safe; skipped for allow-listed domains)
        domain_age_days = None
        if not _is_legit(domain):
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if isinstance(creation_date, datetime.datetime):
                        if creation_date.tzinfo is not None:      # naive/aware mix raised TypeError before
                            creation_date = creation_date.replace(tzinfo=None)
                        domain_age_days = (datetime.datetime.now() - creation_date).days
                        if domain_age_days < 60:
                            flags.append(f"High-Risk Age Multiplier: Domain registered recently ({domain_age_days} days ago).")
                            threat_score += 30
            except Exception:
                pass  # WHOIS timeouts / unregistered domains

        # Step 5: Persist high-risk domains (unchanged)
        if threat_score >= 40:
            primary_reason = flags[0] if flags else "High risk composite score detected."
            record_threat_event(
                indicator=domain,
                indicator_type="DOMAIN",
                threat_score=threat_score,
                reason=primary_reason
            )

        domain_reports.append({
            "domain": domain,
            "url": raw_url,
            "is_typosquat": is_typosquat,
            "domain_age_days": domain_age_days if domain_age_days is not None else "N/A",
            "threat_score": threat_score,
            "flags": flags if flags else ["Safe / Standard Domain"],
            "impersonated_brand": impersonated_brand,     # new, optional key
        })

    return domain_reports
# ---------------------------------------------------------
# Module 3: Linguistic Heuristic Red-Flag Engine (v2)
# ---------------------------------------------------------
# Drop-in replacement. Same function name, same return type: a list of dicts that still
# contains "trigger_phrase" and "description". Two optional keys are added:
#   "category" and "severity" (points, roughly 8-35).
# Imports needed: re, unicodedata
import re
import unicodedata

I = re.IGNORECASE

# (category, severity, pattern, description, negatable)
# negatable=True -> skipped when preceded by "never / do not / beware ..." (safety advice).
_RULE_DEFS = [
    # ---------- Investment-tip scams (your original rules, plus variants) ----------
    ("investment", 25, r"100\s*%\s*(?:guaranteed|guarantee|safe|loss[\s-]?free|risk[\s-]?free|assured|sure)",
     "Guaranteed zero-loss promise (Violates SEBI guidelines)", False),
    ("investment", 25, r"\bguaranteed\s+(?:\d+\s*%\s*)?(?:(?:daily|weekly|monthly)\s*)?(?:profits?|returns?|income|gains?)\b"
     r"|\b(?:profits?|returns?|income|gains?)\s+(?:are\s+|is\s+)?(?:guaranteed|assured)\b",
     "Guaranteed profit/return promise (Violates SEBI guidelines)", False),
    ("investment", 25, r"\b\d+%\s*(?:daily|weekly|monthly)\s*returns?\b",
     "Unrealistic periodic return promises", False),
    ("investment", 15, r"\b(?:[3-9]\d|\d{3,})\s*%\s*(?:profit|returns?|gains?)\b",
     "Unusually high return percentage", False),
    ("investment", 35, r"\b(?:guaranteed|sure|confirmed|fixed)\s+upper\s+circuit\b",
     "Market manipulation / Upper circuit pump promise", False),
    ("investment", 25, r"\bVIP\s+membership\s+fee\b",
     "Unauthorized paid group / subscription fee request", False),
    ("investment", 15, r"\b(?:vip|secret|premium)\s+(?:group|channel|tips?|plan|access|membership)\b",
     "Exclusive 'VIP / secret' tips group pitch", False),
    ("investment", 25, r"\brecover(?:y\s+of)?\s+(?:your\s+)?(?:old\s+|past\s+|all\s+)?loss(?:es)?\b",
     "Loss recovery scam hook targeted at vulnerable traders", False),
    ("investment", 20, r"\bsure[\s-]?shot\b",
     "Deceptive certainty claim in market tips", False),
    ("investment", 25, r"\bdouble\s+(?:your\s+)?(?:money|investment|capital)\b|\bmoney\s+double\b",
     "Ponzi scheme return messaging", False),
    ("investment", 20, r"\b(?:insider|operator)[\s-]?(?:tips?|info|calls?|driven)\b",
     "Insider / operator tip claim (illegal trading inducement)", False),
    ("investment", 15, r"\b(?:zero|no)\s+(?:risk|loss)\b",
     "Risk-free claim (all market investments carry risk)", False),
    ("investment", 12, r"\bjoin\s+(?:our|my|the)\s+(?:whatsapp|telegram)\s+(?:group|channel)\b",
     "Pushes victims into an unregulated WhatsApp/Telegram group", False),

    # ---------- Phishing / account-takeover ----------
    ("phishing", 15, r"\bkyc\b[\w\s]{0,25}?\b(?:verification|verify|update|updation|expired|expiry|pending|suspended|incomplete|required)\b"
                     r"|\b(?:verify|update|complete|renew)\s+(?:your\s+)?kyc\b",
     "KYC update/verification demand (common phishing pretext)", False),
    ("phishing", 30, r"\b(?:freeze|frozen|block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed)|terminat(?:e|ed)|lock(?:ed)?)\s+(?:your\s+)?(?:\w+\s+){0,2}account\b"
                     r"|\baccount\b[\w\s,]{0,30}?\b(?:will\s+be|has\s+been|is\s+being)\s+(?:frozen|blocked|suspended|closed|deactivated|terminated|locked|restricted)\b"
                     r"|\baccount\b[\w\s,]{0,30}?\b(?:is|got|has\s+got)\s+(?:frozen|blocked|suspended|locked|deactivated|restricted)\b"
                     r"|\b(?:trading|demat|services?|sim|card|wallet|upi|number)\s+(?:will|shall)\s+be\s+(?:frozen|blocked|suspended|closed|deactivated|terminated|locked|disconnected)\b",
     "Account freeze / block threat to force quick action", False),
    ("phishing", 20, r"\b(?:log\s*in|login|sign\s*in|click|tap)\s+(?:immediately|now|urgently|here|below|the\s+link|this\s+link)\b",
     "Pressure to log in / click a link immediately", False),
    ("phishing", 20, r"\b(?:verify|confirm|update|validate)\s+(?:your\s+)?(?:details|identity|account|credentials|pan|aadhaar|aadhar|bank\s+details|password|demat)\b",
     "Request to verify personal or account details", False),
    ("phishing", 35, r"\b(?:share|send|tell|provide|enter|give)\s+(?:me\s+|us\s+)?(?:your\s+|the\s+|this\s+|that\s+|any\s+|ur\s+)?(?:otp|pin|password|cvv|mpin|upi\s*pin|card\s+number)\b",
     "Asks for OTP / PIN / password", True),
    ("phishing", 25, r"\b(?:anydesk|teamviewer|quick\s*support|rustdesk|airdroid)\b",
     "Remote-access app mentioned (used to take over devices)", True),
    ("phishing", 30, r"\b\w+\.apk\b|\b(?:install|download)\b[^.\n]{0,30}\bapk\b",
     "Sideloaded APK file (common malware delivery)", False),

    # ---------- Urgency, threats, pressure ----------
    ("urgency", 12, r"\b(?:urgent(?:ly)?|immediate(?:ly)?|asap|last\s+chance|final\s+(?:notice|warning|reminder)|act\s+now|right\s+now|today\s+only|hurry)\b",
     "Urgency pressure language", False),
    ("urgency", 12, r"\bwithin\s+(?:the\s+next\s+)?\d{1,2}\s*(?:hours?|hrs?|minutes?|mins?)\b",
     "Artificial deadline", False),
    ("urgency", 12, r"\b(?:limited\s+(?:time|seats|slots|period)|offer\s+(?:expires|ends)|only\s+\d+\s+(?:seats|slots|spots)\s+left|expires?\s+(?:today|tonight|soon))\b",
     "Scarcity / expiry pressure", False),
    ("threat", 20, r"\b(?:failure|failing)\s+to\s+(?:comply|update|verify|respond|pay)\b|\b(?:legal\s+action|penalty|case\s+will\s+be\s+filed|arrest\s+warrant)\b",
     "Threat of penalty or consequence for non-compliance", False),

    # ---------- Payment requests ----------
    ("payment", 20, r"\b(?:pay|transfer|send|deposit)\b[^.\n]{0,50}?\b(?:upi|paytm|phonepe|gpay|google\s*pay|bank\s+account|account\s+number)\b",
     "Asks for payment to a personal UPI / bank account", False),
    ("payment", 20, r"\b(?:registration|processing|membership|joining|activation|unlock|clearance|release|advance|refundable|security)\s+(?:fee|charges?|deposit)\b",
     "Advance-fee request", False),

    # ---------- Authority impersonation ----------
    ("authority", 25, r"\bsebi\b[^\n]{0,25}\b(?:kyc|verification|account|demat)\b",
     "Regulator name used to demand account verification (regulators don't ask for logins by message)", False),
    ("authority", 25, r"\b(?:income\s+tax|rbi|cbi|cyber\s*cell|police|customs|trai|narcotics)\b[^\n]{0,40}\b(?:notice|case|warrant|arrest|seiz\w+|penalty|refund)\b",
     "Government / agency impersonation with a threat or refund hook", False),

    ("phishing", 15, r"\b(?:pan|aadhaar|aadhar|kyc|bank\s+details?)\s+(?:update|updation|verification|linking|re-?verification)\s+(?:is\s+)?(?:mandatory|required|compulsory|pending|due)\b"
                     r"|\b(?:update|link)\s+(?:your\s+)?(?:pan|aadhaar|aadhar)\b",
     "PAN / Aadhaar update demand (common phishing pretext)", False),
    ("threat", 20, r"\b(?:otherwise|or\s+else)\b[^.\n]{0,30}\b(?:blocked|suspended|frozen|closed|deactivated|locked)\b",
     "'Otherwise it will be blocked' style threat", False),
    ("payment", 15, r"\bpay\s+(?:the\s+|a\s+|your\s+)?(?:penalty|fine|bail|settlement|clearance\s+charges?)\b",
     "Demands payment of a penalty / fine", False),
    ("job", 20, r"\bearn\s+(?:up\s+to\s+)?(?:rs\.?|₹|inr)?\s*\d[\d,]*\s*(?:/-)?\s*(?:per\s+day|daily|a\s+day|every\s+day|per\s+hour|hourly)\b",
     "Unrealistic daily-income promise", False),
    ("job", 15, r"\b(?:like|subscribe|rate|review)\b[^.\n]{0,25}\b(?:videos?|youtube|products?|hotels?|restaurants?)\b[^.\n]{0,40}\b(?:earn|income|paid|pay)\b|\bpart[\s-]?time\s+job\b",
     "Task-for-pay job scam pattern", False),
    ("regional", 12, r"तुरंत|फौरन|जल्द\s*से\s*जल्द",
     "Urgent action demand (Hindi)", False),

    # ---------- Hinglish / Hindi ----------
    ("regional", 25, r"\b(?:pakka|pakki)\s*(?:profit|munafa|fayda|return)\b",
     "Guaranteed-profit claim (Hinglish)", False),
    ("regional", 25, r"\b(?:paisa|paise|money)\s+double\b|\bdouble\s+(?:paisa|paise)\b",
     "Money-doubling claim (Hinglish)", False),
    ("regional", 30, r"\b(?:account|khata|demat)\s+(?:band|block|freeze)\s+ho\s+(?:jayega|jaega|jayegi|sakta)\b",
     "Account-closure threat (Hinglish)", False),
    ("regional", 12, r"\b(?:turant|abhi|jaldi)\s+(?:link|click|verify|update|pay|payment)\b",
     "Urgent action demand (Hinglish)", False),
    ("regional", 25, r"100\s*%\s*(?:मुनाफा|गारंटी|रिटर्न)|गारंटीड",
     "Guaranteed-profit claim (Hindi)", False),
    ("regional", 30, r"(?:खाता|अकाउंट)\s*(?:बंद|ब्लॉक|फ्रीज)",
     "Account-closure threat (Hindi)", False),
    ("regional", 20, r"केवाईसी\s*(?:अपडेट|वेरिफिकेशन|सत्यापन)",
     "KYC update demand (Hindi)", False),
    ("regional", 35, r"(?:अपना|अपनी)\s+(?:ओटीपी|पिन|पासवर्ड)",
     "Asks for OTP / PIN / password (Hindi)", True),
]

_RULES = [(c, s, re.compile(p, I), d, n) for c, s, p, d, n in _RULE_DEFS]

_NEGATION = re.compile(r"\b(?:never|do\s+not|don'?t|dont|not\s+to|should\s+not|shouldn'?t|must\s+not|avoid|stop)\s+(?:ever\s+|please\s+|you\s+)?$", I)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LINK = re.compile(r"https?://|\bwww\.|\b[\w-]+\.(?:com|net|in|xyz|top|click|app|site|online|live|info|link|co)\b", I)


def _normalize_text(text: str) -> str:
    """Undo common obfuscation so rules still match: unicode tricks, spaced-out letters, leetspeak."""
    t = unicodedata.normalize("NFKC", text)
    t = re.sub(r"[\u200b-\u200f\u2060\ufeff\u00ad]", "", t)                      # zero-width chars
    t = re.sub(r"\b(?:[A-Za-z]\s){3,}[A-Za-z]\b", lambda m: re.sub(r"\s", "", m.group(0)), t)  # g u a r a n t e e d
    t = re.sub(r"(?<=[A-Za-z])[013457@$]{1,2}(?=[A-Za-z])",                      # gu@ranteed, guarant33d
               lambda m: m.group(0).translate(_LEET), t)
    t = re.sub(r"(?<=[A-Za-z])0(?![A-Za-z0-9])", "o", t)                           # Zer0 -> Zero
    return t


def scan_linguistic_red_flags(text: str) -> list:
    text = (text or "")[:20000]
    norm = _normalize_text(text)

    candidates = []
    for category, severity, pattern, description, negatable in _RULES:
        for m in pattern.finditer(norm):
            if negatable and _NEGATION.search(norm[max(0, m.start() - 25):m.start()]):
                continue                      # e.g. "Never share your OTP" is safety advice
            candidates.append((severity, category, m.start(), m.end(), m.group(0).strip(), description))
            break                             # one flag per rule, like the original

    # Same words must not be counted twice: within a category, keep the highest-severity
    # flag and drop any other flag whose matched text overlaps it.
    detected, categories, taken = [], set(), []
    for severity, category, start, end, phrase, description in sorted(candidates, key=lambda c: -c[0]):
        if any(cat == category and start < e and s_ < end for cat, s_, e in taken):
            categories.add(category)
            continue
        taken.append((category, start, end))
        categories.add(category)
        detected.append({
            "trigger_phrase": phrase,
            "description": description,
            "category": category,
            "severity": severity,
        })

    # Combined-signal flags: several weak signals together are a strong tell
    has_link = bool(_LINK.search(text))
    if "phishing" in categories and ({"threat", "urgency"} & categories) and has_link:
        detected.append({
            "trigger_phrase": "account demand + urgency/threat + link",
            "description": "Classic phishing pattern: urgent account threat pushing you to a link",
            "category": "combined", "severity": 35,
        })
    if "authority" in categories and ({"phishing", "threat"} & categories):
        detected.append({
            "trigger_phrase": "authority name + account/threat demand",
            "description": "Impersonation pattern: official-sounding sender demanding action",
            "category": "combined", "severity": 25,
        })
    if "investment" in categories and "payment" in categories:
        detected.append({
            "trigger_phrase": "return promise + payment request",
            "description": "Paid-tips scam pattern: guaranteed gains in exchange for a fee",
            "category": "combined", "severity": 30,
        })

    if sum(1 for f in detected if f["category"] == "investment") >= 3:
        detected.append({
            "trigger_phrase": "multiple investment-scam markers",
            "description": "Several independent tip-scam claims in one message",
            "category": "combined", "severity": 20,
        })
    if "job" in categories and "payment" in categories:
        detected.append({
            "trigger_phrase": "income promise + upfront fee",
            "description": "Job / task scam pattern: easy earnings in exchange for a registration fee",
            "category": "combined", "severity": 30,
        })

    detected.sort(key=lambda f: f["severity"], reverse=True)
    return detected


def linguistic_risk_points(flags: list, cap: int = 60) -> int:
    """
    Optional: severity-weighted points instead of len(flags) * 15.
    Falls back to 15 per flag for old-style flags that have no severity.
    """
    return min(sum(f.get("severity", 15) for f in flags), cap)

def get_blacklist_summary():
    """Returns top threats recorded by the app over time."""
    conn = sqlite3.connect(db_engine.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT indicator, indicator_type, threat_score, hit_count, last_detected, reason 
    FROM threat_blacklist 
    ORDER BY hit_count DESC, threat_score DESC 
    LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "indicator": r[0],
            "type": r[1],
            "score": r[2],
            "hits": r[3],
            "last_seen": r[4],
            "reason": r[5]
        }
        for r in rows
    ]

# ---------------------------------------------------------
# UI Layout & Live Presentation Logic
# ---------------------------------------------------------
st.title("🛡️ Sangyan: Multi-Vector Fraud & Scam Interceptor")
st.caption("Track A: Digital Fraud & Scam Resilience | Integrated Engine: SEBI Fuzzy Registry + Domain Inspection + Linguistic Risk")

st.markdown("---")

# Presets for Quick Demo Testing
st.sidebar.header("🎯 Live Demo Presets")
from test_cases import TEST_CASES

def load_sample(text):
    st.session_state["demo_input"] = text      # same key your text_area already reads

sample_labels = [f"{c['id']} - {c['name']}" for c in TEST_CASES]
chosen = st.sidebar.selectbox("Load test sample", sample_labels)
st.sidebar.button(
    "Load sample",
    on_click=load_sample,
    args=(TEST_CASES[sample_labels.index(chosen)]["text"],),
    use_container_width=True,
)
        
# Main Input Area
user_text = st.text_area(
    "Enter text, forward message, or website link to analyze:",
    value=st.session_state.get("demo_input", ""),
    height=160,
    placeholder="Paste suspicious text or URLs here..."
)

if user_text:
    # Run Engine Modules
    sebi_analysis = verify_sebi_registry_sqlite(user_text)
    domain_analysis = inspect_urls_and_domains_enhanced(user_text)
    linguistic_flags = scan_linguistic_red_flags(user_text)
    
    # Calculate Overall Risk Score
    risk_score = 0
    if any("IDENTITY FRAUD" in a["status"] for a in sebi_analysis):
        risk_score += 45
    if any(d["is_typosquat"] for d in domain_analysis):
        risk_score += 40
    risk_score += len(linguistic_flags) * 15
    risk_score = min(risk_score, 100)
    
    # Summary Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Composite Risk Score", f"{risk_score}/100")
    m2.metric("SEBI Impersonation Alerts", sum(1 for a in sebi_analysis if "IDENTITY FRAUD" in a["status"]))
    m3.metric("Cloned / Typosquatted Domains", sum(1 for d in domain_analysis if d["is_typosquat"]))
    m4.metric("Linguistic Red Flags", len(linguistic_flags))
    
    st.markdown("---")

    payload = {
        "composite_risk_score": risk_score,
        "sebi_audit": sebi_analysis,
        "domain_audit": domain_analysis,
        "linguistic_flags": linguistic_flags
    }
    
    # Detailed Analysis Tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🤖 Detailed Risk Report", 
        "📜 SEBI Registry Audit", 
        "🌐 Domain Inspection", 
        "🚩 Red Flags", 
        "📝 Grievance Assistant",  # <-- New Grievance Redressal Tab
        "📊 Raw Payload",
        "Multimodal Analysis"
    ])

    # Inside your main `if user_text:` block in app.py:

    with tab1: # Gemini AI Synthesis Tab
        st.subheader("🤖 Risk Report & Vernacular Voice Output")
        
        col_lang, col_btn = st.columns([2, 1])
        
        with col_lang:
            selected_language = st.selectbox(
                "Select Audio Language for Voice Output:",
                list(LANGUAGE_MAP.keys()),
                index=0 # Default to Hindi
            )
            
        with col_btn:
            st.write(" ") # Spacing offset
            generate_btn = st.button("✨ Generate Report & Voice", type="primary", use_container_width=True)

        if generate_btn:
            with st.spinner(f"Analyzing and synthesizing {selected_language} audio..."):
                report_text, audio_bytes, script_used = analyze_and_synthesize_regional(
                    user_text=user_text,
                    context_json=payload,
                    target_language_label=selected_language,
                    api_key=gemini_api_key
                )
                
                # 1. Display Detailed English Analysis
                st.markdown(report_text)
                
                st.markdown("---")
                
                # 2. Render Regional Audio Player
                if audio_bytes:
                    st.subheader(f"🔊 Vernacular Voice Warning ({selected_language})")
                    st.info(f"🗣️ **Spoken Script:** {script_used}")
                    st.audio(audio_bytes, format="audio/mp3", autoplay=True)    
    with tab2:
        st.subheader("Fuzzy SEBI / NSDL Registration Matcher")
        if sebi_analysis:
            for item in sebi_analysis:
                if "IDENTITY FRAUD" in item["status"]:
                    st.error(f"**{item['status']}** — Reg ID: `{item['id']}`\n\n{item['reason']}")
                elif "VERIFIED" in item["status"]:
                    st.success(f"**{item['status']}** — Reg ID: `{item['id']}`\n\n{item['reason']}")
                else:
                    st.warning(f"**{item['status']}** — Reg ID: `{item['id']}`\n\n{item['reason']}")
        else:
            st.info("No SEBI registration numbers found in input.")

    with tab3:
        st.subheader("Domain Typosquatting & WHOIS Age Audit")
        if domain_analysis:
            for d in domain_analysis:
                if d["is_typosquat"]:
                    st.error(f"🚨 **SUSPICIOUS DOMAIN:** `{d['domain']}`")
                else:
                    st.info(f"🌐 **Analyzed Domain:** `{d['domain']}`")
                st.write(f"- **Domain Age:** {d['domain_age_days']} days")
                st.write(f"- **Security Flags:** {', '.join(d['flags'])}")
                st.markdown("---")
        else:
            st.info("No external links or URLs detected.")

    with tab4:
        st.subheader("Regulatory & Deceptive Language Heuristics")
        if linguistic_flags:
            df_flags = pd.DataFrame(linguistic_flags)
            st.dataframe(df_flags, use_container_width=True, hide_index=True)
        else:
            st.success("No high-risk regulatory violation terms detected.")

    with tab5:
        render_grievance_redressal_tab(
            extracted_payload=payload, 
            risk_score=risk_score, 
            api_key=GEMINI_API_KEY
        )

    with tab6:
        st.subheader("Structured Payload for Downstream LLM Synthesis")
        st.json({
            "composite_risk_score": risk_score,
            "sebi_audit": sebi_analysis,
            "domain_audit": domain_analysis,
            "linguistic_flags": linguistic_flags
        })

    # In app.py - Multimodal Analysis Tab

    with tab7: # Gemini AI Multimodal Tab
        st.subheader("🎥 Multimodal Fraud Scanner (Image / Voice Note / Video)")
        st.caption("Upload a WhatsApp screenshot, regional voice note, or tip video to analyze")

        # File uploader supporting Images, Audio, and Video
        uploaded_media = st.file_uploader(
            "Upload Media Evidence:",
            type=["png", "jpg", "jpeg", "webp", "mp3", "wav", "m4a", "ogg", "mp4", "mov", "avi"],
            help="Upload a chat screenshot, audio voice note, or video clip."
        )

        # Preview section based on file type
        if uploaded_media:
            col_prev, col_info = st.columns([1, 2])
            with col_prev:
                if uploaded_media.type.startswith("image/"):
                    st.image(uploaded_media, caption="Uploaded Screenshot", use_container_width=True)
                elif uploaded_media.type.startswith("audio/"):
                    st.audio(uploaded_media, format=uploaded_media.type)
                elif uploaded_media.type.startswith("video/"):
                    st.video(uploaded_media)
            with col_info:
                st.success(f"📎 File Loaded: **{uploaded_media.name}** ({uploaded_media.type})")

        # Optional additional text prompt
        additional_text = st.text_input(
            "Additional Text Context (Optional):",
            placeholder="e.g., Received this audio note in a Telegram group promising 100% profit..."
        )

        col_lang, col_btn = st.columns([2, 1])
        with col_lang:
            selected_lang = st.selectbox(
                "Target Regional Language for Voice Warning:",
                list(LANGUAGE_MAP.keys()),
                index=0 # Default to Hindi
            )
        with col_btn:
            st.write(" ") # Spacing offset
            scan_btn = st.button("🚀 Analyze", type="primary", use_container_width=True)

        if scan_btn:
            if not uploaded_media and not user_text and not additional_text:
                st.warning("Please upload a file or enter text to analyze.")
            else:
                with st.spinner(f"Processing media and synthesizing {selected_lang} voice output..."):
                    # Combine input text or fallback to additional_text
                    effective_prompt = additional_text if additional_text else user_text
                    
                    report, audio_stream, script_text = analyze_multimodal_with_gemini(
                        uploaded_file=uploaded_media,
                        text_prompt=effective_prompt,
                        context_json=payload,
                        target_language_label=selected_lang,
                        api_key=gemini_api_key
                    )

                    st.markdown("---")
                    
                    # 1. Detailed Report Output
                    st.markdown(report)

                    # 2. Regional Voice Output Player
                    if audio_stream:
                        st.markdown("---")
                        st.subheader(f"🔊 Vernacular Voice Warning ({selected_lang})")
                        st.info(f"🗣️ **Spoken Script:** {script_text}")
                        st.audio(audio_stream, format="audio/mp3", autoplay=True)

    
else:
    st.info("👆 Paste suspicious text or click a **Live Demo Preset** in the sidebar to run the analysis engine.")

st.sidebar.title("🛡️ Threat Metrics")

# Query SQLite after DB write has completed
threats = get_blacklist_summary()
total_threats = len(threats)
total_hits = sum(t["hits"] for t in threats) if threats else 0

st.sidebar.metric("Total Blacklisted Entities", total_threats)
st.sidebar.metric("Total System Hits", total_hits)

if threats:
    st.sidebar.markdown("---")
    st.sidebar.write("##### 🚨 Recent Blacklist Entries")
    for t in threats[:5]:
        st.sidebar.caption(f"• **{t['indicator']}** ({t['type']}) — {t['hits']} hit(s)")

