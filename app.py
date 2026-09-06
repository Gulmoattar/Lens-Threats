"""ThreatLens Streamlit app."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any
from urllib.parse import urlparse

import google.generativeai as genai
import streamlit as st

from input_helpers import get_virustotal, get_whois

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}

VALID_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)


def validate_indicator(indicator_type: str, value: str) -> tuple[bool, str]:
    """Validate indicator input based on selected type."""
    cleaned = value.strip()
    if not cleaned:
        return False, "Please enter a value."

    if indicator_type == "IP":
        try:
            ipaddress.ip_address(cleaned)
            return True, ""
        except ValueError:
            return False, "Invalid IP address format."

    if indicator_type == "Domain":
        if not VALID_DOMAIN_RE.match(cleaned):
            return False, "Invalid domain format."
        return True, ""

    if indicator_type == "URL":
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False, "Invalid URL. Use a full http:// or https:// URL."
        return True, ""

    return False, "Unsupported indicator type."


def build_gemini_prompt(
    indicator_type: str,
    indicator: str,
    knowledge_level: str,
    source_results: dict[str, dict[str, Any]],
) -> str:
    """Build a strict evidence-only Gemini prompt for the selected audience."""
    level_instructions = {
        "Beginner": (
            "Use simple language, define security terms briefly, and avoid heavy jargon."
        ),
        "Intermediate": (
            "Use moderate technical detail and explain why each signal matters."
        ),
        "Expert": (
            "Use precise cybersecurity terminology and discuss evidence quality, confidence, "
            "false positives, false negatives, reputation limits, WHOIS limits, and attribution limits."
        ),
    }
    evidence_json = json.dumps(source_results, indent=2, default=str)
    return f"""
You are a defensive cybersecurity analyst. Use ONLY the provided evidence from VirusTotal and WHOIS.
Do not invent facts or external context.

Audience level: {knowledge_level}
Writing instruction: {level_instructions[knowledge_level]}

Indicator type: {indicator_type}
Indicator: {indicator}

Evidence (JSON):
{evidence_json}

Return exactly this structure:
Verdict: SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN
Confidence: LOW | MEDIUM | HIGH
Why:
- 3 to 5 bullet points based strictly on the evidence above
Recommended action:
- Practical defensive advice
Limitations:
- Explain why reputation and WHOIS are not absolute proof
- Mention possible false positives/false negatives
""".strip()


def call_gemini(prompt: str) -> tuple[bool, str]:
    """Call Gemini and return response text."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return False, "Missing GEMINI_API_KEY. AI insight is unavailable."

    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        if not text:
            return False, "Gemini returned an empty response."
        return True, text
    except Exception as exc:
        return False, f"Gemini request failed: {exc}"


def derive_verdict(source_results: dict[str, dict[str, Any]]) -> tuple[str, str]:
    """Create a source-based fallback verdict from VirusTotal counters."""
    vt_data = source_results.get("VirusTotal", {}).get("data", {})
    if not isinstance(vt_data, dict):
        return "UNKNOWN", "⚪ UNKNOWN"

    malicious = int(vt_data.get("malicious", 0) or 0)
    suspicious = int(vt_data.get("suspicious", 0) or 0)

    if malicious > 0:
        return "MALICIOUS", "🔴 MALICIOUS"
    if suspicious > 0:
        return "SUSPICIOUS", "🟠 SUSPICIOUS"
    if vt_data.get("status") == "submitted_for_analysis":
        return "UNKNOWN", "⚪ UNKNOWN (VirusTotal still analyzing URL)"
    if vt_data.get("status") == "complete":
        return "SAFE", "🟢 SAFE / NO MALICIOUS DETECTIONS"
    return "UNKNOWN", "⚪ UNKNOWN"


def render_source(name: str, result: dict[str, Any]) -> None:
    """Render source output with graceful error handling."""
    with st.expander(name, expanded=True):
        if not result.get("ok"):
            st.error(result.get("error", "Unknown source error"))
            return

        data = result.get("data", {})
        if name == "VirusTotal" and data.get("status") == "submitted_for_analysis":
            st.warning(data.get("message", "URL was submitted and is still being analyzed."))
        elif name == "WHOIS" and data.get("applicable") is False:
            st.info(data.get("message", "WHOIS is not applicable for this indicator."))
        else:
            st.json(data)

        st.caption("Raw evidence")
        st.code(json.dumps(result, indent=2, default=str), language="json")


def main() -> None:
    """Render ThreatLens application UI and orchestration flow."""
    st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")
    st.title("ThreatLens")
    st.caption("Defensive IP, Domain & URL Reputation Checker")

    indicator_type = st.selectbox("Indicator Type", ["IP", "Domain", "URL"])
    indicator = st.text_input("Enter Indicator", placeholder="e.g. 8.8.8.8, example.com, https://example.com")
    knowledge_level = st.selectbox("Knowledge Level", ["Beginner", "Intermediate", "Expert"])

    if st.button("🔍 Check Indicator", type="primary"):
        is_valid, message = validate_indicator(indicator_type, indicator)
        if not is_valid:
            st.error(message)
            return

        vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_api_key:
            st.error("Missing VIRUSTOTAL_API_KEY. Set it in your environment before running checks.")
            return

        source_results: dict[str, dict[str, Any]] = {}
        with st.spinner("Collecting evidence from registered sources..."):
            for source_name, source_fn in SOURCES.items():
                try:
                    if source_name == "VirusTotal":
                        source_results[source_name] = source_fn(indicator_type, indicator.strip(), vt_api_key)
                    else:
                        source_results[source_name] = source_fn(indicator_type, indicator.strip())
                except Exception as exc:
                    source_results[source_name] = {
                        "source": source_name,
                        "ok": False,
                        "error": f"Unhandled source failure: {exc}",
                        "data": {},
                    }

        fallback_verdict, label = derive_verdict(source_results)

        prompt = build_gemini_prompt(indicator_type, indicator.strip(), knowledge_level, source_results)
        gemini_ok, gemini_text = call_gemini(prompt)

        st.subheader("Security Verdict")
        if fallback_verdict == "MALICIOUS":
            st.error(label)
        elif fallback_verdict == "SUSPICIOUS":
            st.warning(label)
        elif fallback_verdict == "SAFE":
            st.success(label)
        else:
            st.info(label)
        st.caption("No malicious detections are not absolute proof of safety.")

        st.subheader("Source Results")
        for source_name, source_result in source_results.items():
            render_source(source_name, source_result)

        st.subheader("AI Insight")
        if gemini_ok:
            st.markdown(gemini_text)
        else:
            st.warning(gemini_text)


if __name__ == "__main__":
    main()
