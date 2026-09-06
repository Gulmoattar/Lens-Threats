"""ThreatLens Streamlit application."""

from __future__ import annotations

import json
import os
import re
from ipaddress import ip_address
from typing import Any, Callable
from urllib.parse import urlparse

import streamlit as st
from google import genai

from input_helpers import get_virustotal, get_whois

SOURCES: dict[str, Callable[[str, str], dict[str, Any]]] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}


def validate_indicator(indicator_type: str, value: str) -> tuple[bool, str | None]:
    """Validate indicator input before calling external sources."""
    value = value.strip()
    if not value:
        return False, "Indicator value is required."

    if indicator_type == "IP":
        try:
            ip_address(value)
            return True, None
        except ValueError:
            return False, "Invalid IP address format."

    if indicator_type == "Domain":
        if len(value) > 253:
            return False, "Domain is too long."
        domain_regex = re.compile(
            r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
        )
        if not domain_regex.match(value):
            return False, "Invalid domain format."
        return True, None

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False, "Invalid URL format. Include http:// or https://"
    return True, None


def build_prompt(
    indicator_type: str,
    indicator_value: str,
    knowledge_level: str,
    source_results: dict[str, dict[str, Any]],
) -> str:
    """Build a Gemini prompt tuned to the selected knowledge level."""
    level_instructions = {
        "Beginner": (
            "Use plain language. Briefly explain technical terms when used."
        ),
        "Intermediate": (
            "Use moderate technical detail and explain why each evidence item matters."
        ),
        "Expert": (
            "Use precise cybersecurity terminology and discuss evidence quality, confidence, "
            "false positives, false negatives, reputation limitations, WHOIS limitations, "
            "and attribution limitations."
        ),
    }
    evidence = json.dumps(source_results, indent=2, sort_keys=True)
    return f"""
You are a defensive cybersecurity analyst.
Analyze ONLY the evidence provided below from VirusTotal and WHOIS.
Do NOT invent data. If evidence is missing, say it is unavailable.

Indicator Type: {indicator_type}
Indicator Value: {indicator_value}
Knowledge Level: {knowledge_level}

Guidance:
{level_instructions[knowledge_level]}

Return exactly these sections:
1. Verdict: SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN
2. Confidence: LOW / MEDIUM / HIGH
3. Why: 3-5 concise, evidence-based bullet points
4. Recommended action: practical defensive advice
5. Limitations: explain why reputation and WHOIS are not absolute proof

Evidence JSON:
{evidence}
""".strip()


def fallback_verdict(source_results: dict[str, dict[str, Any]]) -> str:
    """Compute a conservative fallback verdict if Gemini is unavailable."""
    vt = source_results.get("VirusTotal", {}).get("data", {})
    malicious = int(vt.get("malicious", 0) or 0)
    suspicious = int(vt.get("suspicious", 0) or 0)
    harmless = int(vt.get("harmless", 0) or 0)
    undetected = int(vt.get("undetected", 0) or 0)

    if malicious > 0:
        return "MALICIOUS"
    if suspicious > 0:
        return "SUSPICIOUS"
    if harmless > 0 and malicious == 0 and suspicious == 0:
        return "SAFE (no malicious detections; not guaranteed safe)"
    if undetected > 0:
        return "UNKNOWN"
    return "UNKNOWN"


def verdict_badge(verdict_text: str) -> str:
    """Render a color-coded verdict badge."""
    if "MALICIOUS" in verdict_text:
        color, icon = "#ff4d4f", "🔴"
    elif "SUSPICIOUS" in verdict_text:
        color, icon = "#fa8c16", "🟠"
    elif "SAFE" in verdict_text:
        color, icon = "#52c41a", "🟢"
    else:
        color, icon = "#8c8c8c", "⚪"

    return (
        f"<div style='padding:12px;border-radius:10px;background:{color};"
        f"color:white;font-weight:700;font-size:20px'>{icon} {verdict_text}</div>"
    )


def get_gemini_insight(prompt: str) -> tuple[bool, str]:
    """Call Gemini and return response text or a failure message."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return False, "Missing GEMINI_API_KEY environment variable."

    try:
        client = genai.Client(api_key=api_key)
        model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        response = client.models.generate_content(model=model, contents=prompt)
        text = response.text
        if not text:
            return False, "Gemini returned an empty response."
        return True, text
    except Exception as exc:
        return False, f"Gemini analysis failed: {exc}"


def main() -> None:
    st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")
    st.title("ThreatLens")
    st.caption("Defensive IP, Domain & URL Reputation Checker")

    indicator_type = st.selectbox("Indicator Type", ["IP", "Domain", "URL"])
    indicator_value = st.text_input("Enter Indicator", placeholder="e.g., 8.8.8.8 | example.com | https://example.com")
    knowledge_level = st.selectbox("Knowledge Level", ["Beginner", "Intermediate", "Expert"])
    st.caption(f"Explanation mode: {knowledge_level}")

    if st.button("🔍 Check Indicator", type="primary"):
        is_valid, validation_error = validate_indicator(indicator_type, indicator_value)
        if not is_valid:
            st.error(validation_error)
            return

        with st.spinner("Collecting source evidence..."):
            source_results: dict[str, dict[str, Any]] = {}
            for source_name, source_func in SOURCES.items():
                try:
                    source_results[source_name] = source_func(indicator_type, indicator_value.strip())
                except Exception as exc:
                    source_results[source_name] = {
                        "source": source_name,
                        "status": "error",
                        "ok": False,
                        "error": f"Unexpected failure: {exc}",
                        "data": {},
                    }

        prompt = build_prompt(indicator_type, indicator_value.strip(), knowledge_level, source_results)
        ok, gemini_text = get_gemini_insight(prompt)

        parsed_verdict = fallback_verdict(source_results)
        if ok:
            match = re.search(r"\*{0,2}Verdict\*{0,2}\s*:\s*(.+)", gemini_text, re.IGNORECASE)
            if match:
                parsed_verdict = match.group(1).strip()

        st.subheader("Security Verdict")
        st.markdown(verdict_badge(parsed_verdict), unsafe_allow_html=True)
        st.info(
            "No malicious detections are not absolute proof of safety. "
            "Treat this output as decision support, not certainty."
        )

        st.subheader("AI Insight")
        if ok:
            st.markdown(gemini_text)
        else:
            st.warning(gemini_text)
            st.markdown(
                f"**Fallback verdict:** {parsed_verdict}\n\n"
                "Gemini insight is unavailable. Review source evidence below."
            )

        st.subheader("Source Results")
        for source_name, result in source_results.items():
            with st.expander(f"{source_name} ({result.get('status', 'unknown')})", expanded=False):
                if result.get("error"):
                    st.warning(result["error"])
                st.json(result)


if __name__ == "__main__":
    main()
