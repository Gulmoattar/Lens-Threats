"""External source helper functions for ThreatLens."""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import requests
import whois


def get_virustotal(
    indicator_type: str,
    indicator: str,
    api_key: str,
    timeout: int = 20,
) -> dict[str, Any]:
    """Query VirusTotal for IP, domain, or URL reputation data."""
    result: dict[str, Any] = {
        "source": "VirusTotal",
        "ok": False,
        "error": None,
        "data": {},
    }

    if not api_key:
        result["error"] = "Missing VIRUSTOTAL_API_KEY."
        return result

    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    endpoint = ""
    if indicator_type == "IP":
        endpoint = f"/ip_addresses/{indicator}"
    elif indicator_type == "Domain":
        endpoint = f"/domains/{indicator}"
    elif indicator_type == "URL":
        url_id = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("utf-8").rstrip("=")
        endpoint = f"/urls/{url_id}"
    else:
        result["error"] = f"Unsupported indicator type for VirusTotal: {indicator_type}"
        return result

    try:
        response = requests.get(
            f"{base_url}{endpoint}",
            headers=headers,
            timeout=timeout,
        )

        if indicator_type == "URL" and response.status_code == 404:
            submit_response = requests.post(
                f"{base_url}/urls",
                headers=headers,
                data={"url": indicator},
                timeout=timeout,
            )
            if submit_response.status_code >= 400:
                result["error"] = (
                    f"VirusTotal URL submission failed ({submit_response.status_code}): "
                    f"{submit_response.text[:300]}"
                )
                return result
            submit_payload = submit_response.json()
            submit_data = submit_payload.get("data", {})
            result["ok"] = True
            result["data"] = {
                "status": "submitted_for_analysis",
                "analysis_id": submit_data.get("id"),
                "analysis_type": submit_data.get("type"),
                "message": (
                    "URL submitted to VirusTotal, but analysis is still pending. "
                    "Try again shortly for full verdicts."
                ),
            }
            return result

        if response.status_code >= 400:
            result["error"] = f"VirusTotal request failed ({response.status_code}): {response.text[:300]}"
            return result

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        analysis_stats = attributes.get("last_analysis_stats", {}) or {}

        result["ok"] = True
        result["data"] = {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0),
            "timeout": analysis_stats.get("timeout", 0),
            "reputation": attributes.get("reputation"),
            "last_analysis_date": (
                datetime.utcfromtimestamp(attributes["last_analysis_date"]).isoformat() + "Z"
                if attributes.get("last_analysis_date")
                else None
            ),
            "analysis_summary": {
                "type": payload.get("data", {}).get("type"),
                "id": payload.get("data", {}).get("id"),
                "times_submitted": attributes.get("times_submitted"),
                "total_votes": attributes.get("total_votes"),
            },
            "status": "complete",
        }
        return result
    except requests.Timeout:
        result["error"] = "VirusTotal request timed out."
        return result
    except requests.RequestException as exc:
        result["error"] = f"VirusTotal request error: {exc}"
        return result
    except (ValueError, TypeError, KeyError) as exc:
        result["error"] = f"VirusTotal malformed response: {exc}"
        return result


def get_whois(
    indicator_type: str,
    indicator: str,
    timeout: int = 20,
) -> dict[str, Any]:
    """Retrieve WHOIS metadata for a domain or URL hostname."""
    result: dict[str, Any] = {
        "source": "WHOIS",
        "ok": False,
        "error": None,
        "data": {},
    }

    if indicator_type == "IP":
        result["ok"] = True
        result["data"] = {
            "applicable": False,
            "message": "WHOIS metadata is not shown for raw IP checks in this app.",
        }
        return result

    lookup_target = indicator
    if indicator_type == "URL":
        parsed = urlparse(indicator)
        lookup_target = parsed.hostname or ""

    if not lookup_target:
        result["error"] = "Could not extract a hostname for WHOIS lookup."
        return result

    previous_timeout = getattr(whois, "timeout", None)
    try:
        whois.timeout = timeout
        record = whois.whois(lookup_target)

        if not record:
            result["error"] = "WHOIS returned no data."
            return result

        def normalize(value: Any) -> Any:
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if isinstance(value, datetime):
                return value.isoformat()
            return value

        result["ok"] = True
        result["data"] = {
            "applicable": True,
            "target": lookup_target,
            "registrar": normalize(record.get("registrar")),
            "creation_date": normalize(record.get("creation_date")),
            "expiration_date": normalize(record.get("expiration_date")),
            "updated_date": normalize(record.get("updated_date")),
            "name_servers": normalize(record.get("name_servers")),
            "domain_status": normalize(record.get("status")),
            "country": normalize(record.get("country")),
        }
        return result
    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {exc}"
        return result
    finally:
        whois.timeout = previous_timeout
