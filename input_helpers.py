"""External source helpers for ThreatLens."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois


def get_virustotal(indicator_type: str, indicator_value: str) -> dict:
    """Query VirusTotal for IP, domain, or URL and return structured evidence."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "error",
            "ok": False,
            "error": "Missing VIRUSTOTAL_API_KEY environment variable.",
            "data": {},
        }

    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"

    try:
        if indicator_type == "IP":
            endpoint = f"{base_url}/ip_addresses/{indicator_value}"
            response = requests.get(endpoint, headers=headers, timeout=20)
        elif indicator_type == "Domain":
            endpoint = f"{base_url}/domains/{indicator_value}"
            response = requests.get(endpoint, headers=headers, timeout=20)
        else:
            url_id = base64.urlsafe_b64encode(indicator_value.encode("utf-8")).decode("utf-8").strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
            response = requests.get(endpoint, headers=headers, timeout=20)
            if response.status_code == 404:
                submit = requests.post(
                    f"{base_url}/urls",
                    headers=headers,
                    data={"url": indicator_value},
                    timeout=20,
                )
                if submit.ok:
                    return {
                        "source": "VirusTotal",
                        "status": "pending",
                        "ok": False,
                        "error": "URL submitted to VirusTotal but analysis is still pending.",
                        "data": {"submission": submit.json()},
                    }
                return {
                    "source": "VirusTotal",
                    "status": "error",
                    "ok": False,
                    "error": f"VirusTotal URL submission failed ({submit.status_code}).",
                    "data": {},
                }

        if not response.ok:
            return {
                "source": "VirusTotal",
                "status": "error",
                "ok": False,
                "error": f"VirusTotal request failed ({response.status_code}).",
                "data": {},
            }

        payload = response.json()
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs.get("last_analysis_stats"), dict) else {}
        last_analysis_date = attrs.get("last_analysis_date")
        analysis_time = (
            datetime.fromtimestamp(last_analysis_date, tz=timezone.utc).isoformat()
            if isinstance(last_analysis_date, (int, float))
            else None
        )

        return {
            "source": "VirusTotal",
            "status": "ok",
            "ok": True,
            "error": None,
            "data": {
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
                "total_votes": attrs.get("total_votes"),
                "analysis_stats": stats,
                "analysis_date": analysis_time,
            },
        }
    except requests.Timeout:
        return {
            "source": "VirusTotal",
            "status": "error",
            "ok": False,
            "error": "VirusTotal request timed out.",
            "data": {},
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "source": "VirusTotal",
            "status": "error",
            "ok": False,
            "error": f"VirusTotal request failed: {exc}",
            "data": {},
        }


def get_whois(indicator_type: str, indicator_value: str) -> dict:
    """Query WHOIS for domains and URL hostnames and return structured metadata."""
    if indicator_type == "IP":
        return {
            "source": "WHOIS",
            "status": "not_applicable",
            "ok": True,
            "error": "WHOIS domain metadata is not applicable to raw IP indicators.",
            "data": {},
        }

    domain = indicator_value if indicator_type == "Domain" else urlparse(indicator_value).hostname
    if not domain:
        return {
            "source": "WHOIS",
            "status": "error",
            "ok": False,
            "error": "Unable to derive hostname for WHOIS lookup.",
            "data": {},
        }

    try:
        record = whois.whois(domain)
        if not record:
            return {
                "source": "WHOIS",
                "status": "unavailable",
                "ok": False,
                "error": "WHOIS data unavailable for this indicator.",
                "data": {"domain": domain},
            }

        def _first(value):
            if isinstance(value, list):
                return value[0] if value else None
            return value

        def _to_string(value):
            v = _first(value)
            if isinstance(v, datetime):
                return v.isoformat()
            return str(v) if v is not None else None

        return {
            "source": "WHOIS",
            "status": "ok",
            "ok": True,
            "error": None,
            "data": {
                "domain": domain,
                "registrar": _to_string(record.registrar),
                "creation_date": _to_string(record.creation_date),
                "expiration_date": _to_string(record.expiration_date),
                "updated_date": _to_string(record.updated_date),
                "name_servers": record.name_servers if isinstance(record.name_servers, list) else [record.name_servers] if record.name_servers else [],
                "domain_status": record.status if isinstance(record.status, list) else [record.status] if record.status else [],
                "country": _to_string(record.country),
            },
        }
    except Exception as exc:  # python-whois can raise varied parser/network exceptions
        return {
            "source": "WHOIS",
            "status": "error",
            "ok": False,
            "error": f"WHOIS lookup failed: {exc}",
            "data": {"domain": domain},
        }
