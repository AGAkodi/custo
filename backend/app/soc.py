"""Splunk HEC formatting and explicitly initiated delivery."""
from urllib.parse import urlsplit

import httpx


def hec_envelope(assessment):
    # Deliberately do not include raw events, account identifiers, or IP addresses.
    return {"sourcetype": "custos:assessment", "source": "custos", "event": {"decision_id": assessment["decision_id"], "timestamp": assessment["timestamp"], "scenario_id": assessment["scenario_id"], "classification": assessment["classification"], "action": assessment["action"], "confidence": assessment["confidence"], "matched_rules": assessment["matched_rules"], "memory_influences": assessment["memory_influences"], "evidence_event_ids": assessment["evidence_event_ids"], "explanation": assessment["explanation"]}}


def validate_hec_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path != "/services/collector/event":
        raise ValueError("HEC URL must be HTTPS and end in /services/collector/event")
    return url


async def send_hec(url, token, envelope, transport=None):
    validate_hec_url(url)
    if not token or "\n" in token or "\r" in token:
        raise ValueError("HEC token is not configured")
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, transport=transport) as client:
        response = await client.post(url, json=envelope, headers={"Authorization": "Splunk " + token})
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or result.get("code") != 0:
            raise ValueError("HEC did not accept the event")
        return {"accepted": True, "indexed": False, "ack_id": result.get("ackId")}
