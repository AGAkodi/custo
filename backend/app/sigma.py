"""Sigma correlation export for the reproducible single-source baseline only."""
import yaml


def baseline_sigma():
    event = {"title": "Custos failed authentication event", "name": "custos_failed_authentication", "id": "cbe5555d-1d22-42d3-9f55-264a827b2e45", "status": "experimental", "description": "Matches normalized Custos login failure events. Map fields to your log source before use.", "logsource": {"category": "authentication"}, "detection": {"selection": {"result": "failure"}, "condition": "selection"}, "level": "informational"}
    correlation = {"title": "Custos single source failed login burst", "id": "4d90bb0f-4205-49bf-b7ca-7124c0eff9f4", "status": "experimental", "description": "Approximation: at least ten normalized failed login events per source over ten minutes. Custos chooses the densest global window first; this correlation does not. Target backend window semantics may also differ.", "correlation": {"type": "event_count", "rules": ["custos_failed_authentication"], "group-by": ["source_ip"], "timespan": "10m", "condition": {"gte": 10}}, "falsepositives": ["Shared networks or misconfigured clients"], "level": "medium"}
    return yaml.safe_dump_all([event, correlation], sort_keys=False, explicit_start=True)
