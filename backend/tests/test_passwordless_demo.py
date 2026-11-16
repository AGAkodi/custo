import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires isolated HydraDB")
def test_passwordless_sessions_isolate_review_and_reset(monkeypatch):
    config = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex,
                                               "reviewer_token": "secret", "app_env": "development",
                                               "passwordless_demo_enabled": True})
    monkeypatch.setattr(main, "settings", config)
    with TestClient(main.app) as first, TestClient(main.app) as second:
        preflight = first.options("/api/reviews", headers={"Origin": config.cors_origins.split(",")[0], "Access-Control-Request-Method": "GET"})
        assert preflight.status_code == 200
        assert first.get("/api/reviews").status_code == 401
        assert first.get("/api/demo/session").json()["passwordless"] is True
        assert second.get("/api/demo/session").json()["passwordless"] is True
        assert first.cookies.get("custos_demo_session") != second.cookies.get("custos_demo_session")
        decision = first.post("/api/scenarios/distributed/run?baseline=true").json()["assessment"]
        feedback = first.post("/api/scenarios/distributed/feedback", json={"decision_id": decision["decision_id"]})
        assert feedback.status_code == 200, feedback.text
        proposal = feedback.json()
        approved = first.post(f"/api/reviews/{proposal['id']}/approve", json={"actor": "demo reviewer", "reason": "Reviewed"})
        assert approved.status_code == 200, approved.text
        assert first.get("/api/reviews").json()["active_version"]
        assert second.get("/api/reviews").json()["active_version"] is None
        assert first.post("/api/scenarios/held-out/run").json()["assessment"]["classification"] == "distributed_credential_stuffing"
        assert first.get("/api/graph/neighborhood").json()["edges"]
        assert first.post("/api/evaluation/run").status_code == 200
        before = first.cookies.get("custos_demo_session")
        assert second.post("/api/demo/reset").json()["scope"] == "this browser"
        assert first.cookies.get("custos_demo_session") == before
        assert first.get("/api/reviews").json()["active_version"]
        assert first.post("/api/demo/reset").status_code == 200
        assert first.get("/api/reviews").json()["active_version"] is None
        assert first.post("/api/integrations/splunk/send", json={"decision_id": "a" * 32, "confirm_delivery": True}).status_code == 403


def test_passwordless_cannot_be_enabled_in_production(monkeypatch):
    config = main.settings.model_copy(update={"app_env": "production", "passwordless_demo_enabled": True})
    monkeypatch.setattr(main, "settings", config)
    assert not main.local_passwordless()
