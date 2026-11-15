import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_hosted_reset_survives_restart_and_requires_reviewer(monkeypatch):
    settings = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "test-token"})
    monkeypatch.setattr(main, "settings", settings)
    monkeypatch.setattr(main, "hosted_reset_allowed", lambda: True)
    with TestClient(main.app) as client:
        assert client.post("/api/demo/reset").status_code == 403
        result = client.post("/api/demo/reset", headers={"X-Reviewer-Token": "test-token"})
        assert result.status_code == 200, result.text
        expected = result.json()["namespace"]
        assert client.get("/api/reviews").json()["proposals"] == []
    settings.graph_namespace = "initial_namespace"
    with TestClient(main.app) as client:
        assert settings.graph_namespace == expected
        assert client.get("/api/reviews").json()["proposals"] == []
