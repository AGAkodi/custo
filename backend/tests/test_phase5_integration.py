import asyncio
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.memory import memory_graph

CSV = "dur,spkts,dpkts,sbytes,dbytes,label,attack_cat\n1,100,100,100000001,2,1,Exploits\n"


@pytest.mark.skipif(os.getenv("CUSTOS_INTEGRATION") != "1", reason="requires HydraDB")
def test_import_provenance_and_explicit_soc_handoff(monkeypatch):
    settings = main.settings.model_copy(update={"graph_namespace": "test_" + uuid4().hex, "reviewer_token": "test-review", "splunk_hec_url": "https://hec.example.com/services/collector/event", "splunk_hec_token": "test-hec"})
    monkeypatch.setattr(main, "settings", settings)
    delivered = []
    async def fake_send(url, token, envelope):
        delivered.append((url, token, envelope))
        return {"accepted": True, "indexed": False, "ack_id": None}
    monkeypatch.setattr(main, "send_hec", fake_send)
    with TestClient(main.app) as client:
        imported = client.post("/api/datasets/analyze", json={"dataset":"unsw-nb15", "csv_text":CSV})
        assert imported.status_code == 200, imported.text
        body = imported.json()
        assert body["results"][0]["assessment"]["classification"] == "high_outbound_volume"
        assert "dataset_label" not in body["results"][0]
        async def read_import():
            async with memory_graph(settings) as graph:
                return await graph.entities.get("datasetimport:" + body["import_id"])
        entity = asyncio.run(read_import())
        assert entity.properties["sha256"] == body["sha256"]
        assert "csv_text" not in entity.properties
        decision = client.post("/api/scenarios/benign/run").json()["assessment"]
        path = "/api/integrations/splunk/preview/" + decision["decision_id"]
        assert client.get(path).status_code == 403
        headers = {"X-Reviewer-Token":"test-review"}
        preview = client.get(path, headers=headers)
        assert preview.status_code == 200
        assert preview.json()["event"]["decision_id"] == decision["decision_id"]
        assert delivered == []
        status = client.get("/api/integrations/splunk/status", headers=headers).json()
        assert status == {"configured": True, "endpoint": settings.splunk_hec_url}
        assert "test-hec" not in str(status)
        response = client.post("/api/integrations/splunk/send", headers=headers, json={"decision_id":decision["decision_id"], "confirm_delivery":False})
        assert response.status_code == 422 and delivered == []
        response = client.post("/api/integrations/splunk/send", headers=headers, json={"decision_id":decision["decision_id"], "confirm_delivery":True})
        assert response.status_code == 200 and len(delivered) == 1
        assert response.json()["indexed"] is False
