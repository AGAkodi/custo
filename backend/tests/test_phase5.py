import asyncio
import math

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from app.datasets import analyze, parse_csv
from app.sigma import baseline_sigma
from app.soc import hec_envelope, send_hec, validate_hec_url
from app.main import app

UNSW = "dur,spkts,dpkts,sbytes,dbytes,label,attack_cat\n1,100,100,100000001,2,0,Normal\n0.01,100,100,50,20,1,DoS\n0,0,0,0,0,1,Exploits\n"
CIC = "Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n1000000,100,100,100000001,2,BENIGN\n10000,100,100,50,20,DoS\n"


def test_public_dataset_flow_adapters_and_hidden_labels():
    for dataset, text in (("unsw-nb15", UNSW), ("cicids2017", CIC)):
        result = analyze(dataset, text)
        assert result["results"][0]["assessment"]["classification"] == "high_outbound_volume"
        assert result["results"][1]["assessment"]["classification"] == "high_packet_rate"
        assert "dataset_label" not in result["results"][0]
        assert analyze(dataset, text, True)["results"][0]["dataset_label"].lower() in ("benign", "normal")
    assert analyze("unsw-nb15", UNSW)["results"][2]["assessment"]["classification"] == "no_flow_rule_match"
    altered = UNSW.replace("0,Normal", "1,Exploits")
    assert [x["assessment"] for x in analyze("unsw-nb15", UNSW)["results"]] == [x["assessment"] for x in analyze("unsw-nb15", altered)["results"]]


def test_dataset_rejects_malformed_and_oversized_inputs():
    for text in (UNSW.replace("100000001", "NaN"), UNSW.replace("100000001", "-1"), UNSW.replace("100000001", "inf"), "dur,label\n1,0\n", UNSW.replace("0,Normal", "2,Normal")):
        with pytest.raises(ValueError):
            parse_csv("unsw-nb15", text)
    with pytest.raises(ValueError):
        parse_csv("unsw-nb15", "a" * 1_000_001)
    with pytest.raises(ValueError):
        parse_csv("unknown", UNSW)
    with pytest.raises(ValueError):
        parse_csv("unsw-nb15", '"unterminated header\n')
    assert math.isfinite(analyze("unsw-nb15", UNSW)["results"][0]["flow"]["duration_seconds"])


def test_sigma_export_parses_as_sigma_and_rejects_unknown():
    collection = SigmaCollection.from_yaml(baseline_sigma())
    assert len(collection.rules) == 2
    assert isinstance(collection.rules[1], SigmaCorrelationRule)
    documents = list(yaml.safe_load_all(baseline_sigma()))
    assert documents[1]["correlation"]["group-by"] == ["source_ip"]
    assert documents[1]["correlation"]["condition"] == {"gte": 10}
    assert documents[1]["correlation"]["timespan"] == "10m"
    with TestClient(app) as client:
        response = client.get("/api/rules/baseline-single-source-v1/sigma")
        assert response.status_code == 200
        assert "densest global window" in response.text
        assert client.get("/api/rules/ruleversion:unrepresentable/sigma").status_code == 422


def test_splunk_sends_only_explicit_envelope_and_checks_result():
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})
    assessment = {"decision_id":"a" * 32, "timestamp":"2026-01-01T00:00:00Z", "scenario_id":"demo", "classification":"benign", "action":"monitor", "confidence":0.55, "matched_rules":[], "memory_influences":[], "evidence_event_ids":["evt-1"], "explanation":"No match", "source_ip":"192.0.2.1"}
    envelope = hec_envelope(assessment)
    assert "source_ip" not in envelope["event"]
    result = asyncio.run(send_hec("https://hec.example.com/services/collector/event", "secret", envelope, transport=httpx.MockTransport(handler)))
    assert result == {"accepted": True, "indexed": False, "ack_id": None}
    assert seen[0].headers["Authorization"] == "Splunk secret"
    for url in ("http://hec.example.com/services/collector/event", "https://user:secret@hec.example.com/services/collector/event", "https://hec.example.com/other", "https://hec.example.com/services/collector/event?x=1"):
        with pytest.raises(ValueError):
            validate_hec_url(url)
    def rejected(_request):
        return httpx.Response(200, json={"code": 5})
    with pytest.raises(ValueError):
        asyncio.run(send_hec("https://hec.example.com/services/collector/event", "secret", envelope, transport=httpx.MockTransport(rejected)))
