from contextlib import asynccontextmanager
from contextvars import ContextVar
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import Response
from typing import Literal
import httpx
from pydantic import BaseModel, Field, StrictBool
from secrets import compare_digest
from fastapi.middleware.cors import CORSMiddleware
from neo4j.exceptions import Neo4jError
from selfgraph.errors import StoreError
from app.config import get_settings
import app.config as config_module
from app.lifecycle import lock as lifecycle_lock
from uuid import uuid4
from urllib.parse import urlparse
from app.graph import GraphStore
from app.memory import retrieve_context, record_assessment, record_custom_events, related_incidents
from app.detection import assess
from app.simulator import SCENARIOS, generate
from app.lifecycle import (active_version, challenge, create_proposal, current_rule, history,
                           list_entities, review, rollback, verify, revise_proposal, CandidateRule)
from app.memory import memory_graph
from app.evaluation import evaluate
from app.datasets import analyze as analyze_dataset
from app.sigma import baseline_sigma
from app.soc import hec_envelope, send_hec, validate_hec_url
from app.types import SecurityEvent
import json
import re

settings = get_settings()
request_settings = ContextVar("custos_request_settings", default=None)


def current_settings():
    return request_settings.get() or settings


def local_passwordless():
    return settings.passwordless_demo_enabled and settings.app_env == "development" and urlparse(settings.hydradb_uri).hostname in ("localhost", "127.0.0.1", "::1")

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.graph = GraphStore(settings)
    if hosted_reset_allowed():
        await restore_hosted_demo_namespace()
    yield
    app.state.graph.close()

app = FastAPI(title="Custos API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()], allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])


@app.middleware("http")
async def isolated_demo_workspace(request: Request, call_next):
    if not local_passwordless() or request.method == "OPTIONS" or not request.url.path.startswith("/api/") or request.url.path == "/api/demo/session":
        return await call_next(request)
    session = request.cookies.get("custos_demo_session", "")
    if not re.fullmatch(r"[0-9a-f]{32}", session):
        return Response(status_code=401, content="Initialize a demo session first")
    token = request_settings.set(settings.model_copy(update={"graph_namespace": "custos_demo_" + session}))
    try:
        return await call_next(request)
    finally:
        request_settings.reset(token)


@app.get("/api/demo/session")
async def demo_session(request: Request, response: Response):
    if not local_passwordless():
        return {"passwordless": False}
    session = request.cookies.get("custos_demo_session", "")
    if not re.fullmatch(r"[0-9a-f]{32}", session):
        session = uuid4().hex
    response.set_cookie("custos_demo_session", session, httponly=True, samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"passwordless": True}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/ready")
def ready(request: Request):
    try:
        request.app.state.graph.check()
    except (Neo4jError, StoreError, OSError, ValueError):
        raise HTTPException(status_code=503, detail="HydraDB is unavailable") from None
    return {"status": "ready", "hydradb": "connected"}


@app.get("/api/foundation/context")
async def foundation_context():
    """Read the explicitly seeded sample graph; no incident analysis is performed."""
    try:
        context = await retrieve_context(current_settings(), "Foundation incident")
    except (Neo4jError, StoreError, OSError, ValueError):
        raise HTTPException(status_code=503, detail="HydraDB is unavailable") from None
    return {"context": context}




@app.get("/api/scenarios")
def scenarios():
    return [{"id": key, "name": value[0], "split": "held-out" if key == "held-out" or key.startswith("heldout-") else "feedback"} for key, value in SCENARIOS.items()]


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str, baseline: bool = False):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    events = generate(scenario_id, current_settings().demo_seed)
    try:
        context = await retrieve_context(current_settings(), scenario_id)
        rule = None if baseline else await current_rule(current_settings())
        decision = assess(scenario_id, events, context, rule)
        await record_assessment(current_settings(), decision)
    except (Neo4jError, StoreError, OSError, ValueError, RuntimeError):
        raise HTTPException(status_code=503, detail="Unable to retrieve or persist graph data") from None
    return {"events": [e.model_dump(mode="json") for e in events], "assessment": decision.model_dump(mode="json")}


@app.post("/api/scenarios/{scenario_id}/reveal")
def reveal_scenario(scenario_id: str):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    return {"scenario_id": scenario_id, "confirmed_label": SCENARIOS[scenario_id][1], "source": "synthetic fixture"}


@app.post("/api/scenarios/run-batch")
async def run_batch():
    """Run the fixed fixture set without revealing labels."""
    results = []
    for scenario_id in SCENARIOS:
        results.append(await run_scenario(scenario_id))
    return {"seed": current_settings().demo_seed, "results": results}


class FeedbackRequest(BaseModel):
    decision_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")


class ReviewRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=100, pattern=r".*\S.*")
    reason: str = Field(min_length=1, max_length=500, pattern=r".*\S.*")


class RevisionRequest(ReviewRequest):
    rule: CandidateRule


def require_reviewer(token: str | None):
    if local_passwordless() and request_settings.get() is not None:
        return
    if not current_settings().reviewer_token or not token or not compare_digest(token, current_settings().reviewer_token):
        raise HTTPException(status_code=403, detail="Reviewer token required")


@app.post("/api/scenarios/{scenario_id}/feedback")
async def feedback(scenario_id: str, body: FeedbackRequest, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    try:
        return await create_proposal(current_settings(), scenario_id, body.decision_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.get("/api/reviews")
async def reviews():
    async with memory_graph(current_settings()) as graph:
        proposals = [json.loads(e.properties["data"]) for e in await list_entities(graph, "RuleProposal")]
        events = await history(graph)
        active = await active_version(graph)
        states = {"PROPOSED": "UNDER_REVIEW", "APPROVED": "ACTIVE", "REJECTED": "REJECTED", "CHALLENGED": "CHALLENGED", "VERIFIED": "VERIFIED", "ROLLED_BACK": "SUPERSEDED"}
        for proposal in proposals:
            transitions = [e for e in events if e["proposal_id"] == proposal["id"]]
            if transitions:
                proposal["status"] = states[transitions[-1]["kind"]]
            if proposal["status"] in ("ACTIVE", "VERIFIED") and active != f"ruleversion:{proposal['id']}":
                proposal["status"] = "SUPERSEDED"
        return {"proposals": proposals, "history": events, "active_version": active}


@app.post("/api/reviews/{proposal_id}/revise")
async def revise(proposal_id: str, body: RevisionRequest, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    try:
        return await revise_proposal(current_settings(), proposal_id, body.rule, body.actor, body.reason)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/reviews/{proposal_id}/{action}")
async def review_action(proposal_id: str, action: str, body: ReviewRequest, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    if action not in ("approve", "reject", "rollback", "challenge", "verify"):
        raise HTTPException(status_code=404, detail="Unknown action")
    try:
        if action == "rollback":
            return await rollback(current_settings(), proposal_id, body.actor, body.reason)
        if action == "challenge":
            return await challenge(current_settings(), proposal_id, body.actor, body.reason)
        if action == "verify":
            return await verify(current_settings(), proposal_id, body.actor, body.reason)
        return await review(current_settings(), proposal_id, action, body.actor, body.reason)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/evaluation/run")
async def run_evaluation():
    try:
        return await evaluate(current_settings())
    except (Neo4jError, StoreError, OSError, ValueError, RuntimeError):
        raise HTTPException(status_code=503, detail="Unable to run graph-backed evaluation") from None


@app.get("/api/evaluation/latest")
async def latest_evaluation():
    async with memory_graph(current_settings()) as graph:
        runs = [json.loads(e.properties["data"]) for e in await list_entities(graph, "EvaluationRun")]
        return max(runs, key=lambda item: item["created_at"]) if runs else None


@app.get("/api/graph/neighborhood")
async def graph_neighborhood():
    """Bounded view of persisted security entities and their actual relations."""
    kinds = ("Incident", "AttackTechnique", "Assessment", "IncidentEvidence", "ThreatMemory", "RuleProposal", "RuleVersion", "ChallengeEvidence", "DatasetImport", "AuthEventBatch")
    async with memory_graph(current_settings()) as graph:
        nodes = []
        for kind in kinds:
            page = await graph.entities.list(type=kind, limit=30)
            nodes.extend({"id": entity.id, "name": entity.name, "type": entity.type, "properties": entity.properties} for entity in page.items)
        ids = {node["id"] for node in nodes}
        # Include provenance targets even if the general type page is truncated.
        for node in list(nodes):
            if node["type"] not in ("ThreatMemory", "RuleVersion", "RuleProposal", "IncidentEvidence", "ChallengeEvidence"):
                continue
            page = await graph.relations.list(from_entity=node["id"], limit=30)
            for edge in page.items:
                if edge.to_entity not in ids:
                    linked = await graph.entities.get(edge.to_entity)
                    if linked:
                        nodes.append({"id": linked.id, "name": linked.name, "type": linked.type, "properties": linked.properties})
                        ids.add(linked.id)
        edges = []
        for node in nodes:
            page = await graph.relations.list(from_entity=node["id"], limit=30)
            edges.extend({"id": edge.id, "source": edge.from_entity, "target": edge.to_entity, "type": edge.type} for edge in page.items if edge.to_entity in ids)
        return {"nodes": nodes, "edges": edges, "limit_per_type": 30}


def hosted_reset_allowed():
    host = urlparse(current_settings().hydradb_uri).hostname or ""
    return current_settings().hosted_demo_reset_enabled and current_settings().app_env == "production" and host.endswith(".railway.internal")


def control_settings():
    return current_settings().model_copy(update={"graph_namespace": "custos_demo_control"})


async def restore_hosted_demo_namespace():
    async with memory_graph(control_settings()) as graph:
        controls = await list_entities(graph, "DemoSessionControl")
        if controls:
            newest = max(controls, key=lambda item: item.properties.get("created_at", ""))
            namespace = newest.properties.get("namespace", "")
            if re.fullmatch(r"custos_demo_[0-9a-f]{32}", namespace):
                current_settings().graph_namespace = namespace


@app.post("/api/demo/reset")
async def reset_demo(response: Response, x_reviewer_token: str | None = Header(default=None)):
    """Rotate the shared demo namespace without deleting historical data."""
    require_reviewer(x_reviewer_token)
    if local_passwordless():
        session = uuid4().hex
        response.set_cookie("custos_demo_session", session, httponly=True, samesite="strict", path="/")
        return {"status": "reset", "previous_data": "retained", "scope": "this browser"}
    local = current_settings().app_env == "development" and urlparse(current_settings().hydradb_uri).hostname in ("localhost", "127.0.0.1", "::1")
    hosted = hosted_reset_allowed()
    if not local and not hosted:
        raise HTTPException(status_code=403, detail="Reset is disabled for this environment")
    async with lifecycle_lock:
        namespace = "custos_demo_" + uuid4().hex
        if hosted:
            from datetime import datetime, timezone
            async with memory_graph(control_settings()) as graph:
                await graph.entities.create("Demo session", "DemoSessionControl", id="demosessioncontrol:" + uuid4().hex, properties={"namespace": namespace, "created_at": datetime.now(timezone.utc).isoformat()})
        else:
            config_module.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            temp = config_module.SESSION_FILE.with_suffix(".tmp")
            temp.write_text(json.dumps({"namespace": namespace}), encoding="utf-8")
            temp.replace(config_module.SESSION_FILE)
        current_settings().graph_namespace = namespace
    return {"status": "reset", "namespace": namespace, "previous_data": "retained"}


class DatasetRequest(BaseModel):
    dataset: Literal["unsw-nb15", "cicids2017"]
    csv_text: str = Field(min_length=1, max_length=1_000_000)
    include_labels: bool = False


@app.post("/api/datasets/analyze")
async def dataset_analysis(body: DatasetRequest):
    """Analyze bounded public-dataset flow samples without treating labels as evidence."""
    try:
        result = analyze_dataset(body.dataset, body.csv_text, body.include_labels)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    counts = {}
    for row in result["results"]:
        key = row["assessment"]["classification"]
        counts[key] = counts.get(key, 0) + 1
    record_id = uuid4().hex
    async with memory_graph(current_settings()) as graph:
        await graph.entities.create("Dataset import " + record_id, "DatasetImport", id="datasetimport:" + record_id, properties={"dataset": result["dataset"], "sha256": result["sha256"], "record_count": result["record_count"], "classification_counts": json.dumps(counts)})
    result["import_id"] = record_id
    return result


@app.get("/api/rules/{rule_id}/sigma")
def sigma_export(rule_id: str):
    if rule_id != "baseline-single-source-v1":
        raise HTTPException(status_code=422, detail="Only the single-source baseline has a supported Sigma translation; other rules are not exported")
    return Response(content=baseline_sigma(), media_type="application/yaml", headers={"Content-Disposition": "attachment; filename=custos-single-source.yml"})


async def stored_assessment(decision_id: str):
    if len(decision_id) != 32 or any(c not in "0123456789abcdef" for c in decision_id):
        raise HTTPException(status_code=422, detail="Invalid decision ID")
    async with memory_graph(current_settings()) as graph:
        entity = await graph.entities.get("assessment:" + decision_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Decision not found")
        return json.loads(entity.properties["assessment_json"])


@app.get("/api/incidents/related/{decision_id}")
async def find_related_incidents(decision_id: str, x_reviewer_token: str | None = Header(default=None)):
    """Retrieve linked, confirmed incident evidence for an existing assessment."""
    from app.types import Features
    require_reviewer(x_reviewer_token)
    assessment = await stored_assessment(decision_id)
    matches = await related_incidents(current_settings(), Features.model_validate(assessment["features"]))
    return {"decision_id": decision_id, "matches": matches, "search_limit": 100}


@app.get("/api/integrations/splunk/preview/{decision_id}")
async def splunk_preview(decision_id: str, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    return hec_envelope(await stored_assessment(decision_id))


class DeliveryRequest(BaseModel):
    decision_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    confirm_delivery: StrictBool


@app.post("/api/integrations/splunk/send")
async def splunk_send(body: DeliveryRequest, x_reviewer_token: str | None = Header(default=None)):
    if local_passwordless():
        raise HTTPException(status_code=403, detail="Live delivery is disabled in password-free demo mode")
    require_reviewer(x_reviewer_token)
    if body.confirm_delivery is not True:
        raise HTTPException(status_code=422, detail="Explicit delivery confirmation is required")
    if not current_settings().splunk_hec_url or not current_settings().splunk_hec_token:
        raise HTTPException(status_code=503, detail="Splunk HEC is not configured")
    envelope = hec_envelope(await stored_assessment(body.decision_id))
    try:
        result = await send_hec(current_settings().splunk_hec_url, current_settings().splunk_hec_token, envelope)
    except (httpx.HTTPError, ValueError):
        raise HTTPException(status_code=502, detail="Splunk HEC delivery failed or configuration is invalid") from None
    # Acceptance is not indexing confirmation; retries are never automatic.
    return result


@app.get("/api/integrations/splunk/status")
def splunk_status(x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    try:
        endpoint = validate_hec_url(current_settings().splunk_hec_url) if current_settings().splunk_hec_token else None
    except ValueError:
        endpoint = None
    return {"configured": bool(endpoint), "endpoint": endpoint}


class CustomIncidentRequest(BaseModel):
    incident_id: str = Field(min_length=8, max_length=67, pattern=r"^custom-[a-z0-9-]+$")
    events: list[SecurityEvent] = Field(min_length=1, max_length=500)


class CustomFeedbackRequest(BaseModel):
    decision_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    confirmed_label: Literal["distributed_credential_stuffing", "password_spray"]
    reviewer: str = Field(min_length=1, max_length=100, pattern=r".*\S.*")
    evidence_note: str = Field(min_length=1, max_length=500, pattern=r".*\S.*")


@app.post("/api/incidents/analyze")
async def analyze_incident(body: CustomIncidentRequest, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    if any(event.scenario_id != body.incident_id for event in body.events):
        raise HTTPException(status_code=422, detail="All event scenario IDs must match the incident ID")
    try:
        context = await retrieve_context(current_settings(), body.incident_id)
        rule = await current_rule(current_settings())
        decision = assess(body.incident_id, body.events, context, rule)
        await record_assessment(current_settings(), decision)
        await record_custom_events(current_settings(), decision, body.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except (Neo4jError, StoreError, OSError, RuntimeError):
        raise HTTPException(status_code=503, detail="Unable to retrieve or persist graph data") from None
    return {"assessment": decision.model_dump(mode="json")}


@app.post("/api/incidents/{incident_id}/feedback")
async def custom_feedback(incident_id: str, body: CustomFeedbackRequest, x_reviewer_token: str | None = Header(default=None)):
    require_reviewer(x_reviewer_token)
    if not incident_id.startswith("custom-"):
        raise HTTPException(status_code=422, detail="Custom incident ID must start with custom-")
    try:
        return await create_proposal(current_settings(), incident_id, body.decision_id, confirmed_label=body.confirmed_label, evidence_note=body.evidence_note, reviewer=body.reviewer)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
