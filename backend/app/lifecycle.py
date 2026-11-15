"""Evidence-backed review workflow. All records are persisted in HydraDB."""
import asyncio
import json
import math
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from app.detection import features_for
from app.types import Features
from app.memory import memory_graph
from app.simulator import SCENARIOS, generate

# Single-process demo guard, not a distributed transaction or multi-worker lock.
lock = asyncio.Lock()


class CandidateRule(BaseModel):
    min_failures: int = Field(ge=1, le=1000)
    min_ips: int = Field(ge=1, le=1000)
    min_accounts: int = Field(ge=1, le=1000)
    max_failures_per_ip: int = Field(ge=1, le=1000)


def derive_candidate(features: Features) -> CandidateRule:
    """Infer bounded distributed-login thresholds from observed positive evidence.

    The fractions are explicit heuristics, not statistical learning or proof of maliciousness.
    """
    if features.failures < 4 or features.distinct_ips < 2 or features.distinct_accounts < 2:
        raise ValueError("Evidence is insufficient for a distributed-login candidate")
    return CandidateRule(
        min_failures=max(1, math.ceil(features.failures * 0.5)),
        min_ips=max(2, math.ceil(features.distinct_ips * 0.5)),
        min_accounts=max(2, math.ceil(features.distinct_accounts * 0.5)),
        max_failures_per_ip=min(1000, max(1, features.max_failures_per_ip * 2)),
    )


def matches(rule, features):
    return (features.failures >= rule.min_failures and features.distinct_ips >= rule.min_ips
            and features.distinct_accounts >= rule.min_accounts
            and features.max_failures_per_ip <= rule.max_failures_per_ip)


def stamp():
    return datetime.now(timezone.utc).isoformat()


async def list_entities(graph, kind):
    items, cursor = [], None
    while True:
        page = await graph.entities.list(type=kind, cursor=cursor, limit=100)
        items.extend(page.items)
        cursor = page.next_cursor
        if not cursor:
            return items


async def history(graph):
    # A RECORDS edge is the commit marker; orphaned events never activate a rule.
    committed = []
    for entity in await list_entities(graph, "LifecycleEvent"):
        data = json.loads(entity.properties["data"])
        links = await graph.relations.list(from_entity=entity.id, type="RECORDS", to_entity=f"ruleproposal:{data['proposal_id']}", limit=1)
        if links.items:
            committed.append(data)
    return sorted(committed, key=lambda x: (x["timestamp"], x["id"]))


async def ensure_relation(graph, source, relation, target):
    existing = await graph.relations.list(from_entity=source, type=relation, to_entity=target, limit=1)
    if not existing.items:
        await graph.relations.create(source, relation, target)


async def active_version(graph):
    events = await history(graph)
    selections = [e for e in events if e["kind"] in ("APPROVED", "ROLLED_BACK", "CHALLENGED", "VERIFIED")]
    return selections[-1]["active_version"] if selections else None


async def event(graph, kind, proposal_id, actor, reason, active_version=None):
    data = {"id": uuid4().hex, "kind": kind, "proposal_id": proposal_id, "actor": actor, "reason": reason, "timestamp": stamp(), "active_version": active_version}
    await graph.entities.create(f"Lifecycle event {data['id']}", "LifecycleEvent", id=f"lifecycleevent:{data['id']}", properties={"data": json.dumps(data)})
    await graph.relations.create(f"lifecycleevent:{data['id']}", "RECORDS", f"ruleproposal:{proposal_id}")
    return data


async def get_proposal(graph, proposal_id):
    ent = await graph.entities.get(f"ruleproposal:{proposal_id}")
    if not ent:
        raise LookupError("Proposal not found")
    return json.loads(ent.properties["data"])


async def create_proposal(settings, scenario_id, decision_id, *, confirmed_label=None, evidence_note=None, reviewer=None):
    if scenario_id == "held-out" or scenario_id.startswith("heldout-"):
        raise ValueError("Held-out scenarios cannot be used as feedback")
    if scenario_id not in SCENARIOS and not scenario_id.startswith("custom-"):
        raise LookupError("Incident not found")
    if scenario_id.startswith("custom-") and (confirmed_label != "distributed_credential_stuffing" or not evidence_note or not reviewer):
        raise ValueError("Custom feedback requires an analyst attestation for a supported label")
    async with lock, memory_graph(settings) as graph:
        decision = await graph.entities.get(f"assessment:{decision_id}")
        if not decision:
            raise LookupError("Decision not found")
        assessment = json.loads(decision.properties["assessment_json"])
        if assessment["scenario_id"] != scenario_id:
            raise ValueError("Decision does not belong to scenario")
        for ent in await list_entities(graph, "RuleProposal"):
            old = json.loads(ent.properties["data"])
            if old["decision_id"] == decision_id:
                return old
        label = SCENARIOS[scenario_id][1] if scenario_id in SCENARIOS else confirmed_label
        if label != "distributed_credential_stuffing" or assessment["classification"] != "benign":
            raise ValueError("This feedback does not identify the supported distributed detection gap")
        feedback_features = Features.model_validate(assessment["features"])
        rule = derive_candidate(feedback_features)
        benign_results = {}
        for benign_id in ("benign", "benign-shared"):
            benign_features, _ = features_for(generate(benign_id, settings.demo_seed))
            benign_results[benign_id] = matches(rule, benign_features)
        regression = {"feedback_matches": matches(rule, feedback_features), "benign_matches": any(benign_results.values()), "feedback_scenario": scenario_id, "benign_results": benign_results}
        proposal_id = uuid4().hex
        data = {"id": proposal_id, "decision_id": decision_id, "scenario_id": scenario_id, "confirmed_label": label, "rule": rule.model_dump(), "regression": regression, "created_at": stamp(), "memory_id": f"threatmemory:{proposal_id}", "evidence_id": f"incidentevidence:{proposal_id}", "status": "UNDER_REVIEW", "source": "synthetic fixture" if scenario_id in SCENARIOS else "reviewer attestation", "reviewer": reviewer, "evidence_note": evidence_note}
        facts = {"entities": [
            {"id": data["evidence_id"], "type": "IncidentEvidence", "name": f"Confirmed evidence {proposal_id}", "properties": {"scenario_id": scenario_id, "decision_id": decision_id, "label": label, "event_ids": json.dumps(assessment["evidence_event_ids"]), "source": "synthetic fixture" if scenario_id in SCENARIOS else "reviewer attestation", "reviewer": reviewer or "", "note": evidence_note or ""}},
            {"id": data["memory_id"], "type": "ThreatMemory", "name": f"Distributed login lesson {proposal_id}", "properties": {"claim": "Many sources target many accounts with few failures per source", "scope": "authentication events within ten minutes", "status": "UNDER_REVIEW", "feature_signature": feedback_features.model_dump_json(), "signature_version": 1}},
            {"id": f"ruleproposal:{proposal_id}", "type": "RuleProposal", "name": f"Rule proposal {proposal_id}", "properties": {"data": json.dumps(data)}},
        ], "relations": [
            {"from_entity": data["memory_id"], "type": "SUPPORTED_BY", "to_entity": data["evidence_id"]},
            {"from_entity": f"ruleproposal:{proposal_id}", "type": "DERIVED_FROM", "to_entity": data["memory_id"]},
            {"from_entity": data["evidence_id"], "type": "SUPPORTS_REVIEW_OF", "to_entity": f"assessment:{decision_id}"},
        ]}
        await graph.insert.facts(facts)
        await event(graph, "PROPOSED", proposal_id, reviewer or "system", "Confirmed feedback reveals a coverage gap; baseline rule remains valid")
        return data


async def review(settings, proposal_id, action, actor, reason):
    async with lock, memory_graph(settings) as graph:
        proposal = await get_proposal(graph, proposal_id)
        events = await history(graph)
        prior = [e for e in events if e["proposal_id"] == proposal_id and e["kind"] in ("APPROVED", "REJECTED")]
        if prior:
            raise ValueError("Proposal has already been reviewed")
        if action == "approve":
            regression = proposal["regression"]
            if not regression["feedback_matches"] or regression["benign_matches"]:
                raise ValueError("Proposal failed regression checks")
            version = f"ruleversion:{proposal_id}"
            existing = await graph.entities.get(version)
            if existing:
                if existing.properties.get("memory_id") != proposal["memory_id"] or json.loads(existing.properties["rule"]) != proposal["rule"]:
                    raise ValueError("Existing rule version conflicts with the proposal")
            else:
                await graph.entities.create(f"Distributed rule {proposal_id}", "RuleVersion", id=version, properties={"rule": json.dumps(proposal["rule"]), "proposal_id": proposal_id, "memory_id": proposal["memory_id"], "created_at": stamp()})
            previous = await active_version(graph)
            await ensure_relation(graph, version, "DERIVED_FROM", f"ruleproposal:{proposal_id}")
            if previous:
                await ensure_relation(graph, version, "SUPERSEDES", previous)
            await ensure_relation(graph, version, "SUPPORTED_BY", proposal["evidence_id"])
            return await event(graph, "APPROVED", proposal_id, actor, reason, version)
        return await event(graph, "REJECTED", proposal_id, actor, reason)


async def current_rule(settings):
    async with memory_graph(settings) as graph:
        version = await active_version(graph)
        if not version:
            return None
        entity = await graph.entities.get(version)
        if not entity:
            raise RuntimeError("Active rule version is missing")
        memory_id = entity.properties["memory_id"]
        memory = await graph.entities.get(memory_id)
        proposal_id = entity.properties["proposal_id"]
        rule_links = await graph.relations.list(from_entity=version, type="DERIVED_FROM", limit=30)
        proposal_links = await graph.relations.list(from_entity=f"ruleproposal:{proposal_id}", type="DERIVED_FROM", limit=30)
        evidence_links = await graph.relations.list(from_entity=memory_id, type="SUPPORTED_BY", limit=30)
        if not memory or not any(e.to_entity == f"ruleproposal:{proposal_id}" for e in rule_links.items) or not any(e.to_entity == memory_id for e in proposal_links.items):
            raise RuntimeError("Active rule is missing its memory provenance")
        signature = memory.properties.get("feature_signature")
        evidence_id = None
        for edge in evidence_links.items:
            evidence = await graph.entities.get(edge.to_entity)
            if not evidence or evidence.type != "IncidentEvidence":
                continue
            decision_id = evidence.properties.get("decision_id", "")
            if not decision_id:
                continue
            source_id = "assessment:" + decision_id
            source = await graph.entities.get(source_id)
            source_links = await graph.relations.list(from_entity=edge.to_entity, type="SUPPORTS_REVIEW_OF", to_entity=source_id, limit=1)
            if not source or not source_links.items:
                continue
            evidence_id = edge.to_entity
            # Versions created before feature signatures can recover the original assessment.
            if not signature:
                signature = json.dumps(json.loads(source.properties["assessment_json"])["features"])
            break
        if not evidence_id or not signature:
            raise RuntimeError("Active memory lacks supporting evidence or a feature signature")
        return {"version": version, "memory_id": memory_id, "evidence_id": evidence_id, "signature": Features.model_validate_json(signature), "rule": CandidateRule.model_validate_json(entity.properties["rule"])}


async def rollback(settings, proposal_id, actor, reason):
    async with lock, memory_graph(settings) as graph:
        events = await history(graph)
        approved = [e for e in events if e["kind"] == "APPROVED"]
        if not approved:
            raise ValueError("No approved rule to roll back")
        current = await active_version(graph)
        if not current:
            raise ValueError("No active rule to roll back")
        if proposal_id != next((e["proposal_id"] for e in approved if e["active_version"] == current), None):
            raise ValueError("Proposal is not the active version")
        previous_active = None
        target = None
        for item in events:
            if item["kind"] == "APPROVED" and item["active_version"] == current:
                target = previous_active
            if item["kind"] in ("APPROVED", "ROLLED_BACK", "CHALLENGED", "VERIFIED"):
                previous_active = item["active_version"]
        if target:
            target_proposal = target.split(":", 1)[1]
            target_transitions = [item for item in events if item["proposal_id"] == target_proposal and item["kind"] in ("CHALLENGED", "VERIFIED")]
            if target_transitions and target_transitions[-1]["kind"] == "CHALLENGED":
                target = None
        return await event(graph, "ROLLED_BACK", proposal_id, actor, reason, target)


async def challenge(settings, proposal_id, actor, reason):
    async with lock, memory_graph(settings) as graph:
        proposal = await get_proposal(graph, proposal_id)
        version = f"ruleversion:{proposal_id}"
        if await active_version(graph) != version:
            raise ValueError("Only an active rule can be challenged")
        evidence_id = "challengeevidence:" + uuid4().hex
        await graph.entities.create("Conflicting report " + evidence_id.split(":")[1], "ChallengeEvidence", id=evidence_id, properties={"actor": actor, "reason": reason, "source": "reviewer report; unverified", "timestamp": stamp()})
        await graph.relations.create(evidence_id, "CONTRADICTS", proposal["memory_id"])
        record = await event(graph, "CHALLENGED", proposal_id, actor, reason, None)
        await graph.relations.create("lifecycleevent:" + record["id"], "SUPPORTED_BY", evidence_id)
        return record


async def verify(settings, proposal_id, actor, reason):
    async with lock, memory_graph(settings) as graph:
        await get_proposal(graph, proposal_id)
        events = await history(graph)
        transitions = [e for e in events if e["kind"] in ("APPROVED", "ROLLED_BACK", "CHALLENGED", "VERIFIED")]
        if not transitions or transitions[-1]["kind"] != "CHALLENGED" or transitions[-1]["proposal_id"] != proposal_id:
            raise ValueError("Proposal is not the currently challenged rule")
        return await event(graph, "VERIFIED", proposal_id, actor, reason, f"ruleversion:{proposal_id}")
