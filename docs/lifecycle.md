# Phase 3 graph lifecycle

A stored assessment links to an incident with `ASSESSES`. Confirming a missed distributed fixture creates `IncidentEvidence` linked to the assessment, an `UNDER_REVIEW` ThreatMemory linked by `SUPPORTED_BY`, and a structured RuleProposal linked by `DERIVED_FROM`. This is a coverage gap; it does not contradict the existing single-source rule.

A reviewer may approve or reject after reviewing regression results. Approval writes a new RuleVersion with proposal and evidence links, followed by an append-only `APPROVED` event. New matching assessments link to the rule and memory with `INFLUENCED`. A later version links to its predecessor with `SUPERSEDES`. Rollback appends a selection event and does not erase earlier versions.

A separate reviewer-supplied challenge writes explicitly unverified ChallengeEvidence with a `CONTRADICTS` link to the memory, appends a `CHALLENGED` event, and suspends the active rule. A reviewer can append `VERIFIED` to reinstate it. The history endpoint derives current statuses from events and keeps the disagreement.

Custom sanitized authentication incidents can be submitted with `POST /api/incidents/analyze` using an ID beginning `custom-` and a reviewer token. Every event must use that incident ID. Normalized events are stored in bounded AuthEventBatch graph entities linked to the assessment, so submit only data you are authorized to retain. A reviewer can use `POST /api/incidents/{id}/feedback` to attest a supported distributed-credential-stuffing label with a name and evidence note. Custos does not independently verify this attestation. Held-out fixture IDs cannot create proposals.

For the supported distributed-login family, proposal thresholds are derived as bounded heuristics from the recorded incident features: half the observed failure count, distinct IPs and accounts (rounded up), and twice the maximum failures per IP. They are not learned statistically, and the benign regression set and reviewer approval still gate activation. This does not derive arbitrary rule types.

Before an active version can be used, the graph must contain the version-to-proposal-to-memory path, a supporting evidence node and its link to the original assessment. The memory's stored feature signature is compared to the new incident using mean per-feature ratios; it must reach 0.6 before the structured rule can match. Assessments record the score and evidence ID. Old versions without a signature fall back to the original stored assessment. Missing provenance fails closed.

Lifecycle records count as committed only after their `RECORDS` edge exists. Approval retries can reuse an identical partially written rule version, and a tested interrupted approval does not activate the rule. These are recovery measures, not atomic transactions: writes and relation creation span multiple operations, and the process lock cannot coordinate multiple workers. Use a single local backend worker only. Production needs database-supported atomic transitions or a durable, concurrency-safe protocol, real authentication, TLS, backups and monitoring.


The pinned HydraDB release documents auto-commit Bolt operations and rejects `BEGIN`, `COMMIT` and `ROLLBACK`; see its [transaction notes](https://github.com/hydra-db/hydradb/blob/916637477f3f34766b4905b270bd4292109d77e6/USING-HYDRADB.md). The SelfGraph transaction wrapper also drains queued writes even on failure, so it cannot make this multi-operation workflow atomic.
