# Architecture

The Vite/React UI calls the FastAPI backend. A seeded simulator creates fictional authentication events; deterministic feature extraction and rules classify them. SelfGraph 0.2.1 connects over Bolt to the pinned HydraDB container, which stores incidents, assessments, evidence, memories, rule versions, lifecycle events, and evaluation records.

Reviewer-protected feedback derives bounded structured thresholds from recorded incident features; approval activates a version. The detector follows its proposal and supporting-evidence graph links and checks memory feature similarity before applying an active rule, then records memory/rule influence edges. The evaluation runs frozen baseline and active adaptive rule against identical held-out fixtures. The local UI uses the Vite `/api` proxy; `VITE_API_BASE` can select another origin in a separately hosted frontend.

HydraDB and SelfGraph provide persisted graph entities and relationships. Custos implements the detection rules, lifecycle policies, metrics and reviewer flow. Lifecycle writes are multiple graph operations protected by a single-process lock. A final relationship acts as a fail-closed commit marker, but the workflow is not an atomic distributed transaction.
