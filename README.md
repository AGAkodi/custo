# Custos

**An evidence-backed security intelligence demo with persistent graph memory.** Custos analyzes synthetic authentication events, records decisions in HydraDB, and lets a reviewer turn confirmed incident feedback into a candidate detection rule. A later held-out scenario shows how the approved rule and linked memory influence a decision.

[Open the demo](https://custo-production.up.railway.app/) · [Judge walkthrough](docs/demo-script.md) · [Evaluation](docs/evaluation.md) · [Architecture](docs/architecture.md)

The hosted demo requires a shared login. Reviewer actions require a separate token; request access from the project owner. Never commit credentials or publish them in an issue.

## What it demonstrates

1. A baseline rule misses a distributed credential-stuffing scenario.
2. A reviewer confirms the fixture outcome and inspects a feature-derived rule proposal.
3. Approval activates a version linked to its evidence and memory in HydraDB.
4. A held-out variation with different IP addresses and account IDs is assessed using that rule and memory.
5. The evaluation compares the baseline and adaptive versions on identical malicious and benign fixtures, including a difficult benign counterexample.

Custos uses deterministic heuristics and bounded thresholds for distributed-login and analyst-attested password-spray patterns. Reviewers can revise a proposed rule and its revision is recorded separately; approval is still required and the small regression suite still gates activation. Only one rule version can be active at a time. Scores are illustrative; it is not a general incident-learning system and does not perform automated response.

For sanitized custom incidents, reviewers can also look up related graph memories. Matches follow evidence links to prior assessments and show a feature similarity score. They are advisory, may include unapproved proposals, and do not themselves influence a decision. The search examines at most 100 memories. An approved rule and its supporting graph memory can influence the detector.

## Results and limitations

In a hosted twelve-incident synthetic evaluation, the baseline produced TP 0, FP 0, TN 8, FN 4; the adaptive rule produced TP 4, FP 4, TN 4, FN 0. The adaptive false-positive rate was 50% across eight benign incidents. This small, template-based sample does not establish real-world accuracy. During the hosted check, graph records remained visible after one HydraDB restart, and a subsequent decision cited the same rule and memory. See [evaluation methodology and results](docs/evaluation.md).

An offline evaluator can compare a frozen rule against independently collected, labeled authentication incidents and rejects overlapping incident IDs, IPs and accounts between the supplied splits. No independent real-world evaluation or measured false-positive reduction has been completed yet. The synthetic benign overlap cases remain important counterexamples.

The hosted reset is reviewer-protected and starts a fresh **shared** namespace while retaining earlier data. It affects all visitors, not individual judges. Keep one backend worker: lifecycle changes are multiple graph operations protected by an in-process lock, not an atomic distributed transaction. A storage update error has also been observed on an older local database volume; the brief hosted restart test is not a long-term durability guarantee.

## Architecture

The React/TypeScript frontend calls FastAPI. The simulator and deterministic detection engine produce assessments; SelfGraph connects the API to a self-hosted, pinned HydraDB container over Bolt. Incidents, evidence, memories, rule versions, lifecycle events, and decision influences are stored as graph entities and relationships. Railway hosts the web service and private HydraDB service with a persistent volume.

```text
React UI -> FastAPI -> simulator / detection / lifecycle
                         |                 |
                         +---- SelfGraph --+--> HydraDB
```

See [architecture](docs/architecture.md), [graph schema](docs/graph-schema.md), [lifecycle](docs/lifecycle.md), and [HydraDB integration notes](docs/hydradb-spike.md).

## Run locally

Prerequisites: Docker Desktop or Docker Engine, Python 3.12, and Node.js 22. Commands below are for PowerShell from the repository root.

1. Copy `.env.example` to `.env`. Set `HYDRADB_PASSWORD` to a long random value of at least 32 characters and set a separate random `REVIEWER_TOKEN`. Keep `.env` private.

   ```powershell
   Copy-Item .env.example .env
   # Edit .env and set HYDRADB_PASSWORD and REVIEWER_TOKEN.
   docker compose up -d
   ```

2. Start the API in a terminal:

   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements-dev.txt
   python -m uvicorn app.main:app --reload
   ```

3. Start the frontend in a second terminal:

   ```powershell
   cd frontend
   npm ci
   npm run dev
   ```

Open the URL printed by Vite, normally `http://localhost:5173`, and choose **Explore the demo**. The Vite server proxies `/api` to the API on port 8000. The local Docker database is bound to localhost and persists in a named volume. `GET /health` checks API liveness; `GET /ready` checks graph access. The API documentation is available at `http://localhost:8000/docs`.

For a password-free local judge demo, set `PASSWORDLESS_DEMO_ENABLED=true` in the API environment before starting it. Each browser receives an automatic, HttpOnly session cookie and its own graph namespace; reset starts a fresh namespace only for that browser. Reviewer actions need no token in this mode. Use synthetic data: namespaces are retained after reset, and clearing the browser cookie starts another workspace. This mode only activates in development with a localhost HydraDB URI; it is not enabled by this setting in production. Live Splunk delivery is disabled in this mode, although the offline preview remains available.

Optional: from `backend`, run `python -m app.seed` to insert the small foundation graph. The separate `python -m app.spike` reproduces the documented graph integration check.

## Tests

```powershell
# Backend, from backend/
python -m pytest -q
ruff check app tests

# Frontend, from frontend/
npm run build
```

Graph integration tests write to the configured HydraDB database. Against an **isolated test instance**, set `CUSTOS_INTEGRATION=1` before running pytest. Browser tests additionally require the API and Vite to be running against an isolated database and runtime directory; set matching test-only `REVIEWER_TOKEN` and `CUSTOS_E2E_TOKEN`, then run `npm run test:e2e` from `frontend`. These tests reset and change demo state. See [CI configuration](.github/workflows/ci.yml) for the setup.

The latest local verification passed 37 backend tests, including the password-free two-session graph test; four existing protected-mode browser tests; the password-free two-browser test; Ruff; and the frontend build. Two dependency deprecation warnings were reported. The password-free browser test uses `playwright.passwordless.config.ts` and expects its isolated API and frontend on ports 8006 and 5176 respectively; it must run with password-free mode enabled and an isolated HydraDB instance.

## Dataset and SOC extensions

The Data & SOC screen includes narrow CSV adapters for UNSW-NB15 and CICIDS2017 flow schemas, an experimental Sigma export for the baseline rule, and an optional Splunk HEC handoff. Bundled fixtures are fictional schema examples, not the public datasets. The flow heuristics are uncalibrated; the Sigma export approximates the baseline; and live Splunk delivery has not been validated. See [dataset and integration notes](docs/phase5.md).

## Deployment and access

See [Railway deployment notes](docs/railway.md) for services, persistent storage, environment variables, and hosted reset configuration. The demo is password-protected and intended for synthetic data, not production security operations. Backups, production authentication, distributed concurrency, and reliable long-term storage need further work.
