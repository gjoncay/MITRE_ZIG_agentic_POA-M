# MITRE CSD-H — Project Handoff Document

This is the operational handoff for the current working tree, updated on
**2026-07-12**. It describes the implemented system rather than an aspirational
design. The graph data, database schema, and route handlers are the source of
truth if this document ever drifts.

---

## 1. Mission and deployment boundary

MITRE CSD-H turns security-assessment findings and threat-intelligence artifacts
into evidence-backed, multi-framework remediation reports. A single input can
produce multiple ATT&CK technique candidates and multiple validated mappings per
candidate: ATT&CK, native mitigations, D3FEND, ZIG pillars/capabilities/activities,
CREF entities, NIST controls, and CSA context where graph evidence exists. The
system must never let a model invent a framework identifier or graph relationship.

There are deliberately two deployment paths:

1. **CLI / air-gapped path.** The graph and analyst pipeline work without a cloud
   provider, web server, Docker, or vector model. Heuristic narrative generation
   and deterministic keyword matching remain supported fallbacks.
2. **Web path.** FastAPI, SQLite, and the React UI provide durable runs, review,
   report lifecycle operations, progress, and PDF export. It is intended for a
   controlled local/Tailscale deployment, not an internet-facing multi-tenant
   service.

Keep those boundaries clear. A web-only lifecycle feature must not become an
air-gap dependency, and an air-gap-safe pipeline feature must not silently cause
network egress.

---

## 2. Current graph contract

The unified graph is a `networkx.MultiDiGraph`, not a simple `DiGraph`. Parallel
CSV rows and source records are meaningful provenance and are retained rather
than collapsed. The current checked graph is:

| Property | Current value |
|---|---:|
| Nodes | 5,618 |
| Edges / preserved edge rows | 43,387 |
| Snapshot ID | `sha256:c80084453b6ec9823f23777705dcc6625b424a2e84d5c50950be4881315bb2e8` |
| Graph schema | `2` |
| Mapping-matrix version | `1.0` |

`graph_snapshot_manifest.json` binds those counts, source CSV hashes, and the
stable edge-identity formula to one graph snapshot. `scripts/graph_engine.py`
validates the manifest by default. An edge records its dataset, source file, source
record index, endpoints, relationship type, and stable edge ID, so a displayed
mapping path can be traced back to source data.

The graph combines ATT&CK/D3FEND, NSA ZIG, CREF, the DoD Zero Trust crosswalk,
NIST SP 800-53 references, and CSA context from the generated CSV pairs. Do not
hand-edit those generated CSVs. Regenerate from their raw sources in this order:

```bash
python consolidate_mitre_data.py
python scripts/parse_zig_data.py
python consolidate_cref_data.py
python scripts/graph_engine.py --write-manifest --no-embeddings
```

After changing source graph data, the snapshot must be regenerated before the
runtime is considered valid. If semantic retrieval is wanted, regenerate the
embedding index on a connected build machine *after* the new snapshot exists:

```bash
python scripts/embed_graph.py
```

`scripts/embed_graph.py` may download a model while intentionally building an
index. Runtime loading never downloads one: it uses `local_files_only=True`, and
requires a valid `graph_embeddings.npz` plus `embedding_metadata.json` bound to
the exact graph snapshot. Missing, stale, or unavailable embeddings degrade to
typed lexical retrieval; they do not prevent deterministic mapping or report
generation.

Useful graph entry points:

- `scripts/graph_engine.py` — `KnowledgeGraphEngine`, deterministic mapping
  service, snapshot validation, optional semantic retrieval.
- `GraphRepository` — provenance-preserving `MultiDiGraph` loader/facade.
- `get_framework_bundle(technique_id)` — authoritative mapping bundle.
- `get_provenance_paths(technique_id)` — full validated source-to-target paths.
- `get_neighbors(...)` and `search_attack_techniques(...)` — typed, bounded
  retrieval methods.

Run this before diagnosing a graph issue:

```bash
./venv/bin/python scripts/graph_engine.py --no-embeddings
```

It should print the node count, edge count, and snapshot ID above (unless the
dataset was intentionally regenerated).

---

## 3. Analyst pipeline and multi-technique behavior

The active pipeline is `run_analyst_pipeline.py`, built around
`scripts/consolidate_findings.py`. The older `agent_batch_processor.py` remains
only as a compatibility path; do not use it as a model for new work.

The active flow is:

```text
artifact / pasted text
  -> normalized observations and evidence locators
  -> exact ATT&CK IDs and canonical names; typed semantic fallback when needed
  -> one or more technique candidates per observation
  -> deterministic framework bundle and all validated provenance paths per TTP
  -> bounded provider narrative/proofread/QA work (or heuristic fallback)
  -> Markdown + JSON report assets and durable review records
```

Important behavior:

- An observation is not limited to one TTP. For example, a CTI item containing
  six supported ATT&CK techniques creates six technique candidates and may
  contribute to six technique aggregates/reports.
- Exact literal ATT&CK IDs and canonical technique-name matches are deterministic.
  Semantic candidates are typed, scored, and explicitly marked for review where
  appropriate; they are not silently promoted to fact.
- Consolidation is by resolved ATT&CK technique, not by input row. One report may
  aggregate multiple source observations for the same technique.
- The report JSON retains the complete framework bundle, validated direct and
  inherited paths, mapping validation state, graph snapshot ID, source locators,
  evidence, provider metadata, and graph-tool audit when present.
- The model's prose is checked against graph-backed IDs. A provider cannot make
  an arbitrary framework ID authoritative by mentioning it in a draft.
- Heuristic/no-provider QA is deliberately `MANUAL_REVIEW_REQUIRED`; it is never
  treated as an automatic pass.

The legacy CLI still writes its standalone output to `reports/`. That is separate
from the web path. The web path does **not** use repository-root
`processed_assessment.csv` or global `reports/` as working state.

---

## 4. LLM graph crawling, provider boundaries, and embeddings

The LLM can inspect relevant graph facts, but it does not receive NetworkX, an
arbitrary node ID, a filesystem path, or a database handle. The optional
`GraphToolSession` in `scripts/llm_graph_tools.py` exposes only six read-only,
named actions:

| Tool | Purpose |
|---|---|
| `search_attack_techniques` | Typed ATT&CK candidate search |
| `get_node` | Read a previously returned opaque node handle |
| `get_neighbors` | Read bounded, typed one-edge-per-record neighbors |
| `get_framework_bundle` | Obtain authoritative framework path handles for an ATT&CK technique |
| `get_provenance_paths` | Read selected bounded, validated paths |
| `validate_selection` | Validate opaque ATT&CK selections against the current snapshot |

Handles are opaque and session-local. `ToolPolicy` has a hard maximum of 12
calls, 50 returned items, and 50 paths; the deployed default is six provider
requests per technique/report (`LLM_GRAPH_TOOL_MAX_CALLS=6`). The event stream
records a heartbeat before and after every provider request plus every executed
tool action. Cancellation is checked between requests, so a crawl cannot quietly
start another provider call after an operator cancels it; each individual provider
request is bounded by `LLM_REQUEST_TIMEOUT_SECONDS` (90 seconds by default).
The orchestrator records the tool-call audit, validates the final selection
against the deterministic technique being reported, and persists the audit in
report provenance. Invalid, malformed, or over-budget provider calls degrade
safely and require review; they do not open a general graph traversal capability.

`scripts/llm_providers.py` supports `none` (heuristic), `local`
(OpenAI-compatible local endpoint such as Ollama/LM Studio/vLLM), `openai`, and
`gemini`. Local and cloud providers share the constrained JSON action loop and
the same deterministic mapping boundary. Provider timing and degradation metadata
are emitted as progress events and stored with outputs.

**Answer to the recurring embedding question:** the web application initializes
the same graph engine as the CLI. Embeddings are optional and are used only for
typed candidate retrieval when a compatible local index and local model are
already available. Deterministic graph crawling, mapping, evidence paths, report
generation, and review do not depend on embeddings. Runtime startup does not
download a model.

Cloud providers require an explicit per-submission acknowledgement before artifact
evidence can be sent to OpenAI or Gemini. This is enforced even when the server's
default provider is cloud-based. `GET /api/config` exposes the safe submission
policy only; it never exposes keys or provider endpoint secrets.

---

## 5. Durable web architecture

`webapp/backend/` is now a durable run lifecycle, not an in-memory job tracker.
The default state root is `data/`:

```text
data/
├── csdh.sqlite3                 SQLite/WAL lifecycle database
└── runs/<run-uuid>/
    ├── upload/                  original submitted artifact
    ├── normalized/              run-local normalized observations.csv
    ├── mapping/                 reserved mapping workspace
    ├── pipeline_output/         isolated pipeline staging output
    ├── reports/<report-uuid>/   published Markdown and JSON assets
    ├── exports/<report-uuid>/   cached PDF assets
    └── trash/                   soft-deleted assets during undo retention
```

Each request has a UUID workspace. The database records runs, artifacts,
observations, evidence spans, technique candidates, graph paths, reports,
immutable revisions, review decisions, durable progress events, deletion audits,
and retries. SQLite uses WAL and short transactions so readers/SSE clients can
continue while the local worker records progress. Queued work is claimed
atomically and recoverable after restart; the default worker concurrency remains
one because graph/LLM analysis is resource-intensive, not because job state is
in memory.

`webapp/backend/pipeline_adapter.py` normalizes files directly into that run
workspace. It does not call the legacy root-writing ingestion helper. Supported
web inputs are `.csv`, `.xlsx`, `.xls`, `.txt`, `.md`, and `.json`; JSON supports
generic structured threat intelligence and STIX-style objects while preserving
source object locators. Upload validation includes extension/content checks,
spreadsheet archive limits, UTF-8 validation for text-like inputs, input-size
limits, and normalization ceilings.

The report-detail API joins evidence only to the candidates actually represented
by that report, then exposes candidates, complete graph paths, revision history,
review decisions, provider/tool provenance, and the graph snapshot used for the
mapping.

---

## 6. Review gate, delete/restore, retry, and progress semantics

### Review gate

Generation finishing is not automatically a successful run. A run becomes
`awaiting_review` while it contains flagged/manual-review/rework states or
unresolved observations. The Review queue and run counters show what remains.
Review decisions require a server-authenticated actor and a non-empty note/reason,
and use optimistic concurrency (`version` or `If-Match`) to prevent stale UI
actions from overwriting newer decisions. In enabled authentication modes, any
legacy body `actor` value must match the authenticated principal; the stored audit
actor is always derived server-side.

`completed` means there are no remaining pending review states. The default
policy deliberately treats a rejection as `needs_rework`, not a pass: its
immutable review decision is retained, but the report stays in the review queue
and the run remains `awaiting_review` until it receives an accepted disposition
(`approved`, `waived`, or an eligible `auto_passed`) or a replacement run is
reviewed. This implements the operational rule that flagged/rejected work must
not silently turn a run green. If the organization requires literal approval for
every report, remove `waived`/`auto_passed` from the terminal policy and add the
corresponding tests—never infer approval merely from a completed label.

### Deletion and restoration

Deleting a report requires a server-authenticated actor, a non-empty reason, and
the current report version. It is enabled only after an accepted disposition
(`approved`, `waived`, `auto_passed`, or read-only `legacy`) so deletion cannot
bypass the review gate; waive an intentionally inapplicable report first if
retention removal is needed. The backend journals the operation in SQLite before
it moves report assets into the run-local `trash/` directory. This makes a
partial filesystem operation recoverable after a crash. Restore uses the same
server-derived identity and is available until the configured retention window
expires (default derives from `REPORT_DELETE_RETENTION_DAYS`, normally 30 days).

An explicit maintenance command safely purges expired trashed assets only. It
keeps the deletion/audit tombstone rather than erasing the fact of deletion:

```bash
# Dry run (the default): inspect what is eligible.
python -m webapp.backend.maintenance --data-dir data

# Apply only after normal backup/retention checks.
python -m webapp.backend.maintenance --data-dir data --apply
```

The Reports workspace exposes a paginated Trash / restore filter and a timed
undo notice after deletion. The Review Queue is separately paginated from the
server-side pending-state set, so a backlog beyond one browser page cannot be
mistaken for an empty or completed queue.

### Retry and reprocess

`POST /api/runs/{run_id}/retry` copies the retained artifact into a new UUID
workspace and records `retry_of_run_id`. Report-level retry is intentionally a
source-run retry, because one artifact can make multiple technique reports:
`POST /api/reports/{report_id}/retry-source-run`. The older
`/api/reports/{report_id}/reprocess` route is a deprecated alias for that same
operation. The source upload is checked before a retry row is created; a missing
retained upload returns `retry_source_unavailable` and never leaves an orphaned
queued run. A later retry-preparation failure is recorded as a terminal,
auditable `retry_preparation_failed` event rather than being sent to a worker
with zero artifacts.

### Restart and graceful shutdown

At startup, interrupted `queued`, `running`, or `analysis_finished` work is
reserved before recovery. The service removes only derived observations,
candidates, revisions, report assets, and staging output, then replays the
immutable source artifact in its own workspace. It never tries to merge a
half-completed provider response or retain a partially published report.

On graceful shutdown the worker stops accepting new work, cancels unstarted
futures, signals active pipeline checkpoints, and joins its worker threads before
the FastAPI lifespan closes. A shutdown interruption is returned to `queued`, not
misreported as an analyst cancellation; the next healthy startup performs the
safe reset-and-replay sequence. A provider that does not return from its configured
request timeout may delay graceful shutdown, because Python cannot safely kill a
thread that might still be writing evidence or SQLite state.

### Progress

Every meaningful lifecycle and pipeline transition is appended as a durable
event. Events contain a phase/message plus current item, counters, elapsed time,
and where available provider timings, throughput, and ETA. Bounded LLM graph
crawls also emit per-request start/finish and per-tool-action events, so an
operator can see whether the analyst is awaiting a model response or navigating
the graph. The React progress
screen uses SSE first and polls the run snapshot as a fallback, so an operator
can see normalization, candidate generation, deterministic mapping, model work,
report publication, review backlog, cancellation, failure, and retry status.

Progress/ETA are estimates based on observed completed items; they are not a
promise of model latency or a substitute for reviewing the final evidence.

---

## 7. Current HTTP API contract

The React SPA is served by the same FastAPI process when its built `dist/` is
present. All routes below are same-origin `/api/...` routes. In production they
require a configured authentication mode and role-appropriate server principal;
`/api/config` and `/api/health` expose readiness information rather than secrets.

| Method and path | Contract |
|---|---|
| `POST /api/runs` | Create a durable run from one multipart `file` or pasted `text`; optional `provider` and `cloud_acknowledged`. Returns a run snapshot, HTTP 202. |
| `POST /api/analyze` | Compatibility submission alias. Returns `{ "job_id": ... }`. |
| `GET /api/runs` | Paginated/searchable run list (`status`, `search`, `page`, `page_size`/`limit`). |
| `GET /api/config` | Safe provider/consent and authentication-mode/readiness policy for the submission UI; no secrets. |
| `POST /api/session` | Exchange an authenticated bearer token for an HttpOnly, same-origin session cookie so browser `EventSource` can authenticate without putting a token in a query string. |
| `GET /api/runs/{run_id}` | Durable run snapshot, counters, metrics, report states, and report IDs. |
| `POST /api/runs/{run_id}/cancel` | Request cooperative cancellation. |
| `POST /api/runs/{run_id}/retry` | Create and schedule a new run from the retained source artifact. |
| `GET /api/runs/{run_id}/events` | Server-Sent Events. Supports `after` and `Last-Event-ID`; JSON carries the durable event type. |
| `GET /api/jobs/{job_id}` | Backward-compatible job-status projection. |
| `GET /api/reports` | Search/filter/paginate reports by run, technique, lifecycle/review state, QA verdict, and text; `include_deleted` is explicit. |
| `GET /api/reports/{report_id}` | Full current report: evidence, candidates, graph paths, revisions, reviews, and provenance. |
| `GET /api/reports/{report_id}/revisions/{revision_id}` | A specified immutable revision with the same provenance view. |
| `GET /api/reports/{report_id}/markdown` | Current published Markdown asset. |
| `PATCH /api/reports/{report_id}/review` | Record approved/rework/rejected/waived review decision; authenticated reviewer, matching legacy actor field, note/reason, and current version required. |
| `DELETE /api/reports/{report_id}` | Journaled soft delete; authenticated delete-capable actor, reason, and current version required. |
| `POST /api/reports/{report_id}/restore` | Restore a soft-deleted report before its undo window expires, with a delete-capable authenticated actor and current version. |
| `POST /api/reports/{report_id}/retry-source-run` | Retry the complete retained source run for a report. |
| `POST /api/reports/{report_id}/reprocess` | Deprecated alias of `retry-source-run`. |
| `POST /api/reports/{report_id}/pdf` | Render/cache the current Markdown as a PDF. |
| `GET /api/health` | Graph health, node/edge counts, graph snapshot, semantic-search state, and database location. |

Errors have a stable `error.code`/`error.message` envelope while retaining a
`detail` field for older clients. The frontend routes are `/new`, `/runs`,
`/runs/:id/progress`, `/review`, and `/reports/:id`.

### Authentication boundary

Production startup defaults to `CSDH_AUTH_MODE=token` and requires a valid
`CSDH_AUTH_TOKENS_JSON` token-to-principal map (a protected single-token setting
is also supported for a small private deployment). A bearer token maps to a
server-side actor and roles (`viewer`, `analyst`, `reviewer`, or `admin`); client
body fields cannot impersonate a different reviewer. Missing or invalid token
configuration leaves authenticated routes unavailable rather than silently
falling back to anonymous access.

`CSDH_AUTH_MODE=trusted_proxy` is for an authenticated reverse proxy/SSO boundary
only. Use it only when the application is reachable exclusively through that
proxy and the proxy strips and replaces the configured user/role headers. Tailnet
reachability alone is not an identity assertion. `CSDH_AUTH_MODE=disabled` is an
explicit local/in-process development mode, where the legacy actor field is kept
as audit metadata; it must never be used for production.

For browser SSE, `POST /api/session` accepts an already-authenticated bearer
request and sets the `HttpOnly`, same-origin `csdh_session` cookie. This is needed
because native `EventSource` cannot attach an `Authorization` header. Keep the
cookie secure (`CSDH_SESSION_COOKIE_SECURE=true` in HTTPS deployments) and do not
put bearer tokens in URLs.

---

## 8. Legacy reports and migration

Loose historical `reports/*.md` and `reports/*.json` files have no original
artifact, source-to-candidate links, durable graph paths, revisions, or credible
identity provenance. They are not silently mixed into the new lifecycle.

Import them explicitly as read-only `legacy` records:

```bash
# Inspect what would be imported; does not create a database/workspace.
python -m webapp.backend.legacy_import --source-dir reports --data-dir data

# Perform the explicit migration.
python -m webapp.backend.legacy_import --source-dir reports --data-dir data --apply
```

Imported legacy records can be discovered and retained/deleted through the web
store, but cannot be reviewed or source-run-retried as if their historical report
were original evidence. Re-submit the original assessment/CTI artifact to create
a reviewable durable run with validated candidate/path provenance.

---

## 9. Directory map

```text
MITRE_CSD-H/
├── mitre_*.csv, zig_*.csv, cref_*.csv      generated graph inputs; do not hand-edit
├── graph_snapshot_manifest.json             required graph identity/row-count manifest
├── graph_embeddings.npz, embedding_metadata.json
│                                            optional, snapshot-bound semantic index
├── scripts/
│   ├── graph_engine.py                      MultiDiGraph repository + mapping service
│   ├── llm_graph_tools.py                   bounded opaque-handle graph capability
│   ├── llm_providers.py                     local/cloud/heuristic providers
│   ├── consolidate_findings.py              multi-TTP evidence-to-candidate consolidation
│   ├── ingest_assessment.py                 legacy/CLI ingestion helper
│   ├── embed_graph.py                       intentional connected-build index generator
│   └── parse_zig_data.py                    ZIG generator
├── run_analyst_pipeline.py                  active CLI/importable pipeline
├── webapp/
│   ├── backend/
│   │   ├── main.py                          FastAPI routes + durable worker
│   │   ├── db.py                            SQLite/WAL repository and lifecycle policy
│   │   ├── workspace.py                     UUID workspace/path-safe asset operations
│   │   ├── pipeline_adapter.py              run-local normalization/adapter
│   │   ├── validation.py                    submission validation
│   │   ├── legacy_import.py                 explicit historical report import
│   │   ├── maintenance.py                   retention/recovery maintenance
│   │   └── pdf_export.py                    constrained Markdown-to-PDF rendering
│   └── frontend/                            Vite/React lifecycle, review, and report UI
├── tests/, webapp/backend/tests/            graph, tools, pipeline, adapter, lifecycle tests
├── data/                                    runtime database/workspaces; do not commit
├── reports/                                 legacy CLI output; do not use as web state
└── Makefile                                 test/build/operational shortcuts
```

The auto-generated deployment/reconstruction guides are still generated from
their respective `build_*.py` scripts. Do not hand-edit those generated files.
When changing an embedded source file, update the generator as needed and
regenerate the relevant guides.

---

## 10. Safe operating commands

```bash
# Activate the project environment.
source venv/bin/activate

# Validate graph loading without optional semantic-model startup.
python scripts/graph_engine.py --no-embeddings

# Run the active CLI path (heuristic mode by default).
python run_analyst_pipeline.py

# Syntax/tests/frontend build. `make verify` expects pytest test dependencies.
make verify

# Web development/production process (use the documented Compose deployment for Tailscale).
uvicorn webapp.backend.main:app --host 127.0.0.1 --port 8000
```

For Docker/Tailscale-specific setup, use `README.md`, `.env.example`,
`docker-compose.yml`, and `TAILSCALE_SIDECAR.md` rather than copying secrets or
host-specific network values from an old handoff note. Never commit `.env`,
`data/`, `reports/`, uploads, generated frontend `dist/`, or `node_modules/`.

---

## 11. Known limitations and follow-up boundaries

These are deliberate current limits, not evidence that the durable workflow is
in-memory or incomplete:

1. **Authentication is configured, but it is not a multi-tenant IAM product.**
   Production must use `CSDH_AUTH_MODE=token` with
   `CSDH_AUTH_TOKENS_JSON`, or a correctly isolated `trusted_proxy` that asserts
   identity and roles. The backend stores the server-derived principal rather
   than trusting a caller-supplied actor string. Static bearer roles and trusted
   proxy headers are intentionally a small deployment boundary; enterprise SSO,
   token rotation automation, tenant isolation, and richer policy administration
   remain deployment/integration work. Never set `disabled` outside explicit
   local development.
2. **Single-host operational model.** SQLite/WAL and atomic claims make restart
   recovery and local concurrency safe, but this is not a distributed queue or
   multi-node scheduler. Keep the default one analysis worker unless capacity,
   SQLite locking, and provider limits have been tested for the chosen host.
3. **No native PDF or DOCX threat-intelligence adapter.** Submit extracted text,
   Markdown, CSV/XLS(X), or supported JSON/STIX today. Adding a document parser
   needs explicit extraction security, provenance locators, and test fixtures;
   do not simply pass opaque PDFs to an LLM.
4. **Legacy report import is intentionally limited.** It provides controlled
   visibility and retention, not retroactive evidence provenance or safe
   reprocessing.
5. **Embeddings are optional and local-only at runtime.** Semantic retrieval
   is a quality enhancement, not a prerequisite. A compatible model/index must
   be pre-provisioned.
6. **Completion means no pending disposition, not universal approval.** See the
   review-gate policy above if a stricter all-approved definition is required.
7. **`ontology.json` and `import_to_neo4j.py` remain narrower exports.** They do
   not yet model the full ZIG/CREF graph and should not be advertised as a
   substitute for the authoritative in-process graph.
8. **Gemini client maintenance remains due.** The current
   `google-generativeai` compatibility path is upstream-deprecated; migrate to
   the maintained SDK under a separately tested change.

---

## Keeping this document honest

This document is hand-maintained. Before changing a cross-cutting behavior,
read the owning module and its tests, then update this handoff in the same change.
For graph claims, run `scripts/graph_engine.py --no-embeddings`; for web behavior,
inspect `webapp/backend/main.py`, `db.py`, and the lifecycle tests; for the UI,
build `webapp/frontend`. Do not restore the old assumptions that web jobs live
only in memory, that all web runs share `processed_assessment.csv`, or that runtime
embedding startup may download a model—those are specifically no longer true.
