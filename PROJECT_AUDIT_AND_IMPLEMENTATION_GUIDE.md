# MITRE CSD-H Audit and Implementation Guide

## Implementation status

**Implemented in the current working tree on 2026-07-12.** This document began as a
read-only audit and implementation handoff. Its baseline findings and phased design
remain below so that a future maintainer can understand the decisions, but the listed
P0/P1 workflow changes have now been implemented and verified with the project-local
test and smoke-test suite. Treat the sections below as the rationale and acceptance
criteria; trust the source files and generated manifests for live details.

### Delivered architecture

| Area | Delivered behavior | Main implementation |
|---|---|---|
| Graph integrity | Every source relation is retained with a stable edge ID, relationship type, provenance, and deterministic graph snapshot manifest. | `scripts/graph_engine.py`, the three graph generators, `graph_snapshot_manifest.json` |
| Multi-mapping | One artifact/observation can retain many literal or canonical ATT&CK matches. Each result records evidence, candidate method/score/state, and every validated graph path. | `scripts/consolidate_findings.py`, `run_analyst_pipeline.py`, `scripts/report_schema.py` |
| Bounded analyst crawl | A local or provider LLM may call only named, read-only graph tools through opaque handles and a bounded call/result/path budget. It cannot issue arbitrary graph or filesystem queries; each provider request emits progress and is cancellation-checked before the next call. | `scripts/llm_graph_tools.py`, `scripts/llm_providers.py` |
| Durable lifecycle | Runs, artifacts, observations, candidates, graph paths, report revisions, reviews, events, and deletion audit records are persisted in SQLite/WAL under isolated UUID workspaces. Interrupted work is reset to immutable-source replay on recovery; graceful shutdown joins workers before database/workspace ownership ends. | `webapp/backend/db.py`, `workspace.py`, `main.py` |
| Review-gated completion | A run becomes `awaiting_review` until every required report has an accepted outcome. Heuristic/degraded/low-confidence output is never silently treated as a pass. | `webapp/backend/main.py`, `run_analyst_pipeline.py` |
| UI operations | The UI supports paginated run/review/report history, streamed progress with polling fallback, per-provider crawl activity, report review, soft delete/restore/trash, isolated reprocess/retry, and path-level mapping inspection. | `webapp/frontend/src/` |
| Input normalization | The web workflow accepts tabular data, free text/Markdown, generic JSON, and STIX-style JSON while retaining source locators and object context. | `webapp/backend/pipeline_adapter.py` |
| Operational safety | Cloud provider use requires explicit acknowledgement; runtime embedding loading is local-only; legacy loose reports have an explicit dry-run importer; expired soft-deleted assets use an explicit dry-run maintenance command. | `main.py`, `legacy_import.py`, `maintenance.py`, `scripts/graph_engine.py` |

### Important operating boundaries

- “All relevant” means all paths allowed by the versioned mapping matrix, within
  explicit limits; it does not mean an unbounded LLM graph walk.
- The graph and deterministic validation remain the authority. LLM selections and
  prose are auditable additions, never the source of framework identifiers.
- Embeddings are optional typed candidate retrieval only. They are not required for
  graph expansion, never download at runtime, and a stale/incompatible index is
  rejected rather than silently used.
- Production deployments require configured application token authentication or a
  trusted authenticated reverse proxy. In either mode the server derives the audit
  actor and enforces roles; a body `actor` value is only checked for consistency.
  `CSDH_AUTH_MODE=disabled` is an explicit development-only setting, not production
  access control.
- Native adapters currently cover `.xlsx`, `.xls`, `.csv`, `.json`/STIX, `.txt`,
  `.md`, and pasted text. PDF/DOCX extraction/OCR is deliberately not fabricated by
  this implementation; add a traceable extractor as a separate adapter before
  accepting those formats.
- Legacy loose reports can be imported as immutable `legacy` records for browsing or
  deletion retention. They are not silently represented as fully provenance-backed
  results and cannot be approved through the new review workflow.
- Soft deletion is available after an accepted disposition only; it never removes a
  flagged/manual/rework item from the review gate. Use an audited waiver before
  deleting an intentionally inapplicable result.

### Required verification before release

Run the repository checks after dependency installation, and run the two lifecycle
operations in dry-run mode before applying them in production:

```bash
make verify
python -m webapp.backend.legacy_import --source-dir reports --data-dir data
python -m webapp.backend.maintenance --data-dir data
```

Use `--apply` only after inspecting each dry-run summary. The tests exercise graph
edge preservation, multi-TTP mapping, constrained graph-tool calls, STIX/JSON source
locators, review/delete/restore concurrency, cloud-consent enforcement, and run
completion policy.

## Historical audit baseline

The rest of this document records the pre-implementation audit, detailed functional
contract, migration plan, and acceptance criteria. Historical wording such as
“current implementation cannot yet” describes the audited baseline, not the current
working tree.

## Executive conclusion

The project has a strong data mission and useful initial pipeline, but the current
implementation cannot yet make the promise that a local or hosted LLM "crawls all
relevant graph entities" and produces review-ready reports safely.

The main issue is not prompt quality. It is data integrity and lifecycle design:

- The runtime graph silently discards some relationships.
- A report is identified only by ATT&CK technique, so later runs overwrite earlier
  evidence and reports.
- The web application shares one input file and one output folder across all jobs.
- The LLM only writes/proofreads/reviews prose; it has no constrained graph-tool loop.
- A job is marked done even if reports are flagged, and heuristic output calls itself
  PASS despite requiring manual review.
- The UI has neither durable jobs nor report-review/delete lifecycle data to operate on.

The correct order is therefore:

1. Preserve every graph edge and make graph materialization deterministic.
2. Create durable run, artifact, observation, mapping, report-version, review, and
   event records.
3. Replace ambiguous/first-hit mapping with evidence-backed candidate selection and
   validated graph paths.
4. Add a bounded, read-only LLM graph-tool loop on top of that deterministic core.
5. Build review gating, deletion, and live progress against durable records.
6. Harden and test the entire flow before making it the default.

## Audit baseline and evidence

The audited graph loaded as 5,618 nodes and 43,194 runtime edges. The source edge CSVs
contain 43,387 rows. The difference is significant: 193 source rows collapse when
loaded into the current `networkx.DiGraph`, and 44 source/target pairs contain multiple
different relationship types. For example:

- `OA-SHARED-LIBRARY-FILE → T1055.001` has both `loads` and `adds`.
- `CREF-TECH-1 → CREF-STA-1` has both `informs_principle` and
  `requires_principle`.

`scripts/graph_engine.py` constructs `nx.DiGraph()` and adds edges by source/target
only. A later relationship overwrites an earlier one. Both graph regeneration scripts
also collect edges in Python sets and write them unsorted, so even the relationship
that survives can vary after regenerating identical data.

Other verified facts:

- There are 697 ATT&CK technique nodes, including 475 sub-techniques.
- Only 182 ATT&CK nodes have direct ZIG/CREF/CREF-mitigation crosswalks; no
  sub-technique has a direct mapping in the current data.
- The current pipeline can map multiple explicit ATT&CK IDs and canonical technique
  names from an artifact. A six-ID artifact generated six technique groups in an
  offline test.
- The current uncommitted canonical-name prototype needs correction before merge: its
  regex boundary string is double-escaped (`r'(?<!\\\\w)'` / `r'(?!\\\\w)'`), so it
  does not enforce true word boundaries. The new matcher also needs longest-specific
  matching and parent/sub-technique de-duplication rather than a scan of every node per
  observation.
- The current pipeline maps ambiguous prose to one top semantic result. It cannot
  safely identify six implied techniques from one ambiguous sentence.
- Existing loose report JSON files predate the current `framework_mappings` schema, so
  they have null/absent mapping data while the UI treats them as live reports.
- No automated Python, API, frontend, integration, or CI test suite currently exists.

## Required behavior contract

Before implementation, agree that these terms mean the following.

### Artifact hierarchy

The canonical data hierarchy must be:

```text
Run
  └─ Artifact
       └─ Observation
            └─ Technique candidate / match
                 └─ Validated graph mapping paths
                      └─ Report revision
                           └─ QA and human-review decisions
```

Definitions:

- A **run** is one user-initiated analysis request.
- An **artifact** is one uploaded file, pasted body, STIX bundle, PDF, or other input.
- An **observation** is a traceable row, sheet row, sentence/chunk, STIX object, or
  extracted finding from that artifact.
- A **technique candidate** is a possible ATT&CK mapping with method, score, and exact
  evidence span.
- A **validated mapping path** is an ordered list of real graph nodes and edges.
- A **report revision** is an immutable rendered result. It is not just a mutable
  `CONSOL-Txxxx.md` filename.

One artifact may produce zero, one, or many observations. One observation may produce
zero, one, or many technique candidates. A six-TTP CTI artifact must preserve the fact
that all six mappings came from that exact artifact and evidence span.

An aggregate "all T1055 findings" report is valuable, but it must be a derived view,
not the identity of source evidence. Use an optional consolidation view after source
records have been persisted.

### Meaning of "all relevant entities"

"All relevant" cannot mean an unbounded graph crawl. It must mean:

1. Every relationship permitted by a **versioned mapping matrix** is enumerated for a
   selected ATT&CK technique, subject to explicit depth and result limits.
2. Every returned node and edge has a real graph ID, relationship type, source graph
   version, and ordered provenance path.
3. An empty category is recorded explicitly as `not_mapped`; it is never replaced with
   an authoritative-looking keyword guess.
4. Inherited parent-technique mappings are allowed only when labeled
   `mapping_scope: inherited_parent`; they must never appear as direct child mappings.
5. Any inferred or semantic candidate is visibly lower-confidence and requires a
   deterministic validation result and, when policy requires it, human review.

The initial mapping matrix should include at least:

| Starting entity | Allowed verified paths | Result category |
|---|---|---|
| ATT&CK technique | `belongs_to_tactic` | ATT&CK tactic |
| ATT&CK technique | native mitigation / analytics / detection / D3FEND paths | tactical detection and mitigation |
| ATT&CK technique | reverse `mitigates` from ZIG Activity → `belongs_to_capability` → `belongs_to_pillar` | ZIG activity, capability, pillar |
| ATT&CK technique | reverse `mitigates_architecturally` from CREF Approach → `realizes_technique` → `achieves_objective` → `serves_goal`; plus `has_effect` | CREF resiliency chain |
| ATT&CK technique | reverse `mitigates` from both `cref_mitigation` **and** native `attack_mitigation` nodes → controls, activities, approaches | NIST/ZIG/CREF mitigation chain |
| CREF technique | reverse `associated_with_technique` | CSA impact |
| ATT&CK sub-technique | `subtechnique_of` to parent, then one of the above | inherited parent mapping, explicitly labeled |

The matrix must be stored in code and versioned. A report should show a concise
presentation, while JSON/API data carries all paths and any explicitly empty categories.

### Completion policy

Separate **execution completed** from **accepted**:

```text
queued → running → analysis_finished → awaiting_review → completed
                            │                  │
                            └──────────────→ failed / canceled
```

At report level, use more precise states:

```text
draft → mapping_validated → qa_pending
      → auto_passed | auto_flagged | manual_review_required
      → approved | needs_rework | rejected | archived | deleted
```

Recommended default policy:

- A run reaches `analysis_finished` after all generation work has stopped.
- It reaches `awaiting_review` if any report is flagged, unresolved,
  low-confidence, degraded, heuristic-only, or otherwise requires a reviewer.
- It reaches `completed` only when every required report is explicitly approved or
  meets the configured automatic-acceptance policy.
- Heuristic/no-provider output is `manual_review_required`, never automatic PASS.
- Automatic revise-and-re-QA is bounded, for example two attempts. A model must never
  loop indefinitely merely to make a FLAG disappear.

## Priority audit findings

### P0 — graph relation loss

Affected files: `scripts/graph_engine.py`, `consolidate_mitre_data.py`,
`consolidate_cref_data.py`, all traversal callers.

Why it matters: no later LLM or UI can recover an edge that the in-memory graph has
discarded. This directly violates the mission requirement to match all relevant nodes
and relationships.

Required correction:

1. Replace the runtime `nx.DiGraph` with `nx.MultiDiGraph`, or introduce a graph facade
   that preserves an ordered list of relationship objects per source/target pair.
2. Give each imported edge a stable `edge_id`, such as a deterministic hash of dataset
   version, source ID, target ID, relationship type, and source-row identity.
3. Preserve `relationship_type`, dataset/source file, source row or source record, and
   any confidence/source metadata on each edge.
4. Refactor direct `graph.in_edges`, `out_edges`, and `get_edge_data` usage behind graph
   repository methods so callers cannot accidentally drop edge keys.
5. Sort all source exports deterministically before writing CSVs. Do not serialize a
   Python set directly.
6. Add a graph invariant test that loaded edge count equals raw CSV edge-row count and
   that every unique `(source, target, relationship_type)` survives loading.

Do not start LLM tool-calling work until this test passes.

### P0 — shared job files and report overwrite

Affected files: `webapp/backend/main.py`, `scripts/ingest_assessment.py`,
`run_analyst_pipeline.py`.

Current failure modes:

- All web jobs write to root `processed_assessment.csv`.
- File ingestion also overwrites root assessment embedding/metadata files.
- All reports use `CONSOL-<TTP>` paths, overwriting history on later runs.
- `run_in_executor` allows more than one job to run, so two users can cross-contaminate
  input and output.
- A report cannot be reliably deleted, reviewed, or attributed to an artifact because
  it has no run-scoped identity.

Required correction:

1. Create a workspace per run: `data/runs/<run_uuid>/`.
2. Store `upload/`, `normalized/`, `mapping/`, `reports/`, and `exports/` beneath that
   workspace.
3. Never use root `processed_assessment.csv` or global report paths from the web path.
4. Write temporary files, validate them, then atomically rename and publish their DB
   record in one transaction.
5. Use a UUID as report identity. Keep `CONSOL-Txxxx` only as a display label or a
   queryable aggregate key.
6. Use a durable bounded worker. SQLite is sufficient for the single-host deployment;
   use Postgres only when multi-user/high-availability requirements are real.

### P0 — LLM behavior does not match requested graph crawling

Affected files: `scripts/llm_providers.py`, `run_analyst_pipeline.py`,
`scripts/consolidate_findings.py`, `threat_assessment_skill.md`.

The current automated LLM receives a serialized context after deterministic code has
already crawled the graph. It can draft narrative, proofread Markdown, and return a QA
verdict, but it cannot query graph nodes or paths. The interactive skill document
describes an agent workflow that the automated pipeline does not execute.

Required correction: create one graph mapping service that is used by CLI, web, and
LLM tools. Do not replicate manual-agent crawl logic in a third location.

### P0 — unsafe lifecycle for review/delete/progress

Current UI features cannot be safely bolted on because job status is an in-memory dict,
report files are mutable loose files, and there is no review or audit model. Build
persistence first, then endpoints, then UI.

### P0 — deployment secret leakage

There is no `.dockerignore`, but the Dockerfile uses `COPY . .`. A local `.env`, `.git`,
`venv`, uploads, reports, and other ignored files can enter the build context and image
layers. This can leak Tailscale/provider credentials and makes builds unnecessarily large.

Add a deny-first `.dockerignore`, replace broad copies with allowlisted `COPY` steps,
run the container as a dedicated non-root UID/GID, and remove `chmod 0666` output
workarounds. Use proper volume ownership or ACLs instead.

## Proposed durable data model

Use SQLite with WAL mode for the local/Tailscale web application. Wrap all SQL in a small
repository layer. Do not expose raw SQL in route handlers.

### Tables

| Table | Minimum fields | Purpose |
|---|---|---|
| `analysis_runs` | `id`, `status`, `created_at`, `started_at`, `finished_at`, `policy_version`, `graph_snapshot_id`, requested/effective provider/model, `degraded_reason`, counters, `error` | one requested analysis |
| `artifacts` | `id`, `run_id`, original name/type, SHA-256, storage key, byte size, classification/redaction policy | immutable input artifact |
| `observations` | `id`, `artifact_id`, source locator (sheet,row/chunk/STIX ID), raw text hash, normalized text, asset metadata, parse status | traceable unit of analysis |
| `evidence_spans` | `id`, `observation_id`, start/end offsets, text, field/source locator | evidence used for a mapping |
| `technique_candidates` | `id`, `observation_id`, technique ID, method, score, evidence span IDs, candidate rank, state, reason | direct/exact/semantic/LLM candidate decisions |
| `graph_paths` | `id`, `candidate_id`, category, scope, ordered node/edge JSON, graph snapshot ID, validation state | every verified direct/inherited mapping path |
| `reports` | `id`, `run_id`, aggregate key, current revision ID, lifecycle state | stable report identity |
| `report_revisions` | `id`, `report_id`, number, mapping snapshot hash, narrative JSON, Markdown path, JSON path, PDF path, content hashes, QA state | immutable output version |
| `review_decisions` | `id`, `report_revision_id`, actor ID, decision, reason, notes, timestamp | human review record |
| `job_events` | `run_id`, monotonic sequence, timestamp, event type, structured JSON payload | progress/reconnect/audit timeline |
| `deletion_audit` | target type/ID, actor, reason, request time, tombstone/trash path, undo expiry | controlled deletion trail |

Recommended constraints:

- `UNIQUE(run_id, artifact_sha256, policy_version)` where idempotency is desired.
- `UNIQUE(observation_id, technique_id, method, evidence_span_set_hash)` for candidate
  idempotency.
- Every graph path references a graph snapshot and has a validator result.
- Every report revision is immutable after publication.
- A delete is a state transition/tombstone, not an immediate unlogged `os.remove`.

### Graph snapshot manifest

Generate and store a manifest for every graph build:

```json
{
  "graph_snapshot_id": "sha256:...",
  "node_csv_hashes": {"mitre": "...", "zig": "...", "cref": "..."},
  "edge_csv_hashes": {"mitre": "...", "zig": "...", "cref": "..."},
  "node_count": 5618,
  "edge_row_count": 43387,
  "runtime_edge_count": 43387,
  "embedding_model": "all-MiniLM-L6-v2",
  "embedding_dimension": 384,
  "embedding_node_order_hash": "..."
}
```

The runtime must fail readiness/startup when required CSVs, schema, counts, or embedding
manifest data disagree. Do not print an error and continue with a partial graph.

## Mapping and LLM architecture

### Core rule

The LLM may help **select, rank, explain, and narrate**. It may not create graph facts.
Only deterministic code can turn a final selection into a node ID, edge, path, or report
mapping.

### Stage A — artifact ingestion and normalization

Support inputs through named adapters rather than a single loose dataframe heuristic:

- CSV/XLSX assessment exports.
- Pasted threat intelligence.
- ATT&CK group/software technique exports.
- STIX JSON bundles when explicitly added.
- PDF/DOCX/text extraction adapters when explicitly added.
- Vulnerability exports with CVE, asset, severity, finding, and remediation fields.

Each adapter must return observations with a source locator and a standard schema:

```json
{
  "observation_id": "...",
  "artifact_id": "...",
  "source": {"kind": "xlsx_row", "sheet": "Findings", "row": 42},
  "behavior_text": "...",
  "context_text": "...",
  "asset": {"ip": "...", "hostname": "..."},
  "severity": "High",
  "explicit_ids": ["T1566"],
  "evidence_spans": []
}
```

Keep sheet metadata as context, not behavior evidence. The current approach copies sheet
metadata into every row and then searches every column, so one ID in a sheet header can
map every row incorrectly.

Do not truncate source evidence silently. The current pasted-text path truncates chunks
at 500 characters; instead retain full source text and use a separate model-context
excerpt with a recorded range.

### Stage B — candidate generation

Generate candidates in this order:

1. Valid explicit ATT&CK IDs and aliases.
2. Exact canonical names and curated aliases, using longest/specific-first matching.
3. Typed lexical retrieval against ATT&CK technique names/descriptions only.
4. Typed vector retrieval against ATT&CK techniques only, when the local model and
   compatible embedding manifest are available.
5. Optional LLM-assisted choice among returned opaque candidates.

Rules:

- Do not rank all 5,618 node types and filter after the fact. The current untyped search
  can push an appropriate technique below unrelated analytics or artifacts.
- Suppress a parent technique when a more specific sub-technique is matched by the same
  evidence span, unless a separate span supports the parent.
- Implement real Unicode-aware token boundaries; do not retain the current prototype's
  double-escaped `\\w` lookarounds, which match inside longer words.
- Require a configurable score threshold and margin over the next candidate. Below the
  threshold/margin, write candidates as `needs_review` rather than selecting one.
- Record exact evidence span, method, score, retrieval model/index version, and all
  rejected candidates.

### Stage C — constrained graph tools

Expose a narrow read-only tool interface to all providers. Native tool/function calling
may be used where available; local servers without it may use a strict JSON action loop.
The orchestrator, not the provider, executes tools.

Suggested tools:

| Tool | Inputs | Output | Limits |
|---|---|---|---|
| `search_attack_techniques` | query, top_k | opaque candidate handles, score, source fields | top_k ≤ 20 |
| `get_node` | handle | node ID/type/name/description/provenance | only previously returned handles |
| `get_neighbors` | handle, allowed relationship types, direction | typed edge records + opaque handles | page size ≤ 50 |
| `get_provenance_paths` | technique handle, category, inherited-parent allowed | validated ordered paths | declared mapping matrix only |
| `get_framework_bundle` | technique handle, pagination/categorical filters | concise mapping summary + path handles | token/result budget |
| `validate_selection` | candidate handles, evidence span IDs | pass/fail and reasons | no free-form IDs |

Set explicit budgets, for example 12 tool calls, depth 4, 50 results per call, and a
provider/model-specific token ceiling. Persist every request, response summary, tool
call, elapsed time, and validation result as events. Never give arbitrary Cypher,
NetworkX, filesystem, shell, or HTTP access to a model.

### Stage D — deterministic mapping expansion

For each accepted candidate:

1. Enumerate every allowed direct path from the mapping matrix.
2. If the selected technique is a sub-technique and direct paths are empty, enumerate
   the parent paths only when policy permits; label each `inherited_parent` and include
   the `subtechnique_of` edge in the path.
3. Recognize both `cref_mitigation` and native `attack_mitigation` nodes. The current
   collector misses native `M####` mitigation links that carry CREF/NIST/ZIG edges.
4. Preserve every control, activity, approach, D3FEND relationship, analytic, and
   mitigation path. Do not select `[0]`, `break` after a first result, or collapse
   multiple relationships into a scalar field.
5. Build a concise display bundle from the exhaustive result using an explicit ranking
   rule. Keep the complete result in JSON/API.

For a high-fan-out technique such as T1190, do not put all raw paths into every LLM
prompt. Use deterministic pagination/summary and let the LLM request more bounded
detail. The complete mapping record must still be stored and reviewable.

### Stage E — report generation and QA

Render all graph-backed sections server-side from validated mapping records. An LLM must
only return schema-constrained narrative fields such as impact, exploitation explanation,
and actions. It must not rewrite graph mapping sections.

Use structured response validation for all providers. Record:

- requested provider/model;
- effective provider/model;
- local/cloud/data-egress classification;
- fallback/degradation reason;
- request/response latency, token usage when available, retry count, and timeout;
- raw provider response only when retention policy permits it.

The existing bracket-ID regex check is useful but insufficient. Add deterministic checks
that every displayed node ID belongs to the validated mapping bundle, every edge exists
in the pinned snapshot, and no narrative claim is allowed to create an ID. A real but
unretrieved graph ID must fail validation just as a fabricated ID does.

Treat raw findings as untrusted input. Delimit them as data, do not let them change tool
policy, and provide clear cloud-provider data-egress confirmation/redaction policy in
the UI before sending data to OpenAI or Gemini.

## Web application and API design

### Durable endpoints

The following is a proposed API contract. All IDs are UUIDs validated by database lookup,
not filenames.

| Method | Endpoint | Required behavior |
|---|---|---|
| `POST` | `/api/runs` | Submit one file or text artifact; return `202` run snapshot and idempotency key result. |
| `GET` | `/api/runs` | Paginated run history with filters/status. |
| `GET` | `/api/runs/{run_id}` | Durable snapshot: state, counters, provider, review gate, errors. |
| `POST` | `/api/runs/{run_id}/cancel` | Request cancel; worker checks safe checkpoints. |
| `POST` | `/api/runs/{run_id}/retry` | Create or schedule a controlled retry/reprocess revision. |
| `GET` | `/api/runs/{run_id}/events` | Server-Sent Events; support `Last-Event-ID` replay. |
| `GET` | `/api/reports` | Filter by run, technique, status, review state, severity, provider, date. |
| `GET` | `/api/reports/{report_id}` | Report metadata and current revision. |
| `GET` | `/api/reports/{report_id}/revisions/{revision_id}` | Immutable report data/mappings/provenance. |
| `PATCH` | `/api/reports/{report_id}/review` | Approve, request rework, reject, waive; require actor, note, and optimistic version. |
| `POST` | `/api/reports/{report_id}/reprocess` | Re-run mapping or narrative according to declared scope. |
| `DELETE` | `/api/reports/{report_id}` | Soft delete with reason, audit record, and undo window. |
| `POST` | `/api/reports/{report_id}/restore` | Restore a tombstoned report if within retention window. |
| `POST` | `/api/reports/{report_id}/pdf` | Generate/cache a revision-specific sanitized PDF. |

Use `If-Match` or a revision version field on review/delete actions to prevent a reviewer
from acting on a revision that a worker has just superseded.

### Deletion policy

Do not implement delete as bare `os.remove` from a route handler. Use this sequence:

1. Authenticate and authorize the actor.
2. Require a confirmation dialog and optional/required reason.
3. Check the report revision is not being written; cancel/coordinate if it is active.
4. Insert a deletion audit/tombstone record in a transaction.
5. Move MD, JSON, PDF, and associated revision files to a run-scoped trash directory
   using atomic rename, or mark them inaccessible until a background sweeper runs.
6. Return the tombstone and undo expiry.
7. In the UI, remove the item optimistically, select the next report, and offer Undo.
8. Purge only after the retention period under a controlled maintenance task.

Support batch deletion only after the single-report path and tests are correct.

### Review queue and report detail UX

Add real routes so a browser refresh does not lose state:

```text
/runs
/runs/:runId/progress
/review
/reports/:reportId
```

The Review Queue should filter by:

- `auto_flagged`;
- `manual_review_required`;
- unresolved or low-confidence observation;
- inherited-parent mapping;
- provider degradation;
- pending reviewer decision.

Report detail should have independent tabs that can load/retry separately:

1. Executive report.
2. Source artifacts and observation/evidence spans.
3. ATT&CK candidates, selected/rejected decisions, and confidence.
4. Full typed framework mappings.
5. Graph-path visualization/list with edge relationship and provenance.
6. QA results, provider/degradation information, and revision history.
7. Raw JSON for advanced users.

The current `Promise.all` report detail pattern hides usable JSON if Markdown fails. Make
each tab independently resilient.

### Interactive progress page

Use persisted `job_events` plus SSE, with REST snapshot polling as a fallback. An event
payload should look like:

```json
{
  "seq": 42,
  "at": "2026-07-12T23:45:00Z",
  "type": "llm_request_finished",
  "phase": "candidate_selection",
  "current": {
    "artifact_id": "...",
    "observation_id": "...",
    "technique_id": "T1190"
  },
  "counters": {
    "artifacts_total": 3,
    "observations_total": 120,
    "observations_completed": 77,
    "techniques_total": 34,
    "techniques_completed": 19,
    "reports_total": 19,
    "reports_auto_passed": 11,
    "reports_flagged": 4,
    "reports_review_pending": 4
  },
  "metrics": {
    "elapsed_seconds": 318,
    "items_per_minute": 3.6,
    "eta_seconds": 250,
    "provider_latency_ms": 4200,
    "input_tokens": 0,
    "output_tokens": 0
  },
  "message": "Validated 7 graph paths for T1190"
}
```

The progress page must show:

- determinate progress bar and current phase;
- total/completed/remaining artifacts, observations, techniques, and reports;
- current artifact/observation/TTP;
- pass, flag, review-pending, error, and retry counts;
- elapsed time, rolling throughput, and ETA labeled as an estimate;
- provider/model and any fallback/degradation warning;
- an event timeline and active mapping/path count;
- Cancel and reconnect actions;
- a final transition to the Review Queue if anything still requires review.

Do not auto-navigate to Reports merely because generation stopped.

## Security, reliability, and operational requirements

### Upload and worker safety

- Enforce extension, MIME, byte-size, archive expansion, and schema limits server-side.
- Stream uploads instead of reading unbounded file content into memory.
- Replace `sys.exit()` in library functions with typed exceptions. `SystemExit` is not
  caught by the current worker's `except Exception` and can leave a job stuck running.
- Validate empty/zero-observation ingestion before any pipeline work. Never reuse a
  stale prior CSV.
- Use timeout, retry/backoff, circuit-breaker, cancellation, and heartbeat policy for
  local/cloud LLM requests.
- Record effective provider and fallback reason. Missing keys, a hung endpoint, invalid
  JSON, or heuristic fallback must not look like successful model QA.

### Access control and audit

Tailscale is a network boundary, not a report-level authorization system. Before adding
review or delete operations, choose an identity source and roles such as `viewer`,
`analyst`, `reviewer`, and `admin`. Enforce the policy server-side and record actor/time
on every review, retry, delete, and restore.

### Rendering safety

Escape all untrusted values inserted into Markdown tables. Sanitize Markdown/HTML before
PDF conversion, disallow raw HTML unless explicitly required, limit URL schemes, and
provide a deny-by-default WeasyPrint URL fetcher so report text cannot request external
resources. Browser Markdown rendering is safer by default, but PDF generation is a
server-side attack surface.

### Offline and reproducible operation

- Do not make model downloads occur silently at application startup. Detect local model
  cache/manifest availability and report semantic search as ready or degraded.
- Make assessment embeddings opt-in and run-scoped unless they are actually consumed by
  the pipeline; the current web workflow creates global assessment embeddings that it
  does not use.
- Pin Python dependencies with a lock/constraints file, pin base-image/Tailscale
  digests as appropriate, and separate core, semantic, provider, and web extras.
- Add a `.dockerignore` before the next Docker build.
- Ensure graph-generation scripts use repo-relative `Path` values, explicit input/output
  CLI options, validation before write, staging, atomic replace, and deterministic sort.
  The current ZIG parser/documented root command disagrees with the actual
  `raw_data/zig/` input location.

## Exact implementation sequence

### Phase 0 — freeze behavior and create tests

1. Record a graph snapshot manifest and archive representative inputs/outputs as fixtures.
2. Add `pytest` and a frontend test runner. Add test commands to the project task runner.
3. Write characterization tests for current valid behavior: explicit IDs, canonical names,
   hostless CTI, CSV/XLSX ingestion, report rendering, and provider fallback.
4. Add a test that proves two simultaneous jobs currently collide; use it to validate the
   replacement architecture rather than accepting that behavior.
5. Mark legacy `agent_batch_processor.py` clearly as legacy in README/CLI help. Do not
   remove it until a migration decision is made.

Gate: tests execute locally with a fake/no-network LLM provider.

### Phase 1 — repair graph integrity and retrieval primitives

1. Introduce `GraphRepository` around a relation-preserving graph representation.
2. Migrate loader to `MultiDiGraph` or an equivalent relation list and add stable edge
   identities/provenance.
3. Refactor every graph traversal to use repository methods that return typed nodes and
   edge records; never access an edge attribute that assumes one relation per pair.
4. Make CSV exports deterministic and add a graph integrity manifest.
5. Build a typed ATT&CK retrieval index and validate embedding compatibility with the
   graph snapshot.
6. Implement typed path enumeration from the mapping matrix, including direct and
   explicitly inherited-parent paths.
7. Cover native `attack_mitigation` and `cref_mitigation` paths.

Gate: raw edge-row count equals loaded edge count; duplicate relationship tests pass;
same raw inputs regenerate byte-identical ordered graph data; selected path output is
stable across runs.

### Phase 2 — persistence, workspaces, and durable worker

1. Add SQLite migrations and repository classes for the proposed tables.
2. Create per-run workspace creation, file hashing, atomic publication, retention, and
   cleanup services.
3. Refactor ingestion functions to accept explicit paths and return structured results;
   remove process-exiting behavior from reusable code.
4. Replace global `JOBS` and root paths with a durable job claim/worker loop.
5. Add cancellation checkpoints and restart recovery.
6. Import existing loose reports as `legacy` report records with known schema/pipeline
   versions. Do not silently present them as equivalent to new reports.

Gate: two concurrent runs remain isolated; a restart retains run/review visibility; an
invalid/empty upload transitions to failed rather than remaining running.

### Phase 3 — evidence-first mapping engine

1. Define observation adapters and normalized source/evidence schemas.
2. Implement explicit-ID, alias, specific-name, typed lexical, and typed vector candidate
   stages with source spans and score thresholds.
3. Add parent/sub-technique dedupe and explicit inherited-path labeling.
4. Persist accepted, rejected, and unresolved candidates.
5. Implement exhaustive deterministic framework bundle expansion and path validation.
6. Add bounded result summaries for presentation/LLM use, while preserving complete paths
   in storage.

Gate: a six-TTP artifact yields six linked candidates and report sections; a specific
sub-technique does not spuriously create parent mapping; unmapped/ambiguous text becomes
reviewable triage rather than a false authoritative report.

### Phase 4 — provider/tool orchestration and QA

1. Split provider capabilities into structured narrative, structured review, and optional
   constrained tool planning.
2. Implement opaque-handle graph tools and enforce budgets, schema validation, timeouts,
   cancellation, and data-egress policy.
3. Require the model to select candidates from tool results and cite source span handles.
4. Render graph facts immutably; permit model output only in narrative fields.
5. Replace heuristic `PASS` with `MANUAL_REVIEW_REQUIRED`.
6. Add deterministic mapping/claim validation and bounded rework attempts.

Gate: a mocked model cannot inject fabricated or unrelated existing IDs; timeout and bad
JSON result in review-required; cloud provider use records consent/policy and effective
provider/model.

### Phase 5 — review gate and report lifecycle API

1. Implement report/revision/review-state transitions transactionally.
2. Implement run completion aggregation according to the agreed policy.
3. Implement reviewer approval, rework, reject, waive, retry, and audit notes.
4. Implement soft delete/restore with authorization, version check, trash, retention,
   and audit records.
5. Add filtered report and review-queue endpoints.

Gate: a run with one flag remains `awaiting_review`; it becomes `completed` only after
all required decisions; deleting one revision cannot affect another run/report/PDF.

### Phase 6 — interactive UI

1. Add durable routes for Runs, Live Progress, Review Queue, and Report Detail.
2. Implement SSE event client with reconnect and REST snapshot fallback.
3. Build determinate telemetry, ETA, timeline, status table, cancel/retry controls, and
   provider/degradation display.
4. Build evidence/mapping/path/revision tabs and a reviewer action panel.
5. Add safe delete confirmation/undo and filters/search/pagination.
6. Make all pages keyboard accessible, screen-reader labeled, and responsive.

Gate: browser refresh resumes run monitoring; review actions update state correctly;
progress totals/ETA remain coherent; a user can delete and undo a report without losing
unrelated evidence.

### Phase 7 — hardening, deployment, and documentation

1. Add `.dockerignore`, least-privilege container identity, safe mounts, and image scan.
2. Harden PDF rendering and uploads.
3. Add dependency locks, SBOM/dependency scans, lint/format/type checks, and CI.
4. Repair ZIG parser/dumper path assumptions and test clean-checkout regeneration.
5. Update README, handoff, air-gapped guides, portable bundle, and deployment guides.
6. Regenerate every generated guide only after source changes are final and tests pass.

Gate: production image contains no `.env`, `.git`, venv, node_modules, reports, or
uploads; all guide checksums pass; clean regeneration and core tests pass offline.

## Required test matrix

At minimum, implement these automated tests before declaring the redesign complete:

| Area | Required test |
|---|---|
| Graph | Every CSV relationship survives loading; multi-edge types remain distinct; deterministic regeneration; graph manifest validation. |
| Mapping | Six explicit IDs → six candidates; multiple canonical names → expected mappings; longest sub-technique match suppresses unsupported parent; direct vs inherited parent scope correct. |
| Coverage | T1190 exposes all allowed direct paths, including native `M####` mitigation links; empty categories are recorded as empty. |
| Retrieval | Typed ATT&CK search rejects stale embeddings and low-confidence ambiguity goes to review. |
| LLM | Tool selection cannot mint IDs; prompt injection cannot alter mapping facts; malformed/timeout/degraded response is review-required. |
| Ingestion | XLSX/CSV/text adapters preserve source location; unsupported/empty/oversized input fails cleanly; no silent truncation of evidence. |
| Concurrency | Two runs never share input, embeddings, output, events, or report revisions. |
| Lifecycle | Restart recovery; cancel; bounded retry; all-pass gate; reviewer approval/rejection/waiver audit. |
| Delete | Authorization, active-write coordination, soft delete, restore, undo, and isolation of unrelated revisions/PDFs. |
| Progress | SSE replay/reconnect, counter math, ETA calculation, and UI refresh/deep-link recovery. |
| Rendering | Hostile Markdown/table values cannot produce unsafe HTML or remote PDF fetches. |
| Build | Docker image secret scan, clean graph regeneration, guide bundle self-test, dependency/lock validation. |

## Decisions the owner should make before implementation

The recommended defaults are shown first.

1. **Completion policy:** Require human approval for all flagged, low-confidence, and
   degraded/heuristic reports; allow automatically validated high-confidence reports to
   complete only if explicitly enabled.
2. **Storage:** SQLite/WAL for the local/Tailscale host; migrate to Postgres only if
   concurrent multi-user/HA operation becomes a requirement.
3. **LLM role:** Constrained read-only tool planner/ranker plus prose writer, never a
   free-form graph authority.
4. **Artifact scope:** Start with CSV/XLSX/text and a robust adapter interface; add
   STIX/PDF/DOCX/MISP only with explicit parser/security tests.
5. **Delete retention:** Soft delete with a 30-day default trash/undo period and audit
   reason, or choose a different organizational retention policy.
6. **Cloud policy:** Require an explicit UI acknowledgement before raw artifact content
   is sent to OpenAI/Gemini; make local/no-provider the default for sensitive data.
7. **Legacy reports:** Import them as read-only `legacy` data and reprocess on demand;
   do not falsely label them as compliant with the new provenance schema.

## Notes for the implementing agent

- Make changes in small, testable commits by phase. Do not combine graph migration,
  database migration, UI redesign, and provider changes into one unreviewable patch.
- Prefer standard-library SQLite and simple services before adding Redis, Celery, or a
  large framework. The project must remain deployable in air-gapped environments.
- Maintain the rule that an LLM never invents a framework identifier. Strengthen it by
  ensuring it also cannot select a real-but-unretrieved identifier.
- Preserve direct versus inferred versus inherited provenance everywhere, including
  Markdown labels, JSON, API, PDF, and review UI.
- Run tests before regenerating guides. Generated guides are artifacts, not editable
  source documents.
- Do not use destructive Git commands to clean the current working tree.
