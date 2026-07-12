# MITRE CSD-H — Project Handoff Document

**Read this whole document before touching code.** It exists because this project was
built across a long Claude Code session and the person continuing it is switching to a
different coding agent (Codex) to save tokens — this document is the transferred
context, written to stand in for that conversation history. It is accurate as of
**2026-07-12**, HEAD commit `5c13ec7` on branch `master`, remote
`https://github.com/gjoncay/MITRE_ZIG_agentic_POA-M.git`. If reality has drifted from
what's written here (a moved file, a changed port, a stale count), trust the actual
files over this document and update this document once you've reconciled — see
"Keeping this document honest" at the end.

---

## 1. What this project is and why it exists

**Mission:** translate unstructured threat intelligence or blue/red-team network
assessment findings into standardized, multi-framework-mapped remediation reports — the
kind a defense/DoD customer needs — automatically, at scale, and *without ever
inventing a framework identifier*.

**The owner (Grant)** is building this for two very different environments
simultaneously, and that duality shapes almost every design decision in the codebase:

1. **A local Tailscale-accessible web app** on his own laptop — a nice UI, pick-your-LLM
   flexibility (local Ollama model, OpenAI, Gemini), PDF export, the works.
2. **A fully air-gapped, Top Secret network** where the SAME core graph/pipeline logic
   must run with zero internet access, no Docker, no web UI, and (usually) no ML
   libraries either — CLI only, Python only, keyword search instead of semantic search,
   heuristic text instead of LLM prose, and everything verifiable by hand.

Consequently, **the CLI/backend pipeline and the Docker/web-UI layer are two cleanly
separable things that happen to share the same repo.** The air-gapped deployment guides
never mention Docker/Tailscale/React at all, and the web UI's docker-compose.yml never
assumes internet access is forbidden. Do not blur this line when adding features —
always ask "does this belong in the CLI-only air-gapped path, the web-UI-only path, or
both?"

**What "the graph" is:** a single unified property graph merging four public/DoD
cybersecurity frameworks into one NetworkX `DiGraph`:

| Framework | What it contributes |
|---|---|
| MITRE ATT&CK (v19.1) | Adversary tactics/techniques, native mitigations, groups, software, campaigns, detection strategies, analytics |
| MITRE D3FEND | Defensive countermeasure techniques and artifacts, mapped to ATT&CK |
| NSA Zero Trust Implementation Guide (ZIG) | Pillars → Capabilities → Activities → Technologies |
| NIST SP 800-160 Vol. 2 CREF + DoD Zero Trust Strategy + NIST SP 800-53 + DoD Cyber Survivability Attributes | Cyber resiliency goals/objectives/techniques/approaches, a *direct* ZIG-activity↔ATT&CK crosswalk, NIST 800-53 control citations, and CSA-01..10 mission-level impact framing |

Current live counts: **5,618 nodes / 43,194 edges** (verify with `python3
scripts/graph_engine.py` or `curl https://mitre-csdh.dikdik-macaroni.ts.net/api/health`).

---

## 2. The three things you can build/run here

### 2a. The knowledge graph itself (data layer)
CSV pairs (`*_nodes.csv` id,type,name,description,url / `*_edges.csv`
source_id,target_id,relationship_type) for three sub-graphs — `mitre_*`, `zig_*`,
`cref_*` — loaded together by `scripts/graph_engine.py` into one graph. Regenerated from
raw sources by `consolidate_mitre_data.py`, `scripts/parse_zig_data.py`,
`consolidate_cref_data.py` **in that exact order** (the CREF script reconciles into the
ZIG files and validates against the MITRE file, so it must run last). Never hand-edit
the `*_nodes.csv`/`*_edges.csv` files — always regenerate from the raw sources in
`CREF/`, the ATT&CK xlsx, the D3FEND csvs, or the ZIG PDF text extracts in `raw_data/zig/`.

### 2b. The CLI analyst pipeline (air-gap-compatible)
`run_analyst_pipeline.py` — ingest findings (file or pasted text) → group by resolved
ATT&CK technique → crawl the graph once per technique group → LLM drafts narrative →
LLM proofreads → LLM QA-reviews (+ a deterministic hallucination check) → write matched
`.md`/`.json` per technique to `reports/`. Works with **zero LLM configured** (the
default) via a heuristic fallback that produces legible, if generic, prose from the same
graph facts. This whole path — including the "local LLM" option — is what's expected to
run air-gapped; `openai`/`gemini` providers are cloud-only and explicitly excluded from
that network.

### 2c. The Tailscale web UI (NOT air-gapped)
A FastAPI backend (`webapp/backend/`) wrapping 2b behind an HTTP API, and a React
frontend (`webapp/frontend/`) for pasting/uploading input, watching job progress,
browsing reports, and exporting to PDF. Deployed via Docker Compose with a Tailscale
sidecar, reachable at **https://mitre-csdh.dikdik-macaroni.ts.net** (tailnet-only, not
public). This layer is documented as explicitly out of scope for the air-gapped port.

---

## 3. Directory map (everything that matters)

```
MITRE_CSD-H/
├── PROJECT_HANDOFF.md          ← you are here
├── README.md                   ← the other "start here" doc; more terse, task-oriented
│
├── --- Knowledge graph data (generated; don't hand-edit) ---
├── mitre_nodes.csv / mitre_edges.csv       ← ATT&CK + D3FEND
├── zig_nodes.csv / zig_edges.csv           ← NSA ZIG (+ CREF-layer reconciliation)
├── cref_nodes.csv / cref_edges.csv         ← CREF/NIST-800-53/DoD-ZT-crosswalk/CSA
├── ontology.json                           ← ATT&CK+D3FEND only export (NOT zig/cref — a known gap, see §8)
│
├── --- Raw sources for regenerating the graph ---
├── enterprise-attack-v19.1(1).xlsx, d3fend.csv, d3fend-full-mappings.csv,
│   ATT&CK_D3FEND_Mappings.ods                    ← consolidate_mitre_data.py reads these
├── raw_data/zig/*.PDF.txt, zig_tech_mappings.txt ← scripts/parse_zig_data.py reads these
├── CREF/*.csv (6 files)                          ← consolidate_cref_data.py reads these
│
├── --- Regeneration scripts (run in this order after any raw-source change) ---
├── consolidate_mitre_data.py       → mitre_nodes.csv / mitre_edges.csv / ontology.json
├── scripts/parse_zig_data.py       → zig_nodes.csv / zig_edges.csv
├── consolidate_cref_data.py        → cref_nodes.csv / cref_edges.csv (+ reconciles zig_*.csv) — MUST run last
├── scripts/embed_graph.py          → graph_embeddings.npz / embedding_metadata.json (only if using semantic mode; re-run whenever node set changes)
│
├── --- Core engine ---
├── scripts/graph_engine.py         ← KnowledgeGraphEngine: loads all 3 CSV pairs into one nx.DiGraph;
│                                      query_node / search_nodes / keyword_rank / semantic_search /
│                                      get_neighbors / crawl_subgraph
│
├── --- Ingestion ---
├── scripts/ingest_assessment.py    ← ingest_file() (any-schema xlsx/csv) + ingest_text() (pasted freeform text)
│                                      → processed_assessment.csv (+ optional embeddings)
│
├── --- The analyst pipeline (Phase 1) ---
├── scripts/consolidate_findings.py ← groups processed_assessment.csv rows by resolved technique;
│                                      crawl_correlation() runs the D3FEND/ZIG/CREF/NIST/CSA graph
│                                      traversal ONCE per technique group
├── scripts/llm_providers.py        ← get_provider(): Local(Ollama-etc)/OpenAI/Gemini/Heuristic,
│                                      task-specific interface (draft_narrative/proofread/qa_review)
├── scripts/report_schema.py        ← build_report_json() / render_markdown()
├── assessment_template.md              ← legacy single-finding-per-report template (agent_batch_processor.py)
├── assessment_template_consolidated.md ← the ACTIVE template (run_analyst_pipeline.py), multi-host + QA section
├── run_analyst_pipeline.py         ← CLI entrypoint AND importable run_pipeline() used by the web backend
├── agent_batch_processor.py        ← OLDER, still-functional single-finding batch script (predates consolidation);
│                                      kept for compatibility, not the recommended path anymore
├── agent_crawl_example.py          ← hand-walkthrough demo of a manual graph crawl (illustrative, not production code)
├── threat_assessment_skill.md      ← prompt/instructions for an INTERACTIVE agent (e.g. Claude Code itself)
│                                      to do this analysis by hand via chat — NOT loaded by the automated
│                                      pipeline above, which uses its own prompts baked into llm_providers.py.
│                                      See §7 "Two different meanings of 'the skill'".
│
├── --- The web UI (Phase 2, NOT air-gapped) ---
├── webapp/backend/main.py          ← FastAPI app: /api/analyze, /api/jobs/{id}, /api/reports[/{id}[/markdown]],
│                                      /api/reports/{id}/pdf, /api/health — full contract in §6
├── webapp/backend/pdf_export.py    ← render_report_pdf(): markdown -> HTML -> WeasyPrint -> PDF bytes
├── webapp/backend/requirements.txt ← ADDITIVE to root requirements.txt (fastapi/uvicorn/python-multipart; markdown/weasyprint)
├── webapp/frontend/                ← Vite + React + TS + Tailwind SPA; see §6 for pages/components
├── docker-compose.yml, Dockerfile  ← single container (multi-stage: build the frontend, then the Python backend)
├── tailscale/mitre-csdh.json       ← Tailscale Serve config (proxies to 127.0.0.1:8000 inside the container)
├── TAILSCALE_SIDECAR.md            ← the sidecar recipe, copied verbatim from ~/Projects/app-template — READ THIS
│                                      before touching anything Tailscale-related; "don't re-derive it"
├── .env.example / .env (gitignored) ← TS_AUTHKEY + LLM_PROVIDER + API keys; see §9 for current live values
│
├── --- Air-gapped porting guides (all AUTO-GENERATED — see §5) ---
├── Air_Gapped_Deployment_Guide.md          ← generated by build_deployment_guide.py — full from-scratch reconstruction
├── CREF_ZERO_TRUST_EXTENSION_GUIDE.md      ← generated by build_cref_extension_guide.py — delta: adding the CREF layer
├── ANALYST_PIPELINE_ADDENDUM_GUIDE.md      ← generated by build_pipeline_addendum_guide.py — delta: adding the analyst pipeline
├── PORTABLE_RECONSTRUCTION_BUNDLE.md       ← generated by build_portable_bundle.py — single self-verifying
│                                              text document (SHA-256 per file) for CDS transfers that block .py files
├── extract_bundle.py                       ← the tiny extractor a high-side agent hand-types from the bundle
│
├── --- Misc / legacy ---
├── import_to_neo4j.py              ← optional Neo4j loader (currently only loads mitre_*, a known gap — see §8)
├── mitre_consolidated_ontology.zip, create_mock_excel.py, mock_*.csv/.xlsx, mock_output/  ← old test fixtures, low-stakes
├── venv/                           ← Python 3.14 virtualenv (gitignored) — activate before running anything CLI-side
└── reports/                        ← gitignored; run_analyst_pipeline.py's output, bind-mounted into the Docker container
```

---

## 4. Tech stack (exact versions currently installed/pinned)

**Backend (Python 3.14.4, venv at `venv/`):**
`networkx==3.6.1`, `pandas==3.0.3`, `numpy==2.5.0`, `scikit-learn==1.9.0`,
`sentence-transformers==5.6.0` (pulls `torch==2.13.0` — the optional semantic-search
tier), `fastapi==0.139.0`, `uvicorn==0.51.0`, `weasyprint==69.0`, `Markdown==3.10.2`,
`openai==2.45.0` (used for BOTH the real OpenAI API AND any local
OpenAI-compatible server — see §7), `google-generativeai==0.8.6` (deprecated
upstream in favor of `google-genai`, still functional — see §8).

**Frontend (`webapp/frontend/`):** Vite 5.4, React 18.3, TypeScript 5.5, Tailwind 3.4,
`react-markdown` 9 + `remark-gfm` 4 for rendering report Markdown/tables. Matches the
stack of the sibling `mitre-diamond-dashboard` app (see §7, design system).

**Infra:** Docker + Docker Compose v2, a `tailscale/tailscale:latest` sidecar container.
Base images: `node:20-slim` (frontend build stage) → `python:3.14-slim` (final runtime;
Debian *trixie* — package names differ from older Debian, see the Dockerfile's comment
about `libgdk-pixbuf-2.0-0` vs `libgdk-pixbuf2.0-0`).

**Local LLM runtime (host machine, not containerized):** Ollama, already installed and
running as a systemd service; currently has `qwen2.5-coder:latest` (4.7GB, a
coding-focused model — works but produces fairly mechanical prose; pull a general
instruct model like `llama3.1` for better narrative writing, just change
`LOCAL_LLM_MODEL` in `.env` and restart).

---

## 5. Non-negotiable conventions (violate these and you WILL cause real bugs)

These aren't style preferences — every one of them was established because breaking it
caused (or would have caused) a real, confirmed bug during this project's build.

1. **Guides are code, not prose.** `Air_Gapped_Deployment_Guide.md`,
   `CREF_ZERO_TRUST_EXTENSION_GUIDE.md`, `ANALYST_PIPELINE_ADDENDUM_GUIDE.md`, and
   `PORTABLE_RECONSTRUCTION_BUNDLE.md` are ALL generated by their matching `build_*.py`
   script, which embeds the *actual current file contents* with SHA-256 hashes. Never
   hand-edit any of the four `.md` files — edit the source files they embed, then re-run
   the corresponding `build_*.py` script. If you change `requirements.txt`,
   `run_analyst_pipeline.py`, or any other embedded file, re-run ALL FOUR generators
   (some embed the same files) before considering the change done.

2. **Never let an LLM invent a framework ID.** Every MITRE/D3FEND/ZIG/CREF/NIST/CSA
   identifier that ends up in a report comes from a deterministic graph query, never
   from LLM generation. The LLM only writes prose *from* pre-assembled facts. A regex
   safety net in `run_analyst_pipeline.py` (`find_unknown_ids`) re-validates every
   bracketed `[ID]` token in the final drafted text against the graph and force-flags
   QA if anything doesn't resolve — this override cannot be talked out of it by the
   LLM's own QA verdict.

3. **Graceful degradation is load-bearing, not a nice-to-have.** Semantic search
   degrades to keyword search when `sentence-transformers`/`numpy`/`scikit-learn` are
   absent (`graph_engine.py`'s `SEMANTIC_ENABLED` pattern). LLM-drafted narrative
   degrades to heuristic template text when no provider is configured, when a
   package/API-key is missing (caught at construction time in `get_provider()`), AND
   when a configured provider's network call fails at *runtime* (caught inside
   `_ChatCompletionMixin.draft_narrative`, falls back to `HeuristicFallbackProvider`
   rather than returning blank fields). Preserve every fallback path — the absence of a
   capability must always be a supported, tested configuration, never an unhandled error.

4. **The DoD Zero Trust Strategy pillar/capability/activity taxonomy is the SAME
   taxonomy as NSA ZIG's.** If you ever ingest another "Zero Trust" dataset, check
   whether it's really this same 7-pillar taxonomy before minting new nodes — reconcile
   by ID (`ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*`) instead of duplicating. See
   `consolidate_cref_data.py` for the reference implementation of "add what's missing,
   clean what's garbled, never duplicate what already exists."

5. **Consolidation is by resolved ATT&CK technique, not by input row.** One report
   covers every host/finding that maps to the same technique. Don't regress to
   one-report-per-row (that's what `agent_batch_processor.py`, the legacy path, still
   does — it's kept for compatibility, not as a model to follow).

6. **`uvicorn` runs with exactly one worker.** `webapp/backend/main.py`'s job tracker is
   an in-memory dict, not shared across processes. Don't add `--workers N>1` or a
   multi-process deployment without first replacing that with Redis/a real queue.

7. **Never commit `.env`, `webapp/backend/uploads/`, `reports/`, `.vscode/`,
   `node_modules/`, or `dist/`** — all gitignored already; keep it that way.

---

## 6. The web app's API contract (for anyone touching frontend or backend)

Same-origin: the built React app is served at `/` by the same FastAPI process (via
`StaticFiles` mounted on `webapp/frontend/dist`, built into the image at Docker build
time); all API calls are relative `fetch('/api/...')`.

| Method & path | Purpose |
|---|---|
| `POST /api/analyze` | multipart form: `file` (xlsx/csv) OR `text` (pasted intel), optional `provider` override. Returns `{"job_id": str}` immediately; runs the pipeline as a background job. |
| `GET /api/jobs/{job_id}` | `{"status": "pending"\|"running"\|"done"\|"failed", "stage": str, "error": str\|null, "report_ids": [str]}`. `stage` is human-readable progress ("ingesting", "consolidating findings", "drafting narrative", "proofreading", "qa review", "writing reports"). |
| `GET /api/reports` | List of report summaries, scanned live from `reports/*.json` on every call (not cached) — so CLI-generated reports show up too. |
| `GET /api/reports/{id}` | Full JSON content of that report. |
| `GET /api/reports/{id}/markdown` | Raw `.md` text. |
| `POST /api/reports/{id}/pdf` | Renders (or serves a cached) PDF; `application/pdf` bytes. |
| `GET /api/health` | `{"status":"ok","graph_nodes":int,"graph_edges":int}` — also the Docker healthcheck and Tailscale cert pre-warm target. |

Frontend components (`webapp/frontend/src/components/`): `InputView` (paste/upload +
provider dropdown), `ProgressView` (polls job status every ~2s), `ReportBrowser`
(sidebar list + tab strip: rendered Markdown / raw JSON), `ReportDetail`, `ThemeToggle`
(sets `data-theme` on `<html>`, persisted to localStorage).

---

## 7. Design decisions worth understanding before you change anything nearby

- **"Skills" are ambiguous in this project — know which one is meant.**
  `threat_assessment_skill.md` is a prompt written for an *interactive* agent (a human
  chatting with Claude Code, where the agent itself runs Python against
  `graph_engine.py` step by step). It is **not** loaded by the automated web/CLI
  pipeline. The automated pipeline's LLM calls use their own, much narrower prompts
  hardcoded in `scripts/llm_providers.py` (`_build_narrative_prompt`,
  `_build_proofread_prompt`, `_build_qa_prompt`) — because all the graph-traversal work
  the skill file describes is *already done deterministically in Python* by
  `consolidate_findings.py` before the LLM is ever called. If someone asks "does the web
  UI follow the skill," the honest answer is "conceptually yes, mechanically no."

- **`LocalOpenAICompatProvider` is how "run your own local LLM" works**, and it's
  *literally the `openai` Python package* pointed at a different `base_url` — Ollama,
  LM Studio, vLLM, and llama.cpp-server all speak the OpenAI chat-completions API, so
  one client class covers all of them. There is no separate "local LLM SDK."

- **Docker container ↔ host-machine Ollama is a real networking gotcha.** Ollama
  defaults to binding `127.0.0.1` only, which a container can't reach regardless of
  `host.docker.internal` DNS tricks. Fixed here via a systemd override
  (`/etc/systemd/system/ollama.service.d/override.conf`, `OLLAMA_HOST=0.0.0.0:11434`)
  plus a `ufw` rule scoped *only* to the Docker Compose project's bridge subnet
  (currently `172.23.0.0/16` — re-check with `docker network inspect
  mitre-csdh_default` if it ever changes) plus `extra_hosts:
  ["host.docker.internal:host-gateway"]` in `docker-compose.yml`. All three pieces are
  required; missing any one silently falls back to heuristic mode with a one-line log
  warning, not a crash.

- **Recreating the `app` container orphans the Tailscale sidecar.**
  `network_mode: service:app` binds to a concrete container ID at sidecar-start time.
  After `docker compose up -d --force-recreate app`, you MUST also
  `--force-recreate app-ts` or the site silently goes unreachable. This is documented as
  gotcha #7 in both this repo's `TAILSCALE_SIDECAR.md` and the master template at
  `~/Projects/app-template/TAILSCALE_SIDECAR.md` — it now protects every future
  Tailscale app built from that template, not just this one.

- **Design system is shared with two sibling projects.** `~/Projects/Chinook_Cyber/`
  contains `mitre-diamond-dashboard` (Vite+React, closest sibling — ATT&CK/D3FEND
  visualization) and `cyber-planning-web-app` (Next.js). Both share one CSS-variable
  design system (warm-sand/charcoal-pine light/dark themes, Inter + JetBrains Mono, a
  5-color OAKOC accent palette, ATT&CK tactic colors, D3FEND tactic colors, a
  black-on-white `@media print` convention). `webapp/frontend/src/index.css` ports these
  tokens verbatim from `cyber-planning-web-app/src/app/globals.css`. If you extend the
  UI, pull from that same source rather than inventing new colors.

- **PDF export uses WeasyPrint, not a headless browser.** Deliberate — avoids bundling
  Chromium into the image. Needs native system packages (Pango/cairo/etc., see the
  Dockerfile's apt-get line) that pip alone won't install.

---

## 8. Known gaps / rough edges (things that work but aren't perfect)

- `ontology.json` (the ATT&CK+D3FEND-only combined export) does not include ZIG or CREF
  data. `import_to_neo4j.py` similarly only loads `mitre_*.csv` — extending both to also
  load `zig_*`/`cref_*` would be a nice, contained follow-up.
- `google-generativeai` is upstream-deprecated in favor of `google-genai`; still works
  today, worth migrating `scripts/llm_providers.py`'s `GeminiProvider` eventually.
  `npm audit` flags a moderate/high advisory in Vite's dev server (not the production
  build) — not fixed, to avoid an unrequested Vite major-version bump.
- Some markdown list blocks in the report templates lack a blank line before the first
  `- ` bullet, so `python-markdown` (used by `pdf_export.py`, unlike CommonMark) renders
  them as inline prose instead of a bullet list in the PDF only. Cosmetic; add a blank
  line before bulleted sections in `assessment_template_consolidated.md` if it bothers you.
- A pre-existing (not newly introduced) quirk: in a report's "Traceability" line, the
  ZIG-activity ID sourced from a `cref_mitigation`'s `implements_activity` edge can point
  to a *different* ZIG activity than the one shown in the "Relevant Activities" line
  (sourced from the direct `zig_activity→technique` edge). Both are real graph edges,
  just from different rows of the source data — not a bug, just worth knowing if a
  report looks internally inconsistent on that one line.
- No favicon/logo for the web app (cosmetic).
- `OpenAIProvider`/`GeminiProvider` were verified correct by reading the code and briefly
  installing+exercising the packages (network was available during that check), but
  have not been exercised under sustained real production traffic — if either misbehaves
  under load, start there.
- Currently deployed local model (`qwen2.5-coder:latest`) is coding-focused; narrative
  prose is serviceable but terse. Swapping to a general instruct model is a one-line
  `.env` change (`LOCAL_LLM_MODEL=`) plus `ollama pull <model>`.

---

## 9. Current live deployment state (as of this document's date)

- URL: **https://mitre-csdh.dikdik-macaroni.ts.net** (tailnet-only — only reachable
  while the host laptop is awake and on the tailnet).
- `docker compose ps` should show `mitre-csdh-app-1` (healthy) and `mitre-csdh-app-ts-1`.
- `.env` (gitignored, not in this document): `LLM_PROVIDER=local`,
  `LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1`,
  `LOCAL_LLM_MODEL=qwen2.5-coder:latest`, plus a `TS_AUTHKEY` (reused from another local
  app's `.env` per `TAILSCALE_SIDECAR.md`'s own guidance — treat as low-sensitivity,
  it's only used once at first node registration).
- Host-side Ollama: systemd override sets `OLLAMA_HOST=0.0.0.0:11434`; `ufw` allows
  `172.23.0.0/16` (the compose project's bridge subnet) on port 11434 only.
- Verify the whole chain any time with:
  ```bash
  curl -s https://mitre-csdh.dikdik-macaroni.ts.net/api/health
  ```

---

## 10. How to actually run things

```bash
# CLI / air-gap-compatible path
cd MITRE_CSD-H
source venv/bin/activate
python3 scripts/graph_engine.py                    # sanity check the graph loads
python3 scripts/ingest_assessment.py <report.xlsx> # or use ingest_text() from Python directly
python3 run_analyst_pipeline.py                     # → reports/*.md + *.json (heuristic mode by default)
LLM_PROVIDER=local python3 run_analyst_pipeline.py  # uses Ollama at LOCAL_LLM_BASE_URL

# Web UI (Docker + Tailscale)
docker compose build
docker compose up -d
# after ANY rebuild that recreates the `app` container, also recreate the sidecar:
docker compose up -d --force-recreate app app-ts
curl -sI https://mitre-csdh.dikdik-macaroni.ts.net/    # pre-warm + verify cert
```

Regenerating the graph after a raw-data update (order matters):
```bash
python3 consolidate_mitre_data.py
python3 scripts/parse_zig_data.py       # run from raw_data/zig/, or move outputs to repo root after
python3 consolidate_cref_data.py        # MUST run last
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py
python3 build_cref_extension_guide.py
python3 build_pipeline_addendum_guide.py
python3 build_portable_bundle.py
```

---

## 11. Where to look for more detail than this document has

- `README.md` — shorter, task-oriented; good for "what command do I run."
- `Air_Gapped_Deployment_Guide.md` — the single most complete reference for the graph
  engine + CLI pipeline's schema, node-ID prefixes, and relationship-type vocabulary
  (§8 of that document is a full graph reference table).
- `TAILSCALE_SIDECAR.md` — the sidecar mechanics, verbatim from the shared template.
- `git log --stat` — three large commits (`575d0a1`, `02f6cc3`, `5c13ec7`) correspond
  cleanly to the CREF-graph, analyst-pipeline, and web-UI phases of this build, in that
  order, if you want to see each phase's full diff in isolation.

---

## Keeping this document honest

This document is hand-written, not auto-generated like the `Air_Gapped_*`/`CREF_*`/
`ANALYST_PIPELINE_*`/`PORTABLE_*` guides — there was no time to build a fifth generator
script for it. That means **it can drift from reality and nothing will warn you.**
Before trusting a specific claim here (a port number, a package version, a live URL,
a file's exact behavior), spot-check it against the actual file or a live command. If
you find drift, fix the code first, then update this document to match — don't let this
file become the thing everyone quotes instead of the thing everyone verifies against.
