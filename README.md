# MITRE CSD-H — Threat Intelligence Knowledge Graph & Assessment Engine

A property graph unifying **MITRE ATT&CK**, **MITRE D3FEND**, the **NSA Zero Trust
Implementation Guide (ZIG)**, and **NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF)**
— including the DoD Zero Trust Strategy activity-level crosswalk, NIST SP 800-53
control mappings, and DoD Cyber Survivability Attributes — plus a Python engine and
pipeline that let an LLM agent translate unstructured red/blue team findings or
network vulnerability scans into standardized, framework-mapped Plans of Action &
Milestones (POA&M) spanning tactical, architectural, and compliance layers.

Designed for **air-gapped deployment**: if ML libraries are unavailable, semantic
search degrades automatically to ranked keyword search — see
`Air_Gapped_Deployment_Guide.md` for the full porting/reconstruction plan, or
`CREF_ZERO_TRUST_EXTENSION_GUIDE.md` if you already have the base system deployed
and are only adding the CREF/NIST/CSA layer.

## What's in the graph

| Framework | Contents |
|---|---|
| ATT&CK v19.1 | Tactics, techniques, mitigations, groups, software, campaigns, data components, detection strategies, analytics |
| D3FEND | Countermeasure techniques, tactics, defensive & offensive artifacts, ATT&CK↔D3FEND mappings |
| NSA ZIG | Pillars, capabilities, activities, technology-to-capability mappings |
| CREF (NIST SP 800-160 Vol. 2) | Goals, objectives, techniques, approaches, design principles, effects, direct ATT&CK↔CREF mappings |
| DoD Zero Trust Strategy | Direct ZIG-activity↔ATT&CK mappings, CM#### mitigation catalog, NIST SP 800-53 control citations |
| DoD Cyber Survivability Attributes | CSA-01..CSA-10, linked to CREF design principles and techniques |

Node files (`*_nodes.csv`): `id,type,name,description,url`.
Edge files (`*_edges.csv`): `source_id,target_id,relationship_type`.
ATT&CK/D3FEND also export as a single `ontology.json`.

## Quick start

```bash
pip install -r requirements.txt      # Tier 1 lines are the only hard requirement

# Sanity-check the engine (loads mitre_*.csv + zig_*.csv from the repo root)
python3 scripts/graph_engine.py

# OPTIONAL semantic mode: generate node embeddings once
python3 scripts/embed_graph.py

# Process an assessment report (any-schema Excel/CSV) and generate POA&M reports
python3 scripts/ingest_assessment.py <report.xlsx>
python3 agent_batch_processor.py --limit 5      # reports land in mock_output/
```

An interactive walkthrough of the agent query pattern is in
`agent_crawl_example.py`; the LLM-agent prompt lives in
`threat_assessment_skill.md`.

## Key files

| File | Purpose |
|---|---|
| `scripts/graph_engine.py` | `KnowledgeGraphEngine` — load graph, `semantic_search` / `keyword_rank` / `crawl_subgraph` |
| `scripts/ingest_assessment.py` | Flattens multi-tab, arbitrary-schema assessment reports into `processed_assessment.csv` (+ optional embeddings) |
| `agent_batch_processor.py` | Batch: finding → T-code → D3FEND → ZIG → filled `assessment_template.md` |
| `scripts/consolidate_findings.py` | Groups CSV rows by ATT&CK technique so the graph crawl runs once per technique, not once per row |
| `scripts/llm_providers.py` | `get_provider()` — local-model narrative/proofread/QA drafting, degrading to a network-free heuristic fallback when the local model is unavailable |
| `scripts/report_schema.py` | `build_report_json` / `render_markdown` — fills `assessment_template_consolidated.md` and its JSON twin |
| `assessment_template_consolidated.md` | Template for one-technique-many-hosts consolidated reports, incl. QA/QC section |
| `run_analyst_pipeline.py` | CLI: consolidate findings by technique, draft/proofread/QA with a local model via `--provider local` and optional `--model`, write `reports/*.md` + `*.json` |
| `consolidate_mitre_data.py` | Regenerates `mitre_nodes.csv` / `mitre_edges.csv` / `ontology.json` from the raw ATT&CK xlsx + D3FEND csv/ods |
| `scripts/parse_zig_data.py` | Regenerates `zig_nodes.csv` / `zig_edges.csv` from the ZIG PDF text extracts |
| `consolidate_cref_data.py` | Regenerates `cref_nodes.csv` / `cref_edges.csv` from `CREF/*.csv`, and reconciles the DoD ZT pillar/capability/activity taxonomy into the existing `zig_*.csv` (never re-run `scripts/parse_zig_data.py` afterward — it would overwrite the reconciliation) |
| `build_deployment_guide.py` | Regenerates `Air_Gapped_Deployment_Guide.md` from the live source files — run after any code change |
| `build_cref_extension_guide.py` | Regenerates `CREF_ZERO_TRUST_EXTENSION_GUIDE.md` — a delta guide for applying the CREF/NIST/CSA layer to an already-deployed air-gapped instance |
| `build_pipeline_addendum_guide.py` | Regenerates `ANALYST_PIPELINE_ADDENDUM_GUIDE.md` — a delta guide for adding the local-model analyst/proofreader/QA consolidation pipeline (backend only, no web UI/Docker/Tailscale) to an already-deployed air-gapped instance |
| `build_portable_bundle.py` | Regenerates `PORTABLE_RECONSTRUCTION_BUNDLE.md` — single-document, checksum-verified code transfer for text-only CDS |
| `import_to_neo4j.py` | Optional Neo4j loader (nodes + typed relationships) |

## Regenerating the data

When MITRE releases new data, drop the updated raw files in the repo root and run:

```bash
python3 consolidate_mitre_data.py
python3 scripts/parse_zig_data.py     # only if the ZIG source text changed; run before CREF reconciliation
python3 consolidate_cref_data.py        # only if CREF/*.csv also changed; run AFTER consolidate_mitre_data.py
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py       # keep the deployment guide in sync
python3 build_cref_extension_guide.py   # keep the CREF extension guide in sync
python3 build_pipeline_addendum_guide.py # keep the analyst-pipeline addendum in sync
python3 build_portable_bundle.py        # keep the CDS-transfer bundle in sync
```

## Local-Only Analyst Pipeline

`run_analyst_pipeline.py` consolidates `processed_assessment.csv` findings by
ATT&CK technique (one report per technique, covering every affected host). A single
finding or threat-intelligence artifact can produce multiple reports when it contains
multiple explicit ATT&CK IDs or canonical ATT&CK technique names; each report's JSON
preserves every direct graph-backed ZIG, CREF, NIST, and CSA relationship. It then
drafts/proofreads/QA-reviews each report with a local LLM when one is
configured. Hosted-provider selection is intentionally disabled: submitted
evidence is never sent to OpenAI, Gemini, or another external LLM service.

| `LLM_PROVIDER` / `--provider` | Behavior |
|---|---|
| `local` | Any OpenAI-compatible local server (Ollama, LM Studio, vLLM, llama.cpp) |
| `none` (or unset, CLI only) | Deterministic heuristic fallback — no model-network call |
| `openai` or `gemini` | Disabled; resolves to the network-free heuristic fallback with a warning |

Use `LOCAL_LLM_MODEL` or the CLI's `--model` option to choose a locally
installed model for a single run. If the local provider package or endpoint is
unavailable, the pipeline falls back to the deterministic, network-free mode
with a warning rather than contacting a cloud provider. Run it with:

```bash
python3 run_analyst_pipeline.py
```

Reports land in `reports/` as matched `.md`/`.json` pairs; a deterministic
regex safety net cross-checks every bracketed framework ID (`[T1234]`,
`[D3-XXX]`, ...) in the drafted report against the graph and force-flags QA
if any don't resolve to a real node.

## Web UI (Tailscale)

A web UI (React frontend + FastAPI backend, PDF export via weasyprint) wraps
the graph engine and analyst pipeline. It stores each submitted artifact,
normalized observation, and report revision below `data/runs/<run UUID>/`, with
SQLite/WAL lifecycle and audit records at `data/csdh.sqlite3`, not in the legacy
repository-level `reports/` or upload directories. The review queue and
run-progress pages are therefore durable across service restarts.

The application container is non-root and read-only except for the private
`./data` bind mount. Create that directory with mode `0700`, set `APP_UID` and
`APP_GID` in `.env` to its Linux owner, and treat it as sensitive evidence that
must be backed up. Once deployed on the owner's laptop, the UI is reachable
tailnet-only at:

```
https://mitre-csdh.dikdik-macaroni.ts.net
```

Bring it up with:

```bash
mkdir -p data && chmod 700 data
cp .env.example .env          # set TS_AUTHKEY, APP_UID/APP_GID, local LLM settings, and an auth mode; chmod 600 .env
docker compose config --quiet
docker compose up -d --build
```

The web application accepts only `local` as its LLM provider. Set
`LOCAL_LLM_BASE_URL` to the local server reachable from Compose (usually
`http://host.docker.internal:11434/v1` for a host Ollama server) and optionally
set `LOCAL_LLM_MODEL` as the default. The submission screen discovers models
from that configured endpoint and lets you choose an installed model per run;
the endpoint URL and local API key are never exposed in the UI. The model can
use a bounded, read-only graph-tool crawl, while deterministic validated graph
paths remain the mapping authority. The progress screen records graph-planner
requests and graph-tool actions; an interrupted service shutdown safely
requeues work for clean replay from the retained source artifact on restart.

Application authentication is optional for a deliberately private,
single-operator Tailnet deployment. Set `CSDH_AUTH_MODE=disabled` in the local
`.env` to remove the bearer-token prompt; in that mode, the Tailnet's device
access and ACLs are the access boundary and reviewer actions still retain an
audit record. Use `token` mode with a nonempty `CSDH_AUTH_TOKENS_JSON` map, or
an authenticated `trusted_proxy`, for a shared Tailnet, multiple operators, or
any additional ingress. Application authentication remains useful defense in
depth if Tailnet membership or ACLs ever broaden.

Use [WEB_DEPLOYMENT_OPERATIONS.md](WEB_DEPLOYMENT_OPERATIONS.md) for the full
first-start, UID/GID, backup/restore, retention, image-pinning, and incident
procedures. `TAILSCALE_SIDECAR.md` remains the sidecar-specific recipe/gotchas.

**This entire web UI / Docker / Tailscale layer is NOT part of the air-gapped
port.** `Air_Gapped_Deployment_Guide.md`, `CREF_ZERO_TRUST_EXTENSION_GUIDE.md`,
and `ANALYST_PIPELINE_ADDENDUM_GUIDE.md` cover the CLI/backend pipeline only
and remain fully independent of Docker, Tailscale, and this UI — none of them
require this layer to run.

## Using the graph elsewhere

- **Palantir Foundry/Gotham** — upload the node/edge CSVs (`mitre_*`, `zig_*`,
  `cref_*`); object type keyed on `id`, link type joining `source_id`/`target_id` → `id`.
- **Neo4j** — `python3 import_to_neo4j.py` (edit URI/credentials at the top; currently
  loads `mitre_*` only, extend it the same way for `zig_*`/`cref_*`), or `LOAD CSV` directly.
- **Python/NetworkX** — `from scripts.graph_engine import KnowledgeGraphEngine`
  (loads all three CSV pairs into one graph).
- **Web dashboards / BI** — `ontology.json` currently covers ATT&CK + D3FEND only; for
  ZIG/CREF join `zig_*.csv`/`cref_*.csv` relationally (Tableau, PowerBI) or load them
  into Cytoscape.js/D3.js alongside `ontology.json`.
