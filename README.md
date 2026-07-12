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
| `scripts/llm_providers.py` | `get_provider()` — pluggable narrative/proofread/QA drafting (local/OpenAI/Gemini), degrading to a network-free heuristic fallback |
| `scripts/report_schema.py` | `build_report_json` / `render_markdown` — fills `assessment_template_consolidated.md` and its JSON twin |
| `assessment_template_consolidated.md` | Template for one-technique-many-hosts consolidated reports, incl. QA/QC section |
| `run_analyst_pipeline.py` | CLI: consolidate findings by technique, draft/proofread/QA via `--provider`, write `reports/*.md` + `*.json` |
| `consolidate_mitre_data.py` | Regenerates `mitre_nodes.csv` / `mitre_edges.csv` / `ontology.json` from the raw ATT&CK xlsx + D3FEND csv/ods |
| `scripts/parse_zig_data.py` | Regenerates `zig_nodes.csv` / `zig_edges.csv` from the ZIG PDF text extracts |
| `consolidate_cref_data.py` | Regenerates `cref_nodes.csv` / `cref_edges.csv` from `CREF/*.csv`, and reconciles the DoD ZT pillar/capability/activity taxonomy into the existing `zig_*.csv` (never re-run `scripts/parse_zig_data.py` afterward — it would overwrite the reconciliation) |
| `build_deployment_guide.py` | Regenerates `Air_Gapped_Deployment_Guide.md` from the live source files — run after any code change |
| `build_cref_extension_guide.py` | Regenerates `CREF_ZERO_TRUST_EXTENSION_GUIDE.md` — a delta guide for applying the CREF/NIST/CSA layer to an already-deployed air-gapped instance |
| `build_pipeline_addendum_guide.py` | Regenerates `ANALYST_PIPELINE_ADDENDUM_GUIDE.md` — a delta guide for adding the multi-provider analyst/proofreader/QA consolidation pipeline (backend only, no web UI/Docker/Tailscale) to an already-deployed air-gapped instance |
| `build_portable_bundle.py` | Regenerates `PORTABLE_RECONSTRUCTION_BUNDLE.md` — single-document, checksum-verified code transfer for text-only CDS |
| `import_to_neo4j.py` | Optional Neo4j loader (nodes + typed relationships) |

## Regenerating the data

When MITRE releases new data, drop the updated raw files in the repo root and run:

```bash
python3 consolidate_mitre_data.py
python3 consolidate_cref_data.py        # only if CREF/*.csv also changed; run AFTER consolidate_mitre_data.py
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py       # keep the deployment guide in sync
python3 build_cref_extension_guide.py   # keep the CREF extension guide in sync
python3 build_portable_bundle.py        # keep the CDS-transfer bundle in sync
```

## Multi-Provider Analyst Pipeline

`run_analyst_pipeline.py` consolidates `processed_assessment.csv` findings by
ATT&CK technique (one report per technique, covering every affected host) and
drafts/proofreads/QA-reviews each report via a pluggable LLM provider, chosen
with the `LLM_PROVIDER` env var (or `--provider`):

| `LLM_PROVIDER` | Backend |
|---|---|
| `local` | Any OpenAI-compatible local server (Ollama, LM Studio, vLLM, llama.cpp) |
| `openai` | Hosted OpenAI API (needs `OPENAI_API_KEY`) |
| `gemini` | Hosted Google Gemini API (needs `GEMINI_API_KEY`) |
| `none` (or unset) | Deterministic heuristic fallback — **the safe default**: no API keys, no network access, air-gap-friendly |

Any missing package/key falls back to `none` automatically with a warning —
it never raises. Run it with:

```bash
python3 run_analyst_pipeline.py
```

Reports land in `reports/` as matched `.md`/`.json` pairs; a deterministic
regex safety net cross-checks every bracketed framework ID (`[T1234]`,
`[D3-XXX]`, ...) in the drafted report against the graph and force-flags QA
if any don't resolve to a real node.

## Web UI (Tailscale)

A web UI (React frontend + FastAPI backend, PDF export via weasyprint) wraps
the graph engine and analyst pipeline. Once deployed on the owner's laptop it
is reachable tailnet-only at:

```
https://mitre-csdh.dikdik-macaroni.ts.net
```

Bring it up with:

```bash
cp .env.example .env          # then paste TS_AUTHKEY (see TAILSCALE_SIDECAR.md)
# optionally set LLM_PROVIDER + OPENAI_API_KEY / GEMINI_API_KEY / LOCAL_LLM_BASE_URL
docker compose up -d
```

Full sidecar recipe/gotchas: `TAILSCALE_SIDECAR.md`.

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
