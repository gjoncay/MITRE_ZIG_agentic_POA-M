# MITRE CSD-H — Threat Intelligence Knowledge Graph & Assessment Engine

A property graph unifying **MITRE ATT&CK**, **MITRE D3FEND**, and the **NSA Zero
Trust Implementation Guide (ZIG)**, plus a Python engine and pipeline that let an
LLM agent translate unstructured red/blue team findings into standardized,
framework-mapped Plans of Action & Milestones (POA&M).

Designed for **air-gapped deployment**: if ML libraries are unavailable, semantic
search degrades automatically to ranked keyword search — see
`Air_Gapped_Deployment_Guide.md` for the full porting/reconstruction plan.

## What's in the graph

| Framework | Contents |
|---|---|
| ATT&CK v19.1 | Tactics, techniques, mitigations, groups, software, campaigns, data components, detection strategies, analytics |
| D3FEND | Countermeasure techniques, tactics, defensive & offensive artifacts, ATT&CK↔D3FEND mappings |
| NSA ZIG | Pillars, capabilities, activities, technology-to-capability mappings |

Node files (`*_nodes.csv`): `id,type,name,description,url`.
Edge files (`*_edges.csv`): `source_id,target_id,relationship_type`.
Everything also exports as a single `ontology.json`.

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
| `consolidate_mitre_data.py` | Regenerates `mitre_nodes.csv` / `mitre_edges.csv` / `ontology.json` from the raw ATT&CK xlsx + D3FEND csv/ods |
| `scripts/parse_zig_data.py` | Regenerates `zig_nodes.csv` / `zig_edges.csv` from the ZIG PDF text extracts |
| `build_deployment_guide.py` | Regenerates `Air_Gapped_Deployment_Guide.md` from the live source files — run after any code change |
| `import_to_neo4j.py` | Optional Neo4j loader (nodes + typed relationships) |

## Regenerating the data

When MITRE releases new data, drop the updated raw files in the repo root and run:

```bash
python3 consolidate_mitre_data.py
python3 scripts/embed_graph.py          # only if using semantic mode
python3 build_deployment_guide.py       # keep the deployment guide in sync
```

## Using the graph elsewhere

- **Palantir Foundry/Gotham** — upload the node/edge CSVs; object type keyed on
  `id`, link type joining `source_id`/`target_id` → `id`.
- **Neo4j** — `python3 import_to_neo4j.py` (edit URI/credentials at the top), or
  `LOAD CSV` directly.
- **Python/NetworkX** — `from scripts.graph_engine import KnowledgeGraphEngine`.
- **Web dashboards / BI** — use `ontology.json` (Cytoscape.js, D3.js) or join the
  CSVs relationally (Tableau, PowerBI).
