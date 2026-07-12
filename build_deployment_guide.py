"""Regenerates Air_Gapped_Deployment_Guide.md from the ACTUAL files on disk.

The guide embeds full copies of every source file, so a coding agent on the
air-gapped network can recreate the entire system from the guide alone.
Because the guide is generated from the real files, it can never drift out
of sync with the code the way a hand-maintained guide can.

Run this after ANY change to the scripts or template:
    python3 build_deployment_guide.py
"""
import csv
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Files embedded in the guide, in the order a recreating agent should write them.
EMBEDDED_FILES = [
    ("scripts/graph_engine.py", "python"),
    ("scripts/embed_graph.py", "python"),
    ("scripts/ingest_assessment.py", "python"),
    ("agent_batch_processor.py", "python"),
    ("agent_crawl_example.py", "python"),
    ("assessment_template.md", "markdown"),
    ("requirements.txt", "text"),
]

# Only needed when the pre-built CSVs could NOT be ported and the raw
# source files (ATT&CK xlsx, D3FEND csv, ZIG PDFs, CREF/*.csv) were ported instead.
# Order matters: consolidate_cref_data.py reads mitre_nodes.csv and zig_nodes.csv to
# validate/reconcile against, so it must run AFTER the other two.
REGEN_FILES = [
    ("consolidate_mitre_data.py", "python"),
    ("scripts/parse_zig_data.py", "python"),
    ("consolidate_cref_data.py", "python"),
]


def count_csv(path):
    with open(os.path.join(BASE_DIR, path), encoding="utf-8") as f:
        return sum(1 for _ in csv.DictReader(f))


def graph_counts():
    """Deduplicated counts as the engine will actually report them."""
    import networkx as nx
    g = nx.DiGraph()
    for nodes_file, edges_file in [("mitre_nodes.csv", "mitre_edges.csv"),
                                   ("zig_nodes.csv", "zig_edges.csv"),
                                   ("cref_nodes.csv", "cref_edges.csv")]:
        with open(os.path.join(BASE_DIR, nodes_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_node(row["id"])
        with open(os.path.join(BASE_DIR, edges_file), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                g.add_edge(row["source_id"], row["target_id"])
    return g.number_of_nodes(), g.number_of_edges()


def embed(relpath, lang):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        content = f.read().rstrip()
    return f"### FILE: `{relpath}`\n\n```{lang}\n{content}\n```\n"


def main():
    mitre_nodes = count_csv("mitre_nodes.csv")
    mitre_edges = count_csv("mitre_edges.csv")
    zig_nodes = count_csv("zig_nodes.csv")
    zig_edges = count_csv("zig_edges.csv")
    cref_nodes = count_csv("cref_nodes.csv")
    cref_edges = count_csv("cref_edges.csv")
    total_nodes, total_edges = graph_counts()

    code_sections = "\n---\n\n".join(embed(p, lang) for p, lang in EMBEDDED_FILES)
    regen_sections = "\n---\n\n".join(embed(p, lang) for p, lang in REGEN_FILES)

    guide = GUIDE_TEMPLATE.format(
        mitre_nodes=mitre_nodes, mitre_edges=mitre_edges,
        zig_nodes=zig_nodes, zig_edges=zig_edges,
        cref_nodes=cref_nodes, cref_edges=cref_edges,
        total_nodes=total_nodes, total_edges=total_edges,
        code_sections=code_sections, regen_sections=regen_sections,
    )

    out = os.path.join(BASE_DIR, "Air_Gapped_Deployment_Guide.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out}")
    print(f"Verification numbers baked in: {total_nodes} nodes / {total_edges} edges "
          f"(MITRE {mitre_nodes}/{mitre_edges}, ZIG {zig_nodes}/{zig_edges}, "
          f"CREF {cref_nodes}/{cref_edges})")


GUIDE_TEMPLATE = '''# Air-Gapped Deployment Guide & Agent Reconstruction Plan

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> Your task is to stand up a Python-based threat-intelligence knowledge graph on this
> air-gapped network. The system maps unstructured red/blue team findings or network
> vulnerability scans to MITRE ATT&CK techniques, D3FEND countermeasures, NSA Zero
> Trust (ZIG) capabilities/activities, NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF)
> approaches, NIST SP 800-53 controls, and DoD Cyber Survivability Attributes, then
> generates standardized POA&M reports spanning tactical, architectural, and
> compliance layers.
>
> **Follow this document top to bottom. Do not improvise, do not "improve" the code,
> and do not skip verification steps.** Every source file you need is embedded below
> in full — copy each one byte-for-byte. After every stage, run the listed
> verification command and compare against the expected output before moving on.
> If a verification fails, stop and fix that stage; later stages depend on it.

---

## 1. What This System Is

Three cooperating pieces, all plain Python:

1. **Knowledge Graph Engine** (`scripts/graph_engine.py`) — loads six CSVs into a
   NetworkX directed graph ({total_nodes} nodes, {total_edges} edges) unifying
   MITRE ATT&CK, MITRE D3FEND, the NSA Zero Trust Implementation Guide (ZIG), and
   NIST SP 800-160 Vol. 2 Cyber Resiliency (CREF) — the last of which also carries
   the DoD Zero Trust Strategy activity-level crosswalk, NIST SP 800-53 control
   citations, and DoD Cyber Survivability Attributes (CSA).
   Exposes `query_node`, `search_nodes`, `keyword_rank`, `semantic_search`,
   `get_neighbors`, and `crawl_subgraph`.
2. **Ingestion pipeline** (`scripts/ingest_assessment.py`) — flattens messy
   multi-tab Excel/CSV assessment reports (any column schema) into
   `processed_assessment.csv`, optionally with vector embeddings.
3. **Report generator** (`agent_batch_processor.py`) — walks each finding through
   the graph (technique → countermeasures → ZIG capabilities → technologies) and
   fills in `assessment_template.md` to produce one POA&M report per finding.

**Graceful degradation is a core design requirement.** If the machine-learning
libraries (`numpy`, `scikit-learn`, `sentence-transformers`) cannot be installed
on this network, the engine catches the `ImportError` and transparently routes
`semantic_search()` through `keyword_rank()` — a stopword-filtered, token-scored
keyword search that works on full sentences. **The absence of ML libraries is an
expected, supported configuration, not an error.** `semantic_search()` returns
`(node_id, node_data, score)` 3-tuples in BOTH modes, so calling code never
needs to know which mode is active.

---

## 2. Asset Manifest — what to port, in priority order

| Priority | Asset | Size | Why |
|---|---|---|---|
| 1 | The six graph CSVs: `mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`, `zig_edges.csv`, `cref_nodes.csv`, `cref_edges.csv` | ~9 MB | The knowledge graph itself. Without these you must regenerate from raw sources (Section 7). |
| 2 | This guide | ~200 KB | Contains every source file in full. |
| 3 | `graph_embeddings.npz` + `embedding_metadata.json` | ~9 MB | Pre-computed node vectors. Saves re-running `embed_graph.py`, but semantic mode still needs item 4 to encode queries. |
| 4 | HuggingFace model cache dir `models--sentence-transformers--all-MiniLM-L6-v2` (from `~/.cache/huggingface/hub/`) | ~90 MB | Required to embed NEW text (queries, new assessments) in semantic mode. |
| 5 | Python wheels: `networkx`, `pandas`, `openpyxl`, `odfpy`; optionally `numpy`, `scikit-learn`, `sentence-transformers` (+torch) | varies | Tier 1–2 are small and mandatory; Tier 3 is ~2 GB with torch and optional. |
| 6 | Raw sources: `enterprise-attack-v19.1(1).xlsx`, `d3fend.csv`, `d3fend-full-mappings.csv`, `ATT&CK_D3FEND_Mappings.ods`, ZIG PDF text extracts, `CREF/*.csv` | ~50 MB | Only needed if item 1 could not be ported. |

**Decision tree:**

- Ported the CSVs (item 1)? → Do Sections 3–6. Skip Section 7.
- No CSVs, but raw sources (item 6)? → Do Sections 3–4, then Section 7, then 5–6.
- Have ML wheels AND the model cache (items 4–5)? → Semantic mode. Run `scripts/embed_graph.py` once (Section 5).
- No ML wheels, or no model cache? → Keyword-fallback mode. Skip Section 5 entirely; everything still works.

---

## 3. Directory Layout

Create exactly this structure (files marked * are generated later, not created by hand):

```text
MITRE_CSD-H/
├── mitre_nodes.csv            # ported or generated by consolidate_mitre_data.py
├── mitre_edges.csv            # ported or generated
├── zig_nodes.csv              # ported or generated by scripts/parse_zig_data.py, THEN reconciled by consolidate_cref_data.py
├── zig_edges.csv              # ported or generated
├── cref_nodes.csv             # ported or generated by consolidate_cref_data.py (run LAST — needs mitre_nodes.csv + zig_nodes.csv)
├── cref_edges.csv             # ported or generated
├── assessment_template.md
├── requirements.txt
├── agent_batch_processor.py
├── agent_crawl_example.py
├── graph_embeddings.npz       # * optional, semantic mode only
├── embedding_metadata.json    # * optional, semantic mode only
├── processed_assessment.csv   # * output of ingest_assessment.py
├── mock_output/               # * generated reports land here
└── scripts/
    ├── graph_engine.py
    ├── embed_graph.py
    └── ingest_assessment.py
```

Install dependencies (Tier 1 is mandatory, others per the decision tree):

```bash
pip install networkx pandas          # Tier 1 — required
pip install openpyxl odfpy           # Tier 2 — only to read Excel/ODS inputs
pip install numpy scikit-learn sentence-transformers   # Tier 3 — OPTIONAL semantic mode
```

---

## 4. Source Files (copy each verbatim)

{code_sections}

---

## 5. OPTIONAL — Semantic Mode Setup

Skip this section entirely if Tier 3 libraries are unavailable. The system is
fully functional in keyword-fallback mode.

**5.1 Port the embedding model.** `SentenceTransformer('all-MiniLM-L6-v2')`
normally downloads from the internet, which will fail here. Copy the cached
model directory from the low side:

```text
LOW SIDE:  ~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2/   (~90 MB)
HIGH SIDE: same path under the service account's home directory
```

Then force offline resolution so the library never attempts a network call:

```bash
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
```

(Alternative: place the model folder anywhere and change every
`SentenceTransformer('all-MiniLM-L6-v2')` call to
`SentenceTransformer('/absolute/path/to/model-dir')` — it appears once each in
`graph_engine.py`, `embed_graph.py`, and `ingest_assessment.py`.)

**5.2 Generate graph embeddings** (once, and again whenever the CSVs change).
If `graph_embeddings.npz` + `embedding_metadata.json` were ported, you may skip
this — but you MUST regenerate them if you regenerated the CSVs in Section 7,
because the vector row order must match the node list.

```bash
python3 scripts/embed_graph.py
```

Expected: a progress bar, then
`Successfully saved embeddings to .../graph_embeddings.npz ...`.

---

## 6. VERIFICATION — run after setup, before first real use

**6.1 Engine loads and both frameworks are present:**

```bash
python3 scripts/graph_engine.py
```

Expected output (numbers must match within a few units if you ported the CSVs;
they will differ slightly if MITRE releases new data):

```text
Knowledge Graph initialized with {total_nodes} nodes and {total_edges} edges.

Test: Querying a ZIG Pillar
{{'id': 'ZIG-PIL-1', 'type': 'zig_pillar', 'name': 'User Pillar', ...}}

Test: Querying a MITRE node (e.g. T1548)
{{'id': 'T1548', 'type': 'attack_technique', 'name': 'Abuse Elevation Control Mechanism', ...}}

Test: Search (semantic if available, keyword fallback otherwise)
  [T...] ... (score: ...)
```

Reference counts: MITRE = {mitre_nodes} nodes / {mitre_edges} edges,
ZIG = {zig_nodes} nodes / {zig_edges} edges, CREF = {cref_nodes} nodes / {cref_edges} edges.

**6.2 Search returns 3-tuples in whichever mode is active:**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
r = e.semantic_search('attacker dumped password hashes from memory', top_k=5)
assert r and len(r[0]) == 3, 'search must return (id, data, score) 3-tuples'
for nid, data, score in r: print(nid, data.get('name'), round(score, 3))
"
```

Expected: 5 rows; credential-dumping-related techniques/analytics near the top
(e.g. `T1003.001 OS Credential Dumping: LSASS Memory`). In keyword-fallback mode
you will first see a `[Warning] Semantic search unavailable...` line — that is
correct behavior, not an error.

**6.3 End-to-end pipeline on mock data.** Create a small test CSV, then run:

```bash
python3 - <<'EOF'
import pandas as pd
pd.DataFrame({{
    "IP": ["192.168.1.15", "10.0.50.5"],
    "Hostname": ["DC-01", "EDGE-RTR-01"],
    "Finding": ["Kerberos Pre-Authentication disabled on service accounts",
                 "Weak administrative password set"],
    "Severity": ["High", "Critical"],
}}).to_csv("mock_assessment_data.csv", index=False)
EOF
python3 scripts/ingest_assessment.py mock_assessment_data.csv
python3 agent_batch_processor.py --limit 2
```

Expected: `Generated .../mock_output/ASMT-1000.md -> Mapped to T... & ZIG-CAP-...`
for each finding. Open a generated report and confirm: every section is filled,
every MITRE/D3FEND/ZIG identifier in it exists in the graph (spot-check with
`engine.query_node(...)`), and no section contains invented framework IDs.

---

## 7. ONLY IF CSVs WERE NOT PORTED — regenerate from raw sources

Requires the raw files from Asset Manifest item 6 in the repo root, plus Tier 2
libraries. Create the three scripts below, then run THEM IN THIS ORDER:

```bash
python3 consolidate_mitre_data.py      # → mitre_nodes.csv, mitre_edges.csv, ontology.json
cd raw_data/zig 2>/dev/null || true    # parse_zig_data.py expects the ZIG .txt files in its cwd
python3 scripts/parse_zig_data.py      # → zig_nodes.csv, zig_edges.csv (move them to repo root)
cd - 2>/dev/null || true
python3 consolidate_cref_data.py       # → cref_nodes.csv, cref_edges.csv; ALSO reconciles zig_nodes.csv/zig_edges.csv
```

Notes for the agent:
- `consolidate_mitre_data.py` ends with an integrity pass that drops edges
  referencing unknown node IDs. A small number of dropped edges (tens, not
  hundreds) is normal.
- The ZIG parser reads text extracted from the NSA ZIG PDFs
  (`CTR_ZIG_*.PDF.txt`) plus `zig_tech_mappings.txt`. If only the PDFs are
  available, extract text first (any PDF-to-text tool; `pdfplumber` works).
- `consolidate_cref_data.py` MUST run last: it reads `mitre_nodes.csv` to validate
  edge targets and to detect the ~28 mitigation IDs that are actually native ATT&CK
  `M####` codes (skip creating a duplicate `cref_mitigation` node for those — the
  existing `attack_mitigation` node is authoritative). It also OVERWRITES
  `zig_nodes.csv`/`zig_edges.csv` in place: it reuses the existing
  `ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*` IDs rather than minting duplicates for the
  same DoD Zero Trust pillars, adds the ~3 capabilities and ~59 activities present
  in `CREF/zero-trust-attack.csv` but missing from the PDF extraction, and replaces
  garbled PDF-extracted `zig_activity` names/descriptions with the clean text from
  that file. Do not re-run `scripts/parse_zig_data.py` after this step — it would
  overwrite the reconciliation with the original PDF-scraped data.
- After regenerating CSVs, regenerate embeddings (Section 5.2) if in semantic mode.

{regen_sections}

---

## 8. Graph Reference (for writing queries)

**Node ID prefixes / types:**

| Prefix | `type` attribute | Framework |
|---|---|---|
| `T`, `T....XXX` | `attack_technique` | ATT&CK technique / sub-technique |
| `TA` | `attack_tactic` | ATT&CK tactic |
| `M1` | `attack_mitigation` | ATT&CK mitigation |
| `G` / `S` / `C` | `attack_group` / `attack_software` / `attack_campaign` | ATT&CK threat intel |
| `DET` | `attack_detectionstrategy` | ATT&CK detection strategy |
| `AN` | `attack_analytic` | ATT&CK analytic (name is generic; the useful text is in `description`) |
| `DC` | `attack_datacomponent` | ATT&CK data component |
| `D3-` | `d3fend_technique` | D3FEND countermeasure |
| `D3-TAC-` | `d3fend_tactic` | D3FEND tactic |
| `DA-` / `OA-` | `defensive_artifact` / `offensive_artifact` | D3FEND artifacts |
| `ZIG-PIL-` / `ZIG-CAP-` / `ZIG-ACT-` / `ZIG-TECH-` | `zig_pillar` / `zig_capability` / `zig_activity` / `zig_technology` | NSA Zero Trust |
| `CREF-GOAL-` / `CREF-OBJ-` / `CREF-TECH-` / `CREF-APP-` | `cref_goal` / `cref_objective` / `cref_technique` / `cref_approach` | NIST SP 800-160 Vol. 2 CREF taxonomy |
| `CREF-STA-` / `CREF-STU-` | `cref_design_principle_strategic` / `cref_design_principle_structural` | CREF design principles |
| `CSA-` | `csa` | DoD Cyber Survivability Attribute |
| `CREF-EFFECT-` | `cref_effect` | CREF effect (Contain, Preclude, Recover, ...) |
| `CM####` (or a native `M####` when reused) | `cref_mitigation` | DoD cyber-resiliency mitigation catalog |
| e.g. `AC-4(3)`, `IR-4(2)` | `nist_800_53_control` | NIST SP 800-53 control |

**Key relationship types:** `belongs_to_tactic`, `subtechnique_of`, `uses`
(group/software/campaign → technique), `mitigates` (M → T), `detects` (DET → T),
`has_analytic` (DET → AN), `monitors_data_component` (AN → DC),
`mapped_to_d3fend_technique` (M → D3-), `targets` (DA → OA), plus D3FEND artifact
verbs (`accesses`, `modifies`, `creates`, ...), and ZIG's `belongs_to_pillar`,
`belongs_to_capability`, `implements_capability` (ZIG-TECH → ZIG-CAP). CREF adds:
`realizes_technique` (Approach → Technique), `achieves_objective` (Technique →
Objective), `serves_goal` (Objective → Goal), `requires_principle`/
`informs_principle` (Technique → Design Principle), `embodies_principle` (CSA →
Design Principle), `associated_with_technique` (CSA → Technique), `has_effect`
(Approach → Effect), `mitigates_architecturally` (Approach → T-code, the
architectural counterpart to native `mitigates`), `implements_approach` (CM → CREF
Approach), `satisfies_control` (CM → NIST control), `implements_activity` (CM →
ZIG Activity), and a **direct** `mitigates` edge from `zig_activity` straight to a
T-code (sourced from the DoD Zero Trust Strategy crosswalk — no keyword matching
required where this edge exists).

**CSV schemas:** node files are `id,type,name,description,url`; edge files are
`source_id,target_id,relationship_type`.

---

## 9. Agent Workflow: From Threat Intel to Remediation Plan

When a user hands you unstructured findings, do this per finding (this is what
`agent_batch_processor.py` automates — read it as the reference implementation):

This applies whether the input is unstructured threat intel text or a flattened
network vulnerability finding (Section 6.3's `ingest_assessment.py` path) — both
go through the same technique-mapping step; only the entity-extraction step differs.

1. **Extract** the core technical behavior from the text (e.g. "forged Kerberos tickets").
2. **Map** it to an ATT&CK technique: `engine.semantic_search(text, top_k=20)`,
   then take the highest-scoring result whose ID starts with `T` followed by a
   digit. Never map the primary finding to an `AN`, `M`, or `DET` node.
3. **Crawl** for defenses: `engine.crawl_subgraph(t_code, depth=2)`. From the
   returned nodes collect `d3fend_technique` (countermeasures),
   `defensive_artifact`/`attack_datacomponent` (artifacts), `attack_analytic`
   (detections — quote their `description`), `attack_mitigation`.
4. **Correlate to Zero Trust:** check the Step 3 subgraph's edges for a
   `zig_activity` with a direct `mitigates` edge to the T-code (from the DoD Zero
   Trust Strategy crosswalk); resolve its capability/pillar via `belongs_to_capability`
   then `belongs_to_pillar`. Only if none exists, fall back to
   `engine.keyword_rank(countermeasure_name, top_k=100)`, filtered for
   `zig_capability`/`zig_technology`.
5. **CREF architectural resiliency:** check the same subgraph for a `cref_approach`
   with a `mitigates_architecturally` edge to the T-code. Walk it up via
   `realizes_technique` → `cref_technique` → `achieves_objective` → `cref_objective`
   → `serves_goal` → `cref_goal`, and sideways via `has_effect` → `cref_effect`.
6. **NIST SP 800-53 compliance:** check the same subgraph for a `cref_mitigation`
   with a `mitigates` edge to the T-code, then follow its `satisfies_control`
   edge(s) to cite concrete controls (e.g. `AC-4(3)`). State plainly if none exist.
7. **Cyber Survivability Attribute framing:** from the `cref_technique` resolved in
   step 5, follow the `associated_with_technique` edge backward to a `csa` node —
   this is the mission-level "why leadership should care" line.
8. **Generate** one narrowly-scoped report per finding by filling EVERY
   placeholder in `assessment_template.md` (all 7 sections — there is no severity
   gate; every report gets the CREF/NIST/CSA layer). Write the Exploitation
   Scenario / Impact / POA&M text yourself from the finding's context. **Never
   invent MITRE, D3FEND, ZIG, CREF, NIST, or CSA identifiers — only use IDs
   returned by the engine.** No emojis in reports.

For bulk processing: `python3 scripts/ingest_assessment.py <report.xlsx>` then
`python3 agent_batch_processor.py --limit N` — then review and enrich the
generated reports (the batch script's Exploitation/Impact text is heuristic;
replace it with your own analysis). `agent_batch_processor.py` is the reference
implementation of steps 2-7 above — read it before writing a from-scratch script.

---

## 10. Using an Internal Embedding API Instead of a Local Model

If ML libraries exist high-side but the model cannot be hosted locally, point
the two `encode` call sites at your internal embeddings endpoint:

1. **`scripts/embed_graph.py`** — replace `model.encode(texts_to_embed, ...)`
   with a loop that POSTs each text to the API and collects vectors into
   `embeddings = np.array(list_of_vectors)`.
2. **`scripts/graph_engine.py` → `semantic_search()`** — replace
   `self.embedding_model.encode([query_text])` with one API call. The result
   must be a 2-D array: `query_vec = np.array([vector])`.

Both files contain `EXTERNAL API SCAFFOLDING` comment blocks marking the exact
lines. The cosine-similarity ranking is unchanged. All vectors (graph and
query) must come from the SAME model — never mix local and API embeddings.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Knowledge Graph initialized with 0 nodes` | CSVs missing from the repo root (the engine resolves them relative to its own file, so cwd is not the issue) | Put the four CSVs next to `scripts/`' parent, i.e. the repo root |
| `[Warning] Semantic search unavailable...` | Tier 3 libs or embedding files absent | Expected in keyword-fallback mode; ignore, or complete Section 5 |
| `SentenceTransformer` tries to download / times out | Model cache not ported or offline env vars unset | Section 5.1 |
| Search results are all `AN` analytics | You forgot to filter for `T`-prefixed IDs (workflow step 2) | Filter results |
| `KeyError` in `agent_batch_processor.py` template fill | `assessment_template.md` placeholders don't match — you edited one file but not the other | Diff the `template.format(...)` kwargs against the `{{PLACEHOLDER}}` names |
| Embedding search returns nonsense after CSV regeneration | Stale `graph_embeddings.npz` (row order no longer matches nodes) | Re-run `scripts/embed_graph.py` |
| A `zig_activity` node's `type` attribute got silently changed to `cref_mitigation` (or similar) | Ran `consolidate_cref_data.py` before `mitre_nodes.csv`/`zig_nodes.csv` existed, so its native-ID collision check had nothing to compare against | Re-run in the order given in Section 7: `consolidate_mitre_data.py` → `scripts/parse_zig_data.py` → `consolidate_cref_data.py` |
| ZIG activity names reverted to garbled PDF text (dot-leaders, trailing `D-`) | Ran `scripts/parse_zig_data.py` again after `consolidate_cref_data.py`, overwriting the reconciliation | Re-run `consolidate_cref_data.py` again to re-apply the clean names |
| Section 4/5/7 of a generated report all say "None found in graph" | Normal for techniques the CREF/DoD-ZT-Strategy datasets don't cover yet — not every T-code has an architectural or compliance mapping. Confirm via `engine.crawl_subgraph(t_code, depth=2)` that no `cref_approach`/`cref_mitigation` edges target it | No fix needed; report it as-is rather than inventing a mapping |

---

*This guide is generated by `build_deployment_guide.py` from the live source
files — regenerate it after any code change rather than editing it by hand.*
'''


if __name__ == "__main__":
    main()
