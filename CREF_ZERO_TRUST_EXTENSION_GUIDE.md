# CREF / DoD Zero Trust / NIST 800-53 Extension Guide

> **PROMPT — read this first if you are an autonomous coding agent (e.g. Claude Sonnet):**
> This is a DELTA guide, not a from-scratch build. It assumes the base MITRE
> ATT&CK/D3FEND/ZIG system from `Air_Gapped_Deployment_Guide.md` (or
> `PORTABLE_RECONSTRUCTION_BUNDLE.md`) is ALREADY deployed and working on this
> network — `mitre_nodes.csv`, `mitre_edges.csv`, `zig_nodes.csv`, `zig_edges.csv`
> already exist, and `python3 scripts/graph_engine.py` already runs cleanly.
>
> Your task is to add a fourth framework layer — NIST SP 800-160 Vol. 2 Cyber
> Resiliency (CREF), the DoD Zero Trust Strategy activity-level crosswalk, NIST
> SP 800-53 control citations, and DoD Cyber Survivability Attributes (CSA) — on
> top of that system, WITHOUT duplicating anything already in the graph.
>
> **Do STEP 0 before touching any file.** If it fails, stop and fix the base
> system first — this extension cannot be validated on top of a broken base.
> **Follow this document top to bottom. Do not improvise, do not "improve" the
> code, and do not skip verification steps.** Every source file you need is
> embedded below in full, each with a SHA-256 — copy each one byte-for-byte and
> verify the hash before trusting the copy.

---

## STEP 0 — Verify the base system before starting

```bash
python3 scripts/graph_engine.py
```

Expected: a node/edge count with NO `cref_*` or `CSA-*` or `NIST` mentions in the
test output (this extension has not been applied yet), and no traceback. If this
fails, fix the base deployment first (see `Air_Gapped_Deployment_Guide.md` Section 11).

---

## Why this extension exists

The base system covers tactical response: "what technique is this, what D3FEND
countermeasure blocks it, what ZIG capability does that map to." It has two blind
spots this extension fills:

1. **No architectural/resiliency layer.** D3FEND and ZIG are both about blocking or
   detecting a specific technique. Neither covers systems-engineering controls that
   assume the tactical control will eventually fail — redundancy, non-persistence,
   diversity, deception. CREF (NIST SP 800-160 Vol. 2) fills this gap.
2. **No compliance citation.** Leadership and compliance reviewers need a NIST SP
   800-53 control ID and a DoD Cyber Survivability Attribute, not a D3FEND technique
   name. The DoD Zero Trust Strategy crosswalk and the CSA catalog fill this gap, and
   also add a DIRECT edge from ZIG activities to ATT&CK techniques — replacing the
   base system's fuzzy keyword-matching correlation with a precise graph edge for
   every technique this dataset covers.

**Every report this system generates now includes all three layers (tactical,
architectural, compliance) — there is no severity gate.** A routine finding gets the
CREF/NIST/CSA sections too, same as a critical one.

---

## Critical gotcha: do not duplicate the Zero Trust taxonomy

`CREF/zero-trust-attack.csv` encodes the same 7 DoD Zero Trust pillars, ~45
capabilities, and ~140+ activities that `zig_nodes.csv`/`zig_edges.csv` already
carry (extracted from the NSA ZIG PDFs). Naively loading it as a new taxonomy would
create a duplicate `ZT-PIL-*`-style pillar/capability/activity for every one that
already exists as `ZIG-PIL-*`/`ZIG-CAP-*`/`ZIG-ACT-*`.

`consolidate_cref_data.py` handles this correctly by RECONCILING instead of
duplicating:
- reuses the existing `ZIG-PIL-{n}` / `ZIG-CAP-{id}` / `ZIG-ACT-{id}` IDs verbatim
- adds the ~3 capabilities and ~59 activities present in the new dataset but missing
  from the PDF extraction
- OVERWRITES existing `zig_activity` name/description fields with this dataset's
  clean text (the PDF extraction is dot-leader/pagination garbage, e.g.
  `"Inventory User .......... D-"`; the new dataset is authoritative for this layer)
- never touches `zig_pillar` names or existing `zig_capability` names (those
  extracted cleanly the first time)

Do not re-run `scripts/parse_zig_data.py` after applying this extension — it would
overwrite the reconciliation with the original PDF-scraped data. If you ever need to
re-parse the ZIG PDFs from scratch, re-run `consolidate_cref_data.py` again
immediately afterward to re-apply the reconciliation.

A second, subtler gotcha: about 28 rows in the raw CREF files use a native ATT&CK
`M####` mitigation ID in what is otherwise a `CM####`-catalog column. Writing those
into `cref_nodes.csv` as type `cref_mitigation` would silently overwrite their
correct `attack_mitigation` type when the graph loads `cref_nodes.csv` after
`mitre_nodes.csv`. `consolidate_cref_data.py` checks for this (`add_mitigation_node`)
and skips node creation for any ID that already exists in `mitre_nodes.csv`, while
still wiring up the edges. If you hand-modify the script, preserve this check.

---

## Asset Manifest — what to port, in priority order

| Priority | Asset | Why |
|---|---|---|
| 1 | `CREF/` directory: `cref-relationships.csv`, `design-principles-cref.csv`, `csa-cref-attack.csv`, `impact.csv`, `attack-relationships-sankey-export.csv`, `zero-trust-attack.csv` | Raw sources. Plain CSV text — passes a CDS as-is. Required unless you port item 2 instead. |
| 2 | Pre-built `cref_nodes.csv` / `cref_edges.csv` + the RECONCILED `zig_nodes.csv` / `zig_edges.csv` | Skip regeneration entirely if these can be ported directly. Still port item 1 too if you might need to regenerate later (e.g. MITRE/CREF data updates). |
| 3 | This guide | Contains every changed/new source file in full, with hashes. |
| 4 | `graph_embeddings.npz` + `embedding_metadata.json` (regenerated for the new node set) | MANDATORY to re-run `scripts/embed_graph.py` if you did not port these — the node set changed, so the base system's old embeddings are now stale (row count mismatch). |

**Decision tree:**
- Ported item 2? → Skip to STEP 3 (still overwrite the code files in STEP 2 first).
- Only item 1? → Do STEP 1, then STEP 2, then STEP 2.5 regeneration, then STEP 3.

---

## STEP 1 — Back up before mutating ZIG data

`consolidate_cref_data.py` overwrites `zig_nodes.csv`/`zig_edges.csv` in place. Back
them up first so a bad run is a `cp` away from reversible, not a re-parse of the ZIG
PDFs away:

```bash
cp zig_nodes.csv zig_nodes.csv.bak
cp zig_edges.csv zig_edges.csv.bak
```

---

## STEP 2 — Write / overwrite the changed source files (copy each verbatim)

Verify each file's SHA-256 after copying, before running anything:

| File | Size (bytes) | SHA-256 (first 16 hex chars) |
|---|---|---|
| `consolidate_cref_data.py` | 15424 | `2641d658cd3ec44e...` |
| `scripts/graph_engine.py` | 9001 | `b1b5ae1df769b20c...` |
| `threat_assessment_skill.md` | 8755 | `5be4cf80948c153b...` |
| `assessment_template.md` | 3272 | `f237e6ce6afe37ba...` |
| `agent_batch_processor.py` | 16655 | `03862d6b9ce4518a...` |
| `agent_crawl_example.py` | 7596 | `d3a08b5e7f4b38fe...` |

### FILE: `consolidate_cref_data.py` (sha256=2641d658cd3ec44e682fd51cd4761c63b1ad0d3e8f92807c76144ff028ee2bfd)

````python
"""Regenerates cref_nodes.csv / cref_edges.csv from the raw CREF/*.csv files, and
reconciles the DoD Zero Trust Strategy Pillar/Capability/Activity taxonomy found in
CREF/zero-trust-attack.csv against the EXISTING zig_nodes.csv/zig_edges.csv.

Why a separate reconciliation step: CREF/zero-trust-attack.csv encodes the same 7 DoD
Zero Trust pillars (User, Device, Network & Environment, Application & Workload, Data,
Automation & Orchestration, Visibility & Analytics) that scripts/parse_zig_data.py
already extracted from the NSA ZIG PDFs as ZIG-PIL-*/ZIG-CAP-*/ZIG-ACT-* nodes. Treating
it as a fresh taxonomy would duplicate every pillar/capability/activity. Instead this
script:
  - reuses the existing ZIG-PIL-{n} / ZIG-CAP-{id} / ZIG-ACT-{id} node IDs verbatim
  - ADDS the ~3 capabilities and ~59 activities present in the new dataset but missing
    from the PDF extraction
  - OVERWRITES existing zig_activity name/description with the new dataset's clean text
    (the PDF extraction is dot-leader/pagination garbage, e.g. "Inventory User ... D-";
    zero-trust-attack.csv's activity_name/activity_description is the authoritative
    source of truth for this layer)
  - never touches zig_pillar or existing zig_capability names (those extracted fine)

New node types this script introduces (none of these previously existed in the graph):
  cref_goal, cref_objective, cref_technique, cref_approach,
  cref_design_principle_strategic, cref_design_principle_structural,
  csa (DoD Cyber Survivability Attribute), cref_effect,
  cref_mitigation (CM#### catalog), nist_800_53_control

Source files (NIST SP 800-160 Vol 2 Cyber Resiliency Engineering Framework, the DoD
Cyber Survivability Endorsement Implementation Guide, and the DoD Zero Trust Strategy
activity-level crosswalk):
  CREF/cref-relationships.csv          Goal -> Objective -> Technique -> Approach (canonical taxonomy)
  CREF/design-principles-cref.csv      Strategic/Structural Design Principle -> Technique
  CREF/csa-cref-attack.csv             CSA -> Design Principles -> Technique/Approach -> ATT&CK
  CREF/impact.csv                      Technique/Approach -> Effect
  CREF/attack-relationships-sankey-export.csv   Approach -> ATT&CK -> CM Mitigation -> NIST 800-53 Control
  CREF/zero-trust-attack.csv           ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation

Run after ANY change to the CREF/ raw files:
    python3 consolidate_cref_data.py
"""
import csv
import os
import re

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREF_DIR = os.path.join(BASE_DIR, "CREF")

# ---------------------------------------------------------------------------
# New CREF/CSA/NIST-control nodes + edges (written to cref_nodes.csv / cref_edges.csv)
# ---------------------------------------------------------------------------
cref_nodes = {}   # id -> {id, type, name, description, url}
cref_edges = set()  # (source_id, target_id, relationship_type)


def cref_id(prefix, raw):
    """Turns a raw CREF id ('g1', 'sta4', 'a45') into a globally unique node id."""
    digits = re.sub(r"[^0-9.]", "", str(raw))
    return f"{prefix}-{digits}"


def add_cref_node(id_, type_, name, description=""):
    if pd.isna(id_) or not str(id_).strip():
        return None
    id_ = str(id_).strip()
    if id_ not in cref_nodes:
        cref_nodes[id_] = {
            "id": id_,
            "type": type_,
            "name": str(name).strip() if pd.notna(name) else "",
            "description": str(description).strip() if pd.notna(description) else "",
            "url": "",
        }
    elif not cref_nodes[id_]["description"] and pd.notna(description) and str(description).strip():
        cref_nodes[id_]["description"] = str(description).strip()
    return id_


def add_cref_edge(source_id, target_id, rel_type):
    if pd.isna(source_id) or pd.isna(target_id):
        return
    source_id, target_id = str(source_id).strip(), str(target_id).strip()
    if not source_id or not target_id:
        return
    cref_edges.add((source_id, target_id, rel_type))


def read_csv(name):
    return pd.read_csv(os.path.join(CREF_DIR, name))


# Some rows use a native ATT&CK Mitigation ID (e.g. "M1026") in the mitigation_id
# column instead of the DoD CM#### catalog. Those nodes already exist in
# mitre_nodes.csv as type attack_mitigation -- writing them into cref_nodes.csv as
# type cref_mitigation would silently overwrite the correct type when the graph
# loads mitre_nodes.csv then cref_nodes.csv. Detect and skip node creation for them
# (edges to/from them still get added normally).
print("Loading mitre_nodes.csv IDs (native-mitigation collision check)...")
with open(os.path.join(BASE_DIR, "mitre_nodes.csv"), encoding="utf-8") as f:
    mitre_ids = {row["id"] for row in csv.DictReader(f)}


def add_mitigation_node(raw_id, name):
    mid = str(raw_id).strip() if pd.notna(raw_id) else ""
    if not mid:
        return None
    if mid in mitre_ids:
        return mid
    return add_cref_node(mid, "cref_mitigation", name)


print("Parsing cref-relationships.csv (canonical Goal->Objective->Technique->Approach)...")
df = read_csv("cref-relationships.csv")
for _, row in df.iterrows():
    g = add_cref_node(cref_id("CREF-GOAL", row["goal_id"]), "cref_goal", row["Goal"], row.get("goal_description"))
    o = add_cref_node(cref_id("CREF-OBJ", row["obj_id"]), "cref_objective", row["Objective"], row.get("obj_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["Technique"], row.get("tech_description"))
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["Approach"], row.get("app_description"))
    if g and o:
        add_cref_edge(o, g, "serves_goal")
    if o and t:
        add_cref_edge(t, o, "achieves_objective")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")

print("Parsing design-principles-cref.csv...")
df = read_csv("design-principles-cref.csv")
for _, row in df.iterrows():
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    rel = "requires_principle" if pd.notna(row.get("required")) and int(row["required"]) == 1 else "informs_principle"
    if t and sta:
        add_cref_edge(t, sta, rel)
    if t and stu:
        add_cref_edge(t, stu, rel)

print("Parsing csa-cref-attack.csv (DoD Cyber Survivability Attributes)...")
df = read_csv("csa-cref-attack.csv")
for _, row in df.iterrows():
    csa = add_cref_node(str(row["csa_id"]).strip(), "csa", row["csa_name"])
    sta = add_cref_node(cref_id("CREF-STA", row["strategic_design_principle_id"]),
                         "cref_design_principle_strategic", row["strategic_design_principle"])
    stu = add_cref_node(cref_id("CREF-STU", row["structural_design_principle_id"]),
                         "cref_design_principle_structural", row["structural_design_principle"])
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["APPROACH_ID"]), "cref_approach", row["approach"])
    if csa and sta:
        add_cref_edge(csa, sta, "embodies_principle")
    if csa and stu:
        add_cref_edge(csa, stu, "embodies_principle")
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if csa and t:
        add_cref_edge(csa, t, "associated_with_technique")
    if a and pd.notna(row.get("attack_technique_id")):
        add_cref_edge(a, str(row["attack_technique_id"]).strip(), "mitigates_architecturally")

print("Parsing impact.csv (Approach -> Effect)...")
df = read_csv("impact.csv")
for _, row in df.iterrows():
    t = add_cref_node(cref_id("CREF-TECH", row["cref_technique_id"]), "cref_technique", row["technique"])
    a = add_cref_node(cref_id("CREF-APP", row["approach_id"]), "cref_approach", row["approach"])
    e = add_cref_node(cref_id("CREF-EFFECT", row["effect_id"]), "cref_effect", row["effect"])
    if t and a:
        add_cref_edge(a, t, "realizes_technique")
    if a and e:
        add_cref_edge(a, e, "has_effect")

print("Parsing attack-relationships-sankey-export.csv (Approach -> ATT&CK -> CM Mitigation -> NIST 800-53)...")
df = read_csv("attack-relationships-sankey-export.csv")
for _, row in df.iterrows():
    a = add_cref_node(cref_id("CREF-APP", row["app_id"]), "cref_approach", row["approach"], row.get("app_description"))
    t = add_cref_node(cref_id("CREF-TECH", row["tech_id"]), "cref_technique", row["technique"], row.get("tech_description"))
    if a and t:
        add_cref_edge(a, t, "realizes_technique")

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and pd.notna(row.get("control")):
            control = add_cref_node(str(row["control"]).strip(), "nist_800_53_control", row["control"])
            if cm and control:
                add_cref_edge(cm, control, "satisfies_control")

# ---------------------------------------------------------------------------
# zero-trust-attack.csv: reconcile against existing ZIG nodes, then add the new
# cref_mitigation/cref_approach edges plus the direct ZIG-activity<->ATT&CK bridge.
# ---------------------------------------------------------------------------
print("Loading existing zig_nodes.csv / zig_edges.csv for reconciliation...")
zig_nodes = {}
with open(os.path.join(BASE_DIR, "zig_nodes.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_nodes[row["id"]] = dict(row)

zig_edges = set()
with open(os.path.join(BASE_DIR, "zig_edges.csv"), encoding="utf-8") as f:
    for row in csv.DictReader(f):
        zig_edges.add((row["source_id"], row["target_id"], row["relationship_type"]))

new_zig_activities = new_zig_capabilities = 0

print("Parsing zero-trust-attack.csv (ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation)...")
df = read_csv("zero-trust-attack.csv")
for _, row in df.iterrows():
    pillar_id = str(row["pillar_id"]).strip() if pd.notna(row.get("pillar_id")) else None
    cap_id = str(row["capability_id"]).strip() if pd.notna(row.get("capability_id")) else None
    act_id = str(row["activity_id"]).strip() if pd.notna(row.get("activity_id")) else None

    zig_pil = f"ZIG-PIL-{pillar_id}" if pillar_id else None
    zig_cap = f"ZIG-CAP-{cap_id}" if cap_id else None
    zig_act = f"ZIG-ACT-{act_id}" if act_id else None

    # Add capabilities missing from the PDF extraction (never overwrite existing ones).
    if zig_cap and zig_cap not in zig_nodes:
        zig_nodes[zig_cap] = {"id": zig_cap, "type": "zig_capability",
                               "name": str(row["capability_name"]).strip(), "description": "", "url": ""}
        new_zig_capabilities += 1
        if zig_pil:
            zig_edges.add((zig_cap, zig_pil, "belongs_to_pillar"))

    # Activities: add if missing, or overwrite the PDF-scraped garbage name/description
    # with this dataset's clean text (authoritative source for this layer).
    if zig_act:
        clean_name = str(row["activity_name"]).strip() if pd.notna(row.get("activity_name")) else ""
        clean_desc = str(row["activity_description"]).strip() if pd.notna(row.get("activity_description")) else ""
        if zig_act not in zig_nodes:
            zig_nodes[zig_act] = {"id": zig_act, "type": "zig_activity",
                                   "name": clean_name, "description": clean_desc, "url": ""}
            new_zig_activities += 1
            if zig_cap:
                zig_edges.add((zig_act, zig_cap, "belongs_to_capability"))
        elif clean_name:
            zig_nodes[zig_act]["name"] = clean_name
            zig_nodes[zig_act]["description"] = clean_desc

    a = add_cref_node(cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("approach")) \
        if pd.notna(row.get("app_id")) else None

    attack_id = str(row["attack_technique_id"]).strip() if pd.notna(row.get("attack_technique_id")) else None
    if a and attack_id:
        add_cref_edge(a, attack_id, "mitigates_architecturally")

    # The direct ZIG-activity <-> ATT&CK bridge: previously this correlation only
    # existed via fuzzy keyword matching of D3FEND countermeasure names (see
    # threat_assessment_skill.md Step 4). This is a precise graph edge instead.
    if zig_act and attack_id:
        cref_edges.add((zig_act, attack_id, "mitigates"))

    if pd.notna(row.get("mitigation_id")):
        cm = add_mitigation_node(row["mitigation_id"], row["mitigation"])
        if cm and attack_id:
            add_cref_edge(cm, attack_id, "mitigates")
        if cm and a:
            add_cref_edge(cm, a, "implements_approach")
        if cm and zig_act:
            add_cref_edge(cm, zig_act, "implements_activity")

print(f"  Added {new_zig_capabilities} new zig_capability nodes, {new_zig_activities} new zig_activity nodes.")
print(f"  Cleaned activity names/descriptions for {len(df['activity_id'].dropna().astype(str).str.strip().unique()) - new_zig_activities} existing zig_activity nodes.")

# ---------------------------------------------------------------------------
# Integrity pass: drop cref_edges whose endpoint is not a real node anywhere in
# the graph (mitre_nodes.csv, the now-reconciled zig_nodes, or our own new nodes).
# Mirrors the same pass in consolidate_mitre_data.py.
# ---------------------------------------------------------------------------
known_ids = set(cref_nodes.keys()) | set(zig_nodes.keys()) | mitre_ids
before = len(cref_edges)
cref_edges = {e for e in cref_edges if e[0] in known_ids and e[1] in known_ids}
dropped = before - len(cref_edges)
if dropped:
    print(f"Integrity pass: dropped {dropped} edges referencing unknown node IDs ({len(cref_edges)} remain).")

# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------
print("Writing cref_nodes.csv / cref_edges.csv...")
pd.DataFrame(list(cref_nodes.values())).to_csv(os.path.join(BASE_DIR, "cref_nodes.csv"), index=False)
pd.DataFrame(list(cref_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "cref_edges.csv"), index=False)

print("Writing reconciled zig_nodes.csv / zig_edges.csv...")
pd.DataFrame(list(zig_nodes.values())).to_csv(os.path.join(BASE_DIR, "zig_nodes.csv"), index=False)
pd.DataFrame(list(zig_edges), columns=["source_id", "target_id", "relationship_type"]) \
    .to_csv(os.path.join(BASE_DIR, "zig_edges.csv"), index=False)

print(f"Done! CREF: {len(cref_nodes)} nodes, {len(cref_edges)} edges. "
      f"ZIG (reconciled): {len(zig_nodes)} nodes, {len(zig_edges)} edges.")
````

---

### FILE: `scripts/graph_engine.py` (sha256=b1b5ae1df769b20cd57e2d4b8df294a8af9444680ea8ff5d2390c09a4ce69bce)

````python
import csv
import json
import os
import re
import networkx as nx

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False

# All data files live in the repository root (the parent of this scripts/ dir),
# so the engine works no matter what directory it is launched from.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Words too generic to score on during keyword-fallback search
STOPWORDS = {
    'the', 'a', 'an', 'and', 'or', 'of', 'on', 'in', 'to', 'for', 'with',
    'by', 'is', 'are', 'was', 'were', 'be', 'been', 'this', 'that', 'it',
    'as', 'at', 'from', 'has', 'have', 'had', 'via', 'using', 'used', 'use'
}

class KnowledgeGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.load_data()

        self.semantic_enabled = SEMANTIC_ENABLED
        self.embedding_model = None
        self.embeddings = None
        self.embedding_node_ids = None

        if self.semantic_enabled:
            self._load_embeddings()

    def _load_embeddings(self):
        try:
            npz_path = os.path.join(BASE_DIR, 'graph_embeddings.npz')
            meta_path = os.path.join(BASE_DIR, 'embedding_metadata.json')

            if os.path.exists(npz_path) and os.path.exists(meta_path):
                self.embeddings = np.load(npz_path)['embeddings']
                with open(meta_path, 'r', encoding='utf-8') as f:
                    self.embedding_node_ids = json.load(f)['node_ids']
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            else:
                print("[Info] Embedding files not found. Semantic search disabled; keyword fallback active.")
                self.semantic_enabled = False
        except Exception as e:
            print(f"Failed to load semantic model/embeddings: {e}")
            self.semantic_enabled = False

    def load_data(self):
        # Order matters: cref_edges.csv references node IDs defined in the mitre and
        # zig files (attack_technique, zig_activity), so it must load last.
        for nodes_file, edges_file in [('mitre_nodes.csv', 'mitre_edges.csv'),
                                       ('zig_nodes.csv', 'zig_edges.csv'),
                                       ('cref_nodes.csv', 'cref_edges.csv')]:
            try:
                with open(os.path.join(BASE_DIR, nodes_file), 'r', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        self.graph.add_node(row['id'], **row)
                with open(os.path.join(BASE_DIR, edges_file), 'r', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        self.graph.add_edge(row['source_id'], row['target_id'], relationship=row['relationship_type'])
            except Exception as e:
                print(f"Error loading {nodes_file}/{edges_file}: {e}")

        print(f"Knowledge Graph initialized with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")

    def query_node(self, node_id):
        """Returns the attributes of a specific node."""
        if self.graph.has_node(node_id):
            return self.graph.nodes[node_id]
        return None

    def search_nodes(self, keyword, exact_match=False):
        """Searches node IDs, Names, or Descriptions for a keyword (substring match)."""
        results = []
        keyword = keyword.lower()
        for n, data in self.graph.nodes(data=True):
            if exact_match:
                if keyword == str(n).lower() or keyword == str(data.get('name', '')).lower():
                    results.append((n, data))
            else:
                if (keyword in str(n).lower() or
                    keyword in str(data.get('name', '')).lower() or
                    keyword in str(data.get('description', '')).lower()):
                    results.append((n, data))
        return results

    def keyword_rank(self, query_text, top_k=3):
        """Ranks nodes by how many words of the query appear in their name/description.

        This is the air-gapped fallback for semantic_search(): unlike search_nodes(),
        it does not require the entire query to appear as one substring, so full
        sentences of threat intel still return useful matches.
        Returns [(node_id, node_data, score)] with score in 0..1.
        """
        tokens = [t for t in re.findall(r'[a-z0-9\-]+', query_text.lower())
                  if len(t) > 2 and t not in STOPWORDS]
        if not tokens:
            return []

        scored = []
        for n, data in self.graph.nodes(data=True):
            name = str(data.get('name', '')).lower()
            desc = str(data.get('description', '')).lower()
            score = 0.0
            for t in tokens:
                if t in name:
                    score += 2.0  # name hits are far stronger signals
                elif t in desc:
                    score += 1.0
            if score > 0:
                scored.append((n, data, score / (2.0 * len(tokens))))

        scored.sort(key=lambda x: x[2], reverse=True)
        return scored[:top_k]

    def semantic_search(self, query_text, top_k=3):
        """Performs a semantic vector search if enabled, else falls back to ranked keyword search.

        Always returns a list of (node_id, node_data, score) 3-tuples in both modes.
        """
        if not self.semantic_enabled or self.embeddings is None:
            print("[Warning] Semantic search unavailable. Falling back to ranked keyword search.")
            return self.keyword_rank(query_text, top_k=top_k)

        # --- EXTERNAL API SCAFFOLDING ---
        # If using an Agency API instead of a local model:
        # query_vec = get_api_embedding(query_text) # Must return a 2D array e.g. np.array([[0.1, 0.2, ...]])
        # --------------------------------

        query_vec = self.embedding_model.encode([query_text])
        similarities = cosine_similarity(query_vec, self.embeddings)[0]

        # Get top K indices
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        results = []
        for idx in top_indices:
            node_id = self.embedding_node_ids[idx]
            if self.graph.has_node(node_id):
                results.append((node_id, self.graph.nodes[node_id], float(similarities[idx])))

        return results

    def get_neighbors(self, node_id, direction='both'):
        """Gets immediate neighbors of a node."""
        if not self.graph.has_node(node_id):
            return []

        neighbors = []
        if direction in ['out', 'both']:
            for target in self.graph.successors(node_id):
                edge_data = self.graph.get_edge_data(node_id, target)
                neighbors.append({'id': target, 'direction': 'out', 'relationship': edge_data.get('relationship')})
        if direction in ['in', 'both']:
            for source in self.graph.predecessors(node_id):
                edge_data = self.graph.get_edge_data(source, node_id)
                neighbors.append({'id': source, 'direction': 'in', 'relationship': edge_data.get('relationship')})

        return neighbors

    def crawl_subgraph(self, start_node_id, depth=2):
        """Returns a list of nodes and edges representing the crawled subgraph up to a certain depth."""
        if not self.graph.has_node(start_node_id):
            return {"error": "Node not found"}

        # Extract ego graph (subgraph of neighbors up to a certain radius)
        # Using undirected distance so we can crawl forwards and backwards
        subgraph = nx.ego_graph(self.graph.to_undirected(), start_node_id, radius=depth)

        # Now we extract the directed edges that exist in the original graph for these nodes
        nodes_data = {n: self.graph.nodes[n] for n in subgraph.nodes()}
        edges_data = []

        for u, v in self.graph.edges(subgraph.nodes()):
            if v in subgraph.nodes():
                edge_info = self.graph.get_edge_data(u, v)
                edges_data.append({
                    "source": u,
                    "target": v,
                    "relationship": edge_info.get("relationship", "")
                })

        return {
            "start_node": start_node_id,
            "depth_crawled": depth,
            "nodes": nodes_data,
            "edges": edges_data
        }

if __name__ == "__main__":
    engine = KnowledgeGraphEngine()
    # Simple test
    print("\nTest: Querying a ZIG Pillar")
    print(engine.query_node("ZIG-PIL-1"))

    print("\nTest: Querying a MITRE node (e.g. T1548)")
    print(engine.query_node("T1548"))

    print("\nTest: Search (semantic if available, keyword fallback otherwise)")
    for nid, data, score in engine.semantic_search("attacker dumped password hashes from memory", top_k=3):
        print(f"  [{nid}] {data.get('name', '')} (score: {score:.3f})")
````

---

### FILE: `threat_assessment_skill.md` (sha256=5be4cf80948c153b7cd0f15c7f9ee4fe0bec45c79aca57c0efe712689776d186)

````markdown
---
name: Generate Zero Trust Threat Assessment
description: Analyzes unstructured threat intelligence or blue team reports, queries the MITRE/D3FEND/ZIG/CREF Knowledge Graph, and generates a structured Plan of Action (POA&M) mitigation report spanning tactical, architectural, and compliance layers.
---

# Generate Zero Trust Threat Assessment

You are an expert Cybersecurity AI Agent. Your objective is to ingest unstructured threat intelligence or network assessment data, translate it into standard MITRE, NSA Zero Trust, and NIST cyber-resiliency frameworks, and output a highly structured remediation plan.

To accomplish this, you must use the Python `KnowledgeGraphEngine` provided in the `scripts/graph_engine.py` file. Note: `semantic_search()` always returns `(node_id, node_data, score)` 3-tuples — in semantic mode AND in the air-gapped keyword-fallback mode. A `[Warning] Semantic search unavailable...` message means the fallback is active; that is normal, not an error.

> **CRITICAL INSTRUCTION: NARROW SCOPE**
> Do not generate a single, massive, monolithic report for a large dataset. You must generate a **series of individual, narrowly focused Action Plans**. Each output report should cover only a single finding (or a very small handful of closely related correlations).

> **CRITICAL INSTRUCTION: FORMATTING**
> Do NOT use emojis in your output. Ensure that the primary MITRE mapping is ALWAYS an ATT&CK Technique (T-code), supplemented by Analytics and Mitigations.

> **CRITICAL INSTRUCTION: EVERY REPORT GETS THE FULL STACK**
> Unlike a purely tactical playbook, every report produced by this skill MUST include the tactical (D3FEND/ZIG), architectural (CREF), and compliance (NIST SP 800-53 / Cyber Survivability Attribute) sections — there is no severity gate. Routine findings still get architectural and compliance context; do not skip Steps 5–7 for "small" findings.

## Execution Workflow

Follow these exact steps when a user provides you with threat data:

### Step 1: Entity Extraction
Read the unstructured threat report provided by the user. Identify the core technical actions, vulnerabilities, or attacker behaviors (e.g., "bypassed authentication," "forged Kerberos tickets," "lateral movement").

### Step 2: Graph Mapping
Map the extracted behaviors strictly to a MITRE ATT&CK **Technique** (T-code).
Write and execute a Python script that instantiates `KnowledgeGraphEngine()` and calls `engine.semantic_search(text, top_k=20)`.
- You MUST filter the returned results to the highest-scoring node whose ID starts with `T` followed by a digit (e.g., `T1558.001`). Do not map the primary finding to an Analytic (`AN...`), Mitigation (`M...`), or Detection Strategy (`DET...`).
- The same call works in air-gapped mode (it internally routes to `engine.keyword_rank()`); you do not need a separate code path.

### Step 3: Mitigation Crawling
Once you have the starting MITRE Technique node, crawl the graph for connected defenses: `engine.crawl_subgraph(node_id, depth=2)`.
From the returned subgraph's `nodes`, collect by `type` attribute:
- `d3fend_technique` — D3FEND countermeasures (e.g., Credential Rotation)
- `defensive_artifact` / `attack_datacomponent` — artifacts to monitor or protect
- `attack_analytic` — detections (their useful text is in the `description` field, not `name`)
- `attack_mitigation` — native ATT&CK mitigations

### Step 4: Zero Trust (ZIG) Correlation
The graph now carries a **direct edge** from DoD Zero Trust Activities to the ATT&CK techniques they mitigate (`zig_activity --mitigates--> T-code`), sourced from the DoD Zero Trust Strategy activity-level crosswalk. Prefer this over keyword matching:

1. From the Step 3 subgraph's `edges`, find any edge with `relationship == 'mitigates'` whose target is your T-code and whose source is a `zig_activity` node (check the node's `type` in the subgraph's `nodes`).
2. For each `zig_activity` found, resolve its pillar/capability context: `engine.get_neighbors(zig_activity_id, direction='out')`, filter for the `belongs_to_capability` edge to get the `zig_capability`, then repeat on that capability for the `belongs_to_pillar` edge to get the `zig_pillar`.
3. **Fallback (only if no `zig_activity` was found in step 1):** the ZT crosswalk does not cover every technique yet. Fall back to the legacy correlation: `engine.keyword_rank(countermeasure_name, top_k=100)` using a D3FEND countermeasure's plain name (e.g., "Credential Rotation" — never the "[D3-CRO] Credential Rotation" formatted string) from Step 3, then filter results for `type == 'zig_capability'` and `type == 'zig_technology'`. Resolve the pillar the same way via `belongs_to_pillar`.
4. Optionally crawl the resolved capability (`engine.crawl_subgraph(zig_cap_id, depth=2)`) for its other activities and implementing technologies (`zig_technology`, edge `implements_capability`).

### Step 5: CREF Architectural Resiliency
The graph also carries **strategic mitigations** from NIST SP 800-160 Vol. 2's Cyber Resiliency Engineering Framework (CREF), which cover systems-engineering and recovery-oriented controls that D3FEND/ZIG do not (physical redundancy, non-persistence, diversity, deception).

1. From the Step 3 subgraph, find any `cref_approach` node with a `mitigates_architecturally` edge targeting your T-code.
2. For each `cref_approach` found, walk it up the CREF hierarchy for full context: `engine.get_neighbors(approach_id, direction='out')` → `realizes_technique` edge → `cref_technique` → `achieves_objective` edge → `cref_objective` → `serves_goal` edge → `cref_goal` (one of: Anticipate, Withstand, Recover, Adapt).
3. Also collect the approach's `has_effect` edge → `cref_effect` (e.g., Contain, Preclude, Recover) — this is the plain-English "what this buys you" framing.
4. Report the full chain (Goal → Objective → Technique → Approach → Effect), not just the approach name — the goal/objective context is what makes this section read as architecture rather than a checklist item.

### Step 6: NIST SP 800-53 Compliance Mapping
1. From the Step 3 subgraph, find any `cref_mitigation` node (ID format `CM####`, or occasionally a native `M####` ATT&CK mitigation reused as a CREF mitigation) with a `mitigates` edge targeting your T-code.
2. For each one, call `engine.get_neighbors(cm_id, direction='out')` and collect:
   - `satisfies_control` edges → `nist_800_53_control` nodes (e.g. `AC-4(3)`, `IR-4(2)`) — cite these verbatim for compliance officers.
   - `implements_approach` edges → the `cref_approach` it operationalizes (ties Step 6 back to Step 5).
   - `implements_activity` edges → the `zig_activity` it operationalizes (ties Step 6 back to Step 4).
3. Not every mitigation has a control mapping — if none exists, state that plainly rather than inventing one.

### Step 7: Cyber Survivability Attribute (CSA) Impact
This is the leadership-facing "why the program office should care" framing, from the DoD Cyber Survivability Endorsement catalog.

1. Take the `cref_technique` node(s) resolved in Step 5.
2. Call `engine.get_neighbors(technique_id, direction='in')` and filter for edges with `relationship == 'associated_with_technique'` whose source is a `csa` node (IDs like `CSA-01`).
3. Report the CSA `name` (e.g., "Control Access", "Recover System Capabilities") as the mission-level attribute this finding threatens — this is the sentence a program manager reads, not an engineer.

### Step 8: Assessment Generation
Compile everything gathered in Steps 2–7.
Format your final output strictly according to the structure defined in `assessment_template.md`, filling EVERY placeholder.
Pay special attention to the **"So What?"** section:
1. Executive Summary (Must include the Threat Actor Exploitation & Impact, and the CSA framing from Step 7)
2. MITRE Framework Analysis
3. NSA ZIG Alignment
4. Long-Term Architectural Resiliency (CREF)
5. NIST SP 800-53 Compliance Mapping
6. Technology Recommendations
7. Plan of Action and Milestones (POA&M)

You write the Exploitation Scenario, Business Impact, and POA&M actions yourself from the finding's context — but **never invent MITRE techniques, D3FEND countermeasures, ZIG capabilities, CREF approaches, NIST controls, or CSA IDs. Always pull framework identifiers directly from the `KnowledgeGraphEngine` outputs.**

## Bulk Processing Shortcut
For large multi-tab reports, run `python3 scripts/ingest_assessment.py <report.xlsx>` to flatten all findings into `processed_assessment.csv`, then `python3 agent_batch_processor.py --limit N` to auto-generate draft reports in `mock_output/`. Treat those drafts as scaffolding: review each one and replace the heuristic Exploitation/Impact text with your own analysis.
````

---

### FILE: `assessment_template.md` (sha256=f237e6ce6afe37bace7d343d4008311d7901a52e8d496cebec96663d20299165)

````markdown
# Threat & Mitigation Assessment Report

**Date:** {DATE}
**Assessment ID:** {ASSESSMENT_ID}

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations.*

**Finding / Threat Input:** {THREAT_INPUT_SUMMARY}

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** {EXPLOITATION_SCENARIO}
- **Potential Impact:** {BUSINESS_IMPACT}
- **Mission-Level Attribute at Risk (CSA):** {CSA_NAME} — {CSA_IMPACT_SUMMARY}

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique.*
- **Tactic:** {MITRE_TACTIC}
- **Technique(s):** [{MITRE_TECHNIQUE_ID}] {MITRE_TECHNIQUE_NAME}
- **Description:** {MITRE_TECHNIQUE_DESCRIPTION}

### Supplemental MITRE Data (Analytics & Mitigations)
*Associated defensive guidance from the MITRE framework.*
- **Analytics/Detections:** {MITRE_ANALYTICS}
- **Native Mitigations:** {MITRE_MITIGATIONS}

### D3FEND Countermeasures
*The defensive mechanisms and artifacts required to detect, isolate, or mitigate the threat based on the D3FEND matrix.*
- **Countermeasure(s):** 
  - {D3FEND_COUNTERMEASURE_1}
  - {D3FEND_COUNTERMEASURE_2}
- **Target Artifact(s):** {D3FEND_ARTIFACTS}

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment

*Mapping the required defensive measures to the principles of Zero Trust.*

### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** {ZIG_PILLAR_NAME}
- **Associated Capability:** {ZIG_CAPABILITY_ID} - {ZIG_CAPABILITY_NAME}
- **Relevant Activities:** 
  - {ZIG_ACTIVITY_1}

---

## 4. Long-Term Architectural Resiliency (CREF)

*NIST SP 800-160 Vol. 2 Cyber Resiliency approaches that engineer around this class of threat rather than just blocking today's instance of it — what to build for tomorrow, not what to patch today.*

### Resiliency Chain
- **Goal:** {CREF_GOAL}
- **Objective:** {CREF_OBJECTIVE}
- **Technique:** {CREF_TECHNIQUE}
- **Approach:** {CREF_APPROACH}
- **Effect:** {CREF_EFFECT}

### Architectural Recommendation
*What to engineer, in plain terms, and why tactical controls (Sections 2-3) alone are insufficient here.*
{CREF_RECOMMENDATION}

---

## 5. NIST SP 800-53 Compliance Mapping

*Concrete controls a compliance reviewer can cite. Only list controls actually returned by the graph — state plainly if none exist for this finding.*

- **Mitigation:** {CREF_MITIGATION_ID} - {CREF_MITIGATION_NAME}
- **Satisfies Control(s):** {NIST_800_53_CONTROLS}
- **Traceability:** {TRACEABILITY}

---

## 6. Technology Recommendations

*Specific hardware, software, or configuration classes required to implement the ZIG capabilities and D3FEND countermeasures.*

- **Recommended Technologies:**
  - {ZIG_TECHNOLOGY_1}
  - {ZIG_TECHNOLOGY_2}
- **Implementation Notes:** {TECHNOLOGY_IMPLEMENTATION_NOTES}

---

## 7. Plan of Action and Milestones (POA&M)

*Actionable steps for the engineering and security teams to resolve the gap.*

- [ ] **Phase 1 (Immediate):** {IMMEDIATE_ACTION}
- [ ] **Phase 2 (Short-Term):** {SHORT_TERM_ACTION}
- [ ] **Phase 3 (Long-Term/Strategic):** {LONG_TERM_ACTION}
````

---

### FILE: `agent_batch_processor.py` (sha256=03862d6b9ce4518adc81b2c7e53c428e188a4d45fc9aeb734d95798e3a52ace5)

````python
import sys
import os
import argparse
import pandas as pd
from datetime import datetime

# Add the scripts directory to path to import graph_engine
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, 'scripts'))
from graph_engine import KnowledgeGraphEngine

def first_present(row, candidates, default="Unknown"):
    """Returns the first non-empty value among candidate column names (schemas vary per team)."""
    for col in candidates:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return default

def generate_reports(input_csv, limit):
    print("Initializing Knowledge Graph Engine (loading vectors)...")
    engine = KnowledgeGraphEngine()

    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"Could not find {input_csv}. Did you run scripts/ingest_assessment.py first?")
        return

    # Focus on High/Critical severity issues when a Severity column exists;
    # otherwise process everything up to the limit.
    if 'Severity' in df.columns:
        target_findings = df[df['Severity'].isin(['High', 'Critical'])].head(limit)
    else:
        print("No 'Severity' column found; processing the first rows as-is.")
        target_findings = df.head(limit)

    with open(os.path.join(BASE_DIR, "assessment_template.md"), "r") as f:
        template = f.read()

    output_dir = os.path.join(BASE_DIR, "mock_output")
    os.makedirs(output_dir, exist_ok=True)

    for index, row in target_findings.iterrows():
        finding_text = first_present(row, ['Finding', 'Observation', 'Vulnerability', 'Description'])
        ip = first_present(row, ['IP', 'Target Address', 'Address'], default="N/A")
        hostname = first_present(row, ['Hostname', 'Host', 'Target'], default="N/A")

        print(f"\n[{index}] Processing Threat: {finding_text}")

        # 1. Graph Mapping (Semantic Search)
        # Fetch a wider net so we can filter down to the top Technique (T-code)
        mitre_results = engine.semantic_search(finding_text, top_k=20)
        mitre_node = None
        for nid, ndata, score in mitre_results:
            if nid.startswith('T') and len(nid) > 1 and nid[1].isdigit():
                mitre_node = (nid, ndata, score)
                break

        if not mitre_node:
            print(f"[{index}] No MITRE technique found for '{finding_text}'")
            continue

        mitre_node_id, mitre_node_data, score = mitre_node
        mitre_name = mitre_node_data.get('name', 'Unknown')

        # 1.5 Extract Tactic (belongs_to_tactic points at a TA-node; resolve its name)
        mitre_tactic = "Unknown Tactic"
        for u, v, data in engine.graph.out_edges(mitre_node_id, data=True):
            if data.get('relationship') == 'belongs_to_tactic':
                tactic_node = engine.query_node(v)
                mitre_tactic = f"[{v}] {tactic_node.get('name', v)}" if tactic_node else v
                break

        # 2. Mitigation Crawl (D3FEND & Supplementals)
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        d3fend_countermeasures = []
        d3fend_artifacts = []
        analytics = []
        mitigations = []

        zig_activities_direct = []
        cref_approaches = []
        cref_mitigations = []

        if mitre_subgraph and 'nodes' in mitre_subgraph:
            for nid, ndata in mitre_subgraph['nodes'].items():
                ntype = ndata.get('type')
                if ntype == 'd3fend_technique':
                    d3fend_countermeasures.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ntype in ('defensive_artifact', 'attack_datacomponent'):
                    d3fend_artifacts.append(f"[{nid}] {ndata.get('name', nid)}")
                elif ntype == 'attack_analytic':
                    analytics.append(f"[{nid}] {ndata.get('description', ndata.get('name', 'Analytic'))[:120]}")
                elif ntype == 'attack_mitigation':
                    mitigations.append(f"[{nid}] {ndata.get('name', 'Mitigation')}")

            # Direct ZIG-activity / CREF-approach / CREF-mitigation edges that target
            # this technique (relationship_type 'mitigates' / 'mitigates_architecturally').
            for edge in mitre_subgraph.get('edges', []):
                if edge.get('target') != mitre_node_id:
                    continue
                src_data = mitre_subgraph['nodes'].get(edge['source'], {})
                src_type = src_data.get('type')
                if src_type == 'zig_activity' and edge.get('relationship') == 'mitigates':
                    zig_activities_direct.append((edge['source'], src_data))
                elif src_type == 'cref_approach' and edge.get('relationship') == 'mitigates_architecturally':
                    cref_approaches.append((edge['source'], src_data))
                elif src_type == 'cref_mitigation' and edge.get('relationship') == 'mitigates':
                    cref_mitigations.append((edge['source'], src_data))

        d3fend_cm_1 = d3fend_countermeasures[0] if len(d3fend_countermeasures) > 0 else "None found in graph"
        d3fend_cm_2 = d3fend_countermeasures[1] if len(d3fend_countermeasures) > 1 else "None found in graph"
        d3fend_art_str = ", ".join(d3fend_artifacts[:3]) if d3fend_artifacts else "None found in graph"
        mitre_analytics_str = ("\n  - " + "\n  - ".join(analytics[:2])) if analytics else "None specified"
        mitre_mitigations_str = ("\n  - " + "\n  - ".join(mitigations[:2])) if mitigations else "None specified"

        # 3. Zero Trust (ZIG) Correlation
        # Prefer the direct zig_activity -> attack_technique edge (sourced from the
        # DoD Zero Trust Strategy activity-level crosswalk) over keyword matching.
        zig_activity_id = zig_cap_id = "None found"
        zig_activity_name = zig_cap_name = "No matching ZIG activity"
        zig_techs = []

        if zig_activities_direct:
            zig_activity_id, zig_activity_data = zig_activities_direct[0]
            zig_activity_name = zig_activity_data.get('name', zig_activity_id)
            for u, v, data in engine.graph.out_edges(zig_activity_id, data=True):
                if data.get('relationship') == 'belongs_to_capability':
                    cap_node = engine.query_node(v)
                    zig_cap_id, zig_cap_name = v, (cap_node.get('name', v) if cap_node else v)
                    break
        else:
            # Fallback: the ZT crosswalk doesn't cover every technique yet. Rank ZIG
            # nodes against the top countermeasure NAME (not its "[ID] Name" string).
            search_term = d3fend_countermeasures[0].split('] ', 1)[-1] if d3fend_countermeasures else "Access Control"
            zig_ranked = engine.keyword_rank(search_term, top_k=100)
            zig_caps = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_capability']
            zig_techs = [(n, d) for n, d, s in zig_ranked if d.get('type') == 'zig_technology']

            if not zig_caps:
                fallback_ranked = engine.keyword_rank("access management authentication", top_k=100)
                zig_caps = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_capability']
                if not zig_techs:
                    zig_techs = [(n, d) for n, d, s in fallback_ranked if d.get('type') == 'zig_technology']

            if zig_caps:
                zig_cap_id, zig_cap_name = zig_caps[0][0], zig_caps[0][1].get('name', 'Unknown')

        # Resolve the capability's pillar from the graph instead of hardcoding it
        zig_pillar = "Unknown Pillar"
        if zig_cap_id != "None found":
            for u, v, data in engine.graph.out_edges(zig_cap_id, data=True):
                if data.get('relationship') == 'belongs_to_pillar':
                    pillar_node = engine.query_node(v)
                    zig_pillar = pillar_node.get('name', v) if pillar_node else v
                    break

        # 4. CREF Architectural Resiliency: walk the first approach up
        # Approach -> Technique -> Objective -> Goal, plus its Effect.
        cref_goal = cref_objective = cref_technique_name = cref_approach_name = cref_effect = "None found in graph"
        cref_approach_id = "None"
        cref_technique_id_found = None
        if cref_approaches:
            cref_approach_id, cref_approach_data = cref_approaches[0]
            cref_approach_name = cref_approach_data.get('name', cref_approach_id)
            for u, v, data in engine.graph.out_edges(cref_approach_id, data=True):
                rel = data.get('relationship')
                if rel == 'realizes_technique':
                    cref_technique_id_found = v
                    tech_node = engine.query_node(v)
                    cref_technique_name = tech_node.get('name', v) if tech_node else v
                elif rel == 'has_effect':
                    eff_node = engine.query_node(v)
                    cref_effect = eff_node.get('name', v) if eff_node else v
            if cref_technique_id_found:
                for u, v, data in engine.graph.out_edges(cref_technique_id_found, data=True):
                    rel = data.get('relationship')
                    if rel == 'achieves_objective':
                        obj_node = engine.query_node(v)
                        cref_objective = obj_node.get('name', v) if obj_node else v
                        for _, gv, gdata in engine.graph.out_edges(v, data=True):
                            if gdata.get('relationship') == 'serves_goal':
                                goal_node = engine.query_node(gv)
                                cref_goal = goal_node.get('name', gv) if goal_node else gv
                                break

        cref_recommendation = (
            f"Because {mitre_name} can recur in forms tactical controls won't catch, "
            f"engineer for {cref_approach_name.lower()} ({cref_goal.lower()} the mission) "
            f"rather than relying solely on the Section 2-3 tactical blockers."
            if cref_approaches else
            "No CREF architectural approach mapped to this technique in the graph; "
            "tactical controls (Sections 2-3) are the primary mitigation for this finding."
        )

        # 5. NIST SP 800-53 Compliance Mapping, from the first cref_mitigation found.
        cref_mitigation_id = "None found in graph"
        cref_mitigation_name = "No matching CREF/ATT&CK mitigation with a control mapping"
        nist_controls = []
        zig_activity_id_from_mitigation = None
        if cref_mitigations:
            cref_mitigation_id, cm_data = cref_mitigations[0]
            cref_mitigation_name = cm_data.get('name', cref_mitigation_id)
            for u, v, data in engine.graph.out_edges(cref_mitigation_id, data=True):
                rel = data.get('relationship')
                if rel == 'satisfies_control':
                    nist_controls.append(v)
                elif rel == 'implements_activity':
                    zig_activity_id_from_mitigation = v
        nist_controls_str = ", ".join(nist_controls) if nist_controls else "None mapped in graph"
        traceability = (
            f"Implements CREF Approach {cref_approach_id} / ZIG Activity {zig_activity_id_from_mitigation or zig_activity_id}"
            if cref_mitigations else
            "N/A — no CREF/ATT&CK mitigation mapped to this technique"
        )

        # 6. Cyber Survivability Attribute (CSA) impact, from the resolved CREF technique.
        csa_name = "None found in graph"
        csa_impact_summary = "No DoD Cyber Survivability Attribute mapped to this technique in the graph."
        if cref_technique_id_found:
            for u, v, data in engine.graph.in_edges(cref_technique_id_found, data=True):
                if data.get('relationship') == 'associated_with_technique':
                    csa_node = engine.query_node(u)
                    if csa_node:
                        csa_name = csa_node.get('name', u)
                        csa_impact_summary = f"This finding threatens the ability to {csa_name.lower()}."
                    break

        # AI generated "So What" logic (mocked up based on finding keywords).
        # NOTE: when an LLM agent drives this pipeline, the agent should write
        # these three fields itself from the finding context.
        if "Kerberos" in finding_text or "Delegation" in finding_text:
            exploitation = "An adversary can request authentication tickets offline and crack them, or use unconstrained delegation to impersonate highly privileged users across the domain."
            impact = "Complete domain compromise, unauthorized access to all Active Directory integrated services."
            imm_action = f"Disable unconstrained delegation or enforce Kerberos Pre-Auth on {hostname} ({ip})."
        elif "password" in finding_text.lower():
            exploitation = "Adversaries can easily guess or brute-force administrative credentials to gain elevated privileges."
            impact = "Local system takeover leading to lateral movement across the network."
            imm_action = f"Immediately rotate the local administrator password on {hostname} ({ip}) and deploy LAPS."
        else:
            exploitation = "Adversaries could exploit this misconfiguration to execute unauthorized code or access sensitive data."
            impact = "Data breach or loss of system availability."
            imm_action = f"Investigate and patch/reconfigure {hostname} ({ip})."

        # 4. Generate Output Markdown
        report_content = template.format(
            DATE=datetime.now().strftime('%Y-%m-%d'),
            ASSESSMENT_ID=f"ASMT-{index+1000}",
            THREAT_INPUT_SUMMARY=f"[{ip}] [{hostname}] {finding_text}",
            EXPLOITATION_SCENARIO=exploitation,
            BUSINESS_IMPACT=impact,
            MITRE_TACTIC=mitre_tactic,
            MITRE_TECHNIQUE_ID=mitre_node_id,
            MITRE_TECHNIQUE_NAME=mitre_name,
            MITRE_TECHNIQUE_DESCRIPTION=mitre_node_data.get('description', 'Unknown').split('.')[0] + ".",
            MITRE_ANALYTICS=mitre_analytics_str,
            MITRE_MITIGATIONS=mitre_mitigations_str,
            D3FEND_COUNTERMEASURE_1=d3fend_cm_1,
            D3FEND_COUNTERMEASURE_2=d3fend_cm_2,
            D3FEND_ARTIFACTS=d3fend_art_str,
            CSA_NAME=csa_name,
            CSA_IMPACT_SUMMARY=csa_impact_summary,
            ZIG_PILLAR_NAME=zig_pillar,
            ZIG_CAPABILITY_ID=zig_cap_id,
            ZIG_CAPABILITY_NAME=zig_cap_name,
            ZIG_ACTIVITY_1=f"[{zig_activity_id}] {zig_activity_name}" if zig_activities_direct else "Identify and remediate vulnerable configurations",
            ZIG_TECHNOLOGY_1=f"[{zig_techs[0][0]}] {zig_techs[0][1].get('name')}" if len(zig_techs) > 0 else "None found in graph",
            ZIG_TECHNOLOGY_2=f"[{zig_techs[1][0]}] {zig_techs[1][1].get('name')}" if len(zig_techs) > 1 else "None found in graph",
            CREF_GOAL=cref_goal,
            CREF_OBJECTIVE=cref_objective,
            CREF_TECHNIQUE=cref_technique_name,
            CREF_APPROACH=cref_approach_name,
            CREF_APPROACH_ID=cref_approach_id,
            CREF_EFFECT=cref_effect,
            CREF_RECOMMENDATION=cref_recommendation,
            CREF_MITIGATION_ID=cref_mitigation_id,
            CREF_MITIGATION_NAME=cref_mitigation_name,
            NIST_800_53_CONTROLS=nist_controls_str,
            TRACEABILITY=traceability,
            TECHNOLOGY_IMPLEMENTATION_NOTES="Ensure configurations align with vendor security baselines.",
            IMMEDIATE_ACTION=imm_action,
            SHORT_TERM_ACTION="Implement continuous monitoring for this vulnerability class.",
            LONG_TERM_ACTION=f"Integrate {zig_cap_name} architecture fully; adopt {cref_approach_name} per Section 4." if cref_approaches else f"Integrate {zig_cap_name} architecture fully."
        )

        out_path = os.path.join(output_dir, f"ASMT-{index+1000}.md")
        with open(out_path, "w") as f:
            f.write(report_content)

        print(f"Generated {out_path} -> Mapped to {mitre_node_id} & {zig_cap_id}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch-generate assessment reports from a processed findings CSV")
    parser.add_argument("--input", default="processed_assessment.csv", help="Flattened findings CSV from ingest_assessment.py")
    parser.add_argument("--limit", type=int, default=3, help="Maximum number of findings to process")
    args = parser.parse_args()
    generate_reports(args.input, args.limit)
````

---

### FILE: `agent_crawl_example.py` (sha256=d3a08b5e7f4b38fe9566a13bcb598e8eb225d02b15e79fd58e4ddad6a2c3a4ee)

````python
import sys
import os

# Add the scripts directory to path to import graph_engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
from graph_engine import KnowledgeGraphEngine

def format_subgraph(subgraph_data):
    """Utility to print a subgraph nicely."""
    out = f"--- Crawled Depth {subgraph_data['depth_crawled']} from {subgraph_data['start_node']} ---\n"
    out += "Nodes Found:\n"
    for nid, ndata in subgraph_data['nodes'].items():
        out += f"  - [{nid}] {ndata.get('name', '')} ({ndata.get('type', '')})\n"
    out += "Edges:\n"
    for edge in subgraph_data['edges']:
        out += f"  - {edge['source']} --({edge['relationship']})--> {edge['target']}\n"
    return out

if __name__ == "__main__":
    engine = KnowledgeGraphEngine()
    
    print("\n" + "="*50)
    print("MOCK AGENT CRAWL: THREAT INTELLIGENCE ANALYSIS")
    print("="*50)
    
    threat_intel = "Red team executed a Golden Ticket attack (T1558.001) to persist on the domain."
    print(f"\n[Agent Input] {threat_intel}")
    
    print("\n[Agent] Searching MITRE framework using natural language: 'Red team executed a Golden Ticket attack'...")
    mitre_results = engine.semantic_search("Red team executed a Golden Ticket attack", top_k=1)
    if mitre_results:
        # semantic_search always returns (node_id, node_data, score) 3-tuples,
        # in both semantic and keyword-fallback modes
        mitre_node_id, mitre_node_data, score = mitre_results[0]
        print(f"[Agent] Found closest MITRE Node: {mitre_node_data['name']} (Score: {score:.2f})")
        
        print(f"\n[Agent] Crawling MITRE countermeasures for {mitre_node_id} (Depth=2)...")
        mitre_subgraph = engine.crawl_subgraph(mitre_node_id, depth=2)
        print(format_subgraph(mitre_subgraph))
    
    print("\n[Agent] Based on the MITRE countermeasures (e.g. Identity Management), searching ZIG framework for related Zero Trust concepts...")
    # The agent determines "Identity" and "Access" are key. It searches ZIG nodes for "Authentication" or "Identity"
    zig_results = engine.search_nodes("Identity", exact_match=False)
    zig_candidates = [n for n in zig_results if n[1].get('type') == 'zig_capability']
    
    if zig_candidates:
        # Just pick the first matching capability for the example
        zig_node_id, zig_node_data = zig_candidates[0]
        print(f"[Agent] Found relevant ZIG Node: {zig_node_data['name']} ({zig_node_id})")
        
        print(f"\n[Agent] Crawling ZIG architecture for {zig_node_id} (Depth=2)...")
        zig_subgraph = engine.crawl_subgraph(zig_node_id, depth=2)
        print(format_subgraph(zig_subgraph))
        
    print("\n[Agent] Checking the same MITRE subgraph for direct CREF/ZIG-activity/NIST edges...")
    # These are the new edges added by consolidate_cref_data.py: a zig_activity or
    # cref_approach can point straight at the ATT&CK technique with 'mitigates' /
    # 'mitigates_architecturally', no keyword matching required.
    if mitre_results:
        for edge in mitre_subgraph.get('edges', []):
            if edge['target'] != mitre_node_id:
                continue
            src_data = mitre_subgraph['nodes'].get(edge['source'], {})
            src_type = src_data.get('type')
            if src_type == 'zig_activity':
                print(f"  - Direct ZIG Activity: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
            elif src_type == 'cref_approach':
                print(f"  - CREF Approach: [{edge['source']}] {src_data.get('name')} --mitigates_architecturally--> {mitre_node_id}")
            elif src_type == 'cref_mitigation':
                print(f"  - CREF/NIST Mitigation: [{edge['source']}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
                for _, v, data in engine.graph.out_edges(edge['source'], data=True):
                    if data.get('relationship') == 'satisfies_control':
                        control_node = engine.query_node(v)
                        print(f"      satisfies_control --> [{v}] (NIST SP 800-53)")

    print("\n" + "="*50)
    print("FINAL ASSESSMENT OUTPUT (MARKDOWN TEMPLATE FORMAT)")
    print("="*50 + "\n")
    
    assessment_md = f"""# Threat & Mitigation Assessment Report

**Date:** 2026-07-09
**Assessment ID:** ASMT-90210

---

## 1. Executive Summary
*Provide a high-level overview of the detected threat or vulnerability and the recommended mitigations.*

**Finding / Threat Input:** {threat_intel}

### Threat Actor Exploitation & Impact (The "So What?")
*Detail exactly how an adversary could weaponize this issue, the specific TTPs they would use, and the potential business impact.*
- **Exploitation Scenario:** An adversary could use a stolen or forged Ticket Granting Ticket (TGT) to impersonate any user on the domain indefinitely, bypassing normal authentication mechanisms and password resets.
- **Potential Impact:** Complete domain compromise, allowing unhindered lateral movement, data exfiltration, and ransomware deployment.

---

## 2. MITRE Framework Analysis

### ATT&CK Mapping (TTPs)
*Details on the primary attacker tactic and technique.*
- **Tactic:** Credential Access (Inferred)
- **Technique(s):** [T1550.003] Use Alternate Authentication Material: Pass the Ticket
- **Description:** Adversaries may forge Kerberos tickets to bypass authentication.

### Supplemental MITRE Data (Analytics & Mitigations)
*Associated defensive guidance from the MITRE framework.*
- **Analytics/Detections:** 
  - [AN0316] Detects AS-REP roasting attempts by monitoring for Kerberos AS-REQ/AS-REP
- **Native Mitigations:** 
  - [M1038] Execution Prevention

### D3FEND Countermeasures
- **Countermeasure(s):** 
  - Credential Rotation
  - Access Control
- **Target Artifact(s):** Active Directory Ticket Granting Ticket (TGT)

---

## 3. NSA Zero Trust Implementation Guide (ZIG) Alignment

### ZIG Pillar & Capabilities
- **Primary ZIG Pillar:** ZIG-PIL-1 - User Pillar
- **Associated Capability:** {zig_node_id} - {zig_node_data['name']}
- **Relevant Activities:** 
  - ZIG-ACT-1.5.1 - Organizational Identity Lifecycle Management (ILM)

---

## 4. Long-Term Architectural Resiliency (CREF)

### Resiliency Chain
- **Goal:** Withstand
- **Objective:** Limit Damage
- **Technique:** Privilege Restriction
- **Approach:** Attribute-Based Usage Restriction
- **Effect:** Limit

### Architectural Recommendation
Because forged tickets bypass password-based tactical controls entirely, engineer for
attribute-based usage restriction (limit the mission's blast radius) rather than relying
solely on credential rotation.

---

## 5. NIST SP 800-53 Compliance Mapping

- **Mitigation:** CM1164 - Calibrate Administrative Access
- **Satisfies Control(s):** AC-6(1), AC-6(5)
- **Traceability:** Implements CREF Approach a33 / ZIG Activity 1.2.1

---

## 6. Technology Recommendations

- **Recommended Technologies:**
  - ZIG-TECH-54 - Identity Governance and Administration (IGA)
  - ZIG-TECH-101 - Single Sign-On (SSO) and Federation
- **Implementation Notes:** Ensure IdP is configured to enforce MFA and rotate credentials automatically on a fixed cadence.

---

## 7. Plan of Action and Milestones (POA&M)

- [ ] **Phase 1 (Immediate):** Identify and rotate all potentially compromised service account passwords (krbtgt).
- [ ] **Phase 2 (Short-Term):** Deploy robust Identity Governance and Administration (IGA) tools for continuous monitoring.
- [ ] **Phase 3 (Long-Term/Strategic):** Fully integrate Identity Federation across all enclaves per ZIG Capability 1.5.
"""
    print(assessment_md)
````


---

## STEP 2.5 — Regenerate the CREF layer and embeddings

If you ported the raw `CREF/*.csv` files (Asset Manifest item 1) rather than the
pre-built node/edge CSVs:

```bash
python3 consolidate_cref_data.py
```

Expected output ends with something like:
`Done! CREF: 406 nodes, 14105 edges. ZIG (reconciled): 320 nodes, 422 edges.`
A small number of dropped edges (tens) referencing unknown node IDs is normal — it
usually means one stale ATT&CK technique ID in the raw CREF export that isn't in your
`mitre_nodes.csv` (e.g. a deprecated technique). Dozens is fine; hundreds is not —
stop and investigate if you see hundreds dropped.

Then, REGARDLESS of whether you regenerated or ported the CSVs, regenerate
embeddings — the node set changed, so any embeddings from before this extension are
stale (`embed_graph.py` will encode the wrong number of nodes otherwise):

```bash
python3 scripts/embed_graph.py
```

Skip this only if you are in keyword-fallback mode (no ML libraries) — the fallback
re-derives everything from the CSVs at query time, so there is nothing to regenerate.

---

## STEP 3 — VERIFICATION

**3.1 Full graph loads with all four frameworks:**

```bash
python3 scripts/graph_engine.py
```

Expected: `Knowledge Graph initialized with 5618 nodes and 43194 edges.`
(numbers will differ slightly if your CREF/MITRE source data differs from the one this
guide was generated against).

**3.2 Spot-check the new node types resolve correctly:**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
for nid in ['CSA-01', 'CM1131']:
    print(nid, '->', e.query_node(nid))
# a zig_activity must still be type zig_activity, NOT cref_mitigation or anything else
act = e.query_node('ZIG-ACT-1.1.1')
assert act and act['type'] == 'zig_activity', 'ZIG reconciliation broke a node type!'
print('ZIG-ACT-1.1.1 ->', act)
"
```

Expected: `CSA-01` resolves to type `csa` ("Control Access"), `CM1131` resolves to
type `cref_mitigation` ("Active Deception"), and `ZIG-ACT-1.1.1` resolves to type
`zig_activity` with a CLEAN name ("Inventory User" — not PDF dot-leader garbage) and
the assertion passes.

**3.3 Direct ZIG-activity <-> ATT&CK edges exist (the new correlation path):**

```bash
python3 -c "
import sys; sys.path.append('scripts')
from graph_engine import KnowledgeGraphEngine
e = KnowledgeGraphEngine()
sub = e.crawl_subgraph('T1047', depth=2)
direct = [ed for ed in sub['edges'] if ed['target']=='T1047'
          and sub['nodes'].get(ed['source'], {}).get('type') == 'zig_activity']
assert direct, 'Expected at least one direct zig_activity -> T1047 edge'
print('Direct ZIG correlation for T1047:', direct)
"
```

Expected: at least one edge printed (T1047 / Windows Management Instrumentation is
one of the DoD Zero Trust Strategy crosswalk's example techniques).

**3.4 End-to-end report generation includes all 7 sections:**

```bash
python3 agent_batch_processor.py --limit 1
```

Open the generated report in `mock_output/` and confirm it has SEVEN numbered
sections (Executive Summary through POA&M), with Section 4 (CREF), Section 5 (NIST
800-53), and the CSA line in Section 1 all populated with real graph IDs — not
"None found in graph" for every field (a few "None found" per report is normal and
expected for techniques the new datasets don't cover; ALL of them saying so on every
report would mean the extension did not load).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A node's `type` looks wrong after this extension (e.g. an `M####` node now says `cref_mitigation`) | `consolidate_cref_data.py`'s native-mitigation collision check didn't run against the real `mitre_nodes.csv` (ran before base system was ported, or `mitre_ids` load was edited out) | Restore from your backups, re-port `mitre_nodes.csv`, re-run `consolidate_cref_data.py` |
| ZIG activity names reverted to garbled PDF text (dot-leaders, trailing `D-`) | `scripts/parse_zig_data.py` was re-run after this extension, overwriting the reconciliation | Re-run `consolidate_cref_data.py` again to re-apply the clean names, or restore `zig_nodes.csv.bak` / `zig_edges.csv.bak` from STEP 1 and re-run once |
| `graph_engine.py` node count didn't change after applying this extension | `cref_nodes.csv`/`cref_edges.csv` weren't actually created, or `scripts/graph_engine.py` wasn't updated to load the third file pair | Confirm STEP 2's `graph_engine.py` copy included the `cref_nodes.csv`/`cref_edges.csv` pair in `load_data()` |
| Embedding search returns nonsense after this extension | Ran `scripts/embed_graph.py` BEFORE `consolidate_cref_data.py` finished, or skipped STEP 2.5's embedding regeneration | Re-run `python3 scripts/embed_graph.py` now that the CSVs are final |
| Section 4/5/7 of a generated report say "None found in graph" for every finding you try | Either `cref_edges.csv` is empty/missing, or `scripts/graph_engine.py` isn't loading the third file pair | Run 3.1-3.3 above to isolate which layer is missing |

---

*This guide is generated by `build_cref_extension_guide.py` from the live source
files — regenerate it after any further change rather than editing it by hand.*
