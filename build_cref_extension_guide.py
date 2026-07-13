"""Generates CREF_ZERO_TRUST_EXTENSION_GUIDE.md — a DELTA guide for an agentic
coding agent that already has the base MITRE/D3FEND/ZIG system (from
Air_Gapped_Deployment_Guide.md or PORTABLE_RECONSTRUCTION_BUNDLE.md) running on an
air-gapped network, and needs to add the CREF/NIST-800-53/DoD-Zero-Trust-Strategy/
Cyber-Survivability-Attribute layer on top of it.

Unlike the full reconstruction guide, this assumes mitre_nodes.csv/mitre_edges.csv
and zig_nodes.csv/zig_edges.csv already exist and the base pipeline already works —
it only covers what changed. Every embedded file is byte-verified with a SHA-256,
same rigor as PORTABLE_RECONSTRUCTION_BUNDLE.md, since this is meant to be applied
on a system you cannot easily SSH into to double-check.

Run after ANY change to the files listed in EMBEDDED_FILES below:
    python3 build_cref_extension_guide.py
"""
import csv
import hashlib
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_NAME = "CREF_ZERO_TRUST_EXTENSION_GUIDE.md"

# Every file this extension touches, new or modified, in the order a coding agent
# should write/overwrite them.
EMBEDDED_FILES = [
    ("consolidate_cref_data.py", "python"),
    ("scripts/graph_engine.py", "python"),
    ("threat_assessment_skill.md", "markdown"),
    ("assessment_template.md", "markdown"),
    ("agent_batch_processor.py", "python"),
    ("agent_crawl_example.py", "python"),
]


def read(relpath):
    with open(os.path.join(BASE_DIR, relpath), encoding="utf-8") as f:
        return f.read()


def count_csv(path):
    with open(os.path.join(BASE_DIR, path), encoding="utf-8") as f:
        return sum(1 for _ in csv.DictReader(f))


def graph_counts():
    import networkx as nx
    # Count every retained source relationship, including parallel edges.
    g = nx.MultiDiGraph()
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


def fence_for(content):
    """A backtick fence guaranteed longer than any backtick run in content."""
    longest = max((len(r) for r in re.findall(r"`+", content)), default=0)
    return "`" * max(4, longest + 1)


def embed(relpath, lang):
    content = read(relpath)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    fence = fence_for(content)
    block = (f"### FILE: `{relpath}` (sha256={sha})\n\n"
             f"{fence}{lang}\n{content}{fence}\n")
    return block, sha, len(content.encode("utf-8"))


def main():
    cref_nodes = count_csv("cref_nodes.csv")
    cref_edges = count_csv("cref_edges.csv")
    zig_nodes = count_csv("zig_nodes.csv")
    zig_edges = count_csv("zig_edges.csv")
    mitre_nodes = count_csv("mitre_nodes.csv")
    total_nodes, total_edges = graph_counts()

    sections, manifest_rows = [], []
    for relpath, lang in EMBEDDED_FILES:
        block, sha, size = embed(relpath, lang)
        sections.append(block)
        manifest_rows.append(f"| `{relpath}` | {size} | `{sha[:16]}...` |")

    guide = GUIDE_TEMPLATE.format(
        cref_nodes=cref_nodes, cref_edges=cref_edges,
        zig_nodes=zig_nodes, zig_edges=zig_edges, mitre_nodes=mitre_nodes,
        total_nodes=total_nodes, total_edges=total_edges,
        manifest="\n".join(manifest_rows),
        file_sections="\n---\n\n".join(sections),
    )

    out_path = os.path.join(BASE_DIR, OUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(guide)
    print(f"Wrote {out_path}")
    print(f"Verification numbers baked in: CREF {cref_nodes} nodes / {cref_edges} edges, "
          f"reconciled ZIG {zig_nodes} nodes / {zig_edges} edges, "
          f"full graph {total_nodes} nodes / {total_edges} edges")


GUIDE_TEMPLATE = '''# CREF / DoD Zero Trust / NIST 800-53 Extension Guide

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
- reuses the existing `ZIG-PIL-{{n}}` / `ZIG-CAP-{{id}}` / `ZIG-ACT-{{id}}` IDs verbatim
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
{manifest}

{file_sections}

---

## STEP 2.5 — Regenerate the CREF layer and embeddings

If you ported the raw `CREF/*.csv` files (Asset Manifest item 1) rather than the
pre-built node/edge CSVs:

```bash
python3 consolidate_cref_data.py
```

Expected output ends with something like:
`Done! CREF: {cref_nodes} nodes, {cref_edges} edges. ZIG (reconciled): {zig_nodes} nodes, {zig_edges} edges.`
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

Expected: `Knowledge Graph initialized with {total_nodes} nodes and {total_edges} edges.`
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
          and sub['nodes'].get(ed['source'], {{}}).get('type') == 'zig_activity']
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
'''


if __name__ == "__main__":
    main()
