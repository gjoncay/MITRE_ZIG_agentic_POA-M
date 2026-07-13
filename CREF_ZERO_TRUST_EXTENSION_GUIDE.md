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
| `consolidate_cref_data.py` | 18168 | `27dca3d2d913f7df...` |
| `scripts/graph_engine.py` | 88625 | `ed0f91c902ad6a38...` |
| `threat_assessment_skill.md` | 8755 | `5be4cf80948c153b...` |
| `assessment_template.md` | 3270 | `2d2bc8379e74745c...` |
| `agent_batch_processor.py` | 17658 | `a97e320ec6486524...` |
| `agent_crawl_example.py` | 8102 | `974245fe619fd752...` |

### FILE: `consolidate_cref_data.py` (sha256=27dca3d2d913f7df34c914d85adb855acb9816ea0687ffbe2f2e1edf0c7a965e)

````python
"""Deterministically regenerate CREF inputs and reconcile the ZIG taxonomy.

Every logical input relationship is retained as an edge row.  The graph loader
uses a ``MultiDiGraph`` and keeps distinct relationship types for the same
source/target pair; this generator only collapses exact triples repeated by
denormalized cross-product exports.  It builds lists before normalization so
the number of collapsed source expansions remains visible.  The script resolves
all paths from its own location and can therefore be invoked from any working
directory.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
NODE_FIELDS = ("id", "type", "name", "description", "url")
EDGE_FIELDS = ("source_id", "target_id", "relationship_type")


def _present(value: Any) -> bool:
    return value is not None and not pd.isna(value) and bool(str(value).strip())


def _text(value: Any, default: str = "") -> str:
    return str(value).strip() if _present(value) else default


def _cref_id(prefix: str, raw: Any) -> str:
    """Turn a raw CREF ID (``g1``, ``sta4``, ``a45``) into a global node ID."""
    if not _present(raw):
        return ""
    digits = re.sub(r"[^0-9.]", "", str(raw))
    return f"{prefix}-{digits}" if digits else ""


def _stage_csv(path: Path, fieldnames: Iterable[str], rows: Iterable[dict[str, str]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _replace_staged(staged: list[tuple[Path, Path]]) -> None:
    try:
        for target, temporary in staged:
            os.replace(temporary, target)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def _edge_rows(edges: Iterable[tuple[str, str, str]]) -> list[dict[str, str]]:
    return [
        {"source_id": source, "target_id": target, "relationship_type": relationship}
        for source, target, relationship in sorted(edges)
    ]


def _logical_edges(edges: Iterable[tuple[str, str, str]]) -> tuple[list[tuple[str, str, str]], int]:
    """Stable-deduplicate only exact source/target/relationship triples."""
    unique: dict[tuple[str, str, str], None] = {}
    repeated = 0
    for edge in edges:
        if edge in unique:
            repeated += 1
        else:
            unique[edge] = None
    return list(unique), repeated


def consolidate(
    base_dir: Path = BASE_DIR,
) -> tuple[dict[str, dict[str, str]], list[tuple[str, str, str]], dict[str, dict[str, str]], list[tuple[str, str, str]]]:
    """Build CREF and reconciled ZIG records without changing on-disk outputs."""
    base_dir = Path(base_dir).resolve()
    cref_dir = base_dir / "CREF"
    cref_nodes: dict[str, dict[str, str]] = {}
    # Lists retain raw expansion counts until exact logical normalization below.
    cref_edges: list[tuple[str, str, str]] = []

    def read_csv(name: str) -> pd.DataFrame:
        return pd.read_csv(cref_dir / name)

    def add_cref_node(node_id: Any, node_type: str, name: Any, description: Any = "") -> str | None:
        identifier = _text(node_id)
        if not identifier:
            return None
        if identifier not in cref_nodes:
            cref_nodes[identifier] = {
                "id": identifier,
                "type": node_type,
                "name": _text(name),
                "description": _text(description),
                "url": "",
            }
        elif not cref_nodes[identifier]["description"] and _text(description):
            cref_nodes[identifier]["description"] = _text(description)
        return identifier

    def add_cref_edge(source_id: Any, target_id: Any, rel_type: Any) -> None:
        source, target, relationship = _text(source_id), _text(target_id), _text(rel_type)
        if source and target and relationship:
            cref_edges.append((source, target, relationship))

    print("Loading mitre_nodes.csv IDs (native-mitigation collision check)...")
    with (base_dir / "mitre_nodes.csv").open(encoding="utf-8", newline="") as handle:
        mitre_ids = {row["id"] for row in csv.DictReader(handle) if _text(row.get("id"))}

    def add_mitigation_node(raw_id: Any, name: Any) -> str | None:
        mitigation_id = _text(raw_id)
        if not mitigation_id:
            return None
        if mitigation_id in mitre_ids:
            return mitigation_id
        return add_cref_node(mitigation_id, "cref_mitigation", name)

    print("Parsing cref-relationships.csv (canonical Goal->Objective->Technique->Approach)...")
    for _, row in read_csv("cref-relationships.csv").iterrows():
        goal = add_cref_node(_cref_id("CREF-GOAL", row.get("goal_id")), "cref_goal", row.get("Goal"), row.get("goal_description"))
        objective = add_cref_node(_cref_id("CREF-OBJ", row.get("obj_id")), "cref_objective", row.get("Objective"), row.get("obj_description"))
        technique = add_cref_node(_cref_id("CREF-TECH", row.get("tech_id")), "cref_technique", row.get("Technique"), row.get("tech_description"))
        approach = add_cref_node(_cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("Approach"), row.get("app_description"))
        if goal and objective:
            add_cref_edge(objective, goal, "serves_goal")
        if objective and technique:
            add_cref_edge(technique, objective, "achieves_objective")
        if technique and approach:
            add_cref_edge(approach, technique, "realizes_technique")

    print("Parsing design-principles-cref.csv...")
    for _, row in read_csv("design-principles-cref.csv").iterrows():
        strategic = add_cref_node(
            _cref_id("CREF-STA", row.get("strategic_design_principle_id")),
            "cref_design_principle_strategic",
            row.get("strategic_design_principle"),
        )
        structural = add_cref_node(
            _cref_id("CREF-STU", row.get("structural_design_principle_id")),
            "cref_design_principle_structural",
            row.get("structural_design_principle"),
        )
        technique = add_cref_node(
            _cref_id("CREF-TECH", row.get("cref_technique_id")), "cref_technique", row.get("technique")
        )
        required = _text(row.get("required")).casefold()
        relationship = "requires_principle" if required in {"1", "1.0", "true", "yes"} else "informs_principle"
        if technique and strategic:
            add_cref_edge(technique, strategic, relationship)
        if technique and structural:
            add_cref_edge(technique, structural, relationship)

    print("Parsing csa-cref-attack.csv (DoD Cyber Survivability Attributes)...")
    for _, row in read_csv("csa-cref-attack.csv").iterrows():
        csa = add_cref_node(_text(row.get("csa_id")), "csa", row.get("csa_name"))
        strategic = add_cref_node(
            _cref_id("CREF-STA", row.get("strategic_design_principle_id")),
            "cref_design_principle_strategic",
            row.get("strategic_design_principle"),
        )
        structural = add_cref_node(
            _cref_id("CREF-STU", row.get("structural_design_principle_id")),
            "cref_design_principle_structural",
            row.get("structural_design_principle"),
        )
        technique = add_cref_node(
            _cref_id("CREF-TECH", row.get("cref_technique_id")), "cref_technique", row.get("technique")
        )
        approach = add_cref_node(_cref_id("CREF-APP", row.get("APPROACH_ID")), "cref_approach", row.get("approach"))
        if csa and strategic:
            add_cref_edge(csa, strategic, "embodies_principle")
        if csa and structural:
            add_cref_edge(csa, structural, "embodies_principle")
        if technique and approach:
            add_cref_edge(approach, technique, "realizes_technique")
        if csa and technique:
            add_cref_edge(csa, technique, "associated_with_technique")
        if approach and _text(row.get("attack_technique_id")):
            add_cref_edge(approach, row.get("attack_technique_id"), "mitigates_architecturally")

    print("Parsing impact.csv (Approach -> Effect)...")
    for _, row in read_csv("impact.csv").iterrows():
        technique = add_cref_node(
            _cref_id("CREF-TECH", row.get("cref_technique_id")), "cref_technique", row.get("technique")
        )
        approach = add_cref_node(_cref_id("CREF-APP", row.get("approach_id")), "cref_approach", row.get("approach"))
        effect = add_cref_node(_cref_id("CREF-EFFECT", row.get("effect_id")), "cref_effect", row.get("effect"))
        if technique and approach:
            add_cref_edge(approach, technique, "realizes_technique")
        if approach and effect:
            add_cref_edge(approach, effect, "has_effect")

    print("Parsing attack-relationships-sankey-export.csv (Approach -> ATT&CK -> CM Mitigation -> NIST 800-53)...")
    for _, row in read_csv("attack-relationships-sankey-export.csv").iterrows():
        approach = add_cref_node(
            _cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("approach"), row.get("app_description")
        )
        technique = add_cref_node(
            _cref_id("CREF-TECH", row.get("tech_id")), "cref_technique", row.get("technique"), row.get("tech_description")
        )
        if approach and technique:
            add_cref_edge(approach, technique, "realizes_technique")
        attack_id = _text(row.get("attack_technique_id"))
        if approach and attack_id:
            add_cref_edge(approach, attack_id, "mitigates_architecturally")
        if _text(row.get("mitigation_id")):
            mitigation = add_mitigation_node(row.get("mitigation_id"), row.get("mitigation"))
            if mitigation and attack_id:
                add_cref_edge(mitigation, attack_id, "mitigates")
            if mitigation and approach:
                add_cref_edge(mitigation, approach, "implements_approach")
            control = add_cref_node(_text(row.get("control")), "nist_800_53_control", row.get("control"))
            if mitigation and control:
                add_cref_edge(mitigation, control, "satisfies_control")

    print("Loading existing zig_nodes.csv / zig_edges.csv for reconciliation...")
    zig_nodes: dict[str, dict[str, str]] = {}
    with (base_dir / "zig_nodes.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            node_id = _text(row.get("id"))
            if node_id:
                zig_nodes[node_id] = {field: _text(row.get(field)) for field in NODE_FIELDS}
    zig_edges: list[tuple[str, str, str]] = []
    with (base_dir / "zig_edges.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            source, target, relationship = _text(row.get("source_id")), _text(row.get("target_id")), _text(row.get("relationship_type"))
            if source and target and relationship:
                zig_edges.append((source, target, relationship))

    def add_zig_edge(source_id: Any, target_id: Any, relationship: Any) -> None:
        source, target, relation = _text(source_id), _text(target_id), _text(relationship)
        if source and target and relation:
            zig_edges.append((source, target, relation))

    new_zig_activities = 0
    new_zig_capabilities = 0
    print("Parsing zero-trust-attack.csv (ZT Pillar/Capability/Activity -> Approach -> ATT&CK -> CM Mitigation)...")
    zero_trust = read_csv("zero-trust-attack.csv")
    for _, row in zero_trust.iterrows():
        pillar_id, capability_id, activity_id = (
            _text(row.get("pillar_id")),
            _text(row.get("capability_id")),
            _text(row.get("activity_id")),
        )
        zig_pillar = f"ZIG-PIL-{pillar_id}" if pillar_id else None
        zig_capability = f"ZIG-CAP-{capability_id}" if capability_id else None
        zig_activity = f"ZIG-ACT-{activity_id}" if activity_id else None

        if zig_capability and zig_capability not in zig_nodes:
            zig_nodes[zig_capability] = {
                "id": zig_capability,
                "type": "zig_capability",
                "name": _text(row.get("capability_name")),
                "description": "",
                "url": "",
            }
            new_zig_capabilities += 1
            if zig_pillar:
                add_zig_edge(zig_capability, zig_pillar, "belongs_to_pillar")

        clean_name = _text(row.get("activity_name"))
        clean_description = _text(row.get("activity_description"))
        if zig_activity:
            if zig_activity not in zig_nodes:
                zig_nodes[zig_activity] = {
                    "id": zig_activity,
                    "type": "zig_activity",
                    "name": clean_name,
                    "description": clean_description,
                    "url": "",
                }
                new_zig_activities += 1
                if zig_capability:
                    add_zig_edge(zig_activity, zig_capability, "belongs_to_capability")
            elif clean_name:
                zig_nodes[zig_activity]["name"] = clean_name
                zig_nodes[zig_activity]["description"] = clean_description

        approach = (
            add_cref_node(_cref_id("CREF-APP", row.get("app_id")), "cref_approach", row.get("approach"))
            if _text(row.get("app_id"))
            else None
        )
        attack_id = _text(row.get("attack_technique_id"))
        if approach and attack_id:
            add_cref_edge(approach, attack_id, "mitigates_architecturally")
        # The direct ZIG activity -> ATT&CK bridge is an input-backed row too.
        if zig_activity and attack_id:
            add_cref_edge(zig_activity, attack_id, "mitigates")
        if _text(row.get("mitigation_id")):
            mitigation = add_mitigation_node(row.get("mitigation_id"), row.get("mitigation"))
            if mitigation and attack_id:
                add_cref_edge(mitigation, attack_id, "mitigates")
            if mitigation and approach:
                add_cref_edge(mitigation, approach, "implements_approach")
            if mitigation and zig_activity:
                add_cref_edge(mitigation, zig_activity, "implements_activity")

    print(f"  Added {new_zig_capabilities} new zig_capability nodes, {new_zig_activities} new zig_activity nodes.")
    existing_activity_count = len(zero_trust["activity_id"].dropna().astype(str).str.strip().unique()) - new_zig_activities
    print(f"  Cleaned activity names/descriptions for {max(0, existing_activity_count)} existing zig_activity nodes.")

    known_ids = set(cref_nodes) | set(zig_nodes) | mitre_ids
    before_cref = len(cref_edges)
    cref_edges = [edge for edge in cref_edges if edge[0] in known_ids and edge[1] in known_ids]
    dropped_cref = before_cref - len(cref_edges)
    if dropped_cref:
        print(f"Integrity pass: dropped {dropped_cref} CREF edge rows referencing unknown node IDs ({len(cref_edges)} remain).")
    cref_edges, repeated_cref = _logical_edges(cref_edges)
    if repeated_cref:
        print(
            "Logical-edge normalization: collapsed "
            f"{repeated_cref} repeated CREF cross-product occurrences ({len(cref_edges)} logical edges remain)."
        )

    before_zig = len(zig_edges)
    zig_edges = [edge for edge in zig_edges if edge[0] in zig_nodes and edge[1] in zig_nodes]
    dropped_zig = before_zig - len(zig_edges)
    if dropped_zig:
        print(f"Integrity pass: dropped {dropped_zig} ZIG edge rows referencing unknown node IDs ({len(zig_edges)} remain).")
    zig_edges, repeated_zig = _logical_edges(zig_edges)
    if repeated_zig:
        print(
            "Logical-edge normalization: collapsed "
            f"{repeated_zig} repeated ZIG cross-product occurrences ({len(zig_edges)} logical edges remain)."
        )
    return cref_nodes, cref_edges, zig_nodes, zig_edges


def write_outputs(
    base_dir: Path,
    cref_nodes: dict[str, dict[str, str]],
    cref_edges: list[tuple[str, str, str]],
    zig_nodes: dict[str, dict[str, str]],
    zig_edges: list[tuple[str, str, str]],
) -> None:
    """Stage all regenerated files before atomically replacing their targets."""
    staged = [
        (
            base_dir / "cref_nodes.csv",
            _stage_csv(base_dir / "cref_nodes.csv", NODE_FIELDS, [cref_nodes[node_id] for node_id in sorted(cref_nodes)]),
        ),
        (base_dir / "cref_edges.csv", _stage_csv(base_dir / "cref_edges.csv", EDGE_FIELDS, _edge_rows(cref_edges))),
        (
            base_dir / "zig_nodes.csv",
            _stage_csv(base_dir / "zig_nodes.csv", NODE_FIELDS, [zig_nodes[node_id] for node_id in sorted(zig_nodes)]),
        ),
        (base_dir / "zig_edges.csv", _stage_csv(base_dir / "zig_edges.csv", EDGE_FIELDS, _edge_rows(zig_edges))),
    ]
    _replace_staged(staged)


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate deterministic CREF and reconciled ZIG graph inputs.")
    parser.add_argument("--base-dir", type=Path, default=BASE_DIR, help="Repository root.")
    args = parser.parse_args()
    base_dir = args.base_dir.resolve()
    cref_nodes, cref_edges, zig_nodes, zig_edges = consolidate(base_dir)
    print("Writing cref_nodes.csv / cref_edges.csv and reconciled zig CSVs...")
    write_outputs(base_dir, cref_nodes, cref_edges, zig_nodes, zig_edges)
    print(
        f"Done! CREF: {len(cref_nodes)} nodes, {len(cref_edges)} edge rows. "
        f"ZIG (reconciled): {len(zig_nodes)} nodes, {len(zig_edges)} edge rows."
    )


if __name__ == "__main__":
    main()
````

---

### FILE: `scripts/graph_engine.py` (sha256=ed0f91c902ad6a387d76d43ee02e3e4da469f8828415e6bea21c3990c0c45c72)

````python
"""Relation-preserving graph repository and deterministic framework mapper.

The graph is an evidence store, not a recommendation engine.  In particular,
two source CSV rows are still two records even when they have the same source,
target, and relationship type.  A previous ``DiGraph`` implementation silently
discarded those records.  This module uses a ``MultiDiGraph`` and exposes
repository helpers so callers do not need to depend on NetworkX's single-edge
APIs.

The public compatibility surface remains intentionally small:

* :class:`KnowledgeGraphEngine` keeps ``query_node``, ``semantic_search``,
  ``keyword_rank``, ``get_neighbors``, and ``crawl_subgraph``.
* ``engine.graph`` remains available for legacy read-only callers, but new code
  should use ``engine.repository`` / the typed helpers in this module.
* ``engine.get_framework_bundle(technique_id)`` is the authoritative, complete,
  deterministic mapping result for a selected ATT&CK technique.

No LLM receives a mutable graph or creates graph facts here.  The mapping
service only emits paths that are verified against the loaded snapshot.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

import networkx as nx

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity

    SEMANTIC_ENABLED = True
except ImportError:  # Semantic search is optional in an air-gapped deployment.
    np = None  # type: ignore[assignment]
    SentenceTransformer = None  # type: ignore[assignment,misc]
    cosine_similarity = None  # type: ignore[assignment]
    SEMANTIC_ENABLED = False


# All data files live in the repository root (the parent of this scripts/ dir),
# so the engine works no matter what directory it is launched from.
BASE_DIR = Path(__file__).resolve().parent.parent

GRAPH_SCHEMA_VERSION = "2"
MAPPING_MATRIX_VERSION = "1.0"
MANIFEST_FILENAME = "graph_snapshot_manifest.json"
EMBEDDING_METADATA_FILENAME = "embedding_metadata.json"
EMBEDDING_FILENAME = "graph_embeddings.npz"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# The ordering is part of graph materialization and therefore part of the
# snapshot.  Do not iterate an unordered set of input files here.
DATASET_LAYOUT: tuple[tuple[str, str, str], ...] = (
    ("mitre", "mitre_nodes.csv", "mitre_edges.csv"),
    ("zig", "zig_nodes.csv", "zig_edges.csv"),
    ("cref", "cref_nodes.csv", "cref_edges.csv"),
)

# This is the declared, versioned mapping matrix.  GraphMappingService uses
# exactly these relationship/type constraints; it does not do an unbounded
# neighborhood crawl and then call the result authoritative.
MAPPING_MATRIX: dict[str, dict[str, Any]] = {
    "attack_tactics": {
        "path": ["attack_technique -belongs_to_tactic-> attack_tactic"],
        "scope": "direct",
    },
    "zig": {
        "path": [
            "attack_technique <-mitigates- zig_activity",
            "zig_activity -belongs_to_capability-> zig_capability",
            "zig_capability -belongs_to_pillar-> zig_pillar",
        ],
        "scope": "direct_or_inherited_parent",
    },
    "cref": {
        "path": [
            "attack_technique <-mitigates_architecturally- cref_approach",
            "cref_approach -realizes_technique-> cref_technique",
            "cref_technique -achieves_objective-> cref_objective",
            "cref_objective -serves_goal-> cref_goal",
            "cref_approach -has_effect-> cref_effect",
        ],
        "scope": "direct_or_inherited_parent",
    },
    "mitigations": {
        "path": [
            "attack_technique <-mitigates- cref_mitigation|attack_mitigation",
            "mitigation -satisfies_control-> nist_800_53_control",
            "mitigation -implements_activity-> zig_activity",
            "mitigation -implements_approach-> cref_approach",
            "attack_mitigation -mapped_to_d3fend_technique-> d3fend_technique",
        ],
        "scope": "direct_or_inherited_parent",
    },
    "csa": {
        "path": ["cref_technique <-associated_with_technique- csa"],
        "scope": "direct_or_inherited_parent",
    },
    "analytics": {
        "path": [
            "attack_technique <-detects- attack_detectionstrategy",
            "attack_detectionstrategy -has_analytic-> attack_analytic",
        ],
        "scope": "direct_or_inherited_parent",
    },
}

# Words too generic to score on during keyword-fallback search.
STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "on", "in", "to", "for", "with",
    "by", "is", "are", "was", "were", "be", "been", "this", "that", "it",
    "as", "at", "from", "has", "have", "had", "via", "using", "used", "use",
}


class GraphIntegrityError(RuntimeError):
    """Raised when CSV materialization or a graph/embedding manifest is unsafe."""


class EmbeddingCompatibilityError(GraphIntegrityError):
    """Raised when a vector index does not belong to the loaded graph snapshot."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Write a manifest atomically so readers never see half-written JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _normalise_relationships(
    relationship_types: str | Iterable[str] | None,
) -> set[str] | None:
    if relationship_types is None:
        return None
    if isinstance(relationship_types, str):
        return {relationship_types}
    return set(relationship_types)


class GraphRepository:
    """A deterministic, relation-preserving facade over ``networkx.MultiDiGraph``.

    Every edge receives a stable key/``edge_id`` derived from its input dataset,
    source-row identity, endpoints, and relationship type.  The source record
    is retained even when a logically identical relation appears in another CSV.
    """

    def __init__(self, base_dir: str | Path = BASE_DIR):
        self.base_dir = Path(base_dir).resolve()
        self.graph = nx.MultiDiGraph()
        self.node_row_counts: dict[str, int] = {}
        self.edge_row_counts: dict[str, int] = {}
        self._edge_by_id: dict[str, dict[str, Any]] = {}

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def _path(self, filename: str) -> Path:
        return self.base_dir / filename

    def _require_file(self, filename: str) -> Path:
        path = self._path(filename)
        if not path.is_file():
            raise GraphIntegrityError(f"Required graph input is missing: {path}")
        return path

    @staticmethod
    def _stable_edge_id(
        dataset: str,
        source_file: str,
        source_record_index: int,
        source_id: str,
        target_id: str,
        relationship_type: str,
    ) -> str:
        identity = {
            "dataset": dataset,
            "relationship_type": relationship_type,
            "source_file": source_file,
            "source_id": source_id,
            "source_record_index": source_record_index,
            "target_id": target_id,
        }
        return f"edge:sha256:{_sha256_text(_canonical_json(identity))}"

    def load(self) -> None:
        self.graph.clear()
        self.node_row_counts.clear()
        self.edge_row_counts.clear()
        self._edge_by_id.clear()

        # Load every node file before any relation file.  This makes an unknown
        # endpoint a hard integrity error rather than a silently invented node.
        for dataset, nodes_file, _ in DATASET_LAYOUT:
            self._load_nodes(dataset, nodes_file)
        for dataset, _, edges_file in DATASET_LAYOUT:
            self._load_edges(dataset, edges_file)

        expected_edges = sum(self.edge_row_counts.values())
        if self.graph.number_of_edges() != expected_edges:
            raise GraphIntegrityError(
                "Loaded edge count does not equal raw edge-row count: "
                f"{self.graph.number_of_edges()} != {expected_edges}"
            )

    def _load_nodes(self, dataset: str, filename: str) -> None:
        path = self._require_file(filename)
        count = 0
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"id", "type"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                raise GraphIntegrityError(
                    f"{filename} must contain {sorted(required)} headers; found {reader.fieldnames!r}"
                )
            for record_index, row in enumerate(reader, start=1):
                count += 1
                node_id = (row.get("id") or "").strip()
                node_type = (row.get("type") or "").strip()
                if not node_id or not node_type:
                    raise GraphIntegrityError(
                        f"{filename} record {record_index} has an empty id or type"
                    )
                if self.graph.has_node(node_id):
                    existing = self.graph.nodes[node_id]
                    raise GraphIntegrityError(
                        f"Duplicate node id {node_id!r}: {filename} record {record_index} conflicts "
                        f"with {existing.get('source_file')} record {existing.get('source_record_index')}"
                    )
                attrs = {key: value for key, value in row.items() if key is not None}
                attrs.update(
                    {
                        "source_dataset": dataset,
                        "source_file": filename,
                        "source_record_index": record_index,
                        # ``line_num`` handles quoted multiline cells accurately;
                        # record index remains the stable identity used in hashes.
                        "source_row": reader.line_num,
                        "source_record": f"{filename}#{record_index}",
                    }
                )
                self.graph.add_node(node_id, **attrs)
        self.node_row_counts[dataset] = count

    def _load_edges(self, dataset: str, filename: str) -> None:
        path = self._require_file(filename)
        count = 0
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"source_id", "target_id", "relationship_type"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                raise GraphIntegrityError(
                    f"{filename} must contain {sorted(required)} headers; found {reader.fieldnames!r}"
                )
            for record_index, row in enumerate(reader, start=1):
                count += 1
                source_id = (row.get("source_id") or "").strip()
                target_id = (row.get("target_id") or "").strip()
                relationship_type = (row.get("relationship_type") or "").strip()
                if not source_id or not target_id or not relationship_type:
                    raise GraphIntegrityError(
                        f"{filename} record {record_index} has an empty endpoint or relationship_type"
                    )
                missing = [
                    node_id for node_id in (source_id, target_id)
                    if not self.graph.has_node(node_id)
                ]
                if missing:
                    raise GraphIntegrityError(
                        f"{filename} record {record_index} references unknown node(s): {missing}"
                    )
                edge_id = self._stable_edge_id(
                    dataset,
                    filename,
                    record_index,
                    source_id,
                    target_id,
                    relationship_type,
                )
                if edge_id in self._edge_by_id:
                    raise GraphIntegrityError(f"Stable edge id collision for {edge_id}")
                attrs = {key: value for key, value in row.items() if key is not None}
                attrs.update(
                    {
                        "edge_id": edge_id,
                        # ``relationship`` is retained for compatibility with
                        # existing callers while relationship_type is canonical.
                        "relationship": relationship_type,
                        "relationship_type": relationship_type,
                        "source_dataset": dataset,
                        "source_file": filename,
                        "source_record_index": record_index,
                        "source_row": reader.line_num,
                        "source_record": f"{filename}#{record_index}",
                    }
                )
                self.graph.add_edge(source_id, target_id, key=edge_id, **attrs)
                self._edge_by_id[edge_id] = {
                    "source_id": source_id,
                    "target_id": target_id,
                    "key": edge_id,
                    "data": attrs,
                }
        self.edge_row_counts[dataset] = count

    @staticmethod
    def _edge_sort_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            str(record.get("source_id", "")),
            str(record.get("target_id", "")),
            str(record.get("relationship_type", "")),
            str(record.get("source_dataset", "")),
            str(record.get("source_file", "")),
            int(record.get("source_record_index", 0)),
            str(record.get("edge_id", "")),
        )

    def node_record(self, node_id: str, include_description: bool = False) -> dict[str, Any] | None:
        if not self.graph.has_node(node_id):
            return None
        data = self.graph.nodes[node_id]
        result: dict[str, Any] = {
            "id": node_id,
            "type": data.get("type"),
            "name": data.get("name", node_id),
            "provenance": {
                "dataset": data.get("source_dataset"),
                "file": data.get("source_file"),
                "record": data.get("source_record"),
            },
        }
        if include_description:
            result["description"] = data.get("description", "")
            result["url"] = data.get("url", "")
        return result

    def iter_nodes(self, node_type: str | None = None) -> Iterator[tuple[str, Mapping[str, Any]]]:
        for node_id in sorted(self.graph.nodes):
            data = self.graph.nodes[node_id]
            if node_type is None or data.get("type") == node_type:
                yield node_id, data

    def _record_from_edge(
        self,
        source_id: str,
        target_id: str,
        key: str,
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "edge_id": data.get("edge_id", key),
            "source_id": source_id,
            "target_id": target_id,
            # Deprecated aliases retained for older read-only examples.  New
            # callers must use source_id/target_id, which make the typed graph
            # repository API unambiguous under MultiDiGraph parallel edges.
            "source": source_id,
            "target": target_id,
            "relationship_type": data.get("relationship_type", data.get("relationship", "")),
            "relationship": data.get("relationship", data.get("relationship_type", "")),
            "source_dataset": data.get("source_dataset"),
            "source_file": data.get("source_file"),
            "source_row": data.get("source_row"),
            "source_record_index": data.get("source_record_index"),
            "source_record": data.get("source_record"),
        }

    def edge_by_id(self, edge_id: str) -> dict[str, Any] | None:
        record = self._edge_by_id.get(edge_id)
        if record is None:
            return None
        return self._record_from_edge(
            record["source_id"], record["target_id"], record["key"], record["data"]
        )

    def _filter_and_sort_edges(
        self,
        edges: Iterable[tuple[str, str, str, Mapping[str, Any]]],
        relationship_types: str | Iterable[str] | None = None,
        source_type: str | None = None,
        target_type: str | None = None,
    ) -> list[dict[str, Any]]:
        relationships = _normalise_relationships(relationship_types)
        records: list[dict[str, Any]] = []
        for source_id, target_id, key, data in edges:
            relationship = data.get("relationship_type", data.get("relationship"))
            if relationships is not None and relationship not in relationships:
                continue
            if source_type is not None and self.graph.nodes[source_id].get("type") != source_type:
                continue
            if target_type is not None and self.graph.nodes[target_id].get("type") != target_type:
                continue
            records.append(self._record_from_edge(source_id, target_id, key, data))
        return sorted(records, key=self._edge_sort_key)

    def outgoing(
        self,
        node_id: str,
        relationship_types: str | Iterable[str] | None = None,
        target_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self.graph.has_node(node_id):
            return []
        return self._filter_and_sort_edges(
            self.graph.out_edges(node_id, keys=True, data=True),
            relationship_types=relationship_types,
            target_type=target_type,
        )

    def incoming(
        self,
        node_id: str,
        relationship_types: str | Iterable[str] | None = None,
        source_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self.graph.has_node(node_id):
            return []
        return self._filter_and_sort_edges(
            self.graph.in_edges(node_id, keys=True, data=True),
            relationship_types=relationship_types,
            source_type=source_type,
        )

    def edges(self) -> list[dict[str, Any]]:
        return self._filter_and_sort_edges(self.graph.edges(keys=True, data=True))

    def neighbors(
        self,
        node_id: str,
        direction: str = "both",
        relationship_types: str | Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        if direction not in {"in", "out", "both"}:
            raise ValueError("direction must be 'in', 'out', or 'both'")
        records: list[dict[str, Any]] = []
        if direction in {"out", "both"}:
            for edge in self.outgoing(node_id, relationship_types):
                records.append(
                    {
                        **edge,
                        "id": edge["target_id"],
                        "direction": "out",
                        "node": self.node_record(edge["target_id"]),
                    }
                )
        if direction in {"in", "both"}:
            for edge in self.incoming(node_id, relationship_types):
                records.append(
                    {
                        **edge,
                        "id": edge["source_id"],
                        "direction": "in",
                        "node": self.node_record(edge["source_id"]),
                    }
                )
        return sorted(
            records,
            key=lambda item: (
                item["direction"],
                self._edge_sort_key(item),
                str(item["id"]),
            ),
        )

    def build_snapshot_manifest(self) -> dict[str, Any]:
        """Return a deterministic snapshot description of the loaded graph."""
        node_csv_hashes: dict[str, str] = {}
        edge_csv_hashes: dict[str, str] = {}
        files: dict[str, dict[str, str]] = {}
        for dataset, nodes_file, edges_file in DATASET_LAYOUT:
            node_path = self._require_file(nodes_file)
            edge_path = self._require_file(edges_file)
            node_csv_hashes[dataset] = _sha256_file(node_path)
            edge_csv_hashes[dataset] = _sha256_file(edge_path)
            files[dataset] = {"nodes": nodes_file, "edges": edges_file}

        identity = {
            "edge_csv_hashes": edge_csv_hashes,
            "graph_schema_version": GRAPH_SCHEMA_VERSION,
            "node_csv_hashes": node_csv_hashes,
            "node_count": self.node_count,
            "runtime_edge_count": self.edge_count,
        }
        graph_snapshot_id = f"sha256:{_sha256_text(_canonical_json(identity))}"
        return {
            "graph_schema_version": GRAPH_SCHEMA_VERSION,
            "graph_snapshot_id": graph_snapshot_id,
            "dataset_files": files,
            "node_csv_hashes": node_csv_hashes,
            "edge_csv_hashes": edge_csv_hashes,
            "node_row_count": sum(self.node_row_counts.values()),
            "node_row_counts": dict(sorted(self.node_row_counts.items())),
            "node_count": self.node_count,
            "edge_row_count": sum(self.edge_row_counts.values()),
            "edge_row_counts": dict(sorted(self.edge_row_counts.items())),
            "runtime_edge_count": self.edge_count,
            "multi_edge_preserving": True,
            "edge_identity": "sha256(dataset, source_file, source_record_index, source_id, target_id, relationship_type)",
            "mapping_matrix_version": MAPPING_MATRIX_VERSION,
        }

    def write_snapshot_manifest(self, path: str | Path | None = None) -> dict[str, Any]:
        manifest = self.build_snapshot_manifest()
        target = Path(path) if path is not None else self.base_dir / MANIFEST_FILENAME
        _atomic_write_json(target, manifest)
        return manifest

    def validate_snapshot_manifest(self, path: str | Path | None = None) -> dict[str, Any]:
        target = Path(path) if path is not None else self.base_dir / MANIFEST_FILENAME
        if not target.is_file():
            raise GraphIntegrityError(
                f"Graph snapshot manifest is required but missing: {target}. "
                "Run `python scripts/graph_engine.py --write-manifest` after validating graph inputs."
            )
        try:
            manifest = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GraphIntegrityError(f"Cannot read graph snapshot manifest {target}: {exc}") from exc

        expected = self.build_snapshot_manifest()
        required_keys = (
            "graph_schema_version",
            "graph_snapshot_id",
            "node_csv_hashes",
            "edge_csv_hashes",
            "node_count",
            "edge_row_count",
            "runtime_edge_count",
            "multi_edge_preserving",
        )
        missing = [key for key in required_keys if key not in manifest]
        if missing:
            raise GraphIntegrityError(f"Graph snapshot manifest is missing required keys: {missing}")
        for key in (
            "graph_schema_version",
            "graph_snapshot_id",
            "node_csv_hashes",
            "edge_csv_hashes",
            "node_count",
            "edge_row_count",
            "runtime_edge_count",
            "multi_edge_preserving",
        ):
            if manifest.get(key) != expected.get(key):
                raise GraphIntegrityError(
                    f"Graph snapshot manifest mismatch for {key}: "
                    f"expected {expected.get(key)!r}, found {manifest.get(key)!r}"
                )
        if manifest["edge_row_count"] != manifest["runtime_edge_count"]:
            raise GraphIntegrityError(
                "Manifest declares a lossy graph: edge_row_count must equal runtime_edge_count"
            )
        return manifest


class GraphMappingService:
    """Enumerate only declared, validated graph-backed framework mappings.

    The service deliberately creates paths for each prefix/branch of the
    mapping matrix.  This prevents a missing downstream relationship from
    hiding an otherwise valid activity, approach, or mitigation.
    """

    # Categories that establish a direct framework crosswalk.  Tactics and
    # ATT&CK detection metadata are useful but do not suppress inheritance for
    # a sub-technique that has no direct ZIG/CREF/mitigation mapping.
    _DIRECT_FRAMEWORK_CATEGORIES = {
        "zig_activity",
        "zig_capability",
        "zig_pillar",
        "cref_approach",
        "cref_technique",
        "cref_objective",
        "cref_goal",
        "cref_effect",
        "cref_mitigation",
        "attack_mitigation",
        "mitigation_control",
        "mitigation_activity",
        "mitigation_capability",
        "mitigation_pillar",
        "mitigation_cref_approach",
        "mitigation_cref_technique",
        "mitigation_cref_objective",
        "mitigation_cref_goal",
        "mitigation_cref_effect",
        "mitigation_d3fend",
        "mitigation_d3fend_artifact",
    }

    def __init__(self, repository: GraphRepository, snapshot_manifest: Mapping[str, Any]):
        self.repository = repository
        self.snapshot_manifest = dict(snapshot_manifest)
        self.graph_snapshot_id = str(snapshot_manifest["graph_snapshot_id"])

    def _node_ids_by_type(self, path: Mapping[str, Any], node_type: str) -> list[str]:
        return [
            str(node["id"])
            for node in path.get("nodes", [])
            if node.get("type") == node_type
        ]

    def _new_path(
        self,
        *,
        category: str,
        requested_technique_id: str,
        source_technique_id: str,
        mapping_scope: str,
        node_ids: Sequence[str],
        steps: Sequence[tuple[str, str, Mapping[str, Any]]],
    ) -> dict[str, Any]:
        if len(node_ids) != len(steps) + 1:
            raise GraphIntegrityError(
                f"Invalid path construction for {category}: {len(node_ids)} nodes, {len(steps)} edges"
            )
        nodes: list[dict[str, Any]] = []
        for node_id in node_ids:
            node = self.repository.node_record(node_id)
            if node is None:
                raise GraphIntegrityError(f"Path references unknown node {node_id}")
            nodes.append(node)

        edges: list[dict[str, Any]] = []
        for from_id, to_id, edge in steps:
            edge_id = str(edge.get("edge_id", ""))
            resolved = self.repository.edge_by_id(edge_id)
            if resolved is None:
                raise GraphIntegrityError(f"Path references unknown edge {edge_id}")
            is_out = resolved["source_id"] == from_id and resolved["target_id"] == to_id
            is_in = resolved["source_id"] == to_id and resolved["target_id"] == from_id
            if not is_out and not is_in:
                raise GraphIntegrityError(
                    f"Path step {from_id}->{to_id} does not match edge {edge_id}"
                )
            edges.append(
                {
                    **resolved,
                    "from_id": from_id,
                    "to_id": to_id,
                    "traversal_direction": "out" if is_out else "in",
                }
            )

        identity = {
            "category": category,
            "edge_ids": [edge["edge_id"] for edge in edges],
            "graph_snapshot_id": self.graph_snapshot_id,
            "mapping_scope": mapping_scope,
            "node_ids": list(node_ids),
            "requested_technique_id": requested_technique_id,
            "source_technique_id": source_technique_id,
        }
        path = {
            "path_id": f"path:sha256:{_sha256_text(_canonical_json(identity))}",
            "category": category,
            "mapping_scope": mapping_scope,
            "requested_technique_id": requested_technique_id,
            "source_technique_id": source_technique_id,
            "graph_snapshot_id": self.graph_snapshot_id,
            "nodes": nodes,
            "edges": edges,
        }
        path["validation"] = self.validate_path(path)
        return path

    def validate_path(self, path: Mapping[str, Any]) -> dict[str, Any]:
        """Validate every node, edge, traversal direction, and snapshot ID."""
        errors: list[str] = []
        if path.get("graph_snapshot_id") != self.graph_snapshot_id:
            errors.append("path graph_snapshot_id does not match the loaded graph")
        nodes = path.get("nodes") or []
        edges = path.get("edges") or []
        if len(nodes) != len(edges) + 1:
            errors.append("path does not contain exactly one more node than edge")
        node_ids = [node.get("id") for node in nodes]
        for node_id in node_ids:
            if not isinstance(node_id, str) or self.repository.node_record(node_id) is None:
                errors.append(f"unknown node in path: {node_id!r}")
        for index, edge in enumerate(edges):
            edge_id = edge.get("edge_id")
            resolved = self.repository.edge_by_id(str(edge_id)) if edge_id else None
            if resolved is None:
                errors.append(f"unknown edge in path: {edge_id!r}")
                continue
            if index + 1 >= len(node_ids):
                errors.append(f"edge {edge_id} has no corresponding node pair")
                continue
            from_id, to_id = node_ids[index], node_ids[index + 1]
            if edge.get("from_id") != from_id or edge.get("to_id") != to_id:
                errors.append(f"edge {edge_id} does not preserve ordered path endpoints")
            expected_direction = (
                "out"
                if resolved["source_id"] == from_id and resolved["target_id"] == to_id
                else "in"
                if resolved["source_id"] == to_id and resolved["target_id"] == from_id
                else None
            )
            if expected_direction is None:
                errors.append(f"edge {edge_id} is not incident to its ordered node pair")
            elif edge.get("traversal_direction") != expected_direction:
                errors.append(f"edge {edge_id} has invalid traversal direction")
            if edge.get("relationship_type") != resolved["relationship_type"]:
                errors.append(f"edge {edge_id} has an altered relationship type")
        return {
            "state": "valid" if not errors else "invalid",
            "errors": errors,
            "graph_snapshot_id": self.graph_snapshot_id,
        }

    def _out(
        self,
        node_id: str,
        relationship: str,
        target_type: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.repository.outgoing(node_id, relationship, target_type=target_type)

    def _in(
        self,
        node_id: str,
        relationship: str,
        source_type: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.repository.incoming(node_id, relationship, source_type=source_type)

    def _add_zig_paths(
        self,
        paths: list[dict[str, Any]],
        *,
        requested_id: str,
        source_id: str,
        scope: str,
        prefix_nodes: Sequence[str],
        prefix_steps: Sequence[tuple[str, str, Mapping[str, Any]]],
        activity_id: str,
        first_edge: Mapping[str, Any],
    ) -> None:
        # Caller supplies a traversal from the previous node to activity.
        activity_nodes = [*prefix_nodes, activity_id]
        activity_steps = [*prefix_steps, (prefix_nodes[-1], activity_id, first_edge)]
        paths.append(
            self._new_path(
                category="zig_activity",
                requested_technique_id=requested_id,
                source_technique_id=source_id,
                mapping_scope=scope,
                node_ids=activity_nodes,
                steps=activity_steps,
            )
        )
        for capability_edge in self._out(activity_id, "belongs_to_capability", "zig_capability"):
            capability_id = capability_edge["target_id"]
            capability_nodes = [*activity_nodes, capability_id]
            capability_steps = [*activity_steps, (activity_id, capability_id, capability_edge)]
            paths.append(
                self._new_path(
                    category="zig_capability",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=capability_nodes,
                    steps=capability_steps,
                )
            )
            for pillar_edge in self._out(capability_id, "belongs_to_pillar", "zig_pillar"):
                pillar_id = pillar_edge["target_id"]
                paths.append(
                    self._new_path(
                        category="zig_pillar",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=[*capability_nodes, pillar_id],
                        steps=[*capability_steps, (capability_id, pillar_id, pillar_edge)],
                    )
                )

    def _add_cref_paths(
        self,
        paths: list[dict[str, Any]],
        *,
        requested_id: str,
        source_id: str,
        scope: str,
        prefix_nodes: Sequence[str],
        prefix_steps: Sequence[tuple[str, str, Mapping[str, Any]]],
        approach_id: str,
        first_edge: Mapping[str, Any],
        category_prefix: str = "cref",
    ) -> None:
        """Add every CREF approach branch; no objective/goal/effect is first-picked."""
        approach_nodes = [*prefix_nodes, approach_id]
        approach_steps = [*prefix_steps, (prefix_nodes[-1], approach_id, first_edge)]
        paths.append(
            self._new_path(
                category=f"{category_prefix}_approach",
                requested_technique_id=requested_id,
                source_technique_id=source_id,
                mapping_scope=scope,
                node_ids=approach_nodes,
                steps=approach_steps,
            )
        )
        for effect_edge in self._out(approach_id, "has_effect", "cref_effect"):
            effect_id = effect_edge["target_id"]
            paths.append(
                self._new_path(
                    category=f"{category_prefix}_effect",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=[*approach_nodes, effect_id],
                    steps=[*approach_steps, (approach_id, effect_id, effect_edge)],
                )
            )
        for technique_edge in self._out(approach_id, "realizes_technique", "cref_technique"):
            cref_technique_id = technique_edge["target_id"]
            technique_nodes = [*approach_nodes, cref_technique_id]
            technique_steps = [*approach_steps, (approach_id, cref_technique_id, technique_edge)]
            paths.append(
                self._new_path(
                    category=f"{category_prefix}_technique",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=technique_nodes,
                    steps=technique_steps,
                )
            )
            for objective_edge in self._out(cref_technique_id, "achieves_objective", "cref_objective"):
                objective_id = objective_edge["target_id"]
                objective_nodes = [*technique_nodes, objective_id]
                objective_steps = [*technique_steps, (cref_technique_id, objective_id, objective_edge)]
                paths.append(
                    self._new_path(
                        category=f"{category_prefix}_objective",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=objective_nodes,
                        steps=objective_steps,
                    )
                )
                for goal_edge in self._out(objective_id, "serves_goal", "cref_goal"):
                    goal_id = goal_edge["target_id"]
                    paths.append(
                        self._new_path(
                            category=f"{category_prefix}_goal",
                            requested_technique_id=requested_id,
                            source_technique_id=source_id,
                            mapping_scope=scope,
                            node_ids=[*objective_nodes, goal_id],
                            steps=[*objective_steps, (objective_id, goal_id, goal_edge)],
                        )
                    )
            # CSA is related to CREF technique, not directly to ATT&CK.  The
            # complete ordered path keeps the approach provenance intact.
            for csa_edge in self._in(cref_technique_id, "associated_with_technique", "csa"):
                csa_id = csa_edge["source_id"]
                paths.append(
                    self._new_path(
                        category="csa",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=[*technique_nodes, csa_id],
                        steps=[*technique_steps, (cref_technique_id, csa_id, csa_edge)],
                    )
                )

    def _add_mitigation_paths(
        self,
        paths: list[dict[str, Any]],
        *,
        requested_id: str,
        source_id: str,
        scope: str,
        mitigation_id: str,
        mitigation_edge: Mapping[str, Any],
    ) -> None:
        mitigation_type = self.repository.graph.nodes[mitigation_id].get("type")
        category = "attack_mitigation" if mitigation_type == "attack_mitigation" else "cref_mitigation"
        base_nodes = [source_id, mitigation_id]
        base_steps = [(source_id, mitigation_id, mitigation_edge)]
        paths.append(
            self._new_path(
                category=category,
                requested_technique_id=requested_id,
                source_technique_id=source_id,
                mapping_scope=scope,
                node_ids=base_nodes,
                steps=base_steps,
            )
        )
        for control_edge in self._out(mitigation_id, "satisfies_control", "nist_800_53_control"):
            control_id = control_edge["target_id"]
            paths.append(
                self._new_path(
                    category="mitigation_control",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=[*base_nodes, control_id],
                    steps=[*base_steps, (mitigation_id, control_id, control_edge)],
                )
            )
        for activity_edge in self._out(mitigation_id, "implements_activity", "zig_activity"):
            activity_id = activity_edge["target_id"]
            activity_nodes = [*base_nodes, activity_id]
            activity_steps = [*base_steps, (mitigation_id, activity_id, activity_edge)]
            paths.append(
                self._new_path(
                    category="mitigation_activity",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=activity_nodes,
                    steps=activity_steps,
                )
            )
            for capability_edge in self._out(activity_id, "belongs_to_capability", "zig_capability"):
                capability_id = capability_edge["target_id"]
                capability_nodes = [*activity_nodes, capability_id]
                capability_steps = [*activity_steps, (activity_id, capability_id, capability_edge)]
                paths.append(
                    self._new_path(
                        category="mitigation_capability",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=capability_nodes,
                        steps=capability_steps,
                    )
                )
                for pillar_edge in self._out(capability_id, "belongs_to_pillar", "zig_pillar"):
                    pillar_id = pillar_edge["target_id"]
                    paths.append(
                        self._new_path(
                            category="mitigation_pillar",
                            requested_technique_id=requested_id,
                            source_technique_id=source_id,
                            mapping_scope=scope,
                            node_ids=[*capability_nodes, pillar_id],
                            steps=[*capability_steps, (capability_id, pillar_id, pillar_edge)],
                        )
                    )
        for approach_edge in self._out(mitigation_id, "implements_approach", "cref_approach"):
            self._add_cref_paths(
                paths,
                requested_id=requested_id,
                source_id=source_id,
                scope=scope,
                prefix_nodes=base_nodes,
                prefix_steps=base_steps,
                approach_id=approach_edge["target_id"],
                first_edge=approach_edge,
                category_prefix="mitigation_cref",
            )
        # Native ATT&CK mitigations are currently the source of D3FEND links,
        # but this intentionally reads either type should future CREF data add
        # the same verified relationship.
        for d3fend_edge in self._out(mitigation_id, "mapped_to_d3fend_technique", "d3fend_technique"):
            d3fend_id = d3fend_edge["target_id"]
            d3fend_nodes = [*base_nodes, d3fend_id]
            d3fend_steps = [*base_steps, (mitigation_id, d3fend_id, d3fend_edge)]
            paths.append(
                self._new_path(
                    category="mitigation_d3fend",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=d3fend_nodes,
                    steps=d3fend_steps,
                )
            )
            # Keep defensive artifact paths bounded to the direct D3FEND
            # relation.  Arbitrary D3FEND graph crawls are intentionally out of
            # scope for the mapping matrix.
            for artifact_edge in self.repository.outgoing(d3fend_id):
                artifact_id = artifact_edge["target_id"]
                artifact_type = self.repository.graph.nodes[artifact_id].get("type")
                if artifact_type not in {"defensive_artifact", "attack_datacomponent"}:
                    continue
                paths.append(
                    self._new_path(
                        category="mitigation_d3fend_artifact",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=[*d3fend_nodes, artifact_id],
                        steps=[*d3fend_steps, (d3fend_id, artifact_id, artifact_edge)],
                    )
                )

    def _enumerate_direct_paths(self, requested_id: str, source_id: str, scope: str) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        # ATT&CK tactics.
        for tactic_edge in self._out(source_id, "belongs_to_tactic", "attack_tactic"):
            tactic_id = tactic_edge["target_id"]
            paths.append(
                self._new_path(
                    category="attack_tactic",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=[source_id, tactic_id],
                    steps=[(source_id, tactic_id, tactic_edge)],
                )
            )

        # Direct ZIG mapping: Activity -> ATT&CK technique, traversed inwards
        # from the selected technique, then forward to capability/pillar.
        for activity_edge in self._in(source_id, "mitigates", "zig_activity"):
            self._add_zig_paths(
                paths,
                requested_id=requested_id,
                source_id=source_id,
                scope=scope,
                prefix_nodes=[source_id],
                prefix_steps=[],
                activity_id=activity_edge["source_id"],
                first_edge=activity_edge,
            )

        # Direct CREF architectural approach chain.
        for approach_edge in self._in(source_id, "mitigates_architecturally", "cref_approach"):
            self._add_cref_paths(
                paths,
                requested_id=requested_id,
                source_id=source_id,
                scope=scope,
                prefix_nodes=[source_id],
                prefix_steps=[],
                approach_id=approach_edge["source_id"],
                first_edge=approach_edge,
            )

        # Both native ATT&CK M#### and CREF CM#### mitigations are required.
        for mitigation_type in ("attack_mitigation", "cref_mitigation"):
            for mitigation_edge in self._in(source_id, "mitigates", mitigation_type):
                self._add_mitigation_paths(
                    paths,
                    requested_id=requested_id,
                    source_id=source_id,
                    scope=scope,
                    mitigation_id=mitigation_edge["source_id"],
                    mitigation_edge=mitigation_edge,
                )

        # ATT&CK detection strategies and their explicit analytics are included
        # as verified metadata, not as a semantic/keyword guess.
        for strategy_edge in self._in(source_id, "detects", "attack_detectionstrategy"):
            strategy_id = strategy_edge["source_id"]
            strategy_nodes = [source_id, strategy_id]
            strategy_steps = [(source_id, strategy_id, strategy_edge)]
            paths.append(
                self._new_path(
                    category="attack_detectionstrategy",
                    requested_technique_id=requested_id,
                    source_technique_id=source_id,
                    mapping_scope=scope,
                    node_ids=strategy_nodes,
                    steps=strategy_steps,
                )
            )
            for analytic_edge in self._out(strategy_id, "has_analytic", "attack_analytic"):
                analytic_id = analytic_edge["target_id"]
                paths.append(
                    self._new_path(
                        category="attack_analytic",
                        requested_technique_id=requested_id,
                        source_technique_id=source_id,
                        mapping_scope=scope,
                        node_ids=[*strategy_nodes, analytic_id],
                        steps=[*strategy_steps, (strategy_id, analytic_id, analytic_edge)],
                    )
                )
        return paths

    def _inherit_path(
        self,
        path: Mapping[str, Any],
        child_id: str,
        parent_edge: Mapping[str, Any],
    ) -> dict[str, Any]:
        parent_id = str(parent_edge["target_id"])
        original_nodes = [str(node["id"]) for node in path["nodes"]]
        original_steps = [
            (str(edge["from_id"]), str(edge["to_id"]), edge)
            for edge in path["edges"]
        ]
        if not original_nodes or original_nodes[0] != parent_id:
            raise GraphIntegrityError("Cannot inherit a path that does not begin at the parent technique")
        return self._new_path(
            category=str(path["category"]),
            requested_technique_id=child_id,
            source_technique_id=parent_id,
            mapping_scope="inherited_parent",
            node_ids=[child_id, *original_nodes],
            steps=[(child_id, parent_id, parent_edge), *original_steps],
        )

    @staticmethod
    def _path_sort_key(path: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            str(path.get("category", "")),
            0 if path.get("mapping_scope") == "direct" else 1,
            str(path.get("source_technique_id", "")),
            tuple(node.get("id", "") for node in path.get("nodes", [])),
            tuple(edge.get("edge_id", "") for edge in path.get("edges", [])),
        )

    @staticmethod
    def _unique_sorted(values: Iterable[str]) -> list[str]:
        return sorted({str(value) for value in values if value not in (None, "")})

    def _node_name(self, node_id: str | None) -> str | None:
        if not node_id:
            return None
        node = self.repository.node_record(node_id)
        return node.get("name", node_id) if node else node_id

    def _summarize_paths(
        self,
        requested_id: str,
        paths: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Build compatibility-friendly summaries from exhaustive path records.

        The path list is authoritative.  The summary intentionally retains all
        values in lists and documents scalar legacy fields as presentation-only.
        """
        attack_tactics: dict[tuple[str, str, str], dict[str, Any]] = {}
        zig_candidates: list[dict[str, Any]] = []
        cref_candidates: list[dict[str, Any]] = []
        mitigation_groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        csa_candidates: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        d3fend_candidates: dict[tuple[str, str, str], dict[str, Any]] = {}
        analytic_candidates: dict[tuple[str, str, str], dict[str, Any]] = {}
        strategy_candidates: dict[tuple[str, str, str], dict[str, Any]] = {}

        for path in paths:
            category = str(path["category"])
            scope = str(path["mapping_scope"])
            source_id = str(path["source_technique_id"])
            path_id = str(path["path_id"])
            nodes = path["nodes"]
            ids_by_type: dict[str, list[str]] = defaultdict(list)
            for node in nodes:
                node_type = str(node.get("type", ""))
                ids_by_type[node_type].append(str(node["id"]))

            if category == "attack_tactic":
                for tactic_id in ids_by_type["attack_tactic"]:
                    attack_tactics[(scope, source_id, tactic_id)] = {
                        "tactic_id": tactic_id,
                        "tactic_name": self._node_name(tactic_id),
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "path_ids": [path_id],
                    }

            if category.startswith("zig_"):
                activity_ids = ids_by_type["zig_activity"]
                if activity_ids:
                    zig_candidates.append(
                        {
                            "activity_id": activity_ids[-1],
                            "activity_name": self._node_name(activity_ids[-1]),
                            "capability_id": ids_by_type["zig_capability"][-1] if ids_by_type["zig_capability"] else None,
                            "capability_name": self._node_name(ids_by_type["zig_capability"][-1]) if ids_by_type["zig_capability"] else None,
                            "pillar_id": ids_by_type["zig_pillar"][-1] if ids_by_type["zig_pillar"] else None,
                            "pillar_name": self._node_name(ids_by_type["zig_pillar"][-1]) if ids_by_type["zig_pillar"] else None,
                            "mapping_scope": scope,
                            "source_technique_id": source_id,
                            "path_ids": [path_id],
                        }
                    )

            if category.startswith("cref_") or category.startswith("mitigation_cref_"):
                approach_ids = ids_by_type["cref_approach"]
                if approach_ids:
                    approach_id = approach_ids[-1]
                    technique_ids = ids_by_type["cref_technique"]
                    objective_ids = ids_by_type["cref_objective"]
                    goal_ids = ids_by_type["cref_goal"]
                    effect_ids = ids_by_type["cref_effect"]
                    cref_candidates.append(
                        {
                            "approach_id": approach_id,
                            "approach_name": self._node_name(approach_id),
                            "technique_id": technique_ids[-1] if technique_ids else None,
                            "technique_name": self._node_name(technique_ids[-1]) if technique_ids else None,
                            "objective_id": objective_ids[-1] if objective_ids else None,
                            "objective_name": self._node_name(objective_ids[-1]) if objective_ids else None,
                            "goal_id": goal_ids[-1] if goal_ids else None,
                            "goal_name": self._node_name(goal_ids[-1]) if goal_ids else None,
                            "effect_id": effect_ids[-1] if effect_ids else None,
                            "effect_name": self._node_name(effect_ids[-1]) if effect_ids else None,
                            "via_mitigation_id": ids_by_type["attack_mitigation"][-1] if ids_by_type["attack_mitigation"] else (ids_by_type["cref_mitigation"][-1] if ids_by_type["cref_mitigation"] else None),
                            "mapping_scope": scope,
                            "source_technique_id": source_id,
                            "path_ids": [path_id],
                        }
                    )

            mitigation_ids = ids_by_type["attack_mitigation"] + ids_by_type["cref_mitigation"]
            for mitigation_id in mitigation_ids:
                mitigation_type = self.repository.graph.nodes[mitigation_id].get("type")
                group_key = (scope, source_id, mitigation_id)
                group = mitigation_groups.setdefault(
                    group_key,
                    {
                        "mitigation_id": mitigation_id,
                        "mitigation_name": self._node_name(mitigation_id),
                        "mitigation_type": mitigation_type,
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "nist_800_53_controls": set(),
                        "zig_activity_ids": set(),
                        "zig_capability_ids": set(),
                        "zig_pillar_ids": set(),
                        "cref_approach_ids": set(),
                        "cref_technique_ids": set(),
                        "cref_objective_ids": set(),
                        "cref_goal_ids": set(),
                        "cref_effect_ids": set(),
                        "d3fend_technique_ids": set(),
                        "d3fend_artifact_ids": set(),
                        "path_ids": set(),
                    },
                )
                group["nist_800_53_controls"].update(ids_by_type["nist_800_53_control"])
                group["zig_activity_ids"].update(ids_by_type["zig_activity"])
                group["zig_capability_ids"].update(ids_by_type["zig_capability"])
                group["zig_pillar_ids"].update(ids_by_type["zig_pillar"])
                group["cref_approach_ids"].update(ids_by_type["cref_approach"])
                group["cref_technique_ids"].update(ids_by_type["cref_technique"])
                group["cref_objective_ids"].update(ids_by_type["cref_objective"])
                group["cref_goal_ids"].update(ids_by_type["cref_goal"])
                group["cref_effect_ids"].update(ids_by_type["cref_effect"])
                group["d3fend_technique_ids"].update(ids_by_type["d3fend_technique"])
                group["d3fend_artifact_ids"].update(ids_by_type["defensive_artifact"])
                group["d3fend_artifact_ids"].update(ids_by_type["attack_datacomponent"])
                group["path_ids"].add(path_id)

            if category == "csa":
                csa_ids = ids_by_type["csa"]
                cref_technique_ids = ids_by_type["cref_technique"]
                for csa_id in csa_ids:
                    cref_technique_id = cref_technique_ids[-1] if cref_technique_ids else ""
                    csa_candidates[(scope, source_id, csa_id, cref_technique_id)] = {
                        "csa_id": csa_id,
                        "csa_name": self._node_name(csa_id),
                        "cref_technique_id": cref_technique_id or None,
                        "cref_technique_name": self._node_name(cref_technique_id) if cref_technique_id else None,
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "path_ids": [path_id],
                    }

            if category.startswith("mitigation_d3fend"):
                for d3fend_id in ids_by_type["d3fend_technique"]:
                    d3fend_candidates[(scope, source_id, d3fend_id)] = {
                        "d3fend_id": d3fend_id,
                        "d3fend_name": self._node_name(d3fend_id),
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "path_ids": [path_id],
                    }

            if category == "attack_detectionstrategy":
                for strategy_id in ids_by_type["attack_detectionstrategy"]:
                    strategy_candidates[(scope, source_id, strategy_id)] = {
                        "strategy_id": strategy_id,
                        "strategy_name": self._node_name(strategy_id),
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "path_ids": [path_id],
                    }
            if category == "attack_analytic":
                for analytic_id in ids_by_type["attack_analytic"]:
                    analytic_candidates[(scope, source_id, analytic_id)] = {
                        "analytic_id": analytic_id,
                        "analytic_name": self._node_name(analytic_id),
                        "analytic_description": self.repository.graph.nodes[analytic_id].get("description", ""),
                        "mapping_scope": scope,
                        "source_technique_id": source_id,
                        "path_ids": [path_id],
                    }

        # A path prefix is valuable for provenance but should not masquerade as
        # an additional independent ZIG mapping when a longer path covers it.
        def _zig_is_prefix(candidate: Mapping[str, Any], other: Mapping[str, Any]) -> bool:
            same = all(
                candidate.get(key) == other.get(key)
                for key in ("mapping_scope", "source_technique_id", "activity_id")
            )
            if not same:
                return False
            if candidate.get("capability_id") is None and other.get("capability_id") is not None:
                return True
            return (
                candidate.get("capability_id") == other.get("capability_id")
                and candidate.get("pillar_id") is None
                and other.get("pillar_id") is not None
            )

        zig = [
            candidate for candidate in zig_candidates
            if not any(_zig_is_prefix(candidate, other) for other in zig_candidates if other is not candidate)
        ]
        zig_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for item in zig:
            key = (
                item["mapping_scope"], item["source_technique_id"], item["activity_id"],
                item["capability_id"], item["pillar_id"],
            )
            existing = zig_by_key.setdefault(key, {**item, "path_ids": []})
            existing["path_ids"].extend(item["path_ids"])
        zig = list(zig_by_key.values())

        cref_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for item in cref_candidates:
            key = tuple(item.get(name) for name in (
                "mapping_scope", "source_technique_id", "approach_id", "technique_id",
                "objective_id", "goal_id", "effect_id", "via_mitigation_id",
            ))
            existing = cref_by_key.setdefault(key, {**item, "path_ids": []})
            existing["path_ids"].extend(item["path_ids"])

        mitigations: list[dict[str, Any]] = []
        for group in mitigation_groups.values():
            final = dict(group)
            for key, value in list(final.items()):
                if isinstance(value, set):
                    final[key] = sorted(value)
            # Compatibility fields retain a deterministic presentation value,
            # while the *_ids lists remain the authoritative complete output.
            final["zig_activity_id"] = final["zig_activity_ids"][0] if final["zig_activity_ids"] else None
            final["zig_activity_name"] = self._node_name(final["zig_activity_id"])
            final["path_ids"] = sorted(final["path_ids"])
            final["display_selection"] = "sorted_first_for_legacy_display_only"
            mitigations.append(final)

        def _sort_records(records: Iterable[Mapping[str, Any]], id_key: str) -> list[dict[str, Any]]:
            materialized: list[dict[str, Any]] = []
            for record in records:
                value = dict(record)
                if "path_ids" in value:
                    value["path_ids"] = sorted(set(value["path_ids"]))
                materialized.append(value)
            return sorted(
                materialized,
                key=lambda item: (
                    0 if item.get("mapping_scope") == "direct" else 1,
                    str(item.get("source_technique_id", "")),
                    str(item.get(id_key, "")),
                ),
            )

        attack_tactics_list = _sort_records(attack_tactics.values(), "tactic_id")
        zig_list = _sort_records(zig, "activity_id")
        cref_list = _sort_records(cref_by_key.values(), "approach_id")
        mitigations_list = _sort_records(mitigations, "mitigation_id")
        attack_mitigations = [
            item for item in mitigations_list if item.get("mitigation_type") == "attack_mitigation"
        ]
        cref_mitigations = [
            item for item in mitigations_list if item.get("mitigation_type") == "cref_mitigation"
        ]
        csa_list = _sort_records(csa_candidates.values(), "csa_id")
        d3fend_list = _sort_records(d3fend_candidates.values(), "d3fend_id")
        analytics_list = _sort_records(analytic_candidates.values(), "analytic_id")
        strategies_list = _sort_records(strategy_candidates.values(), "strategy_id")

        categories = {
            "attack_tactics": attack_tactics_list,
            "zig": zig_list,
            "cref": cref_list,
            "mitigations": mitigations_list,
            "attack_mitigations": attack_mitigations,
            "cref_mitigations": cref_mitigations,
            "csa": csa_list,
            "d3fend": d3fend_list,
            "analytics": analytics_list,
            "attack_detectionstrategies": strategies_list,
        }
        # An empty category is an explicit result, not a suggestion to fill the
        # gap with a keyword match.
        not_mapped = [
            name for name in ("zig", "cref", "mitigations", "csa", "d3fend", "analytics")
            if not categories[name]
        ]
        technique = self.repository.node_record(requested_id)
        return {
            "attack_technique": {
                "technique_id": requested_id,
                "technique_name": technique.get("name", requested_id) if technique else requested_id,
            },
            **categories,
            "not_mapped_categories": not_mapped,
            "display_selection_policy": "All mappings are in paths/categories; legacy scalar fields are display-only and sorted deterministically.",
        }

    def build_framework_bundle(
        self,
        technique_id: str,
        *,
        include_inherited_parent: bool = True,
    ) -> dict[str, Any]:
        """Return complete, deterministic, validated mappings for one ATT&CK TTP.

        Parent mappings are used only when a selected sub-technique has no
        direct framework crosswalk.  Every inherited path starts with the real
        ``subtechnique_of`` edge and is visibly labeled ``inherited_parent``.
        """
        node = self.repository.node_record(technique_id)
        if node is None:
            raise ValueError(f"Unknown graph node: {technique_id}")
        if node.get("type") != "attack_technique":
            raise ValueError(f"{technique_id} is not an ATT&CK technique")

        direct_paths = self._enumerate_direct_paths(technique_id, technique_id, "direct")
        paths = list(direct_paths)
        inheritance: list[dict[str, Any]] = []
        has_direct_framework_mapping = any(
            path["category"] in self._DIRECT_FRAMEWORK_CATEGORIES for path in direct_paths
        )
        if include_inherited_parent and not has_direct_framework_mapping:
            for parent_edge in self._out(technique_id, "subtechnique_of", "attack_technique"):
                parent_id = parent_edge["target_id"]
                parent_paths = self._enumerate_direct_paths(parent_id, parent_id, "direct")
                inherited_paths = [
                    self._inherit_path(path, technique_id, parent_edge)
                    for path in parent_paths
                ]
                paths.extend(inherited_paths)
                inheritance.append(
                    {
                        "child_technique_id": technique_id,
                        "parent_technique_id": parent_id,
                        "edge_id": parent_edge["edge_id"],
                        "inherited_path_count": len(inherited_paths),
                    }
                )

        paths = sorted(paths, key=self._path_sort_key)
        # A valid full graph can legitimately have duplicate semantic relations
        # from distinct source records.  Do not deduplicate by endpoints; only
        # path_id (which includes edge IDs) may be safely de-duplicated.
        unique_paths: list[dict[str, Any]] = []
        seen_path_ids: set[str] = set()
        for path in paths:
            if path["path_id"] in seen_path_ids:
                continue
            seen_path_ids.add(path["path_id"])
            unique_paths.append(path)
        paths = unique_paths
        invalid_paths = [path["path_id"] for path in paths if path["validation"]["state"] != "valid"]
        summary = self._summarize_paths(technique_id, paths)
        return {
            "schema_version": "1",
            "mapping_matrix_version": MAPPING_MATRIX_VERSION,
            "graph_snapshot_id": self.graph_snapshot_id,
            "mapping_validation": {
                "state": "valid" if not invalid_paths else "invalid",
                "invalid_path_ids": invalid_paths,
                "path_count": len(paths),
            },
            "inheritance": inheritance,
            "paths": paths,
            **summary,
        }

    def get_provenance_paths(
        self,
        technique_id: str,
        category: str | None = None,
        *,
        include_inherited_parent: bool = True,
    ) -> list[dict[str, Any]]:
        bundle = self.build_framework_bundle(
            technique_id, include_inherited_parent=include_inherited_parent
        )
        paths = bundle["paths"]
        if category is None:
            return paths
        return [path for path in paths if path["category"] == category]


class KnowledgeGraphEngine:
    """Compatibility facade plus typed ATT&CK retrieval and mapping service."""

    def __init__(
        self,
        base_dir: str | Path = BASE_DIR,
        *,
        validate_manifest: bool = True,
        manifest_path: str | Path | None = None,
        load_embeddings: bool = True,
        require_embeddings: bool = False,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.repository = GraphRepository(self.base_dir)
        self.graph = self.repository.graph  # Legacy read-only compatibility.
        self.manifest_path = Path(manifest_path) if manifest_path is not None else self.base_dir / MANIFEST_FILENAME
        self.repository.load()
        self.snapshot_manifest = (
            self.repository.validate_snapshot_manifest(self.manifest_path)
            if validate_manifest
            else self.repository.build_snapshot_manifest()
        )
        self.graph_snapshot_id = self.snapshot_manifest["graph_snapshot_id"]
        self.mapping_service = GraphMappingService(self.repository, self.snapshot_manifest)

        self.semantic_enabled = False
        self.semantic_status = "disabled"
        self.embedding_model: Any | None = None
        self.embeddings: Any | None = None
        self.embedding_node_ids: list[str] | None = None
        self._embedding_indices_by_type: dict[str, list[int]] = {}
        self.embedding_metadata: dict[str, Any] | None = None
        self._attack_name_index = self._build_attack_name_index()

        if load_embeddings:
            self._load_embeddings(require_embeddings=require_embeddings)

    def load_data(self) -> None:
        """Reload CSV data and refresh graph/mapping state (legacy helper)."""
        self.repository.load()
        self.graph = self.repository.graph
        self.snapshot_manifest = self.repository.build_snapshot_manifest()
        self.graph_snapshot_id = self.snapshot_manifest["graph_snapshot_id"]
        self.mapping_service = GraphMappingService(self.repository, self.snapshot_manifest)
        self._attack_name_index = self._build_attack_name_index()

    def _build_attack_name_index(self) -> list[tuple[str, str]]:
        names: list[tuple[str, str]] = []
        for node_id, data in self.repository.iter_nodes("attack_technique"):
            name = " ".join(str(data.get("name", "")).casefold().split())
            if len(name) >= 4:
                names.append((name, node_id))
        # Specific/long names first prevents a parent phrase from consuming the
        # evidence for a named sub-technique.  ID is a stable tie-breaker.
        return sorted(names, key=lambda item: (-len(item[0]), item[0], item[1]))

    def _embedding_paths(self) -> tuple[Path, Path]:
        return self.base_dir / EMBEDDING_FILENAME, self.base_dir / EMBEDDING_METADATA_FILENAME

    def validate_embedding_manifest(self) -> dict[str, Any]:
        """Validate vector metadata against this exact graph snapshot.

        This method raises on stale/malformed files.  Startup can treat vectors
        as optional by calling ``_load_embeddings(require_embeddings=False)``;
        readiness checks may call this method directly and fail closed.
        """
        if np is None:
            raise EmbeddingCompatibilityError("numpy is unavailable; embeddings cannot be validated")
        npz_path, metadata_path = self._embedding_paths()
        if not npz_path.is_file() or not metadata_path.is_file():
            raise EmbeddingCompatibilityError(
                f"Embedding index/manifest missing: {npz_path.name}, {metadata_path.name}"
            )
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            embeddings = np.load(npz_path, allow_pickle=False)["embeddings"]
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            raise EmbeddingCompatibilityError(f"Cannot read embedding index/manifest: {exc}") from exc

        required = {
            "schema_version",
            "model_name",
            "graph_snapshot_id",
            "node_ids",
            "node_order_hash",
            "embedding_dimension",
            "embedding_count",
            "embedding_file_sha256",
        }
        missing = sorted(required - set(metadata))
        if missing:
            raise EmbeddingCompatibilityError(
                f"Embedding manifest is missing required keys: {missing}. Regenerate embeddings."
            )
        node_ids = metadata["node_ids"]
        if not isinstance(node_ids, list) or not all(isinstance(value, str) for value in node_ids):
            raise EmbeddingCompatibilityError("embedding node_ids must be a list of graph node IDs")
        if len(node_ids) != len(set(node_ids)):
            raise EmbeddingCompatibilityError("embedding node_ids contains duplicates")
        if metadata["graph_snapshot_id"] != self.graph_snapshot_id:
            raise EmbeddingCompatibilityError(
                "Embedding graph_snapshot_id does not match the loaded graph; regenerate embeddings."
            )
        expected_order_hash = _sha256_text(_canonical_json(node_ids))
        if metadata["node_order_hash"] != expected_order_hash:
            raise EmbeddingCompatibilityError("embedding node_order_hash does not match node_ids")
        if metadata["embedding_file_sha256"] != _sha256_file(npz_path):
            raise EmbeddingCompatibilityError("embedding_file_sha256 does not match graph_embeddings.npz")
        if getattr(embeddings, "ndim", 0) != 2:
            raise EmbeddingCompatibilityError("embedding matrix must be two-dimensional")
        if embeddings.shape[0] != len(node_ids) or embeddings.shape[0] != metadata["embedding_count"]:
            raise EmbeddingCompatibilityError("embedding count does not match node_ids/manifest")
        if embeddings.shape[1] != metadata["embedding_dimension"]:
            raise EmbeddingCompatibilityError("embedding dimension does not match manifest")
        missing_nodes = [node_id for node_id in node_ids if not self.graph.has_node(node_id)]
        if missing_nodes:
            raise EmbeddingCompatibilityError(
                f"embedding index references node(s) absent from graph: {missing_nodes[:5]}"
            )
        return {**metadata, "_embeddings": embeddings}

    def _load_embeddings(self, *, require_embeddings: bool) -> None:
        if not SEMANTIC_ENABLED:
            self.semantic_status = "degraded: semantic dependencies unavailable"
            if require_embeddings:
                raise EmbeddingCompatibilityError(self.semantic_status)
            return
        try:
            metadata = self.validate_embedding_manifest()
            embeddings = metadata.pop("_embeddings")
            # ``local_files_only`` is non-negotiable for the intended
            # air-gapped deployment: model loading must never trigger a download.
            self.embedding_model = SentenceTransformer(  # type: ignore[misc]
                metadata["model_name"], local_files_only=True
            )
            self.embeddings = embeddings
            self.embedding_node_ids = list(metadata["node_ids"])
            self.embedding_metadata = metadata
            self._embedding_indices_by_type = defaultdict(list)
            for index, node_id in enumerate(self.embedding_node_ids):
                node_type = self.graph.nodes[node_id].get("type")
                self._embedding_indices_by_type[str(node_type)].append(index)
            self.semantic_enabled = True
            self.semantic_status = "ready"
        except Exception as exc:  # noqa: BLE001 - preserve safe lexical fallback.
            self.semantic_enabled = False
            self.embedding_model = None
            self.embeddings = None
            self.embedding_node_ids = None
            self._embedding_indices_by_type = {}
            self.semantic_status = f"degraded: {exc}"
            if require_embeddings:
                if isinstance(exc, EmbeddingCompatibilityError):
                    raise
                raise EmbeddingCompatibilityError(str(exc)) from exc

    def write_embedding_manifest(
        self,
        *,
        node_ids: Sequence[str],
        embeddings: Any,
        model_name: str = EMBEDDING_MODEL_NAME,
        metadata_path: str | Path | None = None,
        npz_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Write metadata that binds an embedding matrix to this graph snapshot."""
        if np is None:
            raise EmbeddingCompatibilityError("numpy is unavailable; cannot write embedding metadata")
        resolved_npz = Path(npz_path) if npz_path is not None else self.base_dir / EMBEDDING_FILENAME
        resolved_metadata = Path(metadata_path) if metadata_path is not None else self.base_dir / EMBEDDING_METADATA_FILENAME
        if getattr(embeddings, "ndim", 0) != 2:
            raise EmbeddingCompatibilityError("embedding matrix must be two-dimensional")
        if len(node_ids) != embeddings.shape[0]:
            raise EmbeddingCompatibilityError("node_ids count does not match embedding matrix")
        if len(node_ids) != len(set(node_ids)):
            raise EmbeddingCompatibilityError("node_ids contains duplicates")
        missing = [node_id for node_id in node_ids if not self.graph.has_node(node_id)]
        if missing:
            raise EmbeddingCompatibilityError(f"Cannot bind embeddings to missing nodes: {missing[:5]}")
        if not resolved_npz.is_file():
            raise EmbeddingCompatibilityError(f"Embedding index does not exist: {resolved_npz}")
        metadata = {
            "schema_version": "2",
            "model_name": model_name,
            "graph_snapshot_id": self.graph_snapshot_id,
            "node_ids": list(node_ids),
            "node_order_hash": _sha256_text(_canonical_json(list(node_ids))),
            "embedding_dimension": int(embeddings.shape[1]),
            "embedding_count": int(embeddings.shape[0]),
            "embedding_file": resolved_npz.name,
            "embedding_file_sha256": _sha256_file(resolved_npz),
        }
        _atomic_write_json(resolved_metadata, metadata)
        return metadata

    def query_node(self, node_id: str) -> Mapping[str, Any] | None:
        """Return attributes of a specific node (legacy compatibility)."""
        if self.graph.has_node(node_id):
            return self.graph.nodes[node_id]
        return None

    def get_node(self, node_id: str, *, include_description: bool = True) -> dict[str, Any] | None:
        """Typed, provenance-carrying node response for graph-tool callers."""
        return self.repository.node_record(node_id, include_description=include_description)

    def search_nodes(self, keyword: str, exact_match: bool = False) -> list[tuple[str, Mapping[str, Any]]]:
        """Search all graph node IDs, names, or descriptions (legacy helper)."""
        results = []
        keyword = keyword.casefold()
        for node_id, data in self.repository.iter_nodes():
            if exact_match:
                if keyword == str(node_id).casefold() or keyword == str(data.get("name", "")).casefold():
                    results.append((node_id, data))
            elif (
                keyword in str(node_id).casefold()
                or keyword in str(data.get("name", "")).casefold()
                or keyword in str(data.get("description", "")).casefold()
            ):
                results.append((node_id, data))
        return results

    def keyword_rank(
        self,
        query_text: str,
        top_k: int = 3,
        *,
        node_type: str | None = None,
    ) -> list[tuple[str, Mapping[str, Any], float]]:
        """Rank nodes lexically, optionally against one explicit node type."""
        tokens = [
            token for token in re.findall(r"[\w-]+", str(query_text).casefold(), flags=re.UNICODE)
            if len(token) > 2 and token not in STOPWORDS
        ]
        if not tokens or top_k <= 0:
            return []
        scored: list[tuple[str, Mapping[str, Any], float]] = []
        for node_id, data in self.repository.iter_nodes(node_type):
            name = str(data.get("name", "")).casefold()
            description = str(data.get("description", "")).casefold()
            score = 0.0
            for token in tokens:
                if token in name:
                    score += 2.0
                elif token in description:
                    score += 1.0
            if score:
                scored.append((node_id, data, score / (2.0 * len(tokens))))
        return sorted(scored, key=lambda item: (-item[2], item[0]))[:top_k]

    def semantic_search(
        self,
        query_text: str,
        top_k: int = 3,
        *,
        node_type: str | None = "attack_technique",
    ) -> list[tuple[str, Mapping[str, Any], float]]:
        """Search vectors only within the requested node type.

        The default is ATT&CK techniques because this API is used for finding
        resolution.  Callers needing broad lexical exploration should use
        ``keyword_rank(..., node_type=None)`` explicitly instead of ranking all
        vector rows and filtering after the fact.
        """
        if top_k <= 0:
            return []
        if not self.semantic_enabled or self.embeddings is None or self.embedding_node_ids is None:
            return self.keyword_rank(query_text, top_k=top_k, node_type=node_type)
        indices = (
            list(range(len(self.embedding_node_ids)))
            if node_type is None
            else self._embedding_indices_by_type.get(node_type, [])
        )
        if not indices:
            return []
        query_vec = self.embedding_model.encode([query_text])
        candidate_embeddings = self.embeddings[indices]
        similarities = cosine_similarity(query_vec, candidate_embeddings)[0]
        # Stable sort makes equal scores reproducible across providers/runs.
        ranked = sorted(
            ((float(score), index) for score, index in zip(similarities, indices)),
            key=lambda item: (-item[0], self.embedding_node_ids[item[1]]),
        )[:top_k]
        return [
            (
                self.embedding_node_ids[index],
                self.graph.nodes[self.embedding_node_ids[index]],
                score,
            )
            for score, index in ranked
        ]

    def search_attack_techniques(self, query_text: str, top_k: int = 20) -> list[dict[str, Any]]:
        """Bounded, typed retrieval API suitable for an LLM graph tool."""
        top_k = max(1, min(int(top_k), 20))
        method = "semantic" if self.semantic_enabled else "lexical"
        return [
            {
                "id": node_id,
                "name": data.get("name", node_id),
                "description": data.get("description", ""),
                "type": data.get("type"),
                "score": score,
                "method": method,
                "graph_snapshot_id": self.graph_snapshot_id,
            }
            for node_id, data, score in self.semantic_search(
                query_text, top_k=top_k, node_type="attack_technique"
            )
        ]

    def match_attack_technique_names(self, text: str) -> list[str]:
        """Return exact canonical ATT&CK names using Unicode-aware boundaries."""
        normalised = " ".join(str(text or "").casefold().split())
        matches: list[str] = []
        for name, node_id in self._attack_name_index:
            # A single backslash is intentional.  The former ``\\w`` pattern
            # looked for a literal backslash and matched names inside words.
            if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", normalised, flags=re.UNICODE):
                matches.append(node_id)
        return self.suppress_parent_techniques(matches)

    def parent_technique_ids(self, technique_id: str) -> list[str]:
        return [edge["target_id"] for edge in self.repository.outgoing(
            technique_id, "subtechnique_of", target_type="attack_technique"
        )]

    def suppress_parent_techniques(self, technique_ids: Iterable[str]) -> list[str]:
        """Suppress a matched parent when the same evidence matched its child."""
        ordered = list(dict.fromkeys(technique_ids))
        selected = set(ordered)
        parents = {
            parent
            for technique_id in selected
            for parent in self.parent_technique_ids(technique_id)
            if parent in selected
        }
        return [technique_id for technique_id in ordered if technique_id not in parents]

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        relationship_types: str | Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return one result per relation, never one arbitrary edge per pair."""
        return self.repository.neighbors(node_id, direction, relationship_types)

    def crawl_subgraph(self, start_node_id: str, depth: int = 2) -> dict[str, Any]:
        """Return an undirected-radius subgraph while preserving directed edge rows."""
        if not self.graph.has_node(start_node_id):
            return {"error": "Node not found"}
        if depth < 0:
            raise ValueError("depth must be non-negative")
        undirected = self.graph.to_undirected(as_view=True)
        distances = nx.single_source_shortest_path_length(undirected, start_node_id, cutoff=depth)
        included = set(distances)
        nodes_data = {
            node_id: dict(self.graph.nodes[node_id])
            for node_id in sorted(included)
        }
        edges_data = [
            edge for edge in self.repository.edges()
            if edge["source_id"] in included and edge["target_id"] in included
        ]
        return {
            "start_node": start_node_id,
            "depth_crawled": depth,
            "nodes": nodes_data,
            "edges": edges_data,
            "graph_snapshot_id": self.graph_snapshot_id,
        }

    def get_framework_bundle(
        self,
        technique_id: str,
        *,
        include_inherited_parent: bool = True,
    ) -> dict[str, Any]:
        """Authoritative deterministic mapping bundle for a selected ATT&CK TTP."""
        return self.mapping_service.build_framework_bundle(
            technique_id, include_inherited_parent=include_inherited_parent
        )

    def get_provenance_paths(
        self,
        technique_id: str,
        category: str | None = None,
        *,
        include_inherited_parent: bool = True,
    ) -> list[dict[str, Any]]:
        return self.mapping_service.get_provenance_paths(
            technique_id,
            category,
            include_inherited_parent=include_inherited_parent,
        )


def _main() -> None:
    parser = argparse.ArgumentParser(description="Validate or inspect the MITRE CSD-H graph")
    parser.add_argument("--write-manifest", action="store_true", help="write graph_snapshot_manifest.json")
    parser.add_argument("--no-embeddings", action="store_true", help="do not load optional vector index")
    parser.add_argument("--technique", help="print a deterministic framework bundle for an ATT&CK technique")
    args = parser.parse_args()

    engine = KnowledgeGraphEngine(
        validate_manifest=not args.write_manifest,
        load_embeddings=not args.no_embeddings,
    )
    if args.write_manifest:
        manifest = engine.repository.write_snapshot_manifest()
        print(f"Wrote {MANIFEST_FILENAME}: {manifest['graph_snapshot_id']}")
    else:
        print(
            f"Knowledge Graph initialized with {engine.graph.number_of_nodes()} nodes and "
            f"{engine.graph.number_of_edges()} edges ({engine.graph_snapshot_id})."
        )
    if args.technique:
        print(json.dumps(engine.get_framework_bundle(args.technique), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()
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

### FILE: `assessment_template.md` (sha256=2d2bc8379e74745c3ca394f1b973b5f4704d056ba99fc538baa59c778b4484f0)

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

### FILE: `agent_batch_processor.py` (sha256=a97e320ec6486524625c73f20324d5db175519e92a6504489e4a76309f21c076)

````python
"""LEGACY demonstration batch reporter.

This script is retained for backwards-compatible examples only.  Production
analysis, review state, and report lifecycle now belong to
``run_analyst_pipeline.py`` and the web API.  Its graph reads use the typed
repository facade so parallel relationship rows in the MultiDiGraph are not
collapsed or accessed through single-edge assumptions.
"""

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
    print("LEGACY EXAMPLE: use run_analyst_pipeline.py for supported report generation.")
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
        for edge in engine.repository.outgoing(
            mitre_node_id, 'belongs_to_tactic', target_type='attack_tactic'
        ):
            tactic_id = edge['target_id']
            tactic_node = engine.query_node(tactic_id)
            mitre_tactic = f"[{tactic_id}] {tactic_node.get('name', tactic_id)}" if tactic_node else tactic_id
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
                if edge.get('target_id') != mitre_node_id:
                    continue
                source_id = edge['source_id']
                src_data = mitre_subgraph['nodes'].get(source_id, {})
                src_type = src_data.get('type')
                if src_type == 'zig_activity' and edge.get('relationship_type') == 'mitigates':
                    zig_activities_direct.append((source_id, src_data))
                elif src_type == 'cref_approach' and edge.get('relationship_type') == 'mitigates_architecturally':
                    cref_approaches.append((source_id, src_data))
                elif src_type == 'cref_mitigation' and edge.get('relationship_type') == 'mitigates':
                    cref_mitigations.append((source_id, src_data))

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
            for edge in engine.repository.outgoing(
                zig_activity_id, 'belongs_to_capability', target_type='zig_capability'
            ):
                capability_id = edge['target_id']
                cap_node = engine.query_node(capability_id)
                zig_cap_id, zig_cap_name = capability_id, (cap_node.get('name', capability_id) if cap_node else capability_id)
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
            for edge in engine.repository.outgoing(
                zig_cap_id, 'belongs_to_pillar', target_type='zig_pillar'
            ):
                pillar_id = edge['target_id']
                pillar_node = engine.query_node(pillar_id)
                zig_pillar = pillar_node.get('name', pillar_id) if pillar_node else pillar_id
                break

        # 4. CREF Architectural Resiliency: walk the first approach up
        # Approach -> Technique -> Objective -> Goal, plus its Effect.
        cref_goal = cref_objective = cref_technique_name = cref_approach_name = cref_effect = "None found in graph"
        cref_approach_id = "None"
        cref_technique_id_found = None
        if cref_approaches:
            cref_approach_id, cref_approach_data = cref_approaches[0]
            cref_approach_name = cref_approach_data.get('name', cref_approach_id)
            for edge in engine.repository.outgoing(cref_approach_id):
                rel = edge['relationship_type']
                target_id = edge['target_id']
                if rel == 'realizes_technique':
                    cref_technique_id_found = target_id
                    tech_node = engine.query_node(target_id)
                    cref_technique_name = tech_node.get('name', target_id) if tech_node else target_id
                elif rel == 'has_effect':
                    eff_node = engine.query_node(target_id)
                    cref_effect = eff_node.get('name', target_id) if eff_node else target_id
            if cref_technique_id_found:
                for edge in engine.repository.outgoing(cref_technique_id_found):
                    rel = edge['relationship_type']
                    target_id = edge['target_id']
                    if rel == 'achieves_objective':
                        obj_node = engine.query_node(target_id)
                        cref_objective = obj_node.get('name', target_id) if obj_node else target_id
                        for goal_edge in engine.repository.outgoing(target_id, 'serves_goal'):
                            goal_id = goal_edge['target_id']
                            goal_node = engine.query_node(goal_id)
                            cref_goal = goal_node.get('name', goal_id) if goal_node else goal_id
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
            for edge in engine.repository.outgoing(cref_mitigation_id):
                rel = edge['relationship_type']
                target_id = edge['target_id']
                if rel == 'satisfies_control':
                    nist_controls.append(target_id)
                elif rel == 'implements_activity':
                    zig_activity_id_from_mitigation = target_id
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
            for edge in engine.repository.incoming(cref_technique_id_found, 'associated_with_technique'):
                source_id = edge['source_id']
                if edge['relationship_type'] == 'associated_with_technique':
                    csa_node = engine.query_node(source_id)
                    if csa_node:
                        csa_name = csa_node.get('name', source_id)
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

### FILE: `agent_crawl_example.py` (sha256=974245fe619fd7529ed722b30feaba143e0ae665af550ec8b5809ba540498b08)

````python
"""LEGACY graph-crawl demonstration.

This is a read-only educational example, not the supported analyst workflow.
Use the bounded graph tools exposed through ``run_analyst_pipeline.py`` or the
web API for production work.  It deliberately uses canonical repository edge
fields so it remains safe with the relation-preserving MultiDiGraph.
"""

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
        out += (
            f"  - {edge['source_id']} --({edge['relationship_type']})--> "
            f"{edge['target_id']}\n"
        )
    return out

if __name__ == "__main__":
    print("LEGACY EXAMPLE: this script does not create reviewable reports.")
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
            if edge['target_id'] != mitre_node_id:
                continue
            source_id = edge['source_id']
            src_data = mitre_subgraph['nodes'].get(source_id, {})
            src_type = src_data.get('type')
            if src_type == 'zig_activity':
                print(f"  - Direct ZIG Activity: [{source_id}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
            elif src_type == 'cref_approach':
                print(f"  - CREF Approach: [{source_id}] {src_data.get('name')} --mitigates_architecturally--> {mitre_node_id}")
            elif src_type == 'cref_mitigation':
                print(f"  - CREF/NIST Mitigation: [{source_id}] {src_data.get('name')} --mitigates--> {mitre_node_id}")
                for control_edge in engine.repository.outgoing(source_id, 'satisfies_control'):
                    control_id = control_edge['target_id']
                    control_node = engine.query_node(control_id)
                    print(f"      satisfies_control --> [{control_id}] (NIST SP 800-53)")

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

Expected: `Knowledge Graph initialized with 5618 nodes and 43387 edges.`
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
