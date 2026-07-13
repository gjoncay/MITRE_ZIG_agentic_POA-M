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
