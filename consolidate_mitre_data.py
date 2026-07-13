"""Deterministically regenerate the ATT&CK/D3FEND graph CSV inputs.

The graph repository is a relation-preserving ``MultiDiGraph``.  This generator
keeps every *logical* relationship type for a source/target pair, while
deterministically collapsing exact triples repeated by denormalized source
cross-products.  Do not use a set while building records: we retain the first
source occurrence and can report how many repeated expansions were normalized.

The script is repository-relative and can be launched from any working
directory:

    python3 consolidate_mitre_data.py
    python3 consolidate_mitre_data.py --base-dir /path/to/repository
"""

from __future__ import annotations

import argparse
import csv
import json
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
    """Return whether a scalar dataframe value contains useful text."""
    return value is not None and not pd.isna(value) and bool(str(value).strip())


def _text(value: Any, default: str = "") -> str:
    return str(value).strip() if _present(value) else default


def _stage_csv(path: Path, fieldnames: Iterable[str], rows: Iterable[dict[str, str]]) -> Path:
    """Write a CSV beside its target, returning a staged path for atomic replace."""
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


def _stage_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _replace_staged(staged: list[tuple[Path, Path]]) -> None:
    """Commit already-written output files without exposing partial file contents."""
    try:
        for target, temporary in staged:
            os.replace(temporary, target)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def _add_node(
    nodes: dict[str, dict[str, str]],
    node_id: Any,
    node_type: str,
    name: Any,
    description: Any = "",
    url: Any = "",
) -> None:
    identifier = _text(node_id)
    if not identifier:
        return
    # Input order is deliberately deterministic, so first authoritative source
    # wins for a shared ID while edges remain individually preserved below.
    nodes.setdefault(
        identifier,
        {
            "id": identifier,
            "type": node_type,
            "name": _text(name),
            "description": _text(description),
            "url": _text(url),
        },
    )


def _add_edge(edges: list[tuple[str, str, str]], source_id: Any, target_id: Any, rel_type: Any) -> None:
    source, target, relationship = _text(source_id), _text(target_id), _text(rel_type)
    if source and target and relationship:
        # A list is intentional.  Exact logical triples are normalized later,
        # after integrity checks and with an auditable repeat count.
        edges.append((source, target, relationship))


def _logical_edges(edges: Iterable[tuple[str, str, str]]) -> tuple[list[tuple[str, str, str]], int]:
    """Stable-deduplicate only exact source/target/relationship triples.

    The raw D3FEND export is denormalized and repeats hierarchy relations for
    every cross-product row.  Collapsing those repeats must not collapse a
    distinct relationship type between the same node pair.
    """
    unique: dict[tuple[str, str, str], None] = {}
    repeated = 0
    for edge in edges:
        if edge in unique:
            repeated += 1
        else:
            unique[edge] = None
    return list(unique), repeated


def _parse_attack(nodes: dict[str, dict[str, str]], edges: list[tuple[str, str, str]], base_dir: Path) -> None:
    path = base_dir / "enterprise-attack-v19.1(1).xlsx"
    print(f"Parsing {path.name}...")
    attack_xls = pd.ExcelFile(path)

    print(" - tactics")
    tactic_name_to_id: dict[str, str] = {}
    for _, row in attack_xls.parse("tactics").iterrows():
        _add_node(nodes, row.get("ID"), "attack_tactic", row.get("name"), row.get("description"), row.get("url"))
        name, identifier = _text(row.get("name")), _text(row.get("ID"))
        if name and identifier:
            tactic_name_to_id[name.casefold()] = identifier

    print(" - techniques")
    for _, row in attack_xls.parse("techniques").iterrows():
        _add_node(nodes, row.get("ID"), "attack_technique", row.get("name"), row.get("description"), row.get("url"))
        tactics = _text(row.get("tactics"))
        for tactic in tactics.split(",") if tactics else ():
            tactic_id = tactic_name_to_id.get(tactic.strip().casefold())
            if tactic_id:
                _add_edge(edges, row.get("ID"), tactic_id, "belongs_to_tactic")
        if _present(row.get("sub-technique of")):
            _add_edge(edges, row.get("ID"), row.get("sub-technique of"), "subtechnique_of")

    print(" - mitigations")
    for _, row in attack_xls.parse("mitigations").iterrows():
        _add_node(nodes, row.get("ID"), "attack_mitigation", row.get("name"), row.get("description"), row.get("url"))

    for sheet, node_type in (
        ("groups", "attack_group"),
        ("software", "attack_software"),
        ("campaigns", "attack_campaign"),
    ):
        print(f" - {sheet}")
        for _, row in attack_xls.parse(sheet).iterrows():
            _add_node(nodes, row.get("ID"), node_type, row.get("name"), row.get("description"), row.get("url"))

    print(" - datacomponents")
    for _, row in attack_xls.parse("datacomponents").iterrows():
        _add_node(nodes, row.get("ID"), "attack_datacomponent", row.get("name"), row.get("description"), row.get("url"))

    print(" - detectionstrategies")
    for _, row in attack_xls.parse("detectionstrategies").iterrows():
        _add_node(nodes, row.get("ID"), "attack_detectionstrategy", row.get("name"), "", row.get("url"))

    print(" - analytics")
    analytic_stix_to_id: dict[str, str] = {}
    for _, row in attack_xls.parse("analytics").iterrows():
        _add_node(nodes, row.get("ID"), "attack_analytic", row.get("name"), row.get("description"), row.get("url"))
        stix_id, analytic_id = _text(row.get("STIX ID")), _text(row.get("ID"))
        if stix_id and analytic_id:
            analytic_stix_to_id[stix_id] = analytic_id

    print(" - defensive mappings")
    for _, row in attack_xls.parse("defensive mappings").iterrows():
        det_id = row.get("detection_strategy_attack_id")
        analytic_id = analytic_stix_to_id.get(_text(row.get("analytic_id")))
        data_component_id = row.get("data_component_attack_id")
        if _present(det_id) and analytic_id:
            _add_edge(edges, det_id, analytic_id, "has_analytic")
        if analytic_id and _present(data_component_id):
            _add_edge(edges, analytic_id, data_component_id, "monitors_data_component")

    print(" - relationships")
    for _, row in attack_xls.parse("relationships").iterrows():
        _add_edge(edges, row.get("source ID"), row.get("target ID"), row.get("mapping type"))


def _parse_d3fend(nodes: dict[str, dict[str, str]], edges: list[tuple[str, str, str]], base_dir: Path) -> None:
    print("Parsing d3fend.csv...")
    d3fend_tech_name_to_id: dict[str, str] = {}
    for _, row in pd.read_csv(base_dir / "d3fend.csv").iterrows():
        tech_id = _text(row.get("ID"))
        tactic_name = _text(row.get("D3FEND Tactic"))
        tech_name = _text(row.get("D3FEND Technique")) or _text(row.get("D3FEND Technique Level 0")) or _text(row.get("D3FEND Technique Level 1"))
        if not tech_id:
            continue
        _add_node(nodes, tech_id, "d3fend_technique", tech_name, row.get("Definition"))
        if tech_name:
            d3fend_tech_name_to_id[tech_name.casefold()] = tech_id
        if tactic_name:
            tactic_id = f"D3-TAC-{tactic_name.replace(' ', '-').upper()}"
            _add_node(nodes, tactic_id, "d3fend_tactic", tactic_name)
            _add_edge(edges, tech_id, tactic_id, "belongs_to_tactic")

    mapping_path = base_dir / "ATT&CK_D3FEND_Mappings.ods"
    print(f"Parsing {mapping_path.name}...")
    try:
        mappings_xls = pd.ExcelFile(mapping_path, engine="odf")
        for _, row in mappings_xls.parse("Sheet1").iterrows():
            attack_id = row.get("ATT&CK ID")
            d3fend_techs = _text(row.get("Related D3FEND Techniques"))
            if _present(attack_id) and d3fend_techs:
                for d3fend_id in re.findall(r"D3-[A-Z0-9]+", d3fend_techs):
                    _add_edge(edges, attack_id, d3fend_id, "mapped_to_d3fend_technique")
    except Exception as exc:  # ODF is optional in some isolated deployments.
        print(f"Warning: Could not parse {mapping_path.name}: {exc}")

    print("Parsing d3fend-full-mappings.csv...")
    for _, row in pd.read_csv(base_dir / "d3fend-full-mappings.csv").iterrows():
        defensive_technique = _text(row.get("def_tech_label"))
        defensive_tactic = _text(row.get("def_tactic_label"))
        defensive_artifact = _text(row.get("def_artifact_label"))
        offensive_artifact = _text(row.get("off_artifact_label"))
        offensive_technique = _text(row.get("off_tech_id"))
        defensive_artifact_rel = _text(row.get("def_artifact_rel_label"), "relates_to")
        offensive_artifact_rel = _text(row.get("off_artifact_rel_label"), "used_by")

        if not defensive_technique:
            continue
        defensive_id = d3fend_tech_name_to_id.get(
            defensive_technique.casefold(), f"D3-{defensive_technique.replace(' ', '-').upper()}"
        )
        _add_node(nodes, defensive_id, "d3fend_technique", defensive_technique)
        if defensive_tactic:
            tactic_id = f"D3-TAC-{defensive_tactic.replace(' ', '-').upper()}"
            _add_node(nodes, tactic_id, "d3fend_tactic", defensive_tactic)
            _add_edge(edges, defensive_id, tactic_id, "belongs_to_tactic")

        if defensive_artifact:
            defensive_artifact_id = f"DA-{defensive_artifact.replace(' ', '-').upper()}"
            _add_node(nodes, defensive_artifact_id, "defensive_artifact", defensive_artifact)
            _add_edge(edges, defensive_id, defensive_artifact_id, defensive_artifact_rel)
            if offensive_artifact:
                offensive_artifact_id = f"OA-{offensive_artifact.replace(' ', '-').upper()}"
                _add_node(nodes, offensive_artifact_id, "offensive_artifact", offensive_artifact)
                _add_edge(edges, defensive_artifact_id, offensive_artifact_id, "targets")
                if offensive_technique:
                    _add_edge(edges, offensive_artifact_id, offensive_technique, offensive_artifact_rel)


def consolidate(base_dir: Path = BASE_DIR) -> tuple[dict[str, dict[str, str]], list[tuple[str, str, str]]]:
    """Build graph records from raw source files without writing them."""
    base_dir = Path(base_dir).resolve()
    nodes: dict[str, dict[str, str]] = {}
    edges: list[tuple[str, str, str]] = []
    _parse_attack(nodes, edges, base_dir)
    _parse_d3fend(nodes, edges, base_dir)

    # Filter each record before normalizing exact logical triples.  A distinct
    # relationship type remains a separate edge even for the same endpoints.
    before = len(edges)
    edges = [edge for edge in edges if edge[0] in nodes and edge[1] in nodes]
    dropped = before - len(edges)
    if dropped:
        print(f"Integrity pass: dropped {dropped} edge rows referencing unknown node IDs ({len(edges)} remain).")
    edges, repeated = _logical_edges(edges)
    if repeated:
        print(f"Logical-edge normalization: collapsed {repeated} repeated denormalized source occurrences ({len(edges)} logical edges remain).")
    return nodes, edges


def write_outputs(
    base_dir: Path,
    nodes: dict[str, dict[str, str]],
    edges: list[tuple[str, str, str]],
) -> None:
    """Stage deterministic outputs, then atomically replace each target file."""
    ordered_nodes = [nodes[node_id] for node_id in sorted(nodes)]
    ordered_edges = sorted(edges)
    edge_rows = [
        {"source_id": source, "target_id": target, "relationship_type": relationship}
        for source, target, relationship in ordered_edges
    ]
    ontology = {"nodes": ordered_nodes, "edges": edge_rows}
    staged = [
        (base_dir / "mitre_nodes.csv", _stage_csv(base_dir / "mitre_nodes.csv", NODE_FIELDS, ordered_nodes)),
        (base_dir / "mitre_edges.csv", _stage_csv(base_dir / "mitre_edges.csv", EDGE_FIELDS, edge_rows)),
        (base_dir / "ontology.json", _stage_json(base_dir / "ontology.json", ontology)),
    ]
    _replace_staged(staged)


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate deterministic ATT&CK/D3FEND graph inputs.")
    parser.add_argument("--base-dir", type=Path, default=BASE_DIR, help="Repository directory containing raw inputs.")
    args = parser.parse_args()
    base_dir = args.base_dir.resolve()
    nodes, edges = consolidate(base_dir)
    print("Exporting to mitre_nodes.csv, mitre_edges.csv, and ontology.json...")
    write_outputs(base_dir, nodes, edges)
    print(f"Done! Exported {len(nodes)} nodes and {len(edges)} logical edge rows.")


if __name__ == "__main__":
    main()
