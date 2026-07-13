"""Focused invariants for the relation-preserving graph/mapping layer."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from consolidate_findings import crawl_correlation  # noqa: E402
from graph_engine import GraphRepository, KnowledgeGraphEngine  # noqa: E402


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def _small_graph(tmp_path: Path) -> KnowledgeGraphEngine:
    # Parent has a direct ZIG mapping; its child intentionally has none.  The
    # duplicate direct relation also proves MultiDiGraph preservation.
    _write_csv(tmp_path / "mitre_nodes.csv", ["id", "type", "name", "description", "url"], [
        ["T0001", "attack_technique", "Parent Technique", "", ""],
        ["T0001.001", "attack_technique", "Child Technique", "", ""],
        ["TA0001", "attack_tactic", "Initial Access", "", ""],
        ["M0001", "attack_mitigation", "Native Mitigation", "", ""],
    ])
    _write_csv(tmp_path / "mitre_edges.csv", ["source_id", "target_id", "relationship_type"], [
        ["T0001.001", "T0001", "subtechnique_of"],
        ["T0001", "TA0001", "belongs_to_tactic"],
        ["M0001", "T0001", "mitigates"],
    ])
    _write_csv(tmp_path / "zig_nodes.csv", ["id", "type", "name", "description", "url"], [
        ["ZIG-ACT-1", "zig_activity", "Activity", "", ""],
        ["ZIG-CAP-1", "zig_capability", "Capability", "", ""],
        ["ZIG-PIL-1", "zig_pillar", "Pillar", "", ""],
        ["ZIG-TECH-1", "zig_technology", "Technology", "", ""],
    ])
    _write_csv(tmp_path / "zig_edges.csv", ["source_id", "target_id", "relationship_type"], [
        ["ZIG-ACT-1", "ZIG-CAP-1", "belongs_to_capability"],
        ["ZIG-CAP-1", "ZIG-PIL-1", "belongs_to_pillar"],
        ["ZIG-TECH-1", "ZIG-CAP-1", "implements_capability"],
    ])
    _write_csv(tmp_path / "cref_nodes.csv", ["id", "type", "name", "description", "url"], [])
    _write_csv(tmp_path / "cref_edges.csv", ["source_id", "target_id", "relationship_type"], [
        ["ZIG-ACT-1", "T0001", "mitigates"],
        # Same logical endpoints/type as the native relation in a second source
        # file: it must remain a distinct edge record.
        ["M0001", "T0001", "mitigates"],
        ["M0001", "ZIG-ACT-1", "implements_activity"],
    ])
    repository = GraphRepository(tmp_path)
    repository.load()
    repository.write_snapshot_manifest()
    return KnowledgeGraphEngine(tmp_path, load_embeddings=False)


def test_loaded_graph_preserves_every_raw_edge_row_and_edge_provenance(tmp_path: Path) -> None:
    engine = _small_graph(tmp_path)
    assert engine.graph.number_of_edges() == 9
    mitigation_edges = engine.repository.incoming("T0001", "mitigates", "attack_mitigation")
    assert len(mitigation_edges) == 2
    assert {edge["source_file"] for edge in mitigation_edges} == {"mitre_edges.csv", "cref_edges.csv"}
    assert len({edge["edge_id"] for edge in mitigation_edges}) == 2
    assert engine.snapshot_manifest["edge_row_count"] == engine.snapshot_manifest["runtime_edge_count"]


def test_inherited_parent_paths_are_explicit_and_validated(tmp_path: Path) -> None:
    engine = _small_graph(tmp_path)
    bundle = engine.get_framework_bundle("T0001.001")
    assert bundle["mapping_validation"]["state"] == "valid"
    assert bundle["inheritance"]
    inherited = [path for path in bundle["paths"] if path["mapping_scope"] == "inherited_parent"]
    assert inherited
    assert all(path["nodes"][0]["id"] == "T0001.001" for path in inherited)
    assert all(path["edges"][0]["relationship_type"] == "subtechnique_of" for path in inherited)
    assert any(path["category"] == "zig_pillar" for path in inherited)
    assert any(item["mitigation_id"] == "M0001" for item in bundle["attack_mitigations"])


def test_zig_technology_paths_are_provenanced_for_direct_and_mitigation_routes(tmp_path: Path) -> None:
    engine = _small_graph(tmp_path)
    bundle = engine.get_framework_bundle("T0001")

    assert bundle["mapping_matrix_version"] == engine.snapshot_manifest["mapping_matrix_version"]
    technology_paths = [
        path for path in bundle["paths"]
        if path["category"] in {"zig_technology", "mitigation_zig_technology"}
    ]
    assert {path["category"] for path in technology_paths} == {
        "zig_technology", "mitigation_zig_technology"
    }
    assert all(path["validation"]["state"] == "valid" for path in technology_paths)
    assert all(path["nodes"][-1]["id"] == "ZIG-TECH-1" for path in technology_paths)
    assert all(path["edges"][-1]["relationship_type"] == "implements_capability" for path in technology_paths)
    assert all(path["edges"][-1]["traversal_direction"] == "in" for path in technology_paths)

    mitigation = next(item for item in bundle["mitigations"] if item["mitigation_id"] == "M0001")
    assert mitigation["zig_technology_ids"] == ["ZIG-TECH-1"]
    correlation = crawl_correlation(engine, "T0001")
    assert correlation["zig_technologies"] == ["[ZIG-TECH-1] Technology"]


def test_real_graph_bundle_keeps_native_and_cref_mitigation_paths() -> None:
    engine = KnowledgeGraphEngine(ROOT, load_embeddings=False)
    bundle = engine.get_framework_bundle("T1190")
    assert engine.graph.number_of_edges() == engine.snapshot_manifest["edge_row_count"]
    assert bundle["mapping_validation"]["state"] == "valid"
    assert bundle["attack_mitigations"]
    assert bundle["cref_mitigations"]
    assert all(path["validation"]["state"] == "valid" for path in bundle["paths"])
    # Tool retrieval cannot return non-ATT&CK entities even when lexical search
    # finds many unrelated graph nodes.
    results = engine.search_attack_techniques("exploit public facing application", top_k=20)
    assert results and all(result["type"] == "attack_technique" for result in results)
