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
