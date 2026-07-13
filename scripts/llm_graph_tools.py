"""Bounded, read-only graph tools for LLM-assisted analyst workflows.

The model never receives NetworkX, a filesystem path, a database handle, or a
free-form graph identifier.  It can only operate on opaque handles returned by
an earlier tool call.  The orchestrator owns execution, rate limits, and the
audit trail; a provider merely proposes the next JSON action.

This module deliberately does *not* decide mappings.  ``GraphToolSession`` is
an optional inspection/ranking layer over the deterministic mapping service in
``graph_engine.py``.  Final report mappings continue to be produced by
``KnowledgeGraphEngine.get_framework_bundle`` and validated by the server.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


class GraphToolError(ValueError):
    """Raised when a tool request violates the constrained tool contract."""


@dataclass(frozen=True)
class ToolPolicy:
    """Explicit budgets applied independently to every LLM graph session."""

    max_calls: int = 12
    max_results: int = 50
    max_paths: int = 50


@dataclass
class ToolCall:
    sequence: int
    action: str
    arguments: dict[str, Any]
    result_summary: dict[str, Any]


TOOL_DESCRIPTIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "search_attack_techniques",
        "description": "Search only MITRE ATT&CK techniques. Returns opaque candidate handles, names, and scores.",
        "arguments": {"query": "string", "top_k": "integer 1..20"},
    },
    {
        "name": "get_node",
        "description": "Read a graph node previously returned as a handle.",
        "arguments": {"handle": "opaque node handle"},
    },
    {
        "name": "get_neighbors",
        "description": "Read typed, one-edge-per-record neighbors of a returned node handle.",
        "arguments": {
            "handle": "opaque node handle",
            "direction": "in | out | both",
            "relationship_types": "optional string list",
            "limit": "integer 1..50",
        },
    },
    {
        "name": "get_framework_bundle",
        "description": "Enumerate allowed, validated framework mapping paths for a returned ATT&CK technique handle.",
        "arguments": {"handle": "opaque ATT&CK technique handle", "include_inherited_parent": "boolean"},
    },
    {
        "name": "get_provenance_paths",
        "description": "Read complete validated paths previously returned by get_framework_bundle.",
        "arguments": {"path_handles": "opaque path handle list", "limit": "integer 1..50"},
    },
    {
        "name": "validate_selection",
        "description": "Validate selected ATT&CK candidate handles. Free-form IDs are not accepted.",
        "arguments": {"candidate_handles": "opaque ATT&CK handle list", "evidence_span_ids": "optional opaque evidence span list"},
    },
)


def _bounded_int(value: Any, *, default: int, maximum: int) -> int:
    try:
        candidate = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(candidate, maximum))


def _as_string_list(value: Any, *, maximum: int) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value[:maximum] if isinstance(item, (str, int))]


class GraphToolSession:
    """A stateful capability boundary around one graph-crawl interaction.

    Handles are process-local and intentionally monotonically assigned.  They
    cannot be converted to graph IDs by a provider and disappear after a run.
    Every result includes enough provenance for a reviewer without exposing a
    generic graph traversal interface.
    """

    def __init__(self, engine: Any, *, policy: ToolPolicy | None = None):
        self.engine = engine
        self.policy = policy or ToolPolicy()
        self._node_by_handle: dict[str, str] = {}
        self._handle_by_node: dict[str, str] = {}
        self._path_by_handle: dict[str, Mapping[str, Any]] = {}
        self.calls: list[ToolCall] = []

    @property
    def remaining_calls(self) -> int:
        return max(0, self.policy.max_calls - len(self.calls))

    def tool_descriptions(self) -> list[dict[str, Any]]:
        return [dict(item) for item in TOOL_DESCRIPTIONS]

    def _node_handle(self, node_id: str) -> str:
        existing = self._handle_by_node.get(node_id)
        if existing:
            return existing
        handle = f"node_{len(self._node_by_handle) + 1:04d}"
        self._node_by_handle[handle] = node_id
        self._handle_by_node[node_id] = handle
        return handle

    def _path_handle(self, path: Mapping[str, Any]) -> str:
        handle = f"path_{len(self._path_by_handle) + 1:04d}"
        self._path_by_handle[handle] = path
        return handle

    def _require_node(self, handle: Any) -> tuple[str, Mapping[str, Any]]:
        node_id = self._node_by_handle.get(str(handle))
        if not node_id:
            raise GraphToolError("Unknown node handle. Use a handle returned by an earlier tool call.")
        data = self.engine.query_node(node_id)
        if not data:
            raise GraphToolError("The referenced node is no longer available in this graph snapshot.")
        return node_id, data

    def _record(self, action: str, arguments: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        if len(self.calls) >= self.policy.max_calls:
            raise GraphToolError(f"Graph tool-call budget ({self.policy.max_calls}) is exhausted.")
        response = dict(result)
        summary = {
            "ok": bool(response.get("ok", True)),
            "result_count": int(response.get("result_count", 0) or 0),
            "graph_snapshot_id": response.get("graph_snapshot_id"),
        }
        self.calls.append(ToolCall(len(self.calls) + 1, action, dict(arguments), summary))
        response["remaining_calls"] = self.remaining_calls
        return response

    def search_attack_techniques(self, *, query: Any, top_k: Any = 10) -> dict[str, Any]:
        query_text = str(query or "").strip()
        if not query_text:
            raise GraphToolError("search_attack_techniques requires a non-empty query.")
        limit = _bounded_int(top_k, default=10, maximum=min(20, self.policy.max_results))
        matches = self.engine.search_attack_techniques(query_text, top_k=limit)
        candidates: list[dict[str, Any]] = []
        for item in matches[:limit]:
            node_id = str(item.get("id", ""))
            if not node_id:
                continue
            candidates.append(
                {
                    "handle": self._node_handle(node_id),
                    "name": item.get("name", node_id),
                    "score": item.get("score"),
                    "method": item.get("method"),
                    "type": item.get("type", "attack_technique"),
                }
            )
        return self._record(
            "search_attack_techniques",
            {"query": query_text, "top_k": limit},
            {
                "ok": True,
                "query": query_text,
                "candidates": candidates,
                "result_count": len(candidates),
                "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
            },
        )

    def get_node(self, *, handle: Any) -> dict[str, Any]:
        node_id, data = self._require_node(handle)
        # Node data originates in the versioned graph.  The model can see the
        # stable ID only after obtaining a valid opaque handle.
        result = {
            "ok": True,
            "handle": str(handle),
            "node": {
                "id": node_id,
                "type": data.get("type"),
                "name": data.get("name"),
                "description": data.get("description", ""),
                "source_dataset": data.get("source_dataset"),
                "source_file": data.get("source_file"),
            },
            "result_count": 1,
            "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
        }
        return self._record("get_node", {"handle": str(handle)}, result)

    def get_neighbors(
        self,
        *,
        handle: Any,
        direction: Any = "both",
        relationship_types: Any = None,
        limit: Any = 25,
    ) -> dict[str, Any]:
        node_id, _ = self._require_node(handle)
        chosen_direction = str(direction or "both").lower()
        if chosen_direction not in {"in", "out", "both"}:
            raise GraphToolError("direction must be 'in', 'out', or 'both'.")
        requested_types = _as_string_list(relationship_types, maximum=25)
        bounded_limit = _bounded_int(limit, default=25, maximum=self.policy.max_results)
        neighbors = self.engine.get_neighbors(
            node_id,
            direction=chosen_direction,
            relationship_types=requested_types or None,
        )
        records: list[dict[str, Any]] = []
        for edge in neighbors[:bounded_limit]:
            adjacent = str(edge.get("id") or edge.get("target_id") or edge.get("source_id") or "")
            if not adjacent:
                continue
            node = edge.get("node") if isinstance(edge.get("node"), Mapping) else self.engine.query_node(adjacent) or {}
            records.append(
                {
                    "edge_id": edge.get("edge_id"),
                    "relationship_type": edge.get("relationship_type", edge.get("relationship")),
                    "direction": edge.get("direction"),
                    "node_handle": self._node_handle(adjacent),
                    "node_name": node.get("name"),
                    "node_type": node.get("type"),
                    "source_dataset": edge.get("source_dataset"),
                    "source_file": edge.get("source_file"),
                    "source_record": edge.get("source_record"),
                }
            )
        return self._record(
            "get_neighbors",
            {"handle": str(handle), "direction": chosen_direction, "relationship_types": requested_types, "limit": bounded_limit},
            {
                "ok": True,
                "neighbors": records,
                "result_count": len(records),
                "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
            },
        )

    def get_framework_bundle(self, *, handle: Any, include_inherited_parent: Any = True) -> dict[str, Any]:
        node_id, data = self._require_node(handle)
        if data.get("type") != "attack_technique":
            raise GraphToolError("get_framework_bundle only accepts an ATT&CK technique handle.")
        inherited = bool(include_inherited_parent)
        bundle = self.engine.get_framework_bundle(node_id, include_inherited_parent=inherited)
        paths = bundle.get("paths") if isinstance(bundle, Mapping) else []
        if not isinstance(paths, list):
            paths = []
        path_handles: list[dict[str, Any]] = []
        categories: dict[str, int] = {}
        for path in paths:
            if isinstance(path, Mapping):
                category = str(path.get("category", "unspecified"))
                categories[category] = categories.get(category, 0) + 1
        for path in paths[: self.policy.max_paths]:
            if not isinstance(path, Mapping):
                continue
            category = str(path.get("category", "unspecified"))
            validation = path.get("validation") if isinstance(path.get("validation"), Mapping) else {}
            path_handles.append(
                {
                    "handle": self._path_handle(path),
                    "category": category,
                    "mapping_scope": path.get("mapping_scope", "direct"),
                    "validation_state": path.get("validation_state") or validation.get("state"),
                }
            )
        return self._record(
            "get_framework_bundle",
            {"handle": str(handle), "include_inherited_parent": inherited},
            {
                "ok": True,
                "technique_handle": str(handle),
                "mapping_matrix_version": bundle.get("mapping_matrix_version"),
                "mapping_validation": bundle.get("mapping_validation"),
                "inheritance": bundle.get("inheritance"),
                "not_mapped_categories": bundle.get("not_mapped_categories", []),
                "path_categories": categories,
                "path_handles": path_handles,
                "path_count": len(paths),
                "path_handles_truncated": len(paths) > len(path_handles),
                "result_count": len(path_handles),
                "graph_snapshot_id": bundle.get("graph_snapshot_id") or getattr(self.engine, "graph_snapshot_id", None),
            },
        )

    def get_provenance_paths(self, *, path_handles: Any, limit: Any = 20) -> dict[str, Any]:
        requested = _as_string_list(path_handles, maximum=self.policy.max_paths)
        if not requested:
            raise GraphToolError("get_provenance_paths requires one or more path handles.")
        bounded_limit = _bounded_int(limit, default=20, maximum=self.policy.max_paths)
        paths: list[Mapping[str, Any]] = []
        for handle in requested[:bounded_limit]:
            path = self._path_by_handle.get(handle)
            if path is None:
                raise GraphToolError("Unknown path handle. Use a handle returned by get_framework_bundle.")
            paths.append(path)
        return self._record(
            "get_provenance_paths",
            {"path_handles": requested, "limit": bounded_limit},
            {
                "ok": True,
                "paths": paths,
                "result_count": len(paths),
                "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
            },
        )

    def validate_selection(self, *, candidate_handles: Any, evidence_span_ids: Any = None) -> dict[str, Any]:
        selected = _as_string_list(candidate_handles, maximum=20)
        if not selected:
            raise GraphToolError("validate_selection requires one or more candidate handles.")
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for handle in selected:
            try:
                node_id, data = self._require_node(handle)
            except GraphToolError as exc:
                rejected.append({"handle": handle, "reason": str(exc)})
                continue
            if data.get("type") != "attack_technique":
                rejected.append({"handle": handle, "reason": "Handle is not an ATT&CK technique."})
                continue
            accepted.append({"handle": handle, "id": node_id, "name": data.get("name", node_id)})
        evidence = _as_string_list(evidence_span_ids, maximum=100)
        return self._record(
            "validate_selection",
            {"candidate_handles": selected, "evidence_span_ids": evidence},
            {
                "ok": not rejected and bool(accepted),
                "accepted": accepted,
                "rejected": rejected,
                "evidence_span_ids": evidence,
                "result_count": len(accepted),
                "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
            },
        )

    def execute(self, action: Any, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Execute one strictly named tool action and return JSON-safe output."""
        name = str(action or "").strip()
        args = dict(arguments or {})
        methods = {
            "search_attack_techniques": self.search_attack_techniques,
            "get_node": self.get_node,
            "get_neighbors": self.get_neighbors,
            "get_framework_bundle": self.get_framework_bundle,
            "get_provenance_paths": self.get_provenance_paths,
            "validate_selection": self.validate_selection,
        }
        method = methods.get(name)
        if method is None:
            raise GraphToolError(f"Unsupported graph tool '{name}'.")
        return method(**args)

    def audit_summary(self) -> dict[str, Any]:
        """Return a compact, persistence-ready audit record for this session."""
        return {
            "tool_policy": {
                "max_calls": self.policy.max_calls,
                "max_results": self.policy.max_results,
                "max_paths": self.policy.max_paths,
            },
            "calls": [
                {
                    "sequence": call.sequence,
                    "action": call.action,
                    "arguments": call.arguments,
                    "result_summary": call.result_summary,
                }
                for call in self.calls
            ],
            "graph_snapshot_id": getattr(self.engine, "graph_snapshot_id", None),
        }


def parse_tool_action(raw: str) -> tuple[str, dict[str, Any]] | None:
    """Parse the small JSON action envelope used by non-native tool providers."""
    try:
        parsed = json.loads((raw or "").strip())
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, Mapping):
        return None
    action = parsed.get("action")
    arguments = parsed.get("arguments", parsed.get("args", {}))
    if not isinstance(action, str) or not isinstance(arguments, Mapping):
        return None
    return action, dict(arguments)
