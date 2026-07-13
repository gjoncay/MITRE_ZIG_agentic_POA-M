"""Unit tests for the opaque-handle boundary used by LLM graph planning."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from llm_graph_tools import GraphToolError, GraphToolSession, ToolPolicy  # noqa: E402
import llm_providers  # noqa: E402
from llm_providers import DEFAULT_TIMEOUT_SECONDS, GeminiProvider, LLMProvider, ProviderOperationCanceled, ProviderStatus, _ChatCompletionMixin  # noqa: E402


class _TinyEngine:
    graph_snapshot_id = "sha256:test-snapshot"

    _nodes = {
        "T0001": {"type": "attack_technique", "name": "Example Technique", "description": "Example"},
        "ZIG-ACT-1": {"type": "zig_activity", "name": "Example Activity"},
    }

    def search_attack_techniques(self, _query: str, top_k: int = 20):
        return [{"id": "T0001", "name": "Example Technique", "type": "attack_technique", "score": 1.0, "method": "lexical"}][:top_k]

    def query_node(self, node_id: str):
        return self._nodes.get(node_id)

    def get_neighbors(self, _node_id: str, direction: str = "both", relationship_types=None):
        return []

    def get_framework_bundle(self, technique_id: str, include_inherited_parent: bool = True):
        assert technique_id == "T0001"
        return {
            "graph_snapshot_id": self.graph_snapshot_id,
            "mapping_matrix_version": "test",
            "mapping_validation": {"state": "valid"},
            "inheritance": [],
            "not_mapped_categories": ["zig"],
            "paths": [],
        }


class _ScriptedProvider(_ChatCompletionMixin, LLMProvider):
    def __init__(self, actions: list[str]):
        LLMProvider.__init__(self, ProviderStatus(
            requested_provider="local",
            effective_provider="local",
            model="test-model",
            data_egress="local_network",
        ))
        self._actions = iter(actions)

    def _complete(self, _prompt: str) -> str:
        return next(self._actions)


def test_local_openai_compatible_provider_accepts_compose_empty_api_key(monkeypatch) -> None:
    """A blank Compose substitution must not override the local no-auth default."""
    captured: dict[str, object] = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(llm_providers, "OPENAI_ENABLED", True)
    monkeypatch.setattr(llm_providers, "OpenAI", _FakeOpenAI)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://local-llm.test/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "")

    provider = llm_providers.LocalOpenAICompatProvider()

    assert provider.api_key == "not-needed"
    assert captured["api_key"] == "not-needed"


def test_graph_tools_accept_only_prior_opaque_handles_and_record_calls() -> None:
    session = GraphToolSession(_TinyEngine(), policy=ToolPolicy(max_calls=4, max_results=20, max_paths=20))

    with_technique = session.search_attack_techniques(query="example", top_k=99)
    handle = with_technique["candidates"][0]["handle"]
    validated = session.validate_selection(candidate_handles=[handle], evidence_span_ids=["span-1"])

    assert handle == "node_0001"
    assert validated["ok"] is True
    assert validated["accepted"] == [{"handle": handle, "id": "T0001", "name": "Example Technique"}]
    assert [call["action"] for call in session.audit_summary()["calls"]] == [
        "search_attack_techniques", "validate_selection",
    ]


def test_graph_tools_reject_minted_ids_and_unknown_actions() -> None:
    session = GraphToolSession(_TinyEngine())
    result = session.validate_selection(candidate_handles=["T0001"])
    assert result["ok"] is False
    assert result["rejected"] == [{"handle": "T0001", "reason": "Unknown node handle. Use a handle returned by an earlier tool call."}]

    try:
        session.execute("read_filesystem", {})
    except GraphToolError as exc:
        assert "Unsupported graph tool" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("An undeclared graph tool must be rejected.")


def test_provider_crawl_can_validate_only_a_handle_returned_by_the_orchestrator() -> None:
    provider = _ScriptedProvider([
        '{"action":"search_attack_techniques","arguments":{"query":"example"}}',
        '{"action":"validate_selection","arguments":{"candidate_handles":["node_0001"]}}',
    ])
    session = GraphToolSession(_TinyEngine(), policy=ToolPolicy(max_calls=4))

    result = provider.crawl_graph(session, {"technique_id": "T0001"})

    assert result["status"] == "validated"
    assert result["selected"][0]["id"] == "T0001"
    assert provider.status["degraded"] is False


def test_provider_crawl_marks_malformed_tool_output_degraded() -> None:
    provider = _ScriptedProvider(["T0001"])  # raw ID is not a JSON tool envelope
    session = GraphToolSession(_TinyEngine())

    result = provider.crawl_graph(session, {"technique_id": "T0001"})

    assert result["status"] == "failed"
    assert provider.status["degraded"] is True


def test_provider_crawl_emits_request_heartbeat_and_checks_cancel_between_requests() -> None:
    provider = _ScriptedProvider([
        '{"action":"search_attack_techniques","arguments":{"query":"example"}}',
        '{"action":"validate_selection","arguments":{"candidate_handles":["node_0001"]}}',
    ])
    session = GraphToolSession(_TinyEngine(), policy=ToolPolicy(max_calls=4))
    events: list[dict] = []

    def progress(event: dict) -> None:
        events.append(event)

    def canceled() -> bool:
        # The first provider response is visible to the progress stream before
        # a second network request can begin.
        return any(event.get("type") == "provider_request_finished" for event in events)

    try:
        provider.crawl_graph(session, {"technique_id": "T0001"}, cancel_cb=canceled, progress_cb=progress)
    except ProviderOperationCanceled:
        pass
    else:  # pragma: no cover
        raise AssertionError("The graph crawl must observe cancellation between provider requests.")

    assert [event["type"] for event in events] == ["provider_request_started", "provider_request_finished"]
    assert session.audit_summary()["calls"] == []


def test_gemini_completion_uses_the_configured_per_request_timeout() -> None:
    calls: list[dict] = []

    class _FakeGeminiModel:
        def generate_content(self, prompt: str, *, request_options: dict):
            calls.append({"prompt": prompt, "request_options": request_options})
            return type("Response", (), {"text": "ok"})()

    provider = object.__new__(GeminiProvider)
    provider.model = _FakeGeminiModel()

    assert provider._complete("bounded request") == "ok"
    assert calls == [{"prompt": "bounded request", "request_options": {"timeout": DEFAULT_TIMEOUT_SECONDS}}]
