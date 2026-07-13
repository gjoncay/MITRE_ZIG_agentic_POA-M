"""Focused local-provider API and model-discovery regression tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from webapp.backend import main as backend_main
from webapp.backend import pipeline_adapter
from webapp.backend.main import BackendSettings, create_app
from webapp.backend.pipeline_adapter import LocalModelDiscoveryError, discover_local_models


def _settings(tmp_path: Path) -> BackendSettings:
    return BackendSettings(
        base_dir=tmp_path,
        data_dir=tmp_path / "data",
        runs_dir=tmp_path / "data" / "runs",
        database_path=tmp_path / "data" / "test.sqlite3",
        frontend_dist=tmp_path / "missing-dist",
        legacy_reports_dir=tmp_path / "legacy-reports",
        max_workers=1,
    )


async def _wait_for_terminal(client: httpx.AsyncClient, run_id: str) -> dict:
    for _ in range(100):
        response = await client.get(f"/api/runs/{run_id}")
        assert response.status_code == 200
        snapshot = response.json()
        if snapshot["status"] not in {"queued", "running", "analysis_finished"}:
            return snapshot
        await asyncio.sleep(0.02)
    raise AssertionError("run did not settle")


def test_local_model_discovery_uses_ollama_fallback_and_keeps_configured_default(monkeypatch) -> None:
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "configured-local:7b")
    calls: list[str] = []

    def fake_fetch(url: str):
        calls.append(url)
        if url.endswith("/v1/models"):
            raise LocalModelDiscoveryError("OpenAI-compatible endpoint is unavailable.")
        return {"models": [{"name": "ollama-discovered:8b"}]}

    monkeypatch.setattr(pipeline_adapter, "_fetch_local_json", fake_fetch)

    discovered = discover_local_models()

    assert discovered == {
        "provider": "local",
        "configured": True,
        "models": ["ollama-discovered:8b", "configured-local:7b"],
        "default_model": "configured-local:7b",
        "source": "ollama",
        "error": None,
    }
    assert calls == [
        "http://127.0.0.1:11434/v1/models",
        "http://127.0.0.1:11434/api/tags",
    ]


def test_local_model_discovery_returns_configured_default_when_endpoint_is_down(monkeypatch) -> None:
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "offline-default:8b")
    monkeypatch.setattr(
        pipeline_adapter,
        "_fetch_local_json",
        lambda _url: (_ for _ in ()).throw(LocalModelDiscoveryError("endpoint unavailable")),
    )

    discovered = discover_local_models()

    assert discovered["configured"] is True
    assert discovered["models"] == ["offline-default:8b"]
    assert discovered["default_model"] == "offline-default:8b"
    assert discovered["source"] is None
    assert "endpoint unavailable" in str(discovered["error"])
    # The response is deliberately operationally useful without disclosing
    # the configured endpoint URL.
    assert "127.0.0.1" not in json.dumps(discovered)


def test_authenticated_discovery_uses_server_owned_bearer_token_without_returning_it(monkeypatch) -> None:
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-discovery-secret")
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return b'{"data": [{"id": "private-local:8b"}]}'

    class Opener:
        def open(self, request, timeout: float):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            return Response()

    monkeypatch.setattr(pipeline_adapter, "build_opener", lambda *_handlers: Opener())

    payload = pipeline_adapter._fetch_local_json("http://127.0.0.1:11434/v1/models")

    assert payload == {"data": [{"id": "private-local:8b"}]}
    assert captured["authorization"] == "Bearer local-discovery-secret"
    assert "local-discovery-secret" not in json.dumps(payload)


def test_local_models_endpoint_rejects_cloud_providers_and_forwards_selected_model(tmp_path: Path, monkeypatch) -> None:
    received: list[tuple[str | None, str | None]] = []

    def runner(
        _engine,
        _input_csv,
        output_dir,
        provider_name=None,
        model_name=None,
        progress_cb=None,
        cancel_cb=None,
    ):
        received.append((provider_name, model_name))
        if progress_cb is not None:
            progress_cb({"type": "mapping_progress", "phase": "mapping", "counters": {"techniques_total": 1}})
        output = Path(output_dir)
        payload = {
            "report_id": "CONSOL-T1003",
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "finding_count": 1,
            "severity_breakdown": {"High": 1},
            "qa_verdict": "PASS",
            "observations": [
                {
                    "source_locator": {"sheet": "text_chunk", "row": "1"},
                    "resolution_method": "explicit_attack_id",
                    "resolution_score": 1.0,
                }
            ],
            "framework_mappings": {"graph_snapshot_id": "sha256:test", "paths": []},
        }
        (output / "CONSOL-T1003.md").write_text("# Local model test\n", encoding="utf-8")
        (output / "CONSOL-T1003.json").write_text(json.dumps(payload), encoding="utf-8")
        return [payload]

    safe_discovery_payload = {
        "provider": "local",
        "configured": True,
        "models": ["selected-local:8b", "fallback-local:7b"],
        "default_model": "fallback-local:7b",
        "source": "openai_compatible",
        "error": None,
    }
    monkeypatch.setattr(backend_main, "discover_local_models", lambda: safe_discovery_payload)

    async def scenario() -> None:
        app = create_app(_settings(tmp_path), engine_factory=lambda: object(), pipeline_runner=runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                models_response = await client.get("/api/local-models")
                assert models_response.status_code == 200
                assert models_response.json() == safe_discovery_payload

                for provider in ("openai", "gemini", "none"):
                    rejected = await client.post(
                        "/api/runs",
                        data={"text": "T1003 should remain local.", "provider": provider},
                    )
                    assert rejected.status_code == 400
                    assert rejected.json()["error"]["code"] == "provider_not_allowed"

                invalid_model = await client.post(
                    "/api/runs",
                    data={"text": "T1003 invalid model.", "provider": "local", "model": "not a valid model"},
                )
                assert invalid_model.status_code == 422
                assert invalid_model.json()["error"]["code"] == "invalid_local_model"

                created = await client.post(
                    "/api/runs",
                    data={"text": "T1003 selected local model.", "provider": "local", "model": "selected-local:8b"},
                )
                assert created.status_code == 202
                queued = created.json()
                assert queued["requested_provider"] == "local"
                assert queued["requested_model"] == "selected-local:8b"
                completed = await _wait_for_terminal(client, queued["id"])
                assert completed["effective_provider"] == "local"
                assert completed["effective_model"] == "selected-local:8b"
                assert received == [("local", "selected-local:8b")]

                retry = await client.post(
                    f"/api/runs/{queued['id']}/retry",
                    json={"model": "retry-local:latest"},
                )
                assert retry.status_code == 202
                retry_snapshot = retry.json()
                assert retry_snapshot["requested_provider"] == "local"
                assert retry_snapshot["requested_model"] == "retry-local:latest"
                retry_artifact = app.state.repository.list_artifacts(retry_snapshot["id"])[0]
                assert retry_artifact["metadata"]["requested_model"] == "retry-local:latest"
                await _wait_for_terminal(client, retry_snapshot["id"])
                assert received == [
                    ("local", "selected-local:8b"),
                    ("local", "retry-local:latest"),
                ]

    asyncio.run(scenario())
