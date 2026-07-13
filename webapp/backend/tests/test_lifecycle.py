"""API-level lifecycle regression tests using an in-process ASGI client.

They deliberately use a fake pipeline so no graph model, local LLM, network,
or global report directory is required.  The same assertions work with
FastAPI's TestClient in environments that pin the legacy TestClient/httpx
combination; ASGITransport avoids that dependency-version coupling here.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import replace
from pathlib import Path

import httpx

from webapp.backend.main import BackendSettings, create_app
from webapp.backend.auth import parse_token_map
from webapp.backend.workspace import RunWorkspace


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


def _runner(_engine, _input_csv, output_dir, provider_name=None, progress_cb=None, cancel_cb=None):
    progress_cb({"type": "mapping_progress", "phase": "mapping", "counters": {"techniques_total": 1, "techniques_completed": 1}})
    output = Path(output_dir)
    payload = {
        "report_id": "CONSOL-T1003",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "finding_count": 1,
        "severity_breakdown": {"High": 1},
        "qa_verdict": "FLAG",
        "observations": [
            {
                "source_locator": {"sheet": "text_chunk", "row": "1"},
                "resolution_method": "explicit_attack_id",
                "resolution_score": 1.0,
            }
        ],
        "framework_mappings": {"graph_snapshot_id": "sha256:test", "paths": []},
        "mapping_snapshot_hash": "sha256:mapping-payload",
    }
    (output / "CONSOL-T1003.md").write_text("# Test report\n", encoding="utf-8")
    (output / "CONSOL-T1003.json").write_text(json.dumps(payload), encoding="utf-8")
    return [payload]


def _multi_pending_runner(_engine, _input_csv, output_dir, provider_name=None, progress_cb=None, cancel_cb=None):
    """Produce two independently reviewable reports for bulk-review tests."""
    output = Path(output_dir)
    payloads = []
    for technique_id, technique_name in (
        ("T1003", "OS Credential Dumping"),
        ("T1059", "Command and Scripting Interpreter"),
    ):
        display_id = f"CONSOL-{technique_id}"
        payload = {
            "report_id": display_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "finding_count": 1,
            "severity_breakdown": {"High": 1},
            "qa_verdict": "FLAG",
            "observations": [
                {
                    "source_locator": {"sheet": "text_chunk", "row": technique_id},
                    "resolution_method": "explicit_attack_id",
                    "resolution_score": 1.0,
                }
            ],
            "framework_mappings": {"graph_snapshot_id": "sha256:test", "paths": []},
        }
        (output / f"{display_id}.md").write_text(f"# {technique_name}\n", encoding="utf-8")
        (output / f"{display_id}.json").write_text(json.dumps(payload), encoding="utf-8")
        payloads.append(payload)
    return payloads


def _passing_runner(_engine, _input_csv, output_dir, provider_name=None, progress_cb=None, cancel_cb=None):
    output = Path(output_dir)
    payload = {
        "report_id": "CONSOL-T1190",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
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
    (output / "CONSOL-T1190.md").write_text("# Passing report\n", encoding="utf-8")
    (output / "CONSOL-T1190.json").write_text(json.dumps(payload), encoding="utf-8")
    return [payload]


class _RerenderEngine:
    """Small graph double exercising renderer-only current-graph output."""

    graph_snapshot_id = "sha256:rerender-test-graph"

    def query_node(self, node_id: str):
        if node_id == "T1003":
            return {
                "id": "T1003",
                "type": "attack_technique",
                "name": "OS Credential Dumping",
                "description": "Adversaries may dump credentials from operating systems.",
            }
        return None

    def get_framework_bundle(self, technique_id: str):
        assert technique_id == "T1003"
        return {
            "graph_snapshot_id": self.graph_snapshot_id,
            "mapping_matrix_version": "rerender-test-v1",
            "mapping_validation": {"state": "valid"},
            "not_mapped_categories": [],
            "attack_tactics": [{"tactic_id": "TA0006", "tactic_name": "Credential Access"}],
            "analytics": [
                {"analytic_id": "AN0001", "analytic_description": "First current analytic"},
                {"analytic_id": "AN0002", "analytic_description": "Second current analytic"},
                {"analytic_id": "AN0003", "analytic_description": "Third current analytic"},
            ],
            "d3fend": [
                {"d3fend_id": "D3-ONE", "d3fend_name": "First countermeasure"},
                {"d3fend_id": "D3-TWO", "d3fend_name": "Second countermeasure"},
                {"d3fend_id": "D3-THREE", "d3fend_name": "Third countermeasure"},
            ],
            "zig": [
                {
                    "pillar_id": "ZIG-PILLAR-1",
                    "pillar_name": "Identity",
                    "capability_id": "ZIG-CAP-1",
                    "capability_name": "Identity capability",
                    "activity_id": "ZIG-ACT-1",
                    "activity_name": "Identity activity",
                }
            ],
            "cref": [
                {
                    "goal_id": "CREF-GOAL-1",
                    "goal_name": "Anticipate",
                    "objective_id": "CREF-OBJ-1",
                    "objective_name": "Prevent or Avoid",
                    "technique_id": "CREF-TECH-1",
                    "technique_name": "Coordinated Protection",
                    "approach_id": "CREF-APP-1",
                    "approach_name": "Dynamic Threat Awareness",
                    "effect_id": "CREF-EFFECT-1",
                    "effect_name": "Detect",
                }
            ],
            "mitigations": [
                {
                    "mitigation_id": "M1027",
                    "mitigation_name": "Operating System Configuration",
                    "nist_800_53_controls": ["CM-6"],
                    "zig_activity_ids": ["ZIG-ACT-1"],
                }
            ],
            "csa": [{"csa_id": "CSA-1", "csa_name": "Control Access"}],
            "paths": [
                {
                    "validation": {"state": "valid"},
                    "nodes": [
                        {"id": "T1003", "type": "attack_technique", "name": "OS Credential Dumping"},
                        {"id": "ART-1", "type": "defensive_artifact", "name": "Credential material"},
                        {"id": "ZIG-TECH-1", "type": "zig_technology", "name": "Privileged access management"},
                        {"id": "ZIG-TECH-2", "type": "zig_technology", "name": "Endpoint detection"},
                    ],
                }
            ],
        }


async def _wait_for_terminal(
    client: httpx.AsyncClient,
    run_id: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict:
    for _ in range(100):
        payload = (await client.get(f"/api/runs/{run_id}", headers=headers)).json()
        if payload["status"] not in {"queued", "running", "analysis_finished"}:
            return payload
        await asyncio.sleep(0.02)
    raise AssertionError("run did not settle")


def test_run_isolated_review_gated_and_restorable(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/api/runs", data={"text": "T1003 credential dumping observed.", "provider": "local"})
                assert response.status_code == 202
                run_id = response.json()["id"]
                run = await _wait_for_terminal(client, run_id)
                assert run["status"] == "awaiting_review"
                assert run["counters"]["reports_review_pending"] == 1

                reports = (await client.get("/api/reports")).json()
                assert len(reports) == 1
                report = reports[0]
                assert report["lifecycle_state"] == "auto_flagged"
                assert report["requires_review"] is True
                assert report["report_id"] != "CONSOL-T1003"  # UUID identity, display key only
                assert (settings.runs_dir / run_id / "reports" / report["report_id"] / "report.md").is_file()

                detail = (await client.get(f"/api/reports/{report['report_id']}")).json()
                assert len(detail["candidates"]) == 1
                assert detail["candidates"][0]["technique_id"] == "T1003"
                assert detail["candidates"][0]["source_locator"] == {"kind": "text_chunk", "chunk": 1}
                assert detail["provenance"]["graph_snapshot_id"] == "sha256:test"
                assert detail["provenance"]["mapping_snapshot_hash"] == "sha256:mapping-payload"

                paged_reports = (await client.get("/api/reports", params={"page": 1, "page_size": 1})).json()
                assert paged_reports["page"] == 1
                assert paged_reports["page_size"] == 1
                assert paged_reports["total"] == 1
                assert len(paged_reports["items"]) == 1

                flagged_reports = (await client.get("/api/reports", params={"review_state": "flagged", "page": 1, "page_size": 20})).json()
                assert flagged_reports["total"] == 1
                assert flagged_reports["items"][0]["report_id"] == report["report_id"]

                event_rows = app.state.repository.list_events(run_id)
                assert [event["seq"] for event in event_rows] == sorted(event["seq"] for event in event_rows)
                assert any(event["type"] == "report_published" for event in event_rows)

                reviewed = await client.patch(
                    f"/api/reports/{report['report_id']}/review",
                    json={"decision": "approve", "actor": "reviewer", "note": "Validated graph evidence and accepted report.", "version": report["version"]},
                )
                assert reviewed.status_code == 200
                assert reviewed.json()["run"]["status"] == "completed"

                deletion = await client.request(
                    "DELETE",
                    f"/api/reports/{report['report_id']}",
                    json={"actor": "reviewer", "reason": "test", "version": reviewed.json()["report"]["version"]},
                )
                assert deletion.status_code == 200
                assert deletion.json()["report"]["lifecycle_state"] == "deleted"
                assert (await client.get("/api/reports")).json() == []

                restored = await client.post(
                    f"/api/reports/{report['report_id']}/restore",
                    json={"actor": "reviewer", "version": deletion.json()["report"]["version"]},
                )
                assert restored.status_code == 200
                assert restored.json()["report"]["lifecycle_state"] == "approved"

    asyncio.run(scenario())


def test_renderer_refresh_appends_immutable_revision_without_provider_calls(tmp_path: Path) -> None:
    """A current-template refresh keeps rev. 1/reviews and reopens review."""

    async def scenario() -> None:
        settings = _settings(tmp_path)
        calls = {"pipeline": 0}

        def runner(*args, **kwargs):
            calls["pipeline"] += 1
            return _runner(*args, **kwargs)

        app = create_app(settings, engine_factory=_RerenderEngine, pipeline_runner=runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 credential dumping observed.", "provider": "local"})
                assert created.status_code == 202
                run_id = created.json()["id"]
                await _wait_for_terminal(client, run_id)
                report = (await client.get("/api/reports", params={"run_id": run_id})).json()[0]
                report_id = report["report_id"]
                before = (await client.get(f"/api/reports/{report_id}")).json()
                original_revision_id = before["current_revision"]["id"]
                original_version = before["version"]
                original_asset = settings.runs_dir / run_id / "reports" / report_id / "report.md"
                original_markdown = original_asset.read_text(encoding="utf-8")
                assert original_markdown == "# Test report\n"

                # An existing approval stays linked to revision 1, not silently
                # transferred to the changed renderer output.
                approved = await client.patch(
                    f"/api/reports/{report_id}/review",
                    json={
                        "decision": "approve",
                        "actor": "reviewer",
                        "note": "Approved the original immutable revision.",
                        "version": original_version,
                    },
                )
                assert approved.status_code == 200
                assert approved.json()["run"]["status"] == "completed"

                refreshed = await client.post(f"/api/reports/{report_id}/rerender")
                assert refreshed.status_code == 200, refreshed.text
                detail = refreshed.json()
                assert detail["lifecycle_state"] == "manual_review_required"
                assert detail["qa_verdict"] == "MANUAL_REVIEW_REQUIRED"
                assert detail["version"] == original_version + 2  # review + re-render
                assert [revision["revision_number"] for revision in detail["revisions"]] == [2, 1]
                assert detail["current_revision"]["id"] != original_revision_id
                assert calls == {"pipeline": 1}  # refresh did not rerun analysis/LLM pipeline

                current_markdown = (await client.get(f"/api/reports/{report_id}/markdown")).text
                assert "[AN0001] First current analytic" in current_markdown
                assert "[AN0003] Third current analytic" in current_markdown
                assert "[D3-THREE] Third countermeasure" in current_markdown
                assert "see JSON/API" not in current_markdown
                assert original_asset.read_text(encoding="utf-8") == original_markdown

                old_revision = (await client.get(f"/api/reports/{report_id}/revisions/{original_revision_id}")).json()
                assert old_revision["current_revision"]["id"] == original_revision_id
                assert old_revision["qa_verdict"] == "MANUAL_REVIEW_REQUIRED" or old_revision["qa_verdict"] == "FLAG"
                reviews = detail["reviews"]
                assert len(reviews) == 1
                assert reviews[0]["report_revision_id"] == original_revision_id

                current = app.state.repository.get_current_revision(report_id)
                assert current is not None
                assert current["created_by"] == "development-local"
                assert current["metadata"]["operation"] == "renderer_refresh"
                assert current["metadata"]["rerendered_from_revision_id"] == original_revision_id
                assert current["metadata"]["provider_calls"] == {"made": False, "reason": "renderer_only"}
                assert "/revisions/" in current["markdown_path"]
                run = (await client.get(f"/api/runs/{run_id}")).json()
                assert run["status"] == "awaiting_review"

    asyncio.run(scenario())


def test_review_note_and_local_only_default_are_enforced(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        original_provider = os.environ.get("LLM_PROVIDER")
        os.environ["LLM_PROVIDER"] = "openai"
        try:
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                    # A stale process-level cloud setting cannot influence the
                    # web API. Omitted provider selection resolves to local;
                    # no cloud acknowledgement can make a hosted provider
                    # available again.
                    created = await client.post("/api/runs", data={"text": "T1003 observed."})
                    assert created.status_code == 202
                    assert created.json()["requested_provider"] == "local"
                    run_id = created.json()["id"]
                    await _wait_for_terminal(client, run_id)
                    report = (await client.get("/api/reports")).json()[0]
                    missing_note = await client.patch(
                        f"/api/reports/{report['report_id']}/review",
                        json={"decision": "approve", "actor": "reviewer", "version": report["version"]},
                    )
                    assert missing_note.status_code == 422
                    assert missing_note.json()["error"]["code"] == "review_note_required"
        finally:
            if original_provider is None:
                os.environ.pop("LLM_PROVIDER", None)
            else:
                os.environ["LLM_PROVIDER"] = original_provider

    asyncio.run(scenario())


def test_run_scoped_bulk_approval_records_current_revision_decisions_and_completes(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_multi_pending_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 and T1059 observed.", "provider": "local"})
                assert created.status_code == 202
                run_id = created.json()["id"]
                initial_run = await _wait_for_terminal(client, run_id)
                assert initial_run["status"] == "awaiting_review"
                initial_reports = (await client.get("/api/reports", params={"run_id": run_id})).json()
                # Input normalization may also materialize an UNMAPPED triage
                # report. The endpoint must approve every current actionable
                # report in the run, rather than only the two synthetic
                # pipeline outputs from this test runner.
                assert len(initial_reports) >= 2
                assert initial_run["counters"]["reports_review_pending"] == len(initial_reports)
                original = {
                    item["report_id"]: {
                        "version": item["version"],
                        "revision_id": item["current_revision_id"],
                    }
                    for item in initial_reports
                }

                approved = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    headers={"If-Match": str(initial_run["version"])},
                    json={"reason": "Validated retained evidence and approved the complete review queue."},
                )
                assert approved.status_code == 200, approved.text
                payload = approved.json()
                assert payload["approved_count"] == len(initial_reports)
                assert payload["run"]["status"] == "completed"
                assert payload["run"]["counters"]["reports_review_pending"] == 0
                assert payload["event"]["type"] == "run_review_pending_bulk_approved"
                assert payload["event"]["review"]["reason"] == "Validated retained evidence and approved the complete review queue."
                assert {item["report_id"] for item in payload["reports"]} == set(original)

                for report_id, before in original.items():
                    detail = (await client.get(f"/api/reports/{report_id}")).json()
                    assert detail["lifecycle_state"] == "approved"
                    assert detail["version"] == before["version"] + 1
                    assert detail["current_revision"]["id"] == before["revision_id"]
                    assert [revision["id"] for revision in detail["revisions"]] == [before["revision_id"]]
                    assert len(detail["reviews"]) == 1
                    decision = detail["reviews"][0]
                    assert decision["report_revision_id"] == before["revision_id"]
                    assert decision["decision"] == "approve"
                    assert decision["actor_id"] == "development-local"
                    assert decision["reason"] == "Validated retained evidence and approved the complete review queue."

                # A stale UI cannot silently turn an already-complete run into
                # a successful no-op; no extra audit row or event is created.
                no_pending = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "Repeated click", "version": payload["run"]["version"]},
                )
                assert no_pending.status_code == 409
                assert no_pending.json()["error"]["code"] == "no_review_pending_reports"
                assert len(app.state.repository.list_events(run_id)) >= 1

    asyncio.run(scenario())


def test_bulk_approval_requires_fresh_version_and_nonblank_shared_reason(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_multi_pending_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 and T1059 observed.", "provider": "local"})
                run_id = created.json()["id"]
                run = await _wait_for_terminal(client, run_id)
                reports = (await client.get("/api/reports", params={"run_id": run_id})).json()
                initial_versions = {report["report_id"]: report["version"] for report in reports}
                initial_states = {report["report_id"]: report["lifecycle_state"] for report in reports}
                initial_events = len(app.state.repository.list_events(run_id))

                missing_version = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "Needs a version precondition."},
                )
                assert missing_version.status_code == 428
                assert missing_version.json()["error"]["code"] == "precondition_required"

                blank_reason = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "   ", "version": run["version"]},
                )
                assert blank_reason.status_code == 422
                assert blank_reason.json()["error"]["code"] == "bulk_review_reason_required"

                stale = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "Stale click", "version": run["version"] - 1},
                )
                assert stale.status_code == 409
                assert stale.json()["error"]["code"] == "conflict"

                disagreeing_preconditions = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    headers={"If-Match": str(run["version"] + 1)},
                    json={"reason": "Disagreeing preconditions", "version": run["version"]},
                )
                assert disagreeing_preconditions.status_code == 400
                assert disagreeing_preconditions.json()["error"]["code"] == "version_mismatch"

                # The request model intentionally does not accept a caller
                # supplied identity for this server-attributed bulk action.
                spoofed_actor = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "Spoof", "version": run["version"], "actor": "not-an-audit-identity"},
                )
                assert spoofed_actor.status_code == 422
                assert spoofed_actor.json()["error"]["code"] == "validation_error"

                unchanged = (await client.get("/api/reports", params={"run_id": run_id})).json()
                assert {report["report_id"]: report["version"] for report in unchanged} == initial_versions
                assert {report["report_id"]: report["lifecycle_state"] for report in unchanged} == initial_states
                assert all(not app.state.repository.report_reviews(report["report_id"]) for report in unchanged)
                assert len(app.state.repository.list_events(run_id)) == initial_events

    asyncio.run(scenario())


def test_bulk_approval_uses_authenticated_actor_and_review_permission(tmp_path: Path) -> None:
    async def scenario() -> None:
        admin_token = "bulk-admin-token-is-long-enough"
        reviewer_token = "bulk-reviewer-token-long-enough"
        viewer_token = "bulk-viewer-token-is-long-enough"
        settings = replace(
            _settings(tmp_path),
            auth_mode="token",
            auth_token_principals=parse_token_map(
                json.dumps(
                    {
                        admin_token: {"actor": "submitter@example", "roles": ["admin"]},
                        reviewer_token: {"actor": "reviewer@example", "roles": ["reviewer"]},
                        viewer_token: {"actor": "viewer@example", "roles": ["viewer"]},
                    }
                )
            ),
        )
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_multi_pending_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
                admin_headers = {"Authorization": f"Bearer {admin_token}"}
                created = await client.post(
                    "/api/runs",
                    headers=admin_headers,
                    data={"text": "T1003 and T1059 observed.", "provider": "local"},
                )
                run_id = created.json()["id"]
                run = await _wait_for_terminal(client, run_id, headers=admin_headers)

                anonymous = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    json={"reason": "Anonymous cannot approve", "version": run["version"]},
                )
                assert anonymous.status_code == 401

                viewer = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    headers={"Authorization": f"Bearer {viewer_token}"},
                    json={"reason": "Viewer cannot approve", "version": run["version"]},
                )
                assert viewer.status_code == 403

                approved = await client.post(
                    f"/api/runs/{run_id}/review-pending/approve",
                    headers={"Authorization": f"Bearer {reviewer_token}"},
                    json={"reason": "Reviewer accepted all current reports.", "version": run["version"]},
                )
                assert approved.status_code == 200
                for report in approved.json()["reports"]:
                    reviews = app.state.repository.report_reviews(report["report_id"])
                    assert len(reviews) == 1
                    assert reviews[0]["actor_id"] == "reviewer@example"

    asyncio.run(scenario())


def test_token_auth_derives_actor_and_browser_session(tmp_path: Path) -> None:
    async def scenario() -> None:
        token = "test-token-that-is-long-enough"
        settings = replace(
            _settings(tmp_path),
            auth_mode="token",
            auth_token_principals=parse_token_map(json.dumps({token: {"actor": "reviewer@example", "roles": ["admin"]}})),
        )
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
                anonymous = await client.get("/api/runs")
                assert anonymous.status_code == 401
                headers = {"Authorization": f"Bearer {token}"}
                session = await client.post("/api/session", headers=headers)
                assert session.status_code == 200
                assert session.json()["actor"] == "reviewer@example"
                # The HttpOnly same-origin cookie now authenticates a request
                # that has no caller-controlled Authorization header.
                authenticated = await client.get("/api/runs")
                assert authenticated.status_code == 200
                # A reload must obtain the same server-derived identity
                # rather than trusting a stale browser-local actor string.
                current_session = await client.get("/api/session")
                assert current_session.status_code == 200
                assert current_session.json() == {
                    "actor": "reviewer@example",
                    "roles": ["admin"],
                    "authentication_mode": "token",
                }
                submitted = await client.post("/api/runs", data={"text": "T1003 credential dumping observed.", "provider": "local"})
                assert submitted.status_code == 202
                await _wait_for_terminal(client, submitted.json()["id"])
                report = (await client.get("/api/reports")).json()[0]
                mismatched_actor = await client.patch(
                    f"/api/reports/{report['report_id']}/review",
                    json={
                        "decision": "approve",
                        "actor": "browser-local-stale-name",
                        "note": "This must not impersonate the session principal.",
                        "version": report["version"],
                    },
                )
                assert mismatched_actor.status_code == 403
                assert mismatched_actor.json()["error"]["code"] == "actor_identity_mismatch"

    asyncio.run(scenario())


def test_concurrent_submissions_keep_workspaces_and_report_ids_isolated(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                first, second = await asyncio.gather(
                    client.post("/api/runs", data={"text": "First T1003 artifact.", "provider": "local"}),
                    client.post("/api/runs", data={"text": "Second T1003 artifact.", "provider": "local"}),
                )
                first_id, second_id = first.json()["id"], second.json()["id"]
                assert first_id != second_id
                await asyncio.gather(_wait_for_terminal(client, first_id), _wait_for_terminal(client, second_id))
                first_reports = (await client.get("/api/reports", params={"run_id": first_id})).json()
                second_reports = (await client.get("/api/reports", params={"run_id": second_id})).json()
                assert len(first_reports) == len(second_reports) == 1
                assert first_reports[0]["report_id"] != second_reports[0]["report_id"]
                assert (settings.runs_dir / first_id / "normalized" / "observations.csv").is_file()
                assert (settings.runs_dir / second_id / "normalized" / "observations.csv").is_file()

    asyncio.run(scenario())


def test_all_auto_passed_reports_complete_the_run_without_human_gate(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_passing_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1190 observed.", "provider": "local"})
                run = await _wait_for_terminal(client, created.json()["id"])
                assert run["status"] == "completed"
                reports = (await client.get("/api/reports", params={"run_id": created.json()["id"]})).json()
                assert reports[0]["lifecycle_state"] == "auto_passed"
                retried = await client.post(f"/api/runs/{created.json()['id']}/retry")
                assert retried.status_code == 202
                assert retried.json()["id"] != created.json()["id"]
                retry_run = await _wait_for_terminal(client, retried.json()["id"])
                assert retry_run["status"] == "completed"

    asyncio.run(scenario())


def test_unresolved_observations_become_an_actionable_triage_report(tmp_path: Path) -> None:
    def no_match_runner(_engine, _input_csv, output_dir, provider_name=None, progress_cb=None, cancel_cb=None):
        return []

    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=no_match_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "Ambiguous behavior with no ATT&CK ID.", "provider": "local"})
                run = await _wait_for_terminal(client, created.json()["id"])
                assert run["status"] == "awaiting_review"
                assert run["counters"]["observations_unresolved"] == 1
                reports = (await client.get("/api/reports", params={"run_id": created.json()["id"]})).json()
                assert len(reports) == 1
                assert reports[0]["technique_id"] == "UNMAPPED"
                assert reports[0]["lifecycle_state"] == "manual_review_required"
                detail = (await client.get(f"/api/reports/{reports[0]['report_id']}")).json()
                assert len(detail["evidence"]) == 1
                assert detail["candidates"][0]["method"] == "unresolved"

    asyncio.run(scenario())


def test_reject_requires_rework_and_source_run_retry_is_explicit(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 observed.", "provider": "local"})
                run_id = created.json()["id"]
                await _wait_for_terminal(client, run_id)
                report = (await client.get("/api/reports")).json()[0]
                response = await client.patch(
                    f"/api/reports/{report['report_id']}/review",
                    json={"decision": "reject", "actor": "reviewer", "note": "Evidence requires rework.", "version": report["version"]},
                )
                assert response.status_code == 200
                assert response.json()["report"]["lifecycle_state"] == "needs_rework"
                assert response.json()["run"]["status"] == "awaiting_review"
                assert response.json()["run"]["counters"]["reports_review_pending"] == 1

                retried = await client.post(f"/api/reports/{report['report_id']}/retry-source-run")
                assert retried.status_code == 202
                assert retried.json()["id"] != run_id
                retry_run = await _wait_for_terminal(client, retried.json()["id"])
                assert retry_run["status"] == "awaiting_review"

    asyncio.run(scenario())


def test_deleting_pending_report_cannot_bypass_review_gate(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 observed.", "provider": "local"})
                run_id = created.json()["id"]
                run = await _wait_for_terminal(client, run_id)
                assert run["status"] == "awaiting_review"
                report = (await client.get("/api/reports", params={"run_id": run_id})).json()[0]

                deletion = await client.request(
                    "DELETE",
                    f"/api/reports/{report['report_id']}",
                    json={"actor": "reviewer", "reason": "attempt to skip review", "version": report["version"]},
                )
                assert deletion.status_code == 409
                assert "cannot bypass the run review gate" in deletion.json()["error"]["message"]

                unchanged = (await client.get(f"/api/runs/{run_id}")).json()
                assert unchanged["status"] == "awaiting_review"
                assert unchanged["counters"]["reports_review_pending"] == 1

    asyncio.run(scenario())


def test_awaiting_review_run_cannot_receive_stale_cancellation(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 observed.", "provider": "local"})
                run = await _wait_for_terminal(client, created.json()["id"])
                assert run["status"] == "awaiting_review"

                cancellation = await client.post(
                    f"/api/runs/{run['id']}/cancel",
                    headers={"If-Match": str(run["version"])},
                )
                assert cancellation.status_code == 409
                assert "not active" in cancellation.json()["error"]["message"]

                unchanged = (await client.get(f"/api/runs/{run['id']}")).json()
                assert unchanged["status"] == "awaiting_review"
                assert unchanged["cancel_requested"] is False

    asyncio.run(scenario())


def test_retry_remains_local_when_legacy_cloud_environment_is_set(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        original_provider = os.environ.get("LLM_PROVIDER")
        original_model = os.environ.get("LOCAL_LLM_MODEL")
        os.environ["LLM_PROVIDER"] = "openai"
        os.environ["LOCAL_LLM_MODEL"] = "configured-local:8b"
        try:
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                    created = await client.post(
                        "/api/runs",
                        data={"text": "T1003 observed through a legacy cloud default."},
                    )
                    assert created.status_code == 202
                    source_run = await _wait_for_terminal(client, created.json()["id"])
                    assert source_run["requested_provider"] == "local"
                    assert source_run["requested_model"] == "configured-local:8b"
                    assert source_run["retry_provider"] == "local"
                    assert source_run["retry_requires_cloud_acknowledgement"] is False

                    retried = await client.post(
                        f"/api/runs/{source_run['id']}/retry",
                        json={"model": "retry-local:latest", "cloud_acknowledged": True},
                    )
                    assert retried.status_code == 202
                    retry = retried.json()
                    assert retry["requested_provider"] == "local"
                    assert retry["requested_model"] == "retry-local:latest"
                    retry_artifact = app.state.repository.list_artifacts(retry["id"])[0]
                    assert retry_artifact["metadata"]["effective_requested_provider"] == "local"
                    assert retry_artifact["metadata"]["requested_model"] == "retry-local:latest"
                    # Do not close the application while a newly scheduled
                    # retry still owns its run workspace/database connection.
                    # This also verifies the retry settles under the durable
                    # graceful-shutdown contract.
                    retry_run = await _wait_for_terminal(client, retry["id"])
                    assert retry_run["status"] == "awaiting_review"
        finally:
            if original_provider is None:
                os.environ.pop("LLM_PROVIDER", None)
            else:
                os.environ["LLM_PROVIDER"] = original_provider
            if original_model is None:
                os.environ.pop("LOCAL_LLM_MODEL", None)
            else:
                os.environ["LOCAL_LLM_MODEL"] = original_model

    asyncio.run(scenario())


def test_graph_startup_failure_rejects_new_work_without_consuming_the_queue(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(
            settings,
            engine_factory=lambda: (_ for _ in ()).throw(RuntimeError("simulated graph initialization failure")),
            pipeline_runner=_runner,
        )
        run_id = str(uuid.uuid4())
        workspace = RunWorkspace.create(settings.runs_dir, run_id)
        source = workspace.store_text("T1003 retained while graph is unavailable.")
        app.state.repository.create_run(run_id=run_id, workspace_path=str(workspace.path), requested_provider="local")
        app.state.repository.create_artifact(
            artifact_id=str(uuid.uuid4()),
            run_id=run_id,
            original_name="pasted-threat-intel.txt",
            media_type="text/plain",
            extension=".txt",
            sha256=source.sha256,
            storage_key=source.relative_path,
            byte_size=source.byte_size,
            kind="text",
        )

        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                rejected = await client.post("/api/runs", data={"text": "T1003 must not be consumed.", "provider": "local"})
                assert rejected.status_code == 503
                assert rejected.json()["error"]["code"] == "graph_unavailable"
                assert app.state.repository.get_run(run_id)["status"] == "queued"
                assert app.state.repository.list_observations(app.state.repository.list_artifacts(run_id)[0]["id"]) == []

    asyncio.run(scenario())


def test_retry_with_missing_retained_upload_does_not_create_an_orphan_queue_row(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_passing_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1190 retained-source retry check.", "provider": "local"})
                source_run = await _wait_for_terminal(client, created.json()["id"])
                artifact = app.state.repository.list_artifacts(source_run["id"])[0]
                workspace = RunWorkspace.open(settings.runs_dir, source_run["id"])
                workspace.resolve_relative(artifact["storage_key"]).unlink()

                retry = await client.post(f"/api/runs/{source_run['id']}/retry")
                assert retry.status_code == 409
                assert retry.json()["error"]["code"] == "retry_source_unavailable"
                runs, total = app.state.repository.list_runs(limit=20)
                assert total == 1
                assert [run["id"] for run in runs] == [source_run["id"]]

    asyncio.run(scenario())


def test_shutdown_requeues_cooperatively_interrupted_work_before_lifespan_returns(tmp_path: Path) -> None:
    """No worker may keep writing after FastAPI closes its lifespan."""
    import threading
    import time

    started = threading.Event()

    def blocking_runner(_engine, _input_csv, _output_dir, provider_name=None, progress_cb=None, cancel_cb=None):
        started.set()
        while True:
            # The worker's progress callback observes service shutdown and
            # raises WorkerShutdown, which this runner intentionally does not
            # swallow. Real upgraded pipeline stages use the same callback.
            progress_cb({"type": "blocking_provider_wait", "phase": "llm_graph_crawl"})
            time.sleep(0.01)

    async def scenario() -> tuple[object, str]:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=blocking_runner)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                created = await client.post("/api/runs", data={"text": "T1003 cooperative shutdown evidence.", "provider": "local"})
                assert created.status_code == 202
                for _ in range(100):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.01)
                assert started.is_set()
                run_id = created.json()["id"]
        # Reaching here proves DurableWorker.shutdown joined every future.
        return app, run_id

    app, run_id = asyncio.run(scenario())
    requeued = app.state.repository.get_run(run_id)
    assert requeued is not None
    assert requeued["status"] == "queued"
    assert any(event["type"] == "run_interrupted_for_shutdown" for event in app.state.repository.list_events(run_id))


def test_interrupted_publishing_is_reset_and_replayed_without_duplicate_observations(tmp_path: Path) -> None:
    async def scenario() -> None:
        settings = _settings(tmp_path)
        app = create_app(settings, engine_factory=lambda: object(), pipeline_runner=_runner)
        repository = app.state.repository
        run_id = str(uuid.uuid4())
        workspace = RunWorkspace.create(settings.runs_dir, run_id)
        source = workspace.store_text("T1003 interrupted publishing evidence.")
        repository.create_run(
            run_id=run_id,
            workspace_path=str(workspace.path),
            requested_provider="local",
        )
        artifact = repository.create_artifact(
            artifact_id=str(uuid.uuid4()),
            run_id=run_id,
            original_name="pasted-threat-intel.txt",
            media_type="text/plain",
            extension=".txt",
            sha256=source.sha256,
            storage_key=source.relative_path,
            byte_size=source.byte_size,
            kind="text",
            metadata={"effective_requested_provider": "local"},
        )
        # Simulate the rows/files left by a process crash after analysis
        # finished but before report publication completed.
        repository.create_observations(
            artifact["id"],
            [{"normalized_text": "stale observation", "source_locator": {"kind": "stale"}}],
        )
        workspace.atomic_write_bytes(workspace.normalized_csv_path, b"Finding\nold\n")
        workspace.atomic_write_bytes(workspace.reports_dir / "stale" / "report.md", b"stale")
        repository.update_run(run_id, status="analysis_finished", phase="publishing")

        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                recovered = await _wait_for_terminal(client, run_id)

        assert recovered["status"] == "awaiting_review"
        assert recovered["generation_finished_at"]
        assert not (workspace.reports_dir / "stale").exists()
        # The stale row was removed before replay, so normalization creates
        # exactly one durable source observation rather than a duplicate.
        assert len(repository.list_observations(artifact["id"])) == 1
        assert any(event["type"] == "run_recovered" for event in repository.list_events(run_id))

    asyncio.run(scenario())
