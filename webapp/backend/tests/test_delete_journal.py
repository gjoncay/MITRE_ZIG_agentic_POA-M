"""Crash-recovery tests for journaled report deletion and restore."""

from __future__ import annotations

import uuid
from pathlib import Path

from webapp.backend.db import LifecycleRepository
from webapp.backend.maintenance import reconcile_incomplete_deletion_operations
from webapp.backend.workspace import RunWorkspace


def _report_fixture(tmp_path: Path):
    data_dir = tmp_path / "data"
    repository = LifecycleRepository(data_dir / "csdh.sqlite3")
    repository.initialize()
    run_id = str(uuid.uuid4())
    workspace = RunWorkspace.create(data_dir / "runs", run_id)
    repository.create_run(run_id=run_id, workspace_path=str(workspace.path), requested_provider="none")
    artifact = repository.create_artifact(
        artifact_id=str(uuid.uuid4()),
        run_id=run_id,
        original_name="evidence.txt",
        media_type="text/plain",
        extension=".txt",
        sha256="0" * 64,
        storage_key="upload/evidence.txt",
        byte_size=1,
        kind="text",
    )
    report_id = str(uuid.uuid4())
    revision_id = str(uuid.uuid4())
    report_dir = workspace.reports_dir / report_id
    markdown = workspace.atomic_write_bytes(report_dir / "report.md", b"# report\n")
    payload = workspace.atomic_write_bytes(report_dir / "report.json", b"{}")
    report = repository.create_report_with_revision(
        report_id=report_id,
        revision_id=revision_id,
        run_id=run_id,
        artifact_id=artifact["id"],
        display_id="CONSOL-T1003",
        aggregate_key="T1003",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        finding_count=1,
        severity_breakdown={},
        qa_verdict="PASS",
        lifecycle_state="approved",
        report_data={"framework_mappings": {"graph_snapshot_id": "sha256:test"}},
        narrative={},
        markdown_path=workspace.relative(markdown),
        json_path=workspace.relative(payload),
        markdown_sha256=RunWorkspace.sha256_file(markdown),
        json_sha256=RunWorkspace.sha256_file(payload),
    )
    return repository, workspace, report


def test_prepared_delete_is_reconciled_after_filesystem_move_and_before_db_commit(tmp_path: Path) -> None:
    repository, workspace, report = _report_fixture(tmp_path)
    revisions = repository.list_revisions(report["id"])
    operation_id = str(uuid.uuid4())
    manifest = workspace.plan_report_trash_manifest(report_id=report["id"], operation_id=operation_id, revisions=revisions)
    reserved, audit = repository.begin_delete(
        report_id=report["id"],
        expected_version=report["version"],
        actor_id="reviewer",
        reason="test crash recovery",
        undo_expires_at="2099-01-01T00:00:00.000Z",
        trash_manifest=manifest,
    )
    assert reserved["lifecycle_state"] == "deleting"
    workspace.move_manifest_to_trash(manifest)
    assert not workspace.resolve_relative(manifest["files"][0]["original"]).exists()

    result = reconcile_incomplete_deletion_operations(repository=repository, runs_dir=workspace.root)
    assert result == {"recovered_operations": 1, "recovery_failures": 0}
    restored = repository.get_report(report["id"])
    assert restored and restored["lifecycle_state"] == "approved"
    assert workspace.resolve_relative(manifest["files"][0]["original"]).is_file()
    assert repository.latest_deletion_audit(report["id"]) is None
    pending = repository.list_pending_deletion_operations()
    assert pending == []
    assert audit["operation_state"] == "delete_prepared"


def test_completed_delete_and_restore_move_every_planned_asset(tmp_path: Path) -> None:
    repository, workspace, report = _report_fixture(tmp_path)
    revisions = repository.list_revisions(report["id"])
    manifest = workspace.plan_report_trash_manifest(report_id=report["id"], operation_id=str(uuid.uuid4()), revisions=revisions)
    _, audit = repository.begin_delete(
        report_id=report["id"],
        expected_version=report["version"],
        actor_id="reviewer",
        reason="retention test",
        undo_expires_at="2099-01-01T00:00:00.000Z",
        trash_manifest=manifest,
    )
    workspace.move_manifest_to_trash(manifest)
    deleted, completed = repository.complete_delete(audit["id"])
    assert deleted["lifecycle_state"] == "deleted"
    assert completed["operation_state"] == "completed"
    assert all(workspace.resolve_relative(item["trash"]).is_file() for item in manifest["files"])

    restoring, restore_audit = repository.begin_restore(
        report_id=report["id"],
        expected_version=deleted["version"],
        actor_id="reviewer",
        reason="undo",
    )
    assert restoring["lifecycle_state"] == "restoring"
    workspace.restore_from_trash(restore_audit["trash_manifest"])
    restored = repository.complete_restore(restore_audit["id"])
    assert restored["lifecycle_state"] == "approved"
    assert all(workspace.resolve_relative(item["original"]).is_file() for item in manifest["files"])
