"""Repository-level atomicity tests for run-scoped bulk approval."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from webapp.backend.db import ConflictError, LifecycleRepository


def _pending_run_fixture(tmp_path: Path, states: tuple[str, ...] = ("auto_flagged", "needs_rework")):
    repository = LifecycleRepository(tmp_path / "data" / "csdh.sqlite3")
    repository.initialize()
    run_id = str(uuid.uuid4())
    run = repository.create_run(
        run_id=run_id,
        workspace_path=str(tmp_path / "data" / "runs" / run_id),
        requested_provider="none",
        status="awaiting_review",
    )
    reports = []
    for index, state in enumerate(states, start=1):
        report_id = str(uuid.uuid4())
        revision_id = str(uuid.uuid4())
        reports.append(
            repository.create_report_with_revision(
                report_id=report_id,
                revision_id=revision_id,
                run_id=run_id,
                artifact_id=None,
                display_id=f"CONSOL-T10{index:02d}",
                aggregate_key=f"T10{index:02d}",
                technique_id=f"T10{index:02d}",
                technique_name=f"Technique {index}",
                finding_count=1,
                severity_breakdown={"High": 1},
                qa_verdict="FLAG",
                lifecycle_state=state,
                report_data={"report_id": report_id, "technique_id": f"T10{index:02d}"},
                narrative={},
                markdown_path=None,
                json_path=None,
                markdown_sha256=None,
                json_sha256=None,
            )
        )
    return repository, run, reports


def test_bulk_approval_rolls_back_every_report_when_one_audit_insert_fails(tmp_path: Path) -> None:
    repository, run, reports = _pending_run_fixture(tmp_path)
    before = {report["id"]: (report["lifecycle_state"], report["version"], report["current_revision_id"]) for report in reports}

    # The trigger fails the second INSERT within the batch. If the repository
    # were to loop through individually committed review_report() calls, the
    # first report would remain approved. The single transaction must instead
    # roll back both report mutations and both decision rows.
    with repository._connect() as conn:  # test-only direct DDL to force a mid-batch write error
        conn.execute(
            """
            CREATE TRIGGER fail_second_bulk_review
            BEFORE INSERT ON review_decisions
            WHEN NEW.reason = 'force full rollback'
             AND (SELECT COUNT(*) FROM review_decisions WHERE reason = 'force full rollback') >= 1
            BEGIN
                SELECT RAISE(ABORT, 'forced second review insert failure');
            END
            """
        )

    with pytest.raises(sqlite3.DatabaseError, match="forced second review insert failure"):
        repository.bulk_approve_review_pending_reports(
            run_id=run["id"],
            expected_run_version=run["version"],
            actor_id="reviewer@example",
            reason="force full rollback",
        )

    for report_id, expected in before.items():
        restored = repository.get_report(report_id)
        assert restored is not None
        assert (restored["lifecycle_state"], restored["version"], restored["current_revision_id"]) == expected
        assert repository.report_reviews(report_id) == []
    unchanged_run = repository.get_run(run["id"])
    assert unchanged_run is not None
    assert unchanged_run["status"] == "awaiting_review"
    assert unchanged_run["version"] == run["version"]
    assert repository.list_events(run["id"]) == []


def test_bulk_approval_rejects_inflight_lifecycle_rows_without_approving_a_subset(tmp_path: Path) -> None:
    repository, run, reports = _pending_run_fixture(
        tmp_path,
        states=("manual_review_required", "deleting"),
    )

    with pytest.raises(ConflictError, match="in-flight lifecycle state"):
        repository.bulk_approve_review_pending_reports(
            run_id=run["id"],
            expected_run_version=run["version"],
            actor_id="reviewer@example",
            reason="A deletion operation is in progress.",
        )

    assert [repository.get_report(report["id"])["lifecycle_state"] for report in reports] == [
        "manual_review_required",
        "deleting",
    ]
    assert all(repository.report_reviews(report["id"]) == [] for report in reports)
    unchanged_run = repository.get_run(run["id"])
    assert unchanged_run is not None
    assert unchanged_run["status"] == "awaiting_review"
    assert unchanged_run["version"] == run["version"]
