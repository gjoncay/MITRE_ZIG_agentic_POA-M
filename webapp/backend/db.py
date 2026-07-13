"""SQLite persistence for the web analysis lifecycle.

The web application is deliberately a small, single-host deployment.  SQLite
with WAL is a good fit for that model, provided that state is kept out of the
process memory and every mutation goes through a short transaction.  This
module is the only place in the backend that contains SQL; route handlers and
workers use :class:`LifecycleRepository` instead.

The schema is intentionally additive.  It records the complete lifecycle even
when an older pipeline can only supply a markdown/JSON report pair.  Newer
pipeline adapters can progressively populate observations, candidates and
validated graph paths without requiring another database migration.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp with a stable ``Z`` suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, separators=(",", ":"), sort_keys=True, default=str)


def json_loads(value: str | bytes | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


class RepositoryError(RuntimeError):
    """Base class for persistence-layer failures."""


class NotFoundError(RepositoryError):
    pass


class ConflictError(RepositoryError):
    pass


class NoReviewPendingReportsError(ConflictError):
    """Raised when a bulk-review request has no actionable reports to approve."""


# These are the report states that still require a human or system action
# before a run can be considered complete. Keep the snapshot counter and the
# durable completion gate on one definition so the UI never reports a green
# run with pending work (or vice versa). A rejection is deliberately not a
# pass: its audit decision is retained, but the report remains actionable as
# ``needs_rework`` until an acceptable replacement or approval is recorded.
REVIEW_PENDING_REPORT_STATES = frozenset(
    {
        "auto_flagged",
        "manual_review_required",
        "needs_rework",
        "mapping_validated",
        "qa_pending",
        "draft",
        "deleting",
        "restoring",
        # Historical rows from the short-lived terminal-rejection behavior
        # remain visible/actionable rather than silently completing a run.
        "rejected",
    }
)

# A deletion/restore transition is deliberately review-pending so it keeps a
# run from looking complete, but it is not safe to convert that in-flight
# lifecycle operation into an approval.  The bulk endpoint rejects the entire
# request when it sees one of these states instead of approving a subset and
# leaving an ambiguous result behind.
BULK_APPROVABLE_REVIEW_STATES = frozenset(
    state for state in REVIEW_PENDING_REPORT_STATES if state not in {"deleting", "restoring"}
)

# Deletion is retention/lifecycle housekeeping, not a review decision. If a
# pending report could be deleted, a user could make a run look complete
# without ever recording an accepted disposition. Require an accepted state
# first; an inapplicable report can be explicitly waived and audited.
DELETE_ELIGIBLE_REPORT_STATES = frozenset({"approved", "auto_passed", "waived", "legacy"})


class LifecycleRepository:
    """A transactional repository backed by one SQLite database file.

    Connections are intentionally short-lived.  Background workers, request
    handlers and SSE readers can then safely use the repository from different
    threads without sharing sqlite connection objects.
    """

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)

    # ------------------------------------------------------------------
    # Connection / migration helpers
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.database_path),
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            # WAL allows SSE readers to continue reading while the worker
            # records progress.  NORMAL is appropriate for recoverable local
            # job state; SQLite still remains crash-consistent.
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    generation_finished_at TEXT,
                    finished_at TEXT,
                    updated_at TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    graph_snapshot_id TEXT,
                    requested_provider TEXT,
                    requested_model TEXT,
                    effective_provider TEXT,
                    effective_model TEXT,
                    degraded_reason TEXT,
                    phase TEXT NOT NULL DEFAULT '',
                    workspace_path TEXT NOT NULL,
                    counters_json TEXT NOT NULL DEFAULT '{}',
                    metrics_json TEXT NOT NULL DEFAULT '{}',
                    error_code TEXT,
                    error_message TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    retry_of_run_id TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(retry_of_run_id) REFERENCES analysis_runs(id)
                );

                CREATE INDEX IF NOT EXISTS idx_analysis_runs_status_created
                    ON analysis_runs(status, created_at DESC);

                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    media_type TEXT,
                    extension TEXT,
                    sha256 TEXT NOT NULL,
                    storage_key TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    classification TEXT,
                    redaction_policy TEXT,
                    parse_status TEXT NOT NULL DEFAULT 'pending',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE,
                    UNIQUE(run_id, sha256, storage_key)
                );

                CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id, created_at);

                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    source_locator_json TEXT NOT NULL DEFAULT '{}',
                    raw_text_hash TEXT,
                    normalized_text TEXT NOT NULL,
                    context_text TEXT,
                    asset_json TEXT NOT NULL DEFAULT '{}',
                    severity TEXT,
                    explicit_ids_json TEXT NOT NULL DEFAULT '[]',
                    parse_status TEXT NOT NULL DEFAULT 'parsed',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_observations_artifact ON observations(artifact_id, created_at);

                CREATE TABLE IF NOT EXISTS evidence_spans (
                    id TEXT PRIMARY KEY,
                    observation_id TEXT NOT NULL,
                    start_offset INTEGER NOT NULL,
                    end_offset INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    field_name TEXT,
                    source_locator_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(observation_id) REFERENCES observations(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_observation ON evidence_spans(observation_id);

                CREATE TABLE IF NOT EXISTS technique_candidates (
                    id TEXT PRIMARY KEY,
                    observation_id TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL,
                    evidence_span_ids_json TEXT NOT NULL DEFAULT '[]',
                    candidate_rank INTEGER,
                    state TEXT NOT NULL,
                    reason TEXT,
                    retrieval_metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(observation_id) REFERENCES observations(id) ON DELETE CASCADE,
                    UNIQUE(observation_id, technique_id, method, evidence_span_ids_json)
                );

                CREATE INDEX IF NOT EXISTS idx_candidates_observation ON technique_candidates(observation_id, state);

                CREATE TABLE IF NOT EXISTS graph_paths (
                    id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    mapping_scope TEXT NOT NULL DEFAULT 'direct',
                    path_json TEXT NOT NULL,
                    graph_snapshot_id TEXT,
                    validation_state TEXT NOT NULL,
                    validation_reason TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES technique_candidates(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_graph_paths_candidate ON graph_paths(candidate_id, category);

                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    artifact_id TEXT,
                    display_id TEXT NOT NULL,
                    aggregate_key TEXT,
                    technique_id TEXT,
                    technique_name TEXT,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    severity_breakdown_json TEXT NOT NULL DEFAULT '{}',
                    qa_verdict TEXT,
                    lifecycle_state TEXT NOT NULL,
                    current_revision_id TEXT,
                    deleted_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE,
                    FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reports_run_state ON reports(run_id, lifecycle_state, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_reports_technique ON reports(technique_id, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_display_per_run
                    ON reports(run_id, display_id);

                CREATE TABLE IF NOT EXISTS report_revisions (
                    id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    revision_number INTEGER NOT NULL,
                    mapping_snapshot_hash TEXT,
                    report_json TEXT NOT NULL DEFAULT '{}',
                    narrative_json TEXT NOT NULL DEFAULT '{}',
                    markdown_path TEXT,
                    json_path TEXT,
                    pdf_path TEXT,
                    markdown_sha256 TEXT,
                    json_sha256 TEXT,
                    pdf_sha256 TEXT,
                    qa_state TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE,
                    UNIQUE(report_id, revision_number)
                );

                CREATE INDEX IF NOT EXISTS idx_report_revisions_report ON report_revisions(report_id, revision_number DESC);

                CREATE TABLE IF NOT EXISTS review_decisions (
                    id TEXT PRIMARY KEY,
                    report_revision_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(report_revision_id) REFERENCES report_revisions(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_reviews_revision ON review_decisions(report_revision_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS job_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE,
                    UNIQUE(run_id, seq)
                );

                CREATE INDEX IF NOT EXISTS idx_events_run_seq ON job_events(run_id, seq);

                CREATE TABLE IF NOT EXISTS deletion_audit (
                    id TEXT PRIMARY KEY,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    report_id TEXT,
                    actor_id TEXT NOT NULL,
                    reason TEXT,
                    requested_at TEXT NOT NULL,
                    completed_at TEXT,
                    undo_expires_at TEXT,
                    prior_state TEXT,
                    trash_manifest_json TEXT NOT NULL DEFAULT '{}',
                    restored_at TEXT,
                    restore_actor_id TEXT,
                    restore_reason TEXT,
                    operation_state TEXT NOT NULL DEFAULT 'completed',
                    purged_at TEXT,
                    FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_deletion_report ON deletion_audit(report_id, requested_at DESC);
                """
            )
            # Additive migration for deployments created by the first durable
            # lifecycle release. SQLite cannot add a column through CREATE
            # TABLE IF NOT EXISTS, so keep this narrow and idempotent.
            deletion_columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(deletion_audit)").fetchall()
            }
            if "operation_state" not in deletion_columns:
                conn.execute("ALTER TABLE deletion_audit ADD COLUMN operation_state TEXT NOT NULL DEFAULT 'completed'")
            if "purged_at" not in deletion_columns:
                conn.execute("ALTER TABLE deletion_audit ADD COLUMN purged_at TEXT")
            run_columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(analysis_runs)").fetchall()
            }
            if "generation_finished_at" not in run_columns:
                conn.execute("ALTER TABLE analysis_runs ADD COLUMN generation_finished_at TEXT")
            if "requested_model" not in run_columns:
                conn.execute("ALTER TABLE analysis_runs ADD COLUMN requested_model TEXT")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Row conversion
    # ------------------------------------------------------------------
    @staticmethod
    def _run_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        data["cancel_requested"] = bool(data["cancel_requested"])
        data["counters"] = json_loads(data.pop("counters_json", None), {})
        data["metrics"] = json_loads(data.pop("metrics_json", None), {})
        return data

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["metadata"] = json_loads(data.pop("metadata_json", None), {})
        return data

    @staticmethod
    def _report_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["severity_breakdown"] = json_loads(data.pop("severity_breakdown_json", None), {})
        data["metadata"] = json_loads(data.pop("metadata_json", None), {})
        return data

    @staticmethod
    def _revision_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        data["report_data"] = json_loads(data.pop("report_json", None), {})
        data["narrative"] = json_loads(data.pop("narrative_json", None), {})
        data["metadata"] = json_loads(data.pop("metadata_json", None), {})
        return data

    @staticmethod
    def _observation_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["source_locator"] = json_loads(data.pop("source_locator_json", None), {})
        data["asset"] = json_loads(data.pop("asset_json", None), {})
        data["explicit_ids"] = json_loads(data.pop("explicit_ids_json", None), [])
        data["metadata"] = json_loads(data.pop("metadata_json", None), {})
        return data

    @staticmethod
    def _candidate_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["evidence_span_ids"] = json_loads(data.pop("evidence_span_ids_json", None), [])
        data["retrieval_metadata"] = json_loads(data.pop("retrieval_metadata_json", None), {})
        return data

    @staticmethod
    def _graph_path_from_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["path"] = json_loads(data.pop("path_json", None), {})
        return data

    # ------------------------------------------------------------------
    # Runs and durable progress events
    # ------------------------------------------------------------------
    def create_run(
        self,
        *,
        run_id: str,
        workspace_path: str,
        requested_provider: str | None,
        requested_model: str | None = None,
        policy_version: str = "v1",
        graph_snapshot_id: str | None = None,
        retry_of_run_id: str | None = None,
        status: str = "queued",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    id, status, created_at, updated_at, policy_version,
                    graph_snapshot_id, requested_provider, requested_model, workspace_path,
                    retry_of_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    status,
                    now,
                    now,
                    policy_version,
                    graph_snapshot_id,
                    requested_provider,
                    requested_model,
                    workspace_path,
                    retry_of_run_id,
                ),
            )
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(row) or {}

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(row)

    def get_run_snapshot(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if run is None:
            return None
        with self._connect() as conn:
            artifact_count = conn.execute("SELECT COUNT(*) FROM artifacts WHERE run_id = ?", (run_id,)).fetchone()[0]
            artifact_row = conn.execute(
                "SELECT metadata_json FROM artifacts WHERE run_id = ? ORDER BY created_at LIMIT 1",
                (run_id,),
            ).fetchone()
            report_rows = conn.execute(
                "SELECT lifecycle_state, COUNT(*) AS n FROM reports WHERE run_id = ? GROUP BY lifecycle_state",
                (run_id,),
            ).fetchall()
            report_ids = conn.execute(
                "SELECT id FROM reports WHERE run_id = ? AND lifecycle_state != 'deleted' ORDER BY created_at",
                (run_id,),
            ).fetchall()
        report_states = {row["lifecycle_state"]: row["n"] for row in report_rows}
        counters = dict(run["counters"])
        counters.setdefault("artifacts_total", artifact_count)
        counters.setdefault("reports_total", sum(report_states.values()))
        counters.setdefault("reports_completed", sum(report_states.values()))
        counters["reports_review_pending"] = sum(
            count for state, count in report_states.items() if state in REVIEW_PENDING_REPORT_STATES
        )
        counters["reports_auto_passed"] = report_states.get("auto_passed", 0)
        counters["reports_flagged"] = report_states.get("auto_flagged", 0)
        run["counters"] = counters
        run["report_states"] = report_states
        run["report_ids"] = [str(row["id"]) for row in report_ids]
        raw_artifact_metadata = json_loads(artifact_row["metadata_json"], {}) if artifact_row else {}
        artifact_metadata = raw_artifact_metadata if isinstance(raw_artifact_metadata, Mapping) else {}
        # Replay is intentionally local-only, including for historical rows
        # that may retain an old cloud provider for provenance.  Exposing that
        # historical value as a retry target would let a stale browser ask for
        # a provider this deployment no longer permits.
        run["retry_provider"] = "local"
        run["retry_requires_cloud_acknowledgement"] = False
        retry_model = artifact_metadata.get("requested_model") or run.get("requested_model")
        if isinstance(retry_model, str) and retry_model.strip():
            run["retry_model"] = retry_model.strip()
        return run

    def list_runs(
        self,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if search and search.strip():
            needle = f"%{search.strip()}%"
            clauses.append(
                "(id LIKE ? OR phase LIKE ? OR requested_provider LIKE ? "
                "OR requested_model LIKE ? OR effective_provider LIKE ? OR effective_model LIKE ?)"
            )
            params.extend([needle, needle, needle, needle, needle, needle])
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM analysis_runs{where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM analysis_runs{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._run_from_row(row) or {} for row in rows], total

    def claim_run(self, run_id: str) -> bool:
        """Atomically transition a queued run to running.

        A second web process may see the same queued row, but it cannot claim
        it after the first one has committed this compare-and-set update.
        """
        now = utc_now()
        with self.transaction() as conn:
            row = conn.execute("SELECT status, cancel_requested FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            if row["cancel_requested"]:
                conn.execute(
                    "UPDATE analysis_runs SET status = 'canceled', finished_at = ?, updated_at = ?, version = version + 1 WHERE id = ?",
                    (now, now, run_id),
                )
                return False
            if row["status"] != "queued":
                return False
            changed = conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'running', started_at = COALESCE(started_at, ?), updated_at = ?, version = version + 1
                WHERE id = ? AND status = 'queued' AND cancel_requested = 0
                """,
                (now, now, run_id),
            ).rowcount
        return bool(changed)

    def reserve_interrupted_runs_for_recovery(self) -> list[str]:
        """Reserve nonterminal work before filesystem/derived-data recovery.

        A run can be interrupted after normalizing observations or while
        publishing report assets.  Marking it ``recovering`` first prevents a
        second process from claiming it while the caller resets derived state.
        The original upload is intentionally never touched.
        """
        now = utc_now()
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id FROM analysis_runs WHERE status IN ('queued', 'running', 'analysis_finished', 'recovering') AND cancel_requested = 0"
            ).fetchall()
            run_ids = [row["id"] for row in rows]
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'recovering', updated_at = ?, phase = 'recovery',
                    version = version + 1
                WHERE status IN ('queued', 'running', 'analysis_finished', 'recovering')
                  AND cancel_requested = 0
                """,
                (now,),
            )
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'canceled', finished_at = COALESCE(finished_at, ?), updated_at = ?, version = version + 1
                WHERE status IN ('queued', 'running', 'analysis_finished', 'recovering') AND cancel_requested = 1
                """,
                (now, now),
            )
        return run_ids

    def reset_interrupted_run_after_recovery(self, run_id: str) -> dict[str, Any]:
        """Delete only derived rows and make a reserved run safely queueable.

        Observation/candidate/report IDs are deliberately regenerated after a
        process interruption.  Reusing a partial publication would make an
        idempotent resume depend on provider output and filesystem timing;
        restarting from the immutable source artifact is deterministic and
        avoids duplicate observations or half-published reports.
        """
        now = utc_now()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            if row["status"] != "recovering":
                raise ConflictError(f"Run '{run_id}' is not reserved for recovery.")
            # Cascades remove revisions/reviews and candidate graph paths.
            conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
            conn.execute(
                "DELETE FROM observations WHERE artifact_id IN (SELECT id FROM artifacts WHERE run_id = ?)",
                (run_id,),
            )
            conn.execute(
                "UPDATE artifacts SET parse_status = 'pending' WHERE run_id = ?",
                (run_id,),
            )
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'queued', phase = 'recovery', started_at = NULL,
                    generation_finished_at = NULL, finished_at = NULL,
                    counters_json = '{}', metrics_json = '{}',
                    effective_provider = NULL, effective_model = NULL,
                    degraded_reason = NULL, error_code = NULL, error_message = NULL,
                    cancel_requested = 0, updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (now, run_id),
            )
            updated = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(updated) or {}

    def requeue_after_worker_shutdown(self, run_id: str, *, message: str) -> dict[str, Any] | None:
        """Return a cooperatively interrupted active run to the durable queue.

        A process shutdown is not an analyst cancellation and must not turn a
        partially executed source artifact into a terminal ``canceled`` or
        ``failed`` run.  The next healthy process reserves this queued row,
        clears its derived output, and replays the immutable upload.  A real
        user cancellation wins the race: its ``cancel_requested`` marker is
        deliberately never cleared or overwritten here.
        """
        now = utc_now()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            if row["status"] not in {"running", "analysis_finished"} or row["cancel_requested"]:
                return self._run_from_row(row)
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'queued', phase = 'queued', error_code = NULL,
                    error_message = ?, finished_at = NULL,
                    generation_finished_at = NULL, updated_at = ?, version = version + 1
                WHERE id = ? AND status IN ('running', 'analysis_finished') AND cancel_requested = 0
                """,
                (message, now, run_id),
            )
            updated = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(updated)

    def fail_interrupted_run_recovery(self, run_id: str, message: str) -> dict[str, Any]:
        """Leave a recovery failure visible rather than silently wedging work."""
        now = utc_now()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            conn.execute(
                """
                UPDATE analysis_runs
                SET status = 'failed', phase = 'recovery_failed', error_code = 'RecoveryError',
                    error_message = ?, generation_finished_at = COALESCE(generation_finished_at, ?),
                    finished_at = COALESCE(finished_at, ?), updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (message, now, now, now, run_id),
            )
            updated = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(updated) or {}

    def recover_interrupted_runs(self) -> list[str]:
        """Backward-compatible reservation alias for lifecycle integrations."""
        return self.reserve_interrupted_runs_for_recovery()

    def update_run(
        self,
        run_id: str,
        *,
        status: str | None = None,
        phase: str | None = None,
        counters: Mapping[str, Any] | None = None,
        metrics: Mapping[str, Any] | None = None,
        effective_provider: str | None = None,
        effective_model: str | None = None,
        degraded_reason: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        finished: bool = False,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            existing = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if existing is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            current_counters = json_loads(existing["counters_json"], {})
            current_metrics = json_loads(existing["metrics_json"], {})
            if counters:
                current_counters.update(counters)
            if metrics:
                current_metrics.update(metrics)
            assignments = [
                "updated_at = ?",
                "counters_json = ?",
                "metrics_json = ?",
                "version = version + 1",
            ]
            params: list[Any] = [now, json_dumps(current_counters), json_dumps(current_metrics)]
            if status is not None:
                assignments.append("status = ?")
                params.append(status)
            if phase is not None:
                assignments.append("phase = ?")
                params.append(phase)
            if effective_provider is not None:
                assignments.append("effective_provider = ?")
                params.append(effective_provider)
            if effective_model is not None:
                assignments.append("effective_model = ?")
                params.append(effective_model)
            if degraded_reason is not None:
                assignments.append("degraded_reason = ?")
                params.append(degraded_reason)
            if error_code is not None:
                assignments.append("error_code = ?")
                params.append(error_code)
            if error_message is not None:
                assignments.append("error_message = ?")
                params.append(error_message)
            if finished:
                assignments.append("generation_finished_at = COALESCE(generation_finished_at, ?)")
                params.append(now)
                assignments.append("finished_at = COALESCE(finished_at, ?)")
                params.append(now)
            params.append(run_id)
            conn.execute(f"UPDATE analysis_runs SET {', '.join(assignments)} WHERE id = ?", params)
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(row) or {}

    def request_cancel(self, run_id: str, *, expected_version: int) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            if row["status"] not in {"queued", "running", "analysis_finished"}:
                raise ConflictError(
                    f"Run '{run_id}' is not active and cannot be canceled (current state: {row['status']})."
                )
            if row["cancel_requested"]:
                raise ConflictError(f"Cancellation was already requested for run '{run_id}'.")
            if row["version"] != expected_version:
                raise ConflictError(
                    f"Run has version {row['version']}; cancellation was submitted for stale version {expected_version}."
                )
            conn.execute(
                "UPDATE analysis_runs SET cancel_requested = 1, updated_at = ?, version = version + 1 WHERE id = ?",
                (now, run_id),
            )
            updated = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(updated) or {}

    def is_cancel_requested(self, run_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT cancel_requested FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return bool(row and row["cancel_requested"])

    def append_event(
        self,
        run_id: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist an ordered progress event and merge counters/metrics into the run."""
        payload_dict = dict(payload or {})
        now = utc_now()
        with self.transaction() as conn:
            run = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM job_events WHERE run_id = ?", (run_id,)).fetchone()[0]
            event = {**payload_dict, "seq": seq, "at": now, "type": event_type}
            conn.execute(
                "INSERT INTO job_events (run_id, seq, created_at, event_type, payload_json) VALUES (?, ?, ?, ?, ?)",
                (run_id, seq, now, event_type, json_dumps(event)),
            )
            current_counters = json_loads(run["counters_json"], {})
            current_metrics = json_loads(run["metrics_json"], {})
            if isinstance(payload_dict.get("counters"), Mapping):
                current_counters.update(payload_dict["counters"])
            if isinstance(payload_dict.get("metrics"), Mapping):
                current_metrics.update(payload_dict["metrics"])
            phase = payload_dict.get("phase")
            assignments = ["updated_at = ?", "counters_json = ?", "metrics_json = ?", "version = version + 1"]
            params: list[Any] = [now, json_dumps(current_counters), json_dumps(current_metrics)]
            if isinstance(phase, str):
                assignments.append("phase = ?")
                params.append(phase)
            params.append(run_id)
            conn.execute(f"UPDATE analysis_runs SET {', '.join(assignments)} WHERE id = ?", params)
        return event

    def list_events(self, run_id: str, *, after: int = 0, limit: int = 250) -> list[dict[str, Any]]:
        with self._connect() as conn:
            exists = conn.execute("SELECT 1 FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if exists is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            rows = conn.execute(
                "SELECT seq, created_at, event_type, payload_json FROM job_events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
                (run_id, after, limit),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            event = json_loads(row["payload_json"], {})
            event.setdefault("seq", row["seq"])
            event.setdefault("at", row["created_at"])
            event.setdefault("type", row["event_type"])
            events.append(event)
        return events

    # ------------------------------------------------------------------
    # Artifacts, observations, evidence, candidates, and paths
    # ------------------------------------------------------------------
    def create_artifact(
        self,
        *,
        artifact_id: str,
        run_id: str,
        original_name: str,
        media_type: str | None,
        extension: str | None,
        sha256: str,
        storage_key: str,
        byte_size: int,
        kind: str,
        classification: str | None = None,
        redaction_policy: str | None = None,
        parse_status: str = "pending",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    id, run_id, original_name, media_type, extension, sha256, storage_key,
                    byte_size, kind, classification, redaction_policy, parse_status,
                    metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    run_id,
                    original_name,
                    media_type,
                    extension,
                    sha256,
                    storage_key,
                    byte_size,
                    kind,
                    classification,
                    redaction_policy,
                    parse_status,
                    json_dumps(dict(metadata or {})),
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        return self._artifact_from_row(row)

    def update_artifact_parse_status(
        self,
        artifact_id: str,
        parse_status: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        with self.transaction() as conn:
            row = conn.execute("SELECT metadata_json FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Artifact '{artifact_id}' was not found.")
            combined = json_loads(row["metadata_json"], {})
            if metadata:
                combined.update(metadata)
            conn.execute(
                "UPDATE artifacts SET parse_status = ?, metadata_json = ? WHERE id = ?",
                (parse_status, json_dumps(combined), artifact_id),
            )

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        return self._artifact_from_row(row) if row else None

    def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY created_at", (run_id,)).fetchall()
        return [self._artifact_from_row(row) for row in rows]

    def create_observations(self, artifact_id: str, observations: Sequence[Mapping[str, Any]]) -> list[str]:
        if not observations:
            return []
        now = utc_now()
        ids: list[str] = []
        with self.transaction() as conn:
            for item in observations:
                observation_id = str(item.get("id") or uuid.uuid4())
                ids.append(observation_id)
                conn.execute(
                    """
                    INSERT INTO observations (
                        id, artifact_id, source_locator_json, raw_text_hash, normalized_text,
                        context_text, asset_json, severity, explicit_ids_json, parse_status,
                        metadata_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observation_id,
                        artifact_id,
                        json_dumps(item.get("source_locator", {})),
                        item.get("raw_text_hash"),
                        item.get("normalized_text", ""),
                        item.get("context_text"),
                        json_dumps(item.get("asset", {})),
                        item.get("severity"),
                        json_dumps(item.get("explicit_ids", [])),
                        item.get("parse_status", "parsed"),
                        json_dumps(item.get("metadata", {})),
                        now,
                    ),
                )
                text = str(item.get("normalized_text", ""))
                if text:
                    conn.execute(
                        """
                        INSERT INTO evidence_spans (
                            id, observation_id, start_offset, end_offset, text, field_name,
                            source_locator_json, created_at
                        ) VALUES (?, ?, 0, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            observation_id,
                            len(text),
                            text,
                            item.get("evidence_field", "behavior_text"),
                            json_dumps(item.get("source_locator", {})),
                            now,
                        ),
                    )
        return ids

    def create_candidate(
        self,
        *,
        candidate_id: str,
        observation_id: str,
        technique_id: str,
        method: str,
        score: float | None,
        evidence_span_ids: Sequence[str] | None,
        candidate_rank: int | None,
        state: str,
        reason: str | None = None,
        retrieval_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO technique_candidates (
                    id, observation_id, technique_id, method, score, evidence_span_ids_json,
                    candidate_rank, state, reason, retrieval_metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    observation_id,
                    technique_id,
                    method,
                    score,
                    json_dumps(list(evidence_span_ids or [])),
                    candidate_rank,
                    state,
                    reason,
                    json_dumps(dict(retrieval_metadata or {})),
                    now,
                ),
            )

    def create_graph_paths(self, candidate_id: str, paths: Sequence[Mapping[str, Any]]) -> list[str]:
        if not paths:
            return []
        now = utc_now()
        ids: list[str] = []
        with self.transaction() as conn:
            for path in paths:
                path_id = str(path.get("id") or uuid.uuid4())
                ids.append(path_id)
                validation = path.get("validation") if isinstance(path.get("validation"), Mapping) else {}
                validation_state = path.get("validation_state") or validation.get("state") or "unknown"
                validation_reason = path.get("validation_reason")
                if validation_reason is None and validation.get("errors"):
                    validation_reason = "; ".join(str(item) for item in validation["errors"])
                conn.execute(
                    """
                    INSERT INTO graph_paths (
                        id, candidate_id, category, mapping_scope, path_json, graph_snapshot_id,
                        validation_state, validation_reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        path_id,
                        candidate_id,
                        path.get("category", "unspecified"),
                        path.get("mapping_scope", "direct"),
                        json_dumps(path.get("path", path)),
                        path.get("graph_snapshot_id"),
                        validation_state,
                        validation_reason,
                        now,
                    ),
                )
        return ids

    def list_observations(self, artifact_id: str, *, include_evidence: bool = True) -> list[dict[str, Any]]:
        """Return durable source observations with their immutable evidence spans."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM observations WHERE artifact_id = ? ORDER BY created_at, id", (artifact_id,)
            ).fetchall()
            evidence_rows = conn.execute(
                "SELECT * FROM evidence_spans WHERE observation_id IN "
                "(SELECT id FROM observations WHERE artifact_id = ?) ORDER BY created_at, id",
                (artifact_id,),
            ).fetchall() if include_evidence else []
        observations = [self._observation_from_row(row) for row in rows]
        evidence_by_observation: dict[str, list[dict[str, Any]]] = {}
        for row in evidence_rows:
            item = dict(row)
            item["source_locator"] = json_loads(item.pop("source_locator_json", None), {})
            evidence_by_observation.setdefault(str(item["observation_id"]), []).append(item)
        for observation in observations:
            observation["evidence_spans"] = evidence_by_observation.get(str(observation["id"]), [])
        return observations

    def list_candidates(
        self,
        *,
        artifact_id: str,
        technique_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["o.artifact_id = ?"]
        params: list[Any] = [artifact_id]
        if technique_id:
            clauses.append("tc.technique_id = ?")
            params.append(technique_id)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT tc.*, o.source_locator_json, o.normalized_text
                FROM technique_candidates tc
                JOIN observations o ON o.id = tc.observation_id
                WHERE {' AND '.join(clauses)}
                ORDER BY o.created_at, tc.candidate_rank, tc.created_at, tc.id
                """,
                params,
            ).fetchall()
        candidates = [self._candidate_from_row(row) for row in rows]
        for candidate in candidates:
            candidate["source_locator"] = json_loads(candidate.pop("source_locator_json", None), {})
        return candidates

    def list_graph_paths(self, candidate_ids: Sequence[str]) -> list[dict[str, Any]]:
        identifiers = [str(item) for item in candidate_ids if item]
        if not identifiers:
            return []
        placeholders = ", ".join("?" for _ in identifiers)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM graph_paths WHERE candidate_id IN ({placeholders}) ORDER BY category, id",
                identifiers,
            ).fetchall()
        return [self._graph_path_from_row(row) for row in rows]

    # ------------------------------------------------------------------
    # Reports, revisions, reviews, and deletion lifecycle
    # ------------------------------------------------------------------
    def create_report_with_revision(
        self,
        *,
        report_id: str,
        revision_id: str,
        run_id: str,
        artifact_id: str | None,
        display_id: str,
        aggregate_key: str | None,
        technique_id: str | None,
        technique_name: str | None,
        finding_count: int,
        severity_breakdown: Mapping[str, Any] | None,
        qa_verdict: str | None,
        lifecycle_state: str,
        report_data: Mapping[str, Any] | None,
        narrative: Mapping[str, Any] | None,
        markdown_path: str | None,
        json_path: str | None,
        markdown_sha256: str | None,
        json_sha256: str | None,
        mapping_snapshot_hash: str | None = None,
        qa_state: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        created_by: str = "pipeline",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO reports (
                    id, run_id, artifact_id, display_id, aggregate_key, technique_id,
                    technique_name, finding_count, severity_breakdown_json, qa_verdict,
                    lifecycle_state, current_revision_id, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    run_id,
                    artifact_id,
                    display_id,
                    aggregate_key,
                    technique_id,
                    technique_name,
                    finding_count,
                    json_dumps(dict(severity_breakdown or {})),
                    qa_verdict,
                    lifecycle_state,
                    revision_id,
                    now,
                    now,
                    json_dumps(dict(metadata or {})),
                ),
            )
            conn.execute(
                """
                INSERT INTO report_revisions (
                    id, report_id, revision_number, mapping_snapshot_hash, report_json,
                    narrative_json, markdown_path, json_path, markdown_sha256, json_sha256,
                    qa_state, created_at, created_by, metadata_json
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    revision_id,
                    report_id,
                    mapping_snapshot_hash,
                    json_dumps(dict(report_data or {})),
                    json_dumps(dict(narrative or {})),
                    markdown_path,
                    json_path,
                    markdown_sha256,
                    json_sha256,
                    qa_state,
                    now,
                    created_by,
                    json_dumps(dict(metadata or {})),
                ),
            )
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        return self._report_from_row(row)

    def append_rerendered_revision(
        self,
        *,
        report_id: str,
        revision_id: str,
        expected_report_version: int,
        expected_current_revision_id: str,
        report_data: Mapping[str, Any],
        narrative: Mapping[str, Any],
        markdown_path: str,
        json_path: str,
        markdown_sha256: str,
        json_sha256: str,
        mapping_snapshot_hash: str | None,
        created_by: str,
        metadata: Mapping[str, Any],
        finding_count: int,
        severity_breakdown: Mapping[str, Any],
        qa_verdict: str = "MANUAL_REVIEW_REQUIRED",
        lifecycle_state: str = "manual_review_required",
    ) -> dict[str, Any]:
        """Append a renderer-only report revision and make it current.

        This is deliberately narrower than a general mutable-update API:
        every prior report revision and review decision remains untouched, and
        the caller supplies unique immutable asset paths before this short
        transaction begins.  A render refresh changes the active report facts
        (for example after a graph/template correction), so it atomically
        reopens the report for review instead of allowing an approval of the
        old revision to silently apply to the new one.
        """
        now = utc_now()
        with self.transaction() as conn:
            report = conn.execute(
                "SELECT * FROM reports WHERE id = ?",
                (report_id,),
            ).fetchone()
            if report is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            if report["lifecycle_state"] in {"deleted", "deleting", "restoring"}:
                raise ConflictError("A deleted, deleting, or restoring report cannot be re-rendered.")
            if report["lifecycle_state"] == "legacy":
                raise ConflictError(
                    "Legacy reports are read-only because they do not retain durable source observations."
                )
            if report["version"] != expected_report_version or report["current_revision_id"] != expected_current_revision_id:
                raise ConflictError(
                    "Report changed while it was being re-rendered; refresh the report and retry."
                )
            next_revision = int(
                conn.execute(
                    "SELECT COALESCE(MAX(revision_number), 0) + 1 FROM report_revisions WHERE report_id = ?",
                    (report["id"],),
                ).fetchone()[0]
            )
            conn.execute(
                """
                INSERT INTO report_revisions (
                    id, report_id, revision_number, mapping_snapshot_hash, report_json,
                    narrative_json, markdown_path, json_path, markdown_sha256, json_sha256,
                    qa_state, created_at, created_by, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    revision_id,
                    report["id"],
                    next_revision,
                    mapping_snapshot_hash,
                    json_dumps(dict(report_data)),
                    json_dumps(dict(narrative)),
                    markdown_path,
                    json_path,
                    markdown_sha256,
                    json_sha256,
                    lifecycle_state,
                    now,
                    created_by,
                    json_dumps(dict(metadata)),
                ),
            )
            conn.execute(
                """
                UPDATE reports
                SET current_revision_id = ?, finding_count = ?, severity_breakdown_json = ?,
                    qa_verdict = ?, lifecycle_state = ?, updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (
                    revision_id,
                    max(0, int(finding_count)),
                    json_dumps(dict(severity_breakdown)),
                    qa_verdict,
                    lifecycle_state,
                    now,
                    report["id"],
                ),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report["id"],)).fetchone()
        return self._report_from_row(updated)

    def get_report(self, report_id: str, *, include_deleted: bool = True) -> dict[str, Any] | None:
        # ``display_id`` lookup retains compatibility with old bookmarks while
        # UUID remains the canonical API identity.  Display IDs are unique only
        # per run, so ambiguity resolves to the newest record.
        clauses = ["(id = ? OR display_id = ?)"]
        params: list[Any] = [report_id, report_id]
        if not include_deleted:
            clauses.append("lifecycle_state != 'deleted'")
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM reports WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 1",
                params,
            ).fetchone()
        return self._report_from_row(row) if row else None

    def get_current_revision(self, report_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT rr.* FROM report_revisions rr
                JOIN reports r ON r.current_revision_id = rr.id
                WHERE r.id = ? OR r.display_id = ?
                ORDER BY r.created_at DESC LIMIT 1
                """,
                (report_id, report_id),
            ).fetchone()
        return self._revision_from_row(row)

    def get_revision(self, report_id: str, revision_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT rr.* FROM report_revisions rr JOIN reports r ON r.id = rr.report_id
                WHERE (r.id = ? OR r.display_id = ?) AND rr.id = ?
                ORDER BY r.created_at DESC LIMIT 1
                """,
                (report_id, report_id, revision_id),
            ).fetchone()
        return self._revision_from_row(row)

    def list_revisions(self, report_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rr.* FROM report_revisions rr
                JOIN reports r ON r.id = rr.report_id
                WHERE r.id = ? OR r.display_id = ?
                ORDER BY rr.revision_number DESC, rr.created_at DESC
                """,
                (report_id, report_id),
            ).fetchall()
        return [self._revision_from_row(row) or {} for row in rows]

    def list_reports(
        self,
        *,
        run_id: str | None = None,
        technique_id: str | None = None,
        lifecycle_state: str | Sequence[str] | None = None,
        qa_verdict: str | None = None,
        search: str | None = None,
        include_deleted: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if technique_id:
            clauses.append("technique_id = ?")
            params.append(technique_id)
        if lifecycle_state:
            states = [lifecycle_state] if isinstance(lifecycle_state, str) else list(lifecycle_state)
            if len(states) == 1:
                clauses.append("lifecycle_state = ?")
                params.append(states[0])
            elif states:
                clauses.append(f"lifecycle_state IN ({','.join('?' for _ in states)})")
                params.extend(states)
        if qa_verdict:
            clauses.append("qa_verdict = ?")
            params.append(qa_verdict)
        if search:
            needle = f"%{search.strip()}%"
            clauses.append("(display_id LIKE ? OR technique_id LIKE ? OR technique_name LIKE ? OR run_id LIKE ?)")
            params.extend([needle, needle, needle, needle])
        if not include_deleted:
            clauses.append("lifecycle_state != 'deleted'")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM reports{where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM reports{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._report_from_row(row) for row in rows], total

    def review_report(
        self,
        *,
        report_id: str,
        expected_version: int,
        decision: str,
        actor_id: str,
        reason: str | None,
        notes: str | None,
    ) -> dict[str, Any]:
        transition = {
            "approve": "approved",
            "approved": "approved",
            "needs_rework": "needs_rework",
            "rework": "needs_rework",
            "reject": "needs_rework",
            "rejected": "needs_rework",
            "waive": "waived",
            "waived": "waived",
        }
        if decision not in transition:
            raise ConflictError(f"Unsupported review decision '{decision}'.")
        now = utc_now()
        with self.transaction() as conn:
            report = conn.execute(
                "SELECT * FROM reports WHERE id = ? OR display_id = ? ORDER BY created_at DESC LIMIT 1",
                (report_id, report_id),
            ).fetchone()
            if report is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            if report["lifecycle_state"] in {"deleted", "deleting"}:
                raise ConflictError("A deleted or deleting report cannot be reviewed.")
            if report["lifecycle_state"] == "legacy":
                raise ConflictError("Legacy reports are read-only; reprocess the source artifact to create a reviewable revision.")
            if report["version"] != expected_version:
                raise ConflictError(
                    f"Report has version {report['version']}; review was submitted for stale version {expected_version}."
                )
            state = transition[decision]
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = ?, updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (state, now, report["id"]),
            )
            conn.execute(
                """
                INSERT INTO review_decisions (
                    id, report_revision_id, actor_id, decision, reason, notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    report["current_revision_id"],
                    actor_id,
                    decision,
                    reason,
                    notes,
                    now,
                ),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report["id"],)).fetchone()
        return self._report_from_row(updated)

    def bulk_approve_review_pending_reports(
        self,
        *,
        run_id: str,
        expected_run_version: int,
        actor_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Approve every actionable review-pending report in one run.

        The query, state changes, per-report review decisions, completion
        recomputation, and summary event intentionally share one
        ``BEGIN IMMEDIATE`` transaction.  A concurrent review, rerender, or
        lifecycle transition therefore either happens before this operation
        (and makes the supplied run version stale) or after the complete
        batch; it can never leave a partially approved run.

        A decision is attached to the current revision of *each* report.  The
        bulk action does not manufacture a synthetic run-level review in place
        of report-level audit history, and it never changes a report's current
        revision pointer.
        """
        shared_reason = str(reason or "").strip()
        if not shared_reason:
            raise ConflictError("A non-empty shared approval reason is required.")
        reviewer = str(actor_id or "").strip()
        if not reviewer:
            raise ConflictError("A server-derived reviewer identity is required.")

        now = utc_now()
        pending_states = tuple(sorted(REVIEW_PENDING_REPORT_STATES))
        placeholders = ", ".join("?" for _ in pending_states)
        with self.transaction() as conn:
            run = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError(f"Run '{run_id}' was not found.")
            if run["status"] in {"failed", "canceled"}:
                raise ConflictError(
                    f"Run '{run_id}' is {run['status']} and cannot receive a bulk review decision."
                )
            if int(run["version"]) != int(expected_run_version):
                raise ConflictError(
                    f"Run has version {run['version']}; bulk approval was submitted for stale version {expected_run_version}."
                )

            reports = conn.execute(
                f"""
                SELECT r.*, rr.id AS current_revision_exists
                FROM reports r
                LEFT JOIN report_revisions rr
                  ON rr.id = r.current_revision_id AND rr.report_id = r.id
                WHERE r.run_id = ? AND r.lifecycle_state IN ({placeholders})
                ORDER BY r.created_at, r.id
                """,
                (run_id, *pending_states),
            ).fetchall()
            if not reports:
                raise NoReviewPendingReportsError(
                    f"Run '{run_id}' has no review-pending reports to approve."
                )

            blocked_states = sorted(
                {str(report["lifecycle_state"]) for report in reports if report["lifecycle_state"] not in BULK_APPROVABLE_REVIEW_STATES}
            )
            if blocked_states:
                raise ConflictError(
                    "Bulk approval cannot proceed while the run contains reports in "
                    f"an in-flight lifecycle state: {', '.join(blocked_states)}."
                )
            missing_revision = [str(report["id"]) for report in reports if not report["current_revision_exists"]]
            if missing_revision:
                raise ConflictError(
                    "Bulk approval cannot proceed because one or more pending reports "
                    "do not have a valid current revision."
                )

            approved_ids: list[str] = []
            approved_rows: list[sqlite3.Row] = []
            for report in reports:
                changed = conn.execute(
                    """
                    UPDATE reports
                    SET lifecycle_state = 'approved', updated_at = ?, version = version + 1
                    WHERE id = ? AND lifecycle_state = ? AND current_revision_id = ?
                    """,
                    (
                        now,
                        report["id"],
                        report["lifecycle_state"],
                        report["current_revision_id"],
                    ),
                ).rowcount
                if changed != 1:  # defensive: a future repository change must not create a partial batch
                    raise ConflictError(
                        f"Report '{report['id']}' changed while bulk approval was being prepared."
                    )
                conn.execute(
                    """
                    INSERT INTO review_decisions (
                        id, report_revision_id, actor_id, decision, reason, notes, created_at
                    ) VALUES (?, ?, ?, 'approve', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        report["current_revision_id"],
                        reviewer,
                        shared_reason,
                        shared_reason,
                        now,
                    ),
                )
                approved_ids.append(str(report["id"]))
                updated_report = conn.execute(
                    "SELECT * FROM reports WHERE id = ?",
                    (report["id"],),
                ).fetchone()
                if updated_report is None:  # pragma: no cover - guarded by the successful update above
                    raise ConflictError(f"Report '{report['id']}' disappeared during bulk approval.")
                approved_rows.append(updated_report)

            updated_run = self._recompute_run_completion_locked(
                conn,
                run_id,
                now=now,
                phase="review",
            )

            seq = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM job_events WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
            event = {
                "seq": seq,
                "at": now,
                "type": "run_review_pending_bulk_approved",
                "phase": "review",
                "message": f"Bulk-approved {len(approved_ids)} review-pending report(s).",
                "current": {
                    "actor": reviewer,
                    "report_count": len(approved_ids),
                    "report_ids": approved_ids,
                },
                "counters": dict(updated_run.get("counters") or {}),
                "review": {
                    "decision": "approve",
                    "reason": shared_reason,
                    "report_count": len(approved_ids),
                },
            }
            conn.execute(
                "INSERT INTO job_events (run_id, seq, created_at, event_type, payload_json) VALUES (?, ?, ?, ?, ?)",
                (run_id, seq, now, event["type"], json_dumps(event)),
            )

        return {
            "run": updated_run,
            "reports": [self._report_from_row(row) for row in approved_rows],
            "event": event,
        }

    def begin_delete(
        self,
        *,
        report_id: str,
        expected_version: int,
        actor_id: str,
        reason: str,
        undo_expires_at: str,
        trash_manifest: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Persist a delete journal before any report asset is moved.

        The journal's ``delete_prepared`` state is intentionally durable.  If
        a process dies during the following filesystem renames, startup
        reconciliation can restore the planned assets and return the report to
        its prior state without guessing what happened.
        """
        now = utc_now()
        audit_id = str(uuid.uuid4())
        with self.transaction() as conn:
            report = conn.execute(
                "SELECT * FROM reports WHERE id = ? OR display_id = ? ORDER BY created_at DESC LIMIT 1",
                (report_id, report_id),
            ).fetchone()
            if report is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            if report["lifecycle_state"] in {"deleted", "deleting", "restoring"}:
                raise ConflictError("Report is already deleted or being changed by another lifecycle operation.")
            if report["lifecycle_state"] not in DELETE_ELIGIBLE_REPORT_STATES:
                raise ConflictError(
                    "A report must be approved, waived, or auto-passed before deletion; "
                    "record a review decision so deletion cannot bypass the run review gate."
                )
            if report["version"] != expected_version:
                raise ConflictError(
                    f"Report has version {report['version']}; delete was submitted for stale version {expected_version}."
                )
            conn.execute(
                "UPDATE reports SET lifecycle_state = 'deleting', updated_at = ?, version = version + 1 WHERE id = ?",
                (now, report["id"]),
            )
            conn.execute(
                """
                INSERT INTO deletion_audit (
                    id, target_type, target_id, report_id, actor_id, reason, requested_at,
                    undo_expires_at, prior_state, trash_manifest_json, operation_state
                ) VALUES (?, 'report', ?, ?, ?, ?, ?, ?, ?, ?, 'delete_prepared')
                """,
                (
                    audit_id,
                    report["id"],
                    report["id"],
                    actor_id,
                    reason,
                    now,
                    undo_expires_at,
                    report["lifecycle_state"],
                    json_dumps(dict(trash_manifest)),
                ),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report["id"],)).fetchone()
            audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
        return self._report_from_row(updated), self._audit_from_row(audit)

    def complete_delete(self, audit_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Commit the database half of a completed journaled delete."""
        now = utc_now()
        with self.transaction() as conn:
            audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
            if audit is None:
                raise NotFoundError(f"Deletion audit '{audit_id}' was not found.")
            if audit["operation_state"] != "delete_prepared":
                raise ConflictError("Deletion operation is not waiting to be completed.")
            report = conn.execute("SELECT * FROM reports WHERE id = ?", (audit["report_id"],)).fetchone()
            if report is None or report["lifecycle_state"] != "deleting":
                raise ConflictError("Report is not reserved for the recorded deletion operation.")
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = 'deleted', deleted_at = ?, updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (now, now, report["id"]),
            )
            conn.execute(
                "UPDATE deletion_audit SET completed_at = ?, operation_state = 'completed' WHERE id = ?",
                (now, audit_id),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report["id"],)).fetchone()
            completed_audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
        return self._report_from_row(updated), self._audit_from_row(completed_audit)

    def abort_delete(self, audit_id: str) -> dict[str, Any]:
        """Roll a prepared delete back to its exact former report state."""
        now = utc_now()
        with self.transaction() as conn:
            audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
            if audit is None:
                raise NotFoundError(f"Deletion audit '{audit_id}' was not found.")
            if audit["operation_state"] != "delete_prepared":
                raise ConflictError("Deletion operation cannot be aborted after it has completed.")
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = ?, updated_at = ?, version = version + 1
                WHERE id = ? AND lifecycle_state = 'deleting'
                """,
                (audit["prior_state"] or "manual_review_required", now, audit["report_id"]),
            )
            conn.execute(
                "UPDATE deletion_audit SET operation_state = 'delete_aborted', completed_at = ? WHERE id = ?",
                (now, audit_id),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (audit["report_id"],)).fetchone()
        return self._report_from_row(updated) or {}

    @staticmethod
    def _audit_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        data = dict(row)
        data["trash_manifest"] = json_loads(data.pop("trash_manifest_json", None), {})
        return data

    def latest_deletion_audit(self, report_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM deletion_audit
                WHERE report_id = ? AND operation_state = 'completed' AND restored_at IS NULL
                ORDER BY requested_at DESC LIMIT 1
                """,
                (report_id,),
            ).fetchone()
        return self._audit_from_row(row)

    def list_pending_deletion_operations(self, *, limit: int = 500) -> list[dict[str, Any]]:
        """Return crash-recoverable delete/restore journals in deterministic order."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM deletion_audit
                WHERE operation_state IN ('delete_prepared', 'restore_prepared')
                ORDER BY requested_at, id
                LIMIT ?
                """,
                (max(1, min(limit, 5_000)),),
            ).fetchall()
        return [self._audit_from_row(row) or {} for row in rows]

    def list_expired_deletion_audits(self, *, now: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Return restorable tombstones whose asset-retention period elapsed."""
        current = now or utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM deletion_audit
                WHERE restored_at IS NULL
                  AND purged_at IS NULL
                  AND operation_state = 'completed'
                  AND undo_expires_at IS NOT NULL
                  AND undo_expires_at < ?
                ORDER BY undo_expires_at
                LIMIT ?
                """,
                (current, max(1, min(limit, 5000))),
            ).fetchall()
        return [self._audit_from_row(row) or {} for row in rows]

    def mark_deletion_purged(self, audit_id: str, *, purged_at: str | None = None) -> None:
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE deletion_audit SET purged_at = ? WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL",
                (purged_at or utc_now(), audit_id),
            ).rowcount
            if not changed:
                raise ConflictError(f"Deletion audit '{audit_id}' is not eligible for purge.")

    def begin_restore(
        self,
        *,
        report_id: str,
        expected_version: int,
        actor_id: str,
        reason: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Persist a restore journal before moving any trashed asset back."""
        now = utc_now()
        with self.transaction() as conn:
            report = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
            if report is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            if report["lifecycle_state"] != "deleted":
                raise ConflictError("Only a deleted report can be restored.")
            if report["version"] != expected_version:
                raise ConflictError(
                    f"Report has version {report['version']}; restore was submitted for stale version {expected_version}."
                )
            audit = conn.execute(
                """
                SELECT * FROM deletion_audit
                WHERE report_id = ? AND restored_at IS NULL AND operation_state = 'completed'
                ORDER BY requested_at DESC LIMIT 1
                """,
                (report_id,),
            ).fetchone()
            if audit is None:
                raise ConflictError("No restorable deletion record exists for this report.")
            # Expiry is checked by the service before moving files as well.  A
            # lexical comparison is safe because timestamps are normalized UTC.
            if audit["undo_expires_at"] and audit["undo_expires_at"] < now:
                raise ConflictError("The restore window for this report has expired.")
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = 'restoring', updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (now, report_id),
            )
            conn.execute(
                """
                UPDATE deletion_audit
                SET restore_actor_id = ?, restore_reason = ?, operation_state = 'restore_prepared'
                WHERE id = ?
                """,
                (actor_id, reason, audit["id"]),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
            updated_audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit["id"],)).fetchone()
        return self._report_from_row(updated) or {}, self._audit_from_row(updated_audit) or {}

    def complete_restore(self, audit_id: str) -> dict[str, Any]:
        """Commit a restore once every asset has moved back from trash."""
        now = utc_now()
        with self.transaction() as conn:
            audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
            if audit is None:
                raise NotFoundError(f"Deletion audit '{audit_id}' was not found.")
            if audit["operation_state"] != "restore_prepared":
                raise ConflictError("Restore operation is not waiting to be completed.")
            report = conn.execute("SELECT * FROM reports WHERE id = ?", (audit["report_id"],)).fetchone()
            if report is None or report["lifecycle_state"] != "restoring":
                raise ConflictError("Report is not reserved for the recorded restore operation.")
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = ?, deleted_at = NULL, updated_at = ?, version = version + 1
                WHERE id = ?
                """,
                (audit["prior_state"] or "manual_review_required", now, report["id"]),
            )
            conn.execute(
                "UPDATE deletion_audit SET restored_at = ?, operation_state = 'restored' WHERE id = ?",
                (now, audit_id),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (report["id"],)).fetchone()
        return self._report_from_row(updated) or {}

    def abort_restore(self, audit_id: str) -> dict[str, Any]:
        """Return an interrupted restore to its durable deleted/tombstone state."""
        now = utc_now()
        with self.transaction() as conn:
            audit = conn.execute("SELECT * FROM deletion_audit WHERE id = ?", (audit_id,)).fetchone()
            if audit is None:
                raise NotFoundError(f"Deletion audit '{audit_id}' was not found.")
            if audit["operation_state"] != "restore_prepared":
                raise ConflictError("Restore operation cannot be aborted after it has completed.")
            conn.execute(
                """
                UPDATE reports
                SET lifecycle_state = 'deleted', updated_at = ?, version = version + 1
                WHERE id = ? AND lifecycle_state = 'restoring'
                """,
                (now, audit["report_id"]),
            )
            conn.execute(
                "UPDATE deletion_audit SET operation_state = 'completed' WHERE id = ?",
                (audit_id,),
            )
            updated = conn.execute("SELECT * FROM reports WHERE id = ?", (audit["report_id"],)).fetchone()
        return self._report_from_row(updated) or {}

    def set_revision_pdf(self, revision_id: str, *, pdf_path: str, pdf_sha256: str) -> None:
        with self.transaction() as conn:
            changed = conn.execute(
                "UPDATE report_revisions SET pdf_path = ?, pdf_sha256 = ? WHERE id = ?",
                (pdf_path, pdf_sha256, revision_id),
            ).rowcount
            if not changed:
                raise NotFoundError(f"Revision '{revision_id}' was not found.")

    def report_reviews(self, report_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rd.* FROM review_decisions rd
                JOIN report_revisions rr ON rr.id = rd.report_revision_id
                JOIN reports r ON r.id = rr.report_id
                WHERE r.id = ? OR r.display_id = ?
                ORDER BY rd.created_at DESC
                """,
                (report_id, report_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def _recompute_run_completion_locked(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        now: str | None = None,
        phase: str | None = None,
    ) -> dict[str, Any]:
        """Apply the completion gate within an already-open write transaction."""
        run = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        if run is None:
            raise NotFoundError(f"Run '{run_id}' was not found.")
        if run["status"] in {"failed", "canceled"}:
            return self._run_from_row(run) or {}
        rows = conn.execute(
            "SELECT lifecycle_state, COUNT(*) AS n FROM reports WHERE run_id = ? GROUP BY lifecycle_state",
            (run_id,),
        ).fetchall()
        states = {row["lifecycle_state"]: row["n"] for row in rows}
        pending = sum(
            count for state, count in states.items() if state in REVIEW_PENDING_REPORT_STATES
        )
        counters = json_loads(run["counters_json"], {})
        # The worker materializes every unresolved observation into one
        # durable UNMAPPED triage report, so it is represented by the same
        # actionable state count as every other review item. Keep the
        # observation counter for progress/audit, but do not add it again here
        # or one triage report would appear as N pending items.
        terminal = "awaiting_review" if pending else "completed"
        current = now or utc_now()
        counters.update(
            {
                "reports_total": sum(states.values()),
                "reports_completed": sum(states.values()),
                "reports_review_pending": pending,
                "reports_auto_passed": states.get("auto_passed", 0),
                "reports_flagged": states.get("auto_flagged", 0),
            }
        )
        assignments = [
            "status = ?",
            "counters_json = ?",
            "updated_at = ?",
            "generation_finished_at = COALESCE(generation_finished_at, ?)",
            "finished_at = CASE WHEN ? = 'completed' THEN COALESCE(finished_at, ?) ELSE finished_at END",
            "version = version + 1",
        ]
        params: list[Any] = [terminal, json_dumps(counters), current, current, terminal, current]
        if phase is not None:
            assignments.append("phase = ?")
            params.append(phase)
        params.append(run_id)
        conn.execute(
            f"UPDATE analysis_runs SET {', '.join(assignments)} WHERE id = ?",
            params,
        )
        updated = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_from_row(updated) or {}

    def recompute_run_completion(self, run_id: str) -> dict[str, Any]:
        """Apply the review gate after generation/review/delete transitions."""
        with self.transaction() as conn:
            return self._recompute_run_completion_locked(conn, run_id)
