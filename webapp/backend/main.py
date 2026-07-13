"""Durable FastAPI lifecycle for MITRE CSD-H analyses.

The web path is intentionally separate from the legacy CLI paths: each request
gets a UUID workspace, SQLite/WAL records survive restarts, and reports have
stable UUID identities/revisions rather than mutable ``CONSOL-Txxxx`` files.

Pipeline adapter contract
-------------------------
``run_pipeline(engine, input_csv, output_dir, provider_name=None,
progress_cb=..., cancel_cb=...)`` should return iterable result dictionaries.
``progress_cb`` may receive a legacy stage string or a structured event mapping
with ``type``, ``phase``, ``message``, ``current``, ``counters`` and ``metrics``.
``cancel_cb`` is optional for backward compatibility.  A result should include
``report_id``/``report_key``, technique fields, QA verdict, and optionally
``markdown_path``/``json_path`` under the supplied output directory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, RLock
from typing import Any, Callable, Mapping

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .auth import AuthPolicy, AuthenticationError, AuthorizationError, Principal, parse_token_map
from .db import (
    ConflictError,
    LifecycleRepository,
    NoReviewPendingReportsError,
    NotFoundError,
    REVIEW_PENDING_REPORT_STATES,
    utc_now,
)
from .maintenance import reconcile_incomplete_deletion_operations
from .pipeline_adapter import (
    LocalModelConfigurationError,
    NormalizationError,
    RunCanceled,
    discover_local_models,
    invoke_pipeline,
    normalize_artifact,
    rerender_report_from_durable_evidence,
    resolve_pipeline_asset,
    validate_local_model_name,
)
from .validation import ALLOWED_EXTENSIONS, ArtifactValidationError, inspect_artifact, validate_text_artifact
from .workspace import RunWorkspace, WorkspaceError


logger = logging.getLogger("mitre_csdh.webapp")
logging.basicConfig(level=logging.INFO)

LOCAL_ONLY_PROVIDER = "local"
VALID_PROVIDERS = frozenset({LOCAL_ONLY_PROVIDER})
TERMINAL_RUN_STATES = {"completed", "failed", "canceled"}
REVIEW_STATE_ALIASES: dict[str, tuple[str, ...]] = {
    "pending": tuple(sorted(REVIEW_PENDING_REPORT_STATES)),
    "needs_review": tuple(sorted(REVIEW_PENDING_REPORT_STATES)),
    "manual": ("manual_review_required",),
    "flagged": ("auto_flagged",),
    "rework": ("needs_rework", "rejected"),
    "attention": ("auto_flagged", "needs_rework", "rejected"),
    "accepted": ("approved", "auto_passed", "waived"),
}


@dataclass(frozen=True)
class BackendSettings:
    base_dir: Path
    data_dir: Path
    runs_dir: Path
    database_path: Path
    frontend_dist: Path
    legacy_reports_dir: Path
    max_upload_bytes: int = 25 * 1024 * 1024
    max_text_characters: int = 2_000_000
    max_workers: int = 1
    delete_retention_hours: int = 24
    # A private single-operator Tailnet may explicitly disable application
    # authentication. The deployed default remains token authentication, so
    # shared deployments do not treat caller-supplied review actor strings as
    # an authoritative identity.
    auth_mode: str = "disabled"
    auth_token_principals: Mapping[str, Principal] = field(default_factory=dict)
    auth_proxy_header: str = "X-CSDH-Authenticated-User"
    auth_configuration_error: str | None = None

    @classmethod
    def from_environment(cls) -> "BackendSettings":
        base = Path(__file__).resolve().parents[2]
        # Keep the CSDH_* names for direct deployments while honoring the
        # documented MITRE_CSDH_* / compose variables as well.
        data = Path(os.environ.get("CSDH_DATA_DIR") or os.environ.get("MITRE_CSDH_DATA_DIR") or str(base / "data")).resolve()
        db_path = Path(os.environ.get("CSDH_DB_PATH", str(data / "csdh.sqlite3"))).resolve()
        retention_hours_value = os.environ.get("CSDH_DELETE_RETENTION_HOURS")
        if retention_hours_value is None:
            retention_hours_value = str(int(os.environ.get("REPORT_DELETE_RETENTION_DAYS", "30")) * 24)
        auth_mode = (os.environ.get("CSDH_AUTH_MODE") or "token").strip().lower()
        auth_configuration_error: str | None = None
        token_principals: Mapping[str, Principal] = {}
        try:
            if auth_mode == "token":
                raw_tokens = os.environ.get("CSDH_AUTH_TOKENS_JSON")
                # A single-token setting is convenient for a private
                # single-user deployment while the JSON map supports roles.
                if not raw_tokens and os.environ.get("CSDH_AUTH_TOKEN"):
                    raw_tokens = json.dumps(
                        {
                            os.environ["CSDH_AUTH_TOKEN"]: {
                                "actor": os.environ.get("CSDH_AUTH_ACTOR", "local-admin"),
                                "roles": ["admin"],
                            }
                        }
                    )
                token_principals = parse_token_map(raw_tokens)
                if not token_principals:
                    auth_configuration_error = (
                        "CSDH_AUTH_MODE=token requires CSDH_AUTH_TOKENS_JSON "
                        "or CSDH_AUTH_TOKEN; refusing to start an unauthenticated production API."
                    )
            elif auth_mode not in {"disabled", "trusted_proxy"}:
                auth_configuration_error = f"Unsupported CSDH_AUTH_MODE '{auth_mode}'."
        except AuthenticationError as exc:
            auth_configuration_error = str(exc)
        return cls(
            base_dir=base,
            data_dir=data,
            runs_dir=data / "runs",
            database_path=db_path,
            frontend_dist=base / "webapp" / "frontend" / "dist",
            legacy_reports_dir=base / "reports",
            max_upload_bytes=int(os.environ.get("CSDH_MAX_UPLOAD_BYTES") or os.environ.get("MAX_UPLOAD_BYTES") or 25 * 1024 * 1024),
            max_text_characters=int(os.environ.get("CSDH_MAX_TEXT_CHARACTERS", 2_000_000)),
            max_workers=max(1, int(os.environ.get("CSDH_WORKER_CONCURRENCY", "1"))),
            delete_retention_hours=max(1, int(retention_hours_value)),
            auth_mode=auth_mode,
            auth_token_principals=token_principals,
            auth_proxy_header=(os.environ.get("CSDH_TRUSTED_PROXY_USER_HEADER") or "X-CSDH-Authenticated-User").strip(),
            auth_configuration_error=auth_configuration_error,
        )


class ApiProblem(Exception):
    def __init__(self, status_code: int, code: str, message: str, details: Mapping[str, Any] | None = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = dict(details or {})
        super().__init__(message)


class ReviewRequest(BaseModel):
    decision: str = Field(min_length=1, max_length=40)
    actor: str = Field(min_length=1, max_length=200)
    reason: str | None = Field(default=None, max_length=4_000)
    notes: str | None = Field(default=None, max_length=20_000)
    note: str | None = Field(default=None, max_length=20_000)
    version: int | None = Field(default=None, ge=1)


class BulkApproveReviewPendingRequest(BaseModel):
    """One auditable reason for approving a run's current pending reports.

    The caller must not supply an actor: the endpoint records only the
    authenticated principal returned by :func:`_authorize`.  Extra fields are
    rejected so a stale browser-side actor cannot be mistaken for an audit
    identity by a future handler change.
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=4_000)
    version: int | None = Field(default=None, ge=1)


class DeleteRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=4_000)
    version: int | None = Field(default=None, ge=1)


class RestoreRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=200)
    reason: str | None = Field(default=None, max_length=4_000)
    version: int | None = Field(default=None, ge=1)


class RetryRequest(BaseModel):
    """Optional local-model override for replaying retained source evidence."""

    model: str | None = Field(default=None, max_length=256)
    # Kept only so an older browser client can submit its prior payload. It is
    # ignored: cloud providers are not available through this backend.
    cloud_acknowledged: bool = False


def _default_engine_factory() -> Any:
    # Import lazily so API/unit-test imports do not trigger model loading or a
    # potential Hugging Face download before FastAPI lifespan begins.
    from scripts.graph_engine import KnowledgeGraphEngine

    return KnowledgeGraphEngine()


def _problem_from_exception(exc: Exception) -> ApiProblem:
    if isinstance(exc, ApiProblem):
        return exc
    if isinstance(exc, ArtifactValidationError):
        return ApiProblem(exc.status_code, exc.code, str(exc))
    if isinstance(exc, NormalizationError):
        # The renderer uses this for an unavailable/ambiguous retained-evidence
        # case. It is an actionable conflict, not an internal server error.
        return ApiProblem(409, "rerender_not_available", str(exc))
    if isinstance(exc, WorkspaceError):
        return ApiProblem(400, "workspace_error", str(exc))
    if isinstance(exc, NotFoundError):
        return ApiProblem(404, "not_found", str(exc))
    if isinstance(exc, NoReviewPendingReportsError):
        return ApiProblem(409, "no_review_pending_reports", str(exc))
    if isinstance(exc, ConflictError):
        return ApiProblem(409, "conflict", str(exc))
    return ApiProblem(500, "internal_error", "An unexpected backend error occurred.")


def _authorize(
    app: FastAPI,
    request: Request,
    permission: str,
    *,
    declared_actor: str | None = None,
) -> str:
    """Require a configured principal and return the server-derived actor ID.

    In explicitly disabled local/Tailnet mode, the legacy required actor field
    is retained as audit metadata. In token or trusted-proxy modes the client
    cannot impersonate another reviewer: a non-empty body actor must match the
    authenticated principal and the stored decision always uses that identity.
    """
    settings: BackendSettings = app.state.settings
    if settings.auth_configuration_error:
        raise ApiProblem(503, "auth_configuration_error", settings.auth_configuration_error)
    policy: AuthPolicy = app.state.auth_policy
    try:
        principal = policy.require(request, permission)
    except AuthorizationError as exc:
        raise ApiProblem(403, "forbidden", str(exc)) from exc
    except AuthenticationError as exc:
        raise ApiProblem(401, "authentication_required", str(exc)) from exc
    claimed = (declared_actor or "").strip()
    if principal is None:
        return claimed or "development-local"
    if claimed and claimed != principal.actor_id:
        raise ApiProblem(
            403,
            "actor_identity_mismatch",
            "The supplied actor does not match the authenticated server identity.",
        )
    return principal.actor_id


def _as_event(raw: Any, *, artifact_id: str | None, started_at: datetime) -> tuple[str, dict[str, Any]]:
    """Normalize either pipeline progress format into a persisted event."""
    if isinstance(raw, Mapping):
        payload = dict(raw)
        event_type = str(payload.pop("type", "pipeline_progress"))
    else:
        stage = str(raw or "working")
        payload = {"phase": stage, "message": stage}
        event_type = "pipeline_progress"
    current = payload.get("current")
    if not isinstance(current, Mapping):
        current = {}
    payload["current"] = {**current, **({"artifact_id": artifact_id} if artifact_id and "artifact_id" not in current else {})}
    payload.setdefault("phase", "pipeline")
    payload.setdefault("message", str(payload["phase"]))
    metrics = dict(payload.get("metrics") or {})
    elapsed = max(0.0, (datetime.now(timezone.utc) - started_at).total_seconds())
    metrics.setdefault("elapsed_seconds", round(elapsed, 3))
    counters = payload.get("counters")
    if isinstance(counters, Mapping):
        completed = counters.get("techniques_completed") or counters.get("observations_completed")
        total = counters.get("techniques_total") or counters.get("observations_total")
        if isinstance(completed, (int, float)) and elapsed > 0:
            rate = completed / elapsed * 60
            metrics.setdefault("items_per_minute", round(rate, 3))
            if isinstance(total, (int, float)) and total > completed and rate > 0:
                metrics.setdefault("eta_seconds", round((total - completed) / rate * 60, 1))
    payload["metrics"] = metrics
    return event_type, payload


def _report_state(result: Mapping[str, Any], provider_name: str | None, report_data: Mapping[str, Any]) -> str:
    qa = report_data.get("qa", {})
    qa_verdict = qa.get("verdict", "") if isinstance(qa, Mapping) else ""
    verdict = str(result.get("qa_verdict") or report_data.get("qa_verdict") or qa_verdict).upper()
    explicit = str(result.get("lifecycle_state") or "").lower()
    if explicit in {"approved", "auto_passed", "auto_flagged", "manual_review_required", "needs_rework"}:
        return explicit
    if provider_name == "none" or verdict in {"MANUAL_REVIEW_REQUIRED", "PENDING", "", "DEGRADED"}:
        return "manual_review_required"
    if verdict in {"FLAG", "FAIL", "FAILED", "REVIEW"}:
        return "auto_flagged"
    return "auto_passed" if verdict == "PASS" else "manual_review_required"


def _source_locator_key(locator: Mapping[str, Any] | None) -> tuple[str, str]:
    """Normalize tabular/text source locators for evidence-to-candidate links."""
    data = dict(locator or {})
    if data.get("sheet") is not None:
        return (str(data.get("sheet")), str(data.get("row", "")))
    if data.get("object_id") is not None:
        return (str(data.get("kind", "json_object")), str(data.get("object_id")))
    return (str(data.get("kind", "")), str(data.get("chunk", data.get("row", ""))))


def _graph_snapshot_from_mapping(value: Any) -> str | None:
    """Return a graph snapshot only when a mapping bundle explicitly carries it."""
    if not isinstance(value, Mapping):
        return None
    snapshot_id = value.get("graph_snapshot_id")
    if isinstance(snapshot_id, str) and snapshot_id.strip():
        return snapshot_id.strip()
    return None


def _report_graph_snapshot_id(
    *,
    report_data: Mapping[str, Any],
    revision_metadata: Mapping[str, Any],
    graph_paths: list[Mapping[str, Any]],
    candidates: list[Mapping[str, Any]],
    run_graph_snapshot_id: Any,
) -> str | None:
    """Resolve a report's actual graph snapshot without confusing it with a hash.

    A mapping snapshot hash identifies the serialized mapping payload; it is not
    the graph snapshot identifier.  Prefer the report's persisted framework
    bundle, then durable graph-path/candidate provenance for older report JSON,
    and use the run snapshot only as a final legacy fallback.
    """
    snapshot_id = _graph_snapshot_from_mapping(report_data.get("framework_mappings"))
    if snapshot_id:
        return snapshot_id
    pipeline_result = revision_metadata.get("pipeline_result")
    if isinstance(pipeline_result, Mapping):
        snapshot_id = _graph_snapshot_from_mapping(pipeline_result.get("framework_mappings"))
        if snapshot_id:
            return snapshot_id
    for path in graph_paths:
        snapshot_id = _graph_snapshot_from_mapping(path)
        if snapshot_id:
            return snapshot_id
    for candidate in candidates:
        retrieval_metadata = candidate.get("retrieval_metadata")
        snapshot_id = _graph_snapshot_from_mapping(retrieval_metadata)
        if snapshot_id:
            return snapshot_id
    if isinstance(run_graph_snapshot_id, str) and run_graph_snapshot_id.strip():
        return run_graph_snapshot_id.strip()
    return None


def _persist_result_candidates(
    repository: LifecycleRepository,
    *,
    artifact_id: str,
    result: Mapping[str, Any],
    persisted_observations: list[Mapping[str, Any]],
) -> list[str]:
    """Persist source-linked candidates and every validated mapping path.

    The pipeline works in technique aggregates, while the durable model must
    retain the observation-level evidence for each aggregate.  Source locators
    written by the normalizer and propagated by ``consolidate_findings`` make
    that link deterministic; no fuzzy re-matching of evidence text is used.
    """
    by_locator: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for observation in persisted_observations:
        by_locator.setdefault(_source_locator_key(observation.get("source_locator")), []).append(observation)
    paths = list((result.get("framework_mappings") or {}).get("paths") or [])
    technique_id = str(result.get("technique_id") or "")
    candidate_ids: list[str] = []
    paths_persisted = False
    seen_observation_ids: set[str] = set()
    for source in result.get("observations") or []:
        if not isinstance(source, Mapping):
            continue
        candidates = by_locator.get(_source_locator_key(source.get("source_locator")), [])
        for observation in candidates:
            observation_id = str(observation.get("id") or "")
            if not observation_id or observation_id in seen_observation_ids:
                continue
            seen_observation_ids.add(observation_id)
            method = str(source.get("resolution_method") or "pipeline_match")
            raw_score = source.get("resolution_score")
            try:
                score = float(raw_score) if raw_score is not None else None
            except (TypeError, ValueError):
                score = None
            candidate_id = str(uuid.uuid4())
            evidence_ids = [str(span["id"]) for span in observation.get("evidence_spans", []) if span.get("id")]
            state = "accepted" if method in {"explicit_attack_id", "canonical_attack_name"} else "needs_review"
            repository.create_candidate(
                candidate_id=candidate_id,
                observation_id=observation_id,
                technique_id=technique_id,
                method=method,
                score=score,
                evidence_span_ids=evidence_ids,
                candidate_rank=1,
                state=state,
                reason=("Exact deterministic technique evidence." if state == "accepted" else "Semantic candidate requires review."),
                retrieval_metadata={
                    "graph_snapshot_id": (result.get("framework_mappings") or {}).get("graph_snapshot_id"),
                    "provider_graph_tool_crawl": result.get("llm_graph_tool_crawl", {}),
                },
            )
            # Mapping paths belong to the technique aggregate, not to every
            # source observation that supports it.  Persist the authoritative
            # path set once against the first durable candidate; report detail
            # queries all aggregate candidates and therefore still returns the
            # complete set without multiplying large path bundles per host.
            if paths and not paths_persisted:
                repository.create_graph_paths(candidate_id, paths)
                paths_persisted = True
            candidate_ids.append(candidate_id)
    return candidate_ids


class WorkerShutdown(RuntimeError):
    """Cooperative interruption used only for a process/service shutdown."""


class DurableWorker:
    """Small bounded worker over durable SQLite queue rows.

    SQLite claims prevent two processes from running the same queued job.  The
    default is one worker because the graph/LLM pipeline is resource intensive;
    each job still has isolated files if an operator raises the limit.
    """

    def __init__(
        self,
        *,
        repository: LifecycleRepository,
        settings: BackendSettings,
        get_engine: Callable[[], Any],
        pipeline_runner: Callable[..., Any] | None = None,
    ):
        self.repository = repository
        self.settings = settings
        self.get_engine = get_engine
        self.pipeline_runner = pipeline_runner
        self.executor = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="csdh-run")
        self._stopping = Event()
        self._lock = RLock()
        self._scheduled: set[str] = set()
        self._futures: set[Future[Any]] = set()
        self._executor_shutdown = False

    def schedule(self, run_id: str) -> bool:
        """Queue a durable run unless graceful shutdown has stopped intake.

        The return value lets callers preserve a queued row when shutdown wins
        the race with a retry/recovery request.  A future callback owns the
        bookkeeping so canceled, completed, and failed tasks cannot leak a
        stale run ID in the in-memory scheduler set.
        """
        with self._lock:
            if self._stopping.is_set() or self._executor_shutdown or run_id in self._scheduled:
                return False
            self._scheduled.add(run_id)
            future = self.executor.submit(self._execute, run_id)
            self._futures.add(future)
            future.add_done_callback(lambda completed, scheduled_run_id=run_id: self._future_finished(scheduled_run_id, completed))
        return True

    def _future_finished(self, run_id: str, future: Future[Any]) -> None:
        with self._lock:
            self._scheduled.discard(run_id)
            self._futures.discard(future)

    def _raise_if_interrupted(self, run_id: str, *, phase: str) -> None:
        """Keep user cancellation distinct from an operator/server shutdown."""
        if self.repository.is_cancel_requested(run_id):
            raise RunCanceled(f"Run cancellation requested {phase}.")
        if self._stopping.is_set():
            raise WorkerShutdown(f"Service shutdown interrupted the run {phase}; it will be replayed from the retained artifact on restart.")

    def recover(self) -> None:
        if self._stopping.is_set():
            return
        for run_id in self.repository.reserve_interrupted_runs_for_recovery():
            try:
                workspace = RunWorkspace.open(self.settings.runs_dir, run_id)
                # A provider call/publish sequence cannot be safely resumed
                # from an arbitrary instruction boundary. Reset only derived
                # data and replay from the immutable input, which prevents
                # duplicate observations and partial report assets.
                workspace.reset_derived_outputs()
                self.repository.reset_interrupted_run_after_recovery(run_id)
                self.repository.append_event(
                    run_id,
                    "run_recovered",
                    {
                        "phase": "recovery",
                        "message": "Recovered interrupted work by resetting derived outputs and replaying the retained source artifact.",
                    },
                )
                self.schedule(run_id)
            except Exception as exc:  # leave a durable, visible failure rather than a wedged run
                logger.exception("Unable to recover interrupted run %s", run_id)
                message = f"Interrupted-run recovery failed: {exc}"
                try:
                    self.repository.fail_interrupted_run_recovery(run_id, message)
                    self.repository.append_event(run_id, "run_recovery_failed", {"phase": "recovery_failed", "message": message})
                except Exception:  # pragma: no cover - database is already unavailable
                    logger.exception("Unable to record recovery failure for run %s", run_id)

    def shutdown(self) -> None:
        """Stop accepting work and wait until no worker can write afterward.

        Python cannot safely kill a thread in the middle of a SQLite/filesystem
        transaction.  We therefore signal cooperative cancellation, cancel
        not-yet-started futures, and join the executor before lifespan exits.
        Active runs are requeued (rather than marked canceled) by
        ``WorkerShutdown`` and are reset/replayed from their original upload
        at the next healthy startup.  This avoids the old post-shutdown write
        race when a temporary workspace or database is being removed.
        """
        with self._lock:
            if self._executor_shutdown:
                return
            self._stopping.set()
            futures = list(self._futures)
            self._executor_shutdown = True
        for future in futures:
            future.cancel()
        self.executor.shutdown(wait=True, cancel_futures=True)

    def _execute(self, run_id: str) -> None:
        try:
            if self._stopping.is_set():
                return
            if not self.repository.claim_run(run_id):
                return
            run = self.repository.get_run(run_id)
            if run is None:
                return
            self._raise_if_interrupted(run_id, phase="before normalization")
            workspace = RunWorkspace.open(self.settings.runs_dir, run_id)
            artifacts = self.repository.list_artifacts(run_id)
            if len(artifacts) != 1:
                raise NormalizationError("This pipeline adapter currently requires exactly one artifact per run.")
            artifact = artifacts[0]
            started_at = datetime.now(timezone.utc)
            self.repository.append_event(run_id, "run_started", {"phase": "normalizing", "message": "Run claimed by worker"})
            self._raise_if_interrupted(run_id, phase="before normalization")

            source_path = workspace.resolve_relative(artifact["storage_key"])
            normalized = normalize_artifact(artifact_path=source_path, extension=artifact["extension"], workspace=workspace)
            self.repository.create_observations(artifact["id"], normalized.observations)
            persisted_observations = self.repository.list_observations(artifact["id"])
            self.repository.update_artifact_parse_status(artifact["id"], "parsed", metadata=normalized.metadata)
            self.repository.append_event(
                run_id,
                "artifact_normalized",
                {
                    "phase": "candidate_generation",
                    "message": f"Normalized {len(normalized.observations)} observation(s)",
                    "current": {"artifact_id": artifact["id"]},
                    "counters": {"artifacts_total": 1, "artifacts_completed": 1, "observations_total": len(normalized.observations), "observations_completed": 0},
                },
            )

            def progress(raw: Any) -> None:
                self._raise_if_interrupted(run_id, phase="during analysis")
                event_type, payload = _as_event(raw, artifact_id=artifact["id"], started_at=started_at)
                self.repository.append_event(run_id, event_type, payload)

            pipeline_report_ids: dict[tuple[str, int], str] = {}

            def report_id_factory(technique_id: str, ordinal: int) -> str:
                # Pipeline staging names may use this UUID too.  The database
                # keeps it as the canonical report identity; CONSOL-Txxxx
                # remains the display/report aggregation key only.
                key = (technique_id, ordinal)
                return pipeline_report_ids.setdefault(key, str(uuid.uuid4()))

            results = invoke_pipeline(
                engine=self.get_engine(),
                input_csv=normalized.input_csv,
                output_dir=workspace.pipeline_dir,
                provider_name=run.get("requested_provider"),
                model_name=run.get("requested_model"),
                progress_cb=progress,
                # ``invoke_pipeline`` treats a true predicate as a user
                # cancellation, so reserve it for the persisted user action.
                # Shutdown is surfaced by the progress callback and explicit
                # checkpoints below, allowing the row to be safely requeued.
                cancel_cb=lambda: self.repository.is_cancel_requested(run_id),
                report_id_factory=report_id_factory,
                run_id=run_id,
                runner=self.pipeline_runner,
            )
            self._raise_if_interrupted(run_id, phase="after analysis")

            self.repository.update_run(run_id, status="analysis_finished", phase="publishing")
            for index, result in enumerate(results, start=1):
                self._raise_if_interrupted(run_id, phase="during report publishing")
                raw_report_id = str(result.get("report_id") or "")
                try:
                    report_id = str(uuid.UUID(raw_report_id))
                except (ValueError, AttributeError):
                    # Adapter compatibility for pre-durable runners that still
                    # return CONSOL-Txxxx; never use that mutable label as ID.
                    report_id = str(uuid.uuid4())
                revision_id = str(uuid.uuid4())
                report_key = str(result.get("report_key") or result.get("report_id") or f"report-{index}")
                md_source = resolve_pipeline_asset(workspace.pipeline_dir, result, "markdown")
                json_source = resolve_pipeline_asset(workspace.pipeline_dir, result, "json")
                assets = workspace.publish_report_assets(
                    report_id=report_id,
                    markdown_source=md_source,
                    json_source=json_source,
                )
                self._raise_if_interrupted(run_id, phase="during report publishing")
                report_data: dict[str, Any] = dict(result)
                if json_source:
                    try:
                        report_data = json.loads(json_source.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        pass
                candidate_ids = _persist_result_candidates(
                    self.repository,
                    artifact_id=artifact["id"],
                    result=result,
                    persisted_observations=persisted_observations,
                )
                markdown_path = assets["markdown_path"]
                json_path = assets["json_path"]
                md_hash = RunWorkspace.sha256_file(workspace.resolve_relative(markdown_path)) if markdown_path else None
                json_hash = RunWorkspace.sha256_file(workspace.resolve_relative(json_path)) if json_path else None
                qa_verdict = str(result.get("qa_verdict") or report_data.get("qa_verdict") or report_data.get("qa", {}).get("verdict", "MANUAL_REVIEW_REQUIRED"))
                provider_record = result.get("provider") if isinstance(result.get("provider"), Mapping) else report_data.get("provider", {})
                if not isinstance(provider_record, Mapping):
                    provider_record = {}
                effective_provider = str(
                    provider_record.get("effective_provider")
                    or result.get("effective_provider")
                    or run.get("requested_provider")
                    or LOCAL_ONLY_PROVIDER
                )
                effective_model = (
                    provider_record.get("model")
                    if "model" in provider_record
                    else run.get("requested_model")
                )
                state = _report_state(result, effective_provider, report_data)
                self.repository.create_report_with_revision(
                    report_id=report_id,
                    revision_id=revision_id,
                    run_id=run_id,
                    artifact_id=artifact["id"],
                    display_id=report_key,
                    aggregate_key=str(result.get("aggregate_key") or result.get("technique_id") or report_key),
                    technique_id=result.get("technique_id") or report_data.get("technique_id"),
                    technique_name=result.get("technique_name") or report_data.get("technique_name"),
                    finding_count=int(result.get("finding_count") or report_data.get("finding_count") or 0),
                    severity_breakdown=result.get("severity_breakdown") or report_data.get("severity_breakdown") or {},
                    qa_verdict=qa_verdict,
                    lifecycle_state=state,
                    report_data=report_data,
                    narrative=result.get("narrative") if isinstance(result.get("narrative"), Mapping) else {},
                    markdown_path=markdown_path,
                    json_path=json_path,
                    markdown_sha256=md_hash,
                    json_sha256=json_hash,
                    mapping_snapshot_hash=result.get("mapping_snapshot_hash"),
                    qa_state=state,
                    metadata={"pipeline_report_key": report_key, "pipeline_result": result},
                )
                self.repository.update_run(
                    run_id,
                    effective_provider=effective_provider,
                    effective_model=effective_model,
                    degraded_reason=provider_record.get("degraded_reason"),
                )
                self.repository.append_event(
                    run_id,
                    "report_published",
                    {
                        "phase": "publishing",
                        "message": f"Published {report_key}",
                        "current": {"artifact_id": artifact["id"], "technique_id": result.get("technique_id"), "report_id": report_id},
                        "counters": {"reports_total": len(results), "reports_completed": index},
                        "mapping": {
                            "candidate_count": len(candidate_ids),
                            "path_count": len((result.get("framework_mappings") or {}).get("paths") or []),
                        },
                    },
                )
            # An observation with no retained ATT&CK candidate must be
            # reviewable, not merely a counter that can hold a run open with
            # no visible UI action. Persist one explicit UNMAPPED triage
            # report backed by per-observation durable candidates.
            persisted_candidates = self.repository.list_candidates(artifact_id=artifact["id"])
            mapped_observation_ids = {
                str(candidate.get("observation_id"))
                for candidate in persisted_candidates
                if candidate.get("observation_id") and str(candidate.get("technique_id") or "") != "UNMAPPED"
            }
            unresolved_observations = [
                observation
                for observation in persisted_observations
                if str(observation.get("id")) not in mapped_observation_ids
            ]
            if unresolved_observations:
                self._raise_if_interrupted(run_id, phase="before unmapped-evidence publishing")
                triage_report_id = str(uuid.uuid4())
                triage_revision_id = str(uuid.uuid4())
                triage_display_id = f"UNMAPPED-{run_id[:8]}"
                for observation in unresolved_observations:
                    evidence_ids = [
                        str(span["id"])
                        for span in observation.get("evidence_spans", [])
                        if span.get("id")
                    ]
                    self.repository.create_candidate(
                        candidate_id=str(uuid.uuid4()),
                        observation_id=str(observation["id"]),
                        technique_id="UNMAPPED",
                        method="unresolved",
                        score=None,
                        evidence_span_ids=evidence_ids,
                        candidate_rank=None,
                        state="needs_review",
                        reason="No validated ATT&CK candidate was retained for this observation.",
                        retrieval_metadata={
                            "graph_snapshot_id": getattr(self.get_engine(), "graph_snapshot_id", None),
                        },
                    )
                evidence_preview = [
                    {
                        "source_locator": observation.get("source_locator", {}),
                        "severity": observation.get("severity"),
                        "explicit_ids": observation.get("explicit_ids", []),
                        "text_excerpt": str(observation.get("normalized_text") or "")[:1_000],
                    }
                    for observation in unresolved_observations[:100]
                ]
                triage_data = {
                    "schema_version": "unmapped-triage-v1",
                    "report_id": triage_display_id,
                    "technique_id": "UNMAPPED",
                    "technique_name": "Unmapped evidence requiring analyst triage",
                    "finding_count": len(unresolved_observations),
                    "severity_breakdown": {},
                    "qa_verdict": "MANUAL_REVIEW_REQUIRED",
                    "lifecycle_state": "manual_review_required",
                    "message": "No validated ATT&CK mapping was found. Review source evidence and retry the source run after remediation or classification.",
                    "evidence_preview": evidence_preview,
                    "evidence_preview_omitted": max(0, len(unresolved_observations) - len(evidence_preview)),
                    "framework_mappings": {
                        "graph_snapshot_id": getattr(self.get_engine(), "graph_snapshot_id", None),
                        "paths": [],
                        "not_mapped_categories": ["attack_technique"],
                    },
                }
                triage_markdown = (
                    f"# {triage_display_id}\n\n"
                    "## Analyst triage required\n\n"
                    f"{len(unresolved_observations)} observation(s) did not retain a validated ATT&CK candidate. "
                    "Review the source evidence, record a decision, or retry the complete source run after classification.\n"
                )
                staging_markdown = workspace.pipeline_dir / f"{triage_report_id}.md"
                staging_json = workspace.pipeline_dir / f"{triage_report_id}.json"
                workspace.atomic_write_bytes(staging_markdown, triage_markdown.encode("utf-8"))
                workspace.atomic_write_bytes(staging_json, json.dumps(triage_data, indent=2, default=str).encode("utf-8"))
                triage_assets = workspace.publish_report_assets(
                    report_id=triage_report_id,
                    markdown_source=staging_markdown,
                    json_source=staging_json,
                )
                self._raise_if_interrupted(run_id, phase="during unmapped-evidence publishing")
                triage_markdown_path = triage_assets["markdown_path"]
                triage_json_path = triage_assets["json_path"]
                self.repository.create_report_with_revision(
                    report_id=triage_report_id,
                    revision_id=triage_revision_id,
                    run_id=run_id,
                    artifact_id=artifact["id"],
                    display_id=triage_display_id,
                    aggregate_key="unmapped_observations",
                    technique_id="UNMAPPED",
                    technique_name="Unmapped evidence requiring analyst triage",
                    finding_count=len(unresolved_observations),
                    severity_breakdown={},
                    qa_verdict="MANUAL_REVIEW_REQUIRED",
                    lifecycle_state="manual_review_required",
                    report_data=triage_data,
                    narrative={},
                    markdown_path=triage_markdown_path,
                    json_path=triage_json_path,
                    markdown_sha256=RunWorkspace.sha256_file(workspace.resolve_relative(triage_markdown_path)) if triage_markdown_path else None,
                    json_sha256=RunWorkspace.sha256_file(workspace.resolve_relative(triage_json_path)) if triage_json_path else None,
                    mapping_snapshot_hash=None,
                    qa_state="manual_review_required",
                    metadata={"unmapped_triage": True, "observation_count": len(unresolved_observations)},
                )
                self.repository.append_event(
                    run_id,
                    "unmapped_triage_published",
                    {
                        "phase": "publishing",
                        "message": f"Published triage for {len(unresolved_observations)} unmapped observation(s)",
                        "current": {"artifact_id": artifact["id"], "report_id": triage_report_id},
                        "counters": {"observations_unresolved": len(unresolved_observations)},
                    },
                )
            self.repository.update_run(
                run_id,
                counters={
                    "observations_completed": len(normalized.observations),
                    "observations_unresolved": len(unresolved_observations),
                },
            )
            final_run = self.repository.recompute_run_completion(run_id)
            self.repository.append_event(
                run_id,
                "run_finished",
                {"phase": final_run["status"], "message": "Generation stopped; review gate evaluated", "counters": final_run["counters"]},
            )
        except WorkerShutdown as exc:
            # A shutdown intentionally leaves the source artifact and any
            # partial derived state durable. Startup recovery clears derived
            # state before replay, so an interruption never duplicates source
            # observations or merges half-published reports.
            try:
                requeued = self.repository.requeue_after_worker_shutdown(run_id, message=str(exc))
                if requeued and requeued.get("status") == "queued":
                    self.repository.append_event(
                        run_id,
                        "run_interrupted_for_shutdown",
                        {"phase": "queued", "message": str(exc)},
                    )
            except Exception:  # pragma: no cover - database failure is logged by the outer server
                logger.exception("Unable to requeue run %s after shutdown interruption", run_id)
        except RunCanceled as exc:
            self.repository.update_run(run_id, status="canceled", phase="canceled", error_code="canceled", error_message=str(exc), finished=True)
            self.repository.append_event(run_id, "run_canceled", {"phase": "canceled", "message": str(exc)})
        except Exception as exc:  # never leave durable work stuck running
            logger.exception("Run %s failed", run_id)
            self.repository.update_run(run_id, status="failed", phase="failed", error_code=type(exc).__name__, error_message=str(exc), finished=True)
            self.repository.append_event(run_id, "run_failed", {"phase": "failed", "message": str(exc), "details": {"exception": type(exc).__name__}})
        finally:
            # The future callback performs thread-safe scheduler bookkeeping.
            pass


def _snapshot_response(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return dict(snapshot)


def _affirmative(value: str | bool | None) -> bool:
    return value is True or str(value or "").strip().lower() in {"1", "true", "yes", "on", "acknowledged"}


def _expected_version(request: Request, supplied: int | None, *, resource: str) -> int:
    """Read optimistic-concurrency version from JSON and/or HTTP If-Match.

    The body field is convenient for form clients while If-Match makes the
    contract explicit for API callers.  Supplying both with different values
    is rejected instead of silently trusting one stale value.
    """
    raw = (request.headers.get("if-match") or "").strip().strip('"')
    if not raw or raw == "*":
        if supplied is None:
            raise ApiProblem(
                428,
                "precondition_required",
                f"An If-Match header or JSON version is required to change this {resource}.",
            )
        return supplied
    try:
        from_header = int(raw)
    except ValueError as exc:
        raise ApiProblem(400, "invalid_if_match", f"If-Match must be an integer {resource} version.") from exc
    if supplied is not None and supplied != from_header:
        raise ApiProblem(400, "version_mismatch", "JSON version and If-Match header disagree.")
    return from_header


def _required_note(body: ReviewRequest) -> str:
    note = (body.notes or body.note or body.reason or "").strip()
    if not note:
        raise ApiProblem(422, "review_note_required", "A review note or reason is required for the audit trail.")
    return note


def _required_bulk_approval_reason(body: BulkApproveReviewPendingRequest) -> str:
    reason = body.reason.strip()
    if not reason:
        raise ApiProblem(
            422,
            "bulk_review_reason_required",
            "A non-empty shared approval reason is required for the audit trail.",
        )
    return reason


def _resolve_local_model(model: str | None) -> str:
    """Resolve and validate the per-run model without changing process env."""
    try:
        return validate_local_model_name(model)
    except LocalModelConfigurationError as exc:
        raise ApiProblem(422, "invalid_local_model", str(exc)) from exc


def _require_local_provider(provider: str | None) -> str:
    """Reject all cloud/no-provider submission modes at the API boundary."""
    candidate = (provider or LOCAL_ONLY_PROVIDER).strip().lower()
    if candidate != LOCAL_ONLY_PROVIDER:
        raise ApiProblem(
            400,
            "provider_not_allowed",
            "Only the local LLM provider is available in this deployment.",
            {"allowed": [LOCAL_ONLY_PROVIDER]},
        )
    return LOCAL_ONLY_PROVIDER


async def _submit_run(
    app: FastAPI,
    *,
    submitted_by: str,
    file: UploadFile | None,
    text: str | None,
    provider: str | None,
    model: str | None,
    cloud_acknowledged: str | bool | None = None,
) -> dict[str, Any]:
    settings: BackendSettings = app.state.settings
    repository: LifecycleRepository = app.state.repository
    # Do this before allocating a workspace or durable run row.  A degraded
    # graph must reject new work with a retryable service error instead of
    # accepting evidence and later turning it into an avoidable failed run.
    engine = _require_engine(app)
    if file is not None and text and text.strip():
        raise ApiProblem(400, "multiple_artifacts", "Submit either one file or pasted text, not both.")
    effective_requested_provider = _require_local_provider(provider)
    requested_model = _resolve_local_model(model)
    if file is None:
        text = validate_text_artifact(text, max_characters=settings.max_text_characters)
    else:
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            raise ApiProblem(415, "unsupported_file_type", f"Unsupported artifact type '{suffix or 'none'}'.")

    run_id = str(uuid.uuid4())
    workspace = RunWorkspace.create(settings.runs_dir, run_id)
    repository.create_run(
        run_id=run_id,
        workspace_path=str(workspace.path),
        # Snapshot the local provider/model at submission. The worker receives
        # this model explicitly; a later environment change cannot alter a
        # queued run or redirect evidence to a cloud provider.
        requested_provider=effective_requested_provider,
        requested_model=requested_model,
        graph_snapshot_id=getattr(engine, "graph_snapshot_id", None),
    )
    try:
        if file is not None:
            stored = await workspace.store_upload(file, filename=file.filename or "artifact", max_bytes=settings.max_upload_bytes)
            inspection = inspect_artifact(stored.path, filename=file.filename or "artifact", content_type=file.content_type)
            original_name = Path(file.filename or "artifact").name
        else:
            stored = workspace.store_text(text or "")
            inspection = inspect_artifact(stored.path, filename=stored.path.name, content_type="text/plain")
            original_name = "pasted-threat-intel.txt"
        artifact_id = str(uuid.uuid4())
        repository.create_artifact(
            artifact_id=artifact_id,
            run_id=run_id,
            original_name=original_name,
            media_type=inspection.media_type,
            extension=inspection.extension,
            sha256=stored.sha256,
            storage_key=stored.relative_path,
            byte_size=stored.byte_size,
            kind=inspection.kind,
            metadata={
                **inspection.metadata,
                "effective_requested_provider": effective_requested_provider,
                "requested_model": requested_model,
                "submitted_by": submitted_by,
            },
        )
        repository.append_event(
            run_id,
            "run_queued",
            {
                "phase": "queued",
                "message": "Artifact accepted for local analysis",
                "current": {"artifact_id": artifact_id, "submitted_by": submitted_by},
                "counters": {"artifacts_total": 1},
                "provider": {"requested_provider": effective_requested_provider, "requested_model": requested_model},
            },
        )
        app.state.worker.schedule(run_id)
        return repository.get_run_snapshot(run_id) or {"id": run_id, "status": "queued"}
    except Exception as exc:
        problem = _problem_from_exception(exc)
        repository.update_run(run_id, status="failed", phase="failed", error_code=problem.code, error_message=problem.message, finished=True)
        repository.append_event(run_id, "submission_failed", {"phase": "failed", "message": problem.message})
        raise problem


def create_app(
    settings: BackendSettings | None = None,
    *,
    engine_factory: Callable[[], Any] | None = None,
    pipeline_runner: Callable[..., Any] | None = None,
) -> FastAPI:
    settings = settings or BackendSettings.from_environment()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    repository = LifecycleRepository(settings.database_path)
    repository.initialize()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        recovery = reconcile_incomplete_deletion_operations(
            repository=repository,
            runs_dir=settings.runs_dir,
        )
        if recovery["recovery_failures"]:
            logger.error("Deletion/restore recovery left %s journal(s) unresolved", recovery["recovery_failures"])
        elif recovery["recovered_operations"]:
            logger.warning("Recovered %s interrupted deletion/restore operation(s)", recovery["recovered_operations"])
        try:
            app.state.engine = (engine_factory or _default_engine_factory)()
            app.state.engine_error = None
        except Exception as exc:  # health exposes degraded startup; jobs fail explicitly rather than hang
            logger.exception("Knowledge graph initialization failed")
            app.state.engine = None
            app.state.engine_error = str(exc)
        if app.state.engine is not None:
            app.state.worker.recover()
        else:
            logger.error("Skipping durable-run recovery because the knowledge graph is unavailable; queued work remains intact for a healthy restart.")
        yield
        app.state.worker.shutdown()

    app = FastAPI(title="MITRE CSD-H Analyst Pipeline API", lifespan=lifespan)
    app.state.settings = settings
    app.state.repository = repository
    app.state.engine = None
    app.state.engine_error = None
    app.state.auth_policy = AuthPolicy(
        mode=settings.auth_mode,
        token_principals=settings.auth_token_principals,
        trusted_proxy_header=settings.auth_proxy_header,
    )
    app.state.worker = DurableWorker(repository=repository, settings=settings, get_engine=lambda: _require_engine(app), pipeline_runner=pipeline_runner)

    @app.exception_handler(ApiProblem)
    async def api_problem_handler(_: Request, exc: ApiProblem):
        # ``detail`` retains compatibility with the original frontend client;
        # ``error`` gives new callers stable machine-readable error codes.
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message, "error": {"code": exc.code, "message": exc.message, "details": exc.details}})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Request validation failed.", "error": {"code": "validation_error", "message": "Request validation failed.", "details": {"errors": exc.errors()}}})

    @app.post("/api/runs", status_code=202)
    async def create_run(
        request: Request,
        file: UploadFile | None = File(None),
        text: str | None = Form(None),
        provider: str | None = Form(None),
        model: str | None = Form(None),
        cloud_acknowledged: str | None = Form(None),
    ):
        actor = _authorize(app, request, "submit")
        return _snapshot_response(await _submit_run(app, submitted_by=actor, file=file, text=text, provider=provider, model=model, cloud_acknowledged=cloud_acknowledged))

    @app.post("/api/analyze", status_code=202)
    async def analyze_legacy(
        request: Request,
        file: UploadFile | None = File(None),
        text: str | None = Form(None),
        provider: str | None = Form(None),
        model: str | None = Form(None),
        cloud_acknowledged: str | None = Form(None),
    ):
        actor = _authorize(app, request, "submit")
        snapshot = await _submit_run(app, submitted_by=actor, file=file, text=text, provider=provider, model=model, cloud_acknowledged=cloud_acknowledged)
        return {"job_id": snapshot["id"]}

    @app.get("/api/runs")
    async def list_runs(
        request: Request,
        status: str | None = None,
        search: str | None = None,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        limit: int | None = Query(None, ge=1, le=200),
    ):
        _authorize(app, request, "view")
        effective_limit = limit or page_size
        runs, total = repository.list_runs(status=status, search=search, limit=effective_limit, offset=(page - 1) * effective_limit)
        return {"items": [_snapshot_response(repository.get_run_snapshot(run["id"]) or run) for run in runs], "total": total, "page": page, "page_size": effective_limit}

    @app.get("/api/config")
    async def public_config():
        """Expose the fixed local-only submission policy without secrets."""
        return {
            "default_provider": LOCAL_ONLY_PROVIDER,
            "allowed_providers": sorted(VALID_PROVIDERS),
            "cloud_acknowledgement_required": False,
            "authentication_mode": settings.auth_mode,
            "authentication_ready": app.state.auth_policy.is_ready and not bool(settings.auth_configuration_error),
        }

    @app.get("/api/local-models")
    async def local_models(request: Request):
        """List model IDs from the configured local endpoint only.

        The route intentionally accepts no URL/query override. Discovery runs
        in a worker thread with a short bounded timeout and never returns the
        configured base URL or local API key.
        """
        _authorize(app, request, "view")
        # The probe may wait for its short network timeout. Keep it off the
        # event loop, but own and join this single-use executor before the
        # response is sent so a request cannot leave background discovery work
        # running during application shutdown.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="csdh-model-discovery") as executor:
            return await asyncio.get_running_loop().run_in_executor(executor, discover_local_models)

    @app.post("/api/session")
    async def establish_browser_session(request: Request):
        """Exchange a bearer token for an HttpOnly same-origin SSE session.

        EventSource cannot send an Authorization header. The cookie is only
        issued after the supplied bearer token has been authenticated, is never
        returned in JSON, and is constrained to the same origin.
        """
        actor = _authorize(app, request, "view")
        principal = app.state.auth_policy.authenticate(request)
        response = JSONResponse(
            {
                "actor": actor,
                "roles": sorted(principal.roles) if principal is not None else ["development"],
                "authentication_mode": settings.auth_mode,
            }
        )
        header = (request.headers.get("authorization") or "").strip()
        scheme, _, token = header.partition(" ")
        if settings.auth_mode == "token" and scheme.lower() == "bearer" and token:
            response.set_cookie(
                "csdh_session",
                token,
                httponly=True,
                secure=_affirmative(os.environ.get("CSDH_SESSION_COOKIE_SECURE", "true")),
                samesite="strict",
                path="/",
            )
        return response

    @app.get("/api/session")
    async def get_browser_session(request: Request):
        """Return the current server-authenticated browser identity.

        The SPA uses this read-only endpoint after a reload and immediately
        before an auditable action.  It intentionally derives the actor from
        the same request principal as review/delete endpoints rather than
        trusting a browser-stored display name.
        """
        actor = _authorize(app, request, "view")
        principal = app.state.auth_policy.authenticate(request)
        return {
            "actor": actor,
            "roles": sorted(principal.roles) if principal is not None else ["development"],
            "authentication_mode": settings.auth_mode,
        }

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str, request: Request):
        _authorize(app, request, "view")
        snapshot = repository.get_run_snapshot(run_id)
        if snapshot is None:
            raise ApiProblem(404, "run_not_found", f"Run '{run_id}' was not found.")
        return _snapshot_response(snapshot)

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, request: Request):
        try:
            actor = _authorize(app, request, "operate")
            run = repository.request_cancel(run_id, expected_version=_expected_version(request, None, resource="run"))
            repository.append_event(run_id, "cancel_requested", {"phase": "canceling", "message": "Cancellation requested", "current": {"actor": actor}})
            return _snapshot_response(run)
        except Exception as exc:
            raise _problem_from_exception(exc)

    @app.post("/api/runs/{run_id}/review-pending/approve")
    async def bulk_approve_review_pending_reports(
        run_id: str,
        body: BulkApproveReviewPendingRequest,
        request: Request,
    ):
        """Approve the run's current actionable review-pending reports.

        The repository performs the whole batch under one SQLite write
        transaction.  Each report receives its own review decision attached to
        its current revision; this endpoint is not a shortcut that replaces
        per-report audit history with a single run-level record.
        """
        try:
            actor = _authorize(app, request, "review")
            result = repository.bulk_approve_review_pending_reports(
                run_id=run_id,
                expected_run_version=_expected_version(request, body.version, resource="run"),
                actor_id=actor,
                reason=_required_bulk_approval_reason(body),
            )
            reports = [
                {
                    "id": report["id"],
                    "report_id": report["id"],
                    "display_id": report["display_id"],
                    "lifecycle_state": report["lifecycle_state"],
                    "version": report["version"],
                    "current_revision_id": report["current_revision_id"],
                }
                for report in result["reports"]
            ]
            run = repository.get_run_snapshot(run_id) or result["run"]
            return {
                "run": _snapshot_response(run),
                "approved_count": len(reports),
                "reports": reports,
                "event": result["event"],
            }
        except Exception as exc:
            raise _problem_from_exception(exc)

    async def retry_run_from_source(
        run_id: str,
        *,
        actor: str,
        model: str | None = None,
        cloud_acknowledged: bool = False,
    ) -> dict[str, Any]:
        engine = _require_engine(app)
        source_run = repository.get_run(run_id)
        if source_run is None:
            raise ApiProblem(404, "run_not_found", f"Run '{run_id}' was not found.")
        artifacts = repository.list_artifacts(run_id)
        if len(artifacts) != 1:
            raise ApiProblem(409, "retry_not_supported", "Retry currently requires a run with exactly one artifact.")
        source_artifact = artifacts[0]
        source_metadata = source_artifact.get("metadata") if isinstance(source_artifact.get("metadata"), Mapping) else {}
        # Retries are also local-only. Historical runs may record a cloud
        # provider, but their retained source evidence is never replayed to
        # that provider; it is reprocessed with the selected/configured local
        # model instead.
        effective_retry_provider = LOCAL_ONLY_PROVIDER
        inherited_model = (
            source_metadata.get("requested_model")
            or source_run.get("requested_model")
        )
        effective_retry_model = _resolve_local_model(model if model is not None else inherited_model)
        retry_id = str(uuid.uuid4())
        source_workspace = RunWorkspace.open(settings.runs_dir, run_id)
        source = source_workspace.resolve_relative(source_artifact["storage_key"])
        if not source.is_file():
            # Detect this before allocating a retry workspace/run row. A
            # source artifact that was manually removed is a retention issue,
            # not a queued analysis that a worker should later fail.
            raise ApiProblem(
                409,
                "retry_source_unavailable",
                "The retained source artifact is unavailable; start a new analysis instead of retrying this run.",
            )

        retry_workspace: RunWorkspace | None = None
        retry_row_created = False
        try:
            retry_workspace = RunWorkspace.create(settings.runs_dir, retry_id)
            repository.create_run(
                run_id=retry_id,
                workspace_path=str(retry_workspace.path),
                requested_provider=effective_retry_provider,
                requested_model=effective_retry_model,
                graph_snapshot_id=getattr(engine, "graph_snapshot_id", None) or source_run.get("graph_snapshot_id"),
                retry_of_run_id=run_id,
            )
            retry_row_created = True
            target = retry_workspace.atomic_copy(source, retry_workspace.uploads_dir / source.name)
            copied = repository.create_artifact(
                artifact_id=str(uuid.uuid4()), run_id=retry_id, original_name=source_artifact["original_name"], media_type=source_artifact.get("media_type"), extension=source_artifact.get("extension"), sha256=source_artifact["sha256"], storage_key=retry_workspace.relative(target), byte_size=source_artifact["byte_size"], kind=source_artifact["kind"], metadata={**source_metadata, "retried_from_artifact_id": source_artifact["id"], "retried_by": actor, "effective_requested_provider": effective_retry_provider, "requested_model": effective_retry_model},
            )
            repository.append_event(retry_id, "run_queued", {"phase": "queued", "message": f"Local-model retry of {run_id}", "current": {"artifact_id": copied["id"], "retried_by": actor}, "counters": {"artifacts_total": 1}, "provider": {"requested_provider": effective_retry_provider, "requested_model": effective_retry_model}})
            app.state.worker.schedule(retry_id)
            return _snapshot_response(repository.get_run_snapshot(retry_id) or {"id": retry_id, "status": "queued"})
        except Exception as exc:
            # Defensive check for a driver failure reported after a committed
            # create_run transaction: never discard a workspace that a durable
            # row now references.
            if not retry_row_created:
                try:
                    retry_row_created = repository.get_run(retry_id) is not None
                except Exception:  # pragma: no cover - preserve the original failure if storage is unavailable
                    pass
            if retry_row_created:
                message = "Retry preparation failed before the source artifact could be queued."
                logger.exception("Unable to prepare retry %s from source run %s", retry_id, run_id)
                try:
                    repository.update_run(
                        retry_id,
                        status="failed",
                        phase="retry_preparation_failed",
                        error_code=type(exc).__name__,
                        error_message=message,
                        finished=True,
                    )
                    repository.append_event(
                        retry_id,
                        "retry_preparation_failed",
                        {"phase": "retry_preparation_failed", "message": message, "details": {"source_run_id": run_id, "exception": type(exc).__name__}},
                    )
                except Exception:  # pragma: no cover - original failure remains authoritative
                    logger.exception("Unable to record failed retry preparation for %s", retry_id)
            elif retry_workspace is not None:
                try:
                    retry_workspace.discard_uncommitted()
                except Exception:  # pragma: no cover - leave a harmless diagnostic directory if cleanup fails
                    logger.exception("Unable to discard uncommitted retry workspace %s", retry_id)
            if isinstance(exc, ApiProblem):
                raise
            if isinstance(exc, (WorkspaceError, OSError)):
                raise ApiProblem(
                    409,
                    "retry_source_unavailable",
                    "The retained source artifact could not be copied into a new retry workspace; start a new analysis instead.",
                ) from exc
            raise

    @app.post("/api/runs/{run_id}/retry", status_code=202)
    async def retry_run(run_id: str, request: Request, body: RetryRequest | None = None):
        actor = _authorize(app, request, "operate")
        return await retry_run_from_source(run_id, actor=actor, model=body.model if body else None, cloud_acknowledged=bool(body and body.cloud_acknowledged))

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, request: Request, after: int = Query(0, ge=0)):
        _authorize(app, request, "view")
        if repository.get_run(run_id) is None:
            raise ApiProblem(404, "run_not_found", f"Run '{run_id}' was not found.")
        raw_last = request.headers.get("Last-Event-ID")
        if raw_last and raw_last.isdigit():
            after = max(after, int(raw_last))

        async def stream():
            last = after
            yield "retry: 3000\n\n"
            while True:
                events = repository.list_events(run_id, after=last)
                for event in events:
                    last = int(event["seq"])
                    # Use the SSE default `message` event so a generic
                    # EventSource client receives every future event type.
                    # The durable domain type remains in the JSON payload;
                    # clients do not need a hard-coded listener list.
                    yield f"id: {last}\ndata: {json.dumps(event, default=str)}\n\n"
                snapshot = repository.get_run(run_id)
                if snapshot and snapshot["status"] in TERMINAL_RUN_STATES | {"awaiting_review"} and not events:
                    break
                if await request.is_disconnected():
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/jobs/{job_id}")
    async def legacy_job_status(job_id: str, request: Request):
        _authorize(app, request, "view")
        snapshot = repository.get_run_snapshot(job_id)
        if snapshot is None:
            raise ApiProblem(404, "run_not_found", f"No job with id '{job_id}'.")
        reports, _ = repository.list_reports(run_id=job_id, limit=500)
        legacy_status = {"queued": "pending", "running": "running", "failed": "failed", "canceled": "failed"}.get(snapshot["status"], "done")
        return {"status": legacy_status, "stage": snapshot.get("phase", ""), "error": snapshot.get("error_message"), "report_ids": [report["id"] for report in reports], "run_id": job_id, "review_required": snapshot["status"] == "awaiting_review", "counters": snapshot["counters"]}

    @app.get("/api/reports")
    async def list_reports(
        request: Request,
        run_id: str | None = None,
        technique_id: str | None = None,
        state: str | None = None,
        status: str | None = None,
        lifecycle_state: str | None = None,
        review_state: str | None = None,
        qa_verdict: str | None = None,
        search: str | None = None,
        include_deleted: bool = False,
        page: int | None = Query(None, ge=1),
        page_size: int = Query(100, ge=1, le=200),
        limit: int | None = Query(None, ge=1, le=200),
    ):
        _authorize(app, request, "view")
        requested_state: str | tuple[str, ...] | None = lifecycle_state or state or status
        if not requested_state and review_state:
            normalized_review_state = review_state.strip().lower()
            requested_state = REVIEW_STATE_ALIASES.get(normalized_review_state)
            if requested_state is None and normalized_review_state not in {"", "all"}:
                requested_state = normalized_review_state
        effective_limit = limit or page_size
        reports, total = repository.list_reports(
            run_id=run_id,
            technique_id=technique_id,
            lifecycle_state=requested_state,
            qa_verdict=qa_verdict,
            search=search,
            include_deleted=include_deleted,
            limit=effective_limit,
            offset=((page or 1) - 1) * effective_limit,
        )
        summaries = [{"report_id": row["id"], "display_id": row["display_id"], "run_id": row["run_id"], "technique_id": row["technique_id"], "technique_name": row["technique_name"], "finding_count": row["finding_count"], "severity_breakdown": row["severity_breakdown"], "qa_verdict": row["qa_verdict"], "lifecycle_state": row["lifecycle_state"], "review_state": row["lifecycle_state"], "requires_review": row["lifecycle_state"] in REVIEW_PENDING_REPORT_STATES, "version": row["version"], "generated_date": row["created_at"], "current_revision_id": row["current_revision_id"]} for row in reports]
        # Original client expects a bare list; explicit pagination opts into the
        # durable envelope used by the new UI.
        return {"items": summaries, "total": total, "page": page or 1, "page_size": effective_limit} if page is not None or limit is not None else summaries

    def report_detail(report_id: str, revision_id: str | None = None) -> dict[str, Any]:
        report = repository.get_report(report_id)
        if report is None:
            raise ApiProblem(404, "report_not_found", f"Report '{report_id}' was not found.")
        revision = repository.get_revision(report["id"], revision_id) if revision_id else repository.get_current_revision(report["id"])
        if revision is None:
            raise ApiProblem(404, "revision_not_found", "Report has no available revision.")
        data = dict(revision["report_data"])
        artifact = repository.get_artifact(report["artifact_id"]) if report.get("artifact_id") else None
        observations = repository.list_observations(report["artifact_id"]) if report.get("artifact_id") else []
        candidates = repository.list_candidates(artifact_id=report["artifact_id"], technique_id=report.get("technique_id")) if report.get("artifact_id") else []
        candidate_observation_ids = {str(candidate.get("observation_id")) for candidate in candidates if candidate.get("observation_id")}
        report_observations = [
            observation for observation in observations
            if not candidate_observation_ids or str(observation.get("id")) in candidate_observation_ids
        ]
        graph_paths = repository.list_graph_paths([candidate["id"] for candidate in candidates])
        revision_metadata = {key: value for key, value in revision.items() if key not in {"report_data", "narrative"}}
        mapping_snapshot_hash = revision.get("mapping_snapshot_hash") or data.get("mapping_snapshot_hash")
        run = repository.get_run(report["run_id"])
        graph_snapshot_id = _report_graph_snapshot_id(
            report_data=data,
            revision_metadata=revision.get("metadata") if isinstance(revision.get("metadata"), Mapping) else {},
            graph_paths=graph_paths,
            candidates=candidates,
            run_graph_snapshot_id=run.get("graph_snapshot_id") if run else None,
        )
        revisions = [
            {key: value for key, value in item.items() if key not in {"report_data", "narrative"}}
            for item in repository.list_revisions(report["id"])
        ]
        data.update({
            "id": report["id"],
            "report_id": report["id"],
            "display_id": report["display_id"],
            "run_id": report["run_id"],
            "lifecycle_state": report["lifecycle_state"],
            "qa_verdict": report["qa_verdict"],
            "version": report["version"],
            "revision": revision_metadata,
            "current_revision": revision_metadata,
            "revisions": revisions,
            "reviews": repository.report_reviews(report["id"]),
            "evidence": report_observations,
            "artifact_observation_count": len(observations),
            "candidates": candidates,
            "graph_paths": graph_paths,
            "provenance": {
                "artifact": artifact,
                "graph_snapshot_id": graph_snapshot_id,
                "mapping_snapshot_hash": mapping_snapshot_hash,
                "provider": data.get("provider"),
                "llm_graph_tool_crawl": data.get("llm_graph_tool_crawl"),
            },
        })
        return data

    @app.get("/api/reports/{report_id}")
    async def get_report(report_id: str, request: Request):
        _authorize(app, request, "view")
        return report_detail(report_id)

    @app.get("/api/reports/{report_id}/revisions/{revision_id}")
    async def get_report_revision(report_id: str, revision_id: str, request: Request):
        _authorize(app, request, "view")
        return report_detail(report_id, revision_id)

    @app.get("/api/reports/{report_id}/markdown")
    async def get_report_markdown(report_id: str, request: Request):
        _authorize(app, request, "view")
        report = repository.get_report(report_id, include_deleted=False)
        revision = repository.get_current_revision(report["id"]) if report else None
        if not report or not revision or not revision.get("markdown_path"):
            raise ApiProblem(404, "report_markdown_not_found", f"Report '{report_id}' markdown was not found.")
        workspace = RunWorkspace.open(settings.runs_dir, report["run_id"])
        path = workspace.resolve_relative(revision["markdown_path"])
        if not path.is_file():
            raise ApiProblem(404, "report_markdown_not_found", f"Report '{report_id}' markdown was not found.")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.post("/api/reports/{report_id}/rerender")
    async def rerender_report(report_id: str, request: Request):
        """Append a current-template/current-graph report revision.

        This route intentionally accepts no body: the actor is always derived
        from the authenticated principal and the retained report evidence is
        the only input.  A renderer refresh is not an analysis retry and does
        not instantiate or call a local/cloud LLM provider.
        """
        try:
            actor = _authorize(app, request, "review")
            engine = _require_engine(app)
            result = await asyncio.to_thread(
                rerender_report_from_durable_evidence,
                repository=repository,
                runs_dir=settings.runs_dir,
                engine=engine,
                report_id=report_id,
                actor_id=actor,
            )
            updated = result["report"]
            repository.append_event(
                updated["run_id"],
                "report_rerendered",
                {
                    "phase": "review",
                    "message": f"Re-rendered {updated['display_id']} with the current graph and template; manual review is required.",
                    "current": {"report_id": updated["id"], "revision_id": result["revision_id"], "rerendered_by": actor},
                    "counters": {"reports_review_pending": 1},
                    "rerender": {
                        "source_observation_count": result["source_observation_count"],
                        "mapping_snapshot_hash": result["mapping_snapshot_hash"],
                        "provider_calls_made": False,
                    },
                },
            )
            repository.recompute_run_completion(updated["run_id"])
            # Keep the client contract simple: it can replace its existing
            # detail state directly, then retrieve the current Markdown as
            # usual. Older revision/review records remain separately readable.
            return report_detail(updated["id"])
        except Exception as exc:
            raise _problem_from_exception(exc)

    @app.patch("/api/reports/{report_id}/review")
    async def review_report(report_id: str, body: ReviewRequest, request: Request):
        try:
            actor = _authorize(app, request, "review", declared_actor=body.actor)
            note = _required_note(body)
            report = repository.review_report(
                report_id=report_id,
                expected_version=_expected_version(request, body.version, resource="report"),
                decision=body.decision.lower(),
                actor_id=actor,
                reason=body.reason,
                notes=note,
            )
            repository.append_event(report["run_id"], "report_reviewed", {"phase": "review", "message": f"Report {report['display_id']} marked {report['lifecycle_state']}", "current": {"report_id": report["id"]}})
            run = repository.recompute_run_completion(report["run_id"])
            return {"report": report, "run": repository.get_run_snapshot(run["id"])}
        except Exception as exc:
            raise _problem_from_exception(exc)

    @app.delete("/api/reports/{report_id}")
    async def delete_report(report_id: str, body: DeleteRequest, request: Request):
        try:
            actor = _authorize(app, request, "delete", declared_actor=body.actor)
            original = repository.get_report(report_id, include_deleted=False)
            if original is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            workspace = RunWorkspace.open(settings.runs_dir, original["run_id"])
            revisions = repository.list_revisions(original["id"])
            if not revisions:
                raise ConflictError("Report has no revision assets to delete.")
            operation_id = str(uuid.uuid4())
            manifest = workspace.plan_report_trash_manifest(
                report_id=original["id"],
                operation_id=operation_id,
                revisions=revisions,
            )
            expiry = (datetime.now(timezone.utc) + timedelta(hours=settings.delete_retention_hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            _, audit = repository.begin_delete(
                report_id=original["id"],
                expected_version=_expected_version(request, body.version, resource="report"),
                actor_id=actor,
                reason=body.reason.strip(),
                undo_expires_at=expiry,
                trash_manifest=manifest,
            )
            try:
                workspace.move_manifest_to_trash(manifest)
            except Exception:
                # The workspace method compensates in-process moves. The
                # durable journal still protects a process interruption.
                repository.abort_delete(str(audit["id"]))
                raise
            try:
                report, audit = repository.complete_delete(str(audit["id"]))
            except Exception:
                # A database error after all renames must not strand a live
                # report whose files are only in trash. Restore first, then
                # return the journaled lifecycle state to its prior value.
                workspace.restore_from_trash(manifest, allow_already_restored=True)
                repository.abort_delete(str(audit["id"]))
                raise
            repository.append_event(report["run_id"], "report_deleted", {"phase": "review", "message": f"Deleted report {report['display_id']}", "current": {"report_id": report["id"]}})
            repository.recompute_run_completion(report["run_id"])
            return {"report": report, "deletion": audit}
        except Exception as exc:
            raise _problem_from_exception(exc)

    @app.post("/api/reports/{report_id}/restore")
    async def restore_report(report_id: str, body: RestoreRequest, request: Request):
        try:
            actor = _authorize(app, request, "delete", declared_actor=body.actor)
            report = repository.get_report(report_id)
            if report is None:
                raise NotFoundError(f"Report '{report_id}' was not found.")
            workspace = RunWorkspace.open(settings.runs_dir, report["run_id"])
            _, audit = repository.begin_restore(
                report_id=report["id"],
                expected_version=_expected_version(request, body.version, resource="report"),
                actor_id=actor,
                reason=body.reason,
            )
            try:
                workspace.restore_from_trash(audit["trash_manifest"])
                restored = repository.complete_restore(str(audit["id"]))
            except Exception:
                # Return any partially restored assets to their durable trash
                # locations before rolling the report back to ``deleted``.
                workspace.return_restored_assets_to_trash(audit["trash_manifest"])
                repository.abort_restore(str(audit["id"]))
                raise
            repository.append_event(restored["run_id"], "report_restored", {"phase": "review", "message": f"Restored report {restored['display_id']}", "current": {"report_id": restored["id"]}})
            repository.recompute_run_completion(restored["run_id"])
            return {"report": restored}
        except Exception as exc:
            raise _problem_from_exception(exc)

    async def retry_source_run_for_report(
        report_id: str,
        request: Request,
        body: RetryRequest | None = None,
    ):
        """Create a new run from the report's retained source artifact.

        Reports are immutable revisions, so this deliberately retries the
        entire source run rather than pretending to reprocess one report in
        isolation.  A source artifact may produce multiple technique reports.
        """
        actor = _authorize(app, request, "operate")
        report = repository.get_report(report_id, include_deleted=False)
        if report is None:
            raise ApiProblem(404, "report_not_found", f"Report '{report_id}' was not found.")
        if report["lifecycle_state"] == "legacy":
            raise ApiProblem(
                409,
                "legacy_source_unavailable",
                "Legacy reports do not retain an original source artifact and cannot start a source-run retry.",
            )
        return await retry_run_from_source(
            report["run_id"],
            actor=actor,
            model=body.model if body else None,
            cloud_acknowledged=bool(body and body.cloud_acknowledged),
        )

    @app.post("/api/reports/{report_id}/retry-source-run", status_code=202)
    async def retry_report_source_run(report_id: str, request: Request, body: RetryRequest | None = None):
        return await retry_source_run_for_report(report_id, request, body)

    @app.post("/api/reports/{report_id}/reprocess", status_code=202, deprecated=True)
    async def reprocess_report_legacy_alias(report_id: str, request: Request, body: RetryRequest | None = None):
        """Deprecated alias; this retries the complete retained source run."""
        return await retry_source_run_for_report(report_id, request, body)

    @app.post("/api/reports/{report_id}/pdf")
    async def report_pdf(report_id: str, request: Request):
        _authorize(app, request, "view")
        report = repository.get_report(report_id, include_deleted=False)
        revision = repository.get_current_revision(report["id"]) if report else None
        if not report or not revision or not revision.get("markdown_path"):
            raise ApiProblem(404, "report_not_found", f"Report '{report_id}' was not found.")
        workspace = RunWorkspace.open(settings.runs_dir, report["run_id"])
        markdown = workspace.resolve_relative(revision["markdown_path"])
        if not markdown.is_file():
            raise ApiProblem(404, "report_markdown_not_found", f"Report '{report_id}' markdown was not found.")
        pdf_path = workspace.exports_dir / report["id"] / f"{revision['id']}.pdf"
        if revision.get("pdf_path"):
            cached = workspace.resolve_relative(revision["pdf_path"])
            if cached.is_file() and cached.stat().st_mtime >= markdown.stat().st_mtime:
                return Response(cached.read_bytes(), media_type="application/pdf")
        try:
            from .pdf_export import render_markdown_pdf
            pdf_bytes = render_markdown_pdf(markdown.read_text(encoding="utf-8"), title=report["display_id"])
        except ImportError as exc:
            raise ApiProblem(501, "pdf_unavailable", "PDF export dependencies are not installed.") from exc
        workspace.atomic_write_bytes(pdf_path, pdf_bytes)
        repository.set_revision_pdf(revision["id"], pdf_path=workspace.relative(pdf_path), pdf_sha256=RunWorkspace.sha256_file(pdf_path) or "")
        return Response(pdf_bytes, media_type="application/pdf")

    @app.get("/api/health")
    async def health():
        engine = app.state.engine
        auth_ready = app.state.auth_policy.is_ready and not bool(settings.auth_configuration_error)
        if engine is None or not auth_ready:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "reason": app.state.engine_error or settings.auth_configuration_error or "authentication configuration is incomplete",
                    "authentication_mode": settings.auth_mode,
                    "authentication_ready": auth_ready,
                },
            )
        graph = getattr(engine, "graph", None)
        return {
            "status": "ok",
            "graph_nodes": graph.number_of_nodes() if graph is not None else None,
            "graph_edges": graph.number_of_edges() if graph is not None else None,
            "graph_snapshot_id": getattr(engine, "graph_snapshot_id", None),
            "semantic_search": getattr(engine, "semantic_status", "unavailable"),
            "authentication_mode": settings.auth_mode,
            "authentication_ready": auth_ready,
        }

    if settings.frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_dist, html=True), name="frontend")
    return app


def _require_engine(app: FastAPI) -> Any:
    if app.state.engine is None:
        raise ApiProblem(
            503,
            "graph_unavailable",
            app.state.engine_error or "Knowledge graph is unavailable; wait for graph initialization to recover before submitting or retrying work.",
        )
    return app.state.engine


app = create_app()
