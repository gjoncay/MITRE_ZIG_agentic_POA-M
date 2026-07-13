"""Run-scoped filesystem storage.

No web request is allowed to write the repository-root
``processed_assessment.csv`` or global ``reports/`` directory.  Every input,
intermediate, generated report and export belongs to exactly one run workspace
under ``data/runs/<uuid>/``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class WorkspaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredFile:
    path: Path
    relative_path: str
    sha256: str
    byte_size: int


@dataclass(frozen=True)
class RunWorkspace:
    """Paths and safe publication operations for a single analysis run."""

    root: Path
    run_id: str

    @property
    def path(self) -> Path:
        return self.root / self.run_id

    @property
    def uploads_dir(self) -> Path:
        return self.path / "upload"

    @property
    def normalized_dir(self) -> Path:
        return self.path / "normalized"

    @property
    def mapping_dir(self) -> Path:
        return self.path / "mapping"

    @property
    def pipeline_dir(self) -> Path:
        return self.path / "pipeline_output"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def exports_dir(self) -> Path:
        return self.path / "exports"

    @property
    def trash_dir(self) -> Path:
        return self.path / "trash"

    @property
    def normalized_csv_path(self) -> Path:
        return self.normalized_dir / "observations.csv"

    @classmethod
    def create(cls, runs_root: str | Path, run_id: str) -> "RunWorkspace":
        workspace = cls(Path(runs_root).resolve(), run_id)
        # UUID validation protects the directory construction, even though the
        # web layer also only generates UUIDs itself.
        try:
            uuid.UUID(run_id)
        except (ValueError, AttributeError) as exc:
            raise WorkspaceError("Run workspace IDs must be UUIDs.") from exc
        for directory in (
            workspace.uploads_dir,
            workspace.normalized_dir,
            workspace.mapping_dir,
            workspace.pipeline_dir,
            workspace.reports_dir,
            workspace.exports_dir,
            workspace.trash_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return workspace

    @classmethod
    def open(cls, runs_root: str | Path, run_id: str) -> "RunWorkspace":
        workspace = cls(Path(runs_root).resolve(), run_id)
        if not workspace.path.is_dir():
            raise WorkspaceError(f"Run workspace '{run_id}' does not exist.")
        return workspace

    def relative(self, path: str | Path) -> str:
        resolved = Path(path).resolve()
        try:
            return str(resolved.relative_to(self.path.resolve()))
        except ValueError as exc:
            raise WorkspaceError("Attempted to publish a path outside its run workspace.") from exc

    def resolve_relative(self, relative_path: str) -> Path:
        candidate = (self.path / relative_path).resolve()
        try:
            candidate.relative_to(self.path.resolve())
        except ValueError as exc:
            raise WorkspaceError("Stored path escapes its run workspace.") from exc
        return candidate

    async def store_upload(
        self,
        upload: Any,
        *,
        filename: str,
        max_bytes: int,
        chunk_bytes: int = 1024 * 1024,
    ) -> StoredFile:
        """Stream an UploadFile-like object into an atomically published file.

        ``UploadFile.read`` is deliberately called in bounded chunks rather
        than loading an untrusted spreadsheet into memory in one request.
        """
        safe_name = Path(filename or "artifact").name
        if safe_name in {"", ".", ".."}:
            safe_name = "artifact"
        destination = self.uploads_dir / safe_name
        # More than one artifact may share a filename in retries/manual API
        # use.  A UUID prefix avoids accidental replacement.
        destination = destination.with_name(f"{uuid.uuid4().hex}_{safe_name}")
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        digest = hashlib.sha256()
        total = 0
        try:
            with temporary.open("xb") as handle:
                while True:
                    chunk = await upload.read(chunk_bytes)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise WorkspaceError(f"Upload exceeds the {max_bytes} byte limit.")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if total == 0:
                raise WorkspaceError("Upload is empty.")
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return StoredFile(
            path=destination,
            relative_path=self.relative(destination),
            sha256=digest.hexdigest(),
            byte_size=total,
        )

    def store_text(self, text: str, *, filename: str = "pasted-threat-intel.txt") -> StoredFile:
        raw = text.encode("utf-8")
        if not raw:
            raise WorkspaceError("Text artifact is empty.")
        destination = self.uploads_dir / filename
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        return StoredFile(
            path=destination,
            relative_path=self.relative(destination),
            sha256=hashlib.sha256(raw).hexdigest(),
            byte_size=len(raw),
        )

    def atomic_copy(self, source: str | Path, destination: str | Path) -> Path:
        """Copy then atomically publish a file inside this workspace."""
        source_path = Path(source).resolve()
        target = Path(destination).resolve()
        self.relative(target)
        if not source_path.is_file():
            raise WorkspaceError(f"Cannot publish missing source file '{source_path}'.")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        try:
            with source_path.open("rb") as read_handle, temporary.open("xb") as write_handle:
                shutil.copyfileobj(read_handle, write_handle, length=1024 * 1024)
                write_handle.flush()
                os.fsync(write_handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return target

    def atomic_write_bytes(self, destination: str | Path, data: bytes) -> Path:
        target = Path(destination).resolve()
        self.relative(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return target

    def reset_derived_outputs(self) -> None:
        """Remove replayable worker outputs while preserving the immutable upload.

        Startup recovery uses this after reserving an interrupted run.  It is
        intentionally idempotent: an interruption during cleanup simply runs
        the same cleanup again on the next startup.  Never include ``upload``
        or ``trash`` here—those hold source evidence and independently
        journaled deletion-retention assets.
        """
        for directory in (
            self.normalized_dir,
            self.mapping_dir,
            self.pipeline_dir,
            self.reports_dir,
            self.exports_dir,
        ):
            resolved = directory.resolve()
            self.relative(resolved)
            if resolved.is_symlink():
                raise WorkspaceError(f"Refusing to reset symlinked workspace directory '{resolved.name}'.")
            if resolved.exists():
                shutil.rmtree(resolved)
            resolved.mkdir(parents=True, exist_ok=True)

    def discard_uncommitted(self) -> None:
        """Remove a newly created workspace that never obtained a DB run row.

        This is intentionally narrower than retention/deletion operations:
        callers may use it only while retry/submission construction has failed
        before a durable run exists. Once a run row is recorded, preserve its
        workspace for the audit trail and mark the run failed instead.
        """
        root = self.root.resolve()
        candidate = self.path.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:  # pragma: no cover - UUID construction already constrains this
            raise WorkspaceError("Refusing to discard a path outside the runs root.") from exc
        if candidate.is_symlink():
            raise WorkspaceError("Refusing to discard a symlinked run workspace.")
        if candidate.exists():
            shutil.rmtree(candidate)

    def publish_report_assets(
        self,
        *,
        report_id: str,
        markdown_source: str | Path | None,
        json_source: str | Path | None,
    ) -> dict[str, str | None]:
        """Publish unique immutable revision assets from pipeline staging."""
        report_dir = self.reports_dir / report_id
        report_dir.mkdir(parents=True, exist_ok=True)
        paths: dict[str, str | None] = {"markdown_path": None, "json_path": None}
        if markdown_source is not None and Path(markdown_source).is_file():
            target = self.atomic_copy(markdown_source, report_dir / "report.md")
            paths["markdown_path"] = self.relative(target)
        if json_source is not None and Path(json_source).is_file():
            target = self.atomic_copy(json_source, report_dir / "report.json")
            paths["json_path"] = self.relative(target)
        return paths

    def plan_report_trash_manifest(
        self,
        *,
        report_id: str,
        operation_id: str,
        revisions: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Build a durable, deterministic deletion manifest before moving files.

        The caller persists this plan in SQLite *before* any rename.  A crash
        can therefore be reconciled by moving any partially moved assets back
        to their original paths.  All revision assets are included, not merely
        the current report revision.
        """
        files: list[dict[str, str]] = []
        seen_originals: set[str] = set()
        for revision in revisions:
            revision_id = str(revision.get("id") or "unknown-revision")
            for kind in ("markdown_path", "json_path", "pdf_path"):
                relative_path = revision.get(kind)
                if not relative_path:
                    continue
                original_relative = str(relative_path)
                # Older revisions can intentionally reference a shared asset.
                # Move it once, and use one manifest record for restoration.
                if original_relative in seen_originals:
                    continue
                original = self.resolve_relative(original_relative)
                if not original.is_file():
                    continue
                seen_originals.add(original_relative)
                target = self.trash_dir / report_id / operation_id / revision_id / f"{kind}-{original.name}"
                files.append(
                    {
                        "kind": kind,
                        "revision_id": revision_id,
                        "original": original_relative,
                        "trash": self.relative(target),
                    }
                )
        return {
            "run_id": self.run_id,
            "report_id": report_id,
            "operation_id": operation_id,
            "files": files,
        }

    def move_manifest_to_trash(self, manifest: Mapping[str, Any]) -> None:
        """Perform the filesystem half of a previously persisted delete plan.

        A failure is compensated immediately.  If the process dies instead,
        startup reconciliation calls :meth:`restore_from_trash` on the same
        manifest and returns the report to its prior lifecycle state.
        """
        moved: list[Mapping[str, Any]] = []
        try:
            for item in manifest.get("files", []):
                original = self.resolve_relative(str(item["original"]))
                target = self.resolve_relative(str(item["trash"]))
                try:
                    target.relative_to(self.trash_dir.resolve())
                except ValueError as exc:
                    raise WorkspaceError("Deletion manifest target is outside the run trash directory.") from exc
                if target.exists() and not original.exists():
                    # Idempotent recovery of an already-completed rename.
                    continue
                if not original.exists():
                    raise WorkspaceError(f"Report asset disappeared before deletion: {item.get('kind', 'unknown')}")
                if target.exists():
                    raise WorkspaceError(f"Deletion trash target already exists: {target.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(original, target)
                moved.append(item)
        except BaseException:
            # Best-effort in-process compensation.  Durable startup recovery
            # covers an interruption that occurs before this block runs.
            self.restore_from_trash({"files": moved}, allow_already_restored=True)
            raise

    def restore_from_trash(self, manifest: Mapping[str, Any], *, allow_already_restored: bool = False) -> None:
        """Restore every asset in a persisted manifest using atomic renames."""
        for item in manifest.get("files", []):
            source = self.resolve_relative(str(item["trash"]))
            destination = self.resolve_relative(str(item["original"]))
            if not source.exists():
                if allow_already_restored and destination.exists():
                    continue
                raise WorkspaceError(f"Deleted asset is no longer available for restore: {item.get('kind', 'unknown')}")
            if destination.exists():
                raise WorkspaceError(f"Cannot restore over an existing asset: {item.get('kind', 'unknown')}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)

    def return_restored_assets_to_trash(self, manifest: Mapping[str, Any]) -> None:
        """Compensate a failed/interrupted restore by returning files to trash."""
        moved: list[Mapping[str, Any]] = []
        try:
            for item in manifest.get("files", []):
                source = self.resolve_relative(str(item["original"]))
                target = self.resolve_relative(str(item["trash"]))
                if target.exists() and not source.exists():
                    continue
                if not source.exists():
                    raise WorkspaceError(f"Restored asset disappeared before recovery: {item.get('kind', 'unknown')}")
                if target.exists():
                    raise WorkspaceError(f"Cannot return asset to occupied trash target: {item.get('kind', 'unknown')}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, target)
                moved.append(item)
        except BaseException:
            self.restore_from_trash({"files": moved}, allow_already_restored=True)
            raise

    def move_revision_assets_to_trash(
        self,
        *,
        report_id: str,
        revision_id: str,
        asset_paths: Mapping[str, str | None],
    ) -> dict[str, Any]:
        """Backward-compatible one-revision wrapper for older callers.

        New durable deletion calls :meth:`plan_report_trash_manifest` followed
        by :meth:`move_manifest_to_trash` after storing the plan in SQLite.
        """
        manifest = self.plan_report_trash_manifest(
            report_id=report_id,
            operation_id=str(uuid.uuid4()),
            revisions=[{"id": revision_id, **dict(asset_paths)}],
        )
        self.move_manifest_to_trash(manifest)
        return manifest

    def purge_trash_manifest(self, manifest: Mapping[str, Any]) -> int:
        """Permanently remove only assets named by an expired deletion audit.

        This is called by the explicit maintenance command, never by a web
        request.  Every candidate path is still constrained to this run's
        ``trash/`` tree, so a malformed database record cannot delete an
        arbitrary workspace file.
        """
        removed = 0
        trash_root = self.trash_dir.resolve()
        for item in manifest.get("files", []):
            relative = str(item.get("trash") or "")
            if not relative:
                continue
            candidate = self.resolve_relative(relative)
            try:
                candidate.relative_to(trash_root)
            except ValueError as exc:
                raise WorkspaceError("Deletion manifest references a path outside the run trash directory.") from exc
            if candidate.is_file() or candidate.is_symlink():
                candidate.unlink()
                removed += 1
        # Leave no empty audit-only directory trees behind, but never walk
        # above ``trash/``.  This is intentionally conservative.
        for directory in sorted(trash_root.rglob("*"), key=lambda path: len(path.parts), reverse=True):
            if directory.is_dir():
                try:
                    directory.rmdir()
                except OSError:
                    pass
        return removed

    @staticmethod
    def sha256_file(path: str | Path) -> str | None:
        candidate = Path(path)
        if not candidate.is_file():
            return None
        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
