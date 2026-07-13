"""Controlled retention maintenance for durable MITRE CSD-H workspaces.

This command purges only report assets whose soft-delete undo window has
already expired.  It does not erase the report/tombstone/audit record, so an
operator can still establish what was deleted, by whom, and when.  Run with
``--apply`` from a scheduled maintenance job after backing up ``data/``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .db import LifecycleRepository
from .workspace import RunWorkspace, WorkspaceError


def reconcile_incomplete_deletion_operations(
    *,
    repository: LifecycleRepository,
    runs_dir: str | Path,
    limit: int = 500,
) -> dict[str, int]:
    """Safely compensate filesystem work interrupted by a process crash.

    The deletion/restore journal is committed before its filesystem rename
    phase.  Rather than guessing whether a partial operation should be
    completed, recovery chooses the conservative result: restore the prior
    durable state and let an operator retry the requested action.  A failed
    compensation is left journaled for investigation; it is never marked
    complete without the assets being reconciled.
    """
    recovered = 0
    failures = 0
    for audit in repository.list_pending_deletion_operations(limit=limit):
        manifest = audit.get("trash_manifest") or {}
        run_id = str(manifest.get("run_id") or "")
        if not run_id:
            failures += 1
            continue
        try:
            workspace = RunWorkspace.open(runs_dir, run_id)
            if audit.get("operation_state") == "delete_prepared":
                workspace.restore_from_trash(manifest, allow_already_restored=True)
                repository.abort_delete(str(audit["id"]))
            elif audit.get("operation_state") == "restore_prepared":
                workspace.return_restored_assets_to_trash(manifest)
                repository.abort_restore(str(audit["id"]))
            else:
                continue
            recovered += 1
        except (WorkspaceError, OSError, RuntimeError):
            failures += 1
    return {"recovered_operations": recovered, "recovery_failures": failures}


def purge_expired_deletions(*, data_dir: str | Path, apply: bool = False, limit: int = 500) -> dict[str, int]:
    root = Path(data_dir).resolve()
    repository = LifecycleRepository(root / "csdh.sqlite3")
    repository.initialize()
    recovery = reconcile_incomplete_deletion_operations(repository=repository, runs_dir=root / "runs", limit=limit)
    audits = repository.list_expired_deletion_audits(limit=limit)
    files = 0
    purged = 0
    failures = 0
    for audit in audits:
        manifest = audit.get("trash_manifest") or {}
        run_id = str(manifest.get("run_id") or "")
        if not run_id:
            failures += 1
            continue
        if not apply:
            purged += 1
            files += len(manifest.get("files") or [])
            continue
        try:
            workspace = RunWorkspace.open(root / "runs", run_id)
            files += workspace.purge_trash_manifest(manifest)
            repository.mark_deletion_purged(str(audit["id"]))
            purged += 1
        except (WorkspaceError, OSError, RuntimeError):
            failures += 1
    return {
        "eligible_audits": len(audits),
        "purged_audits": purged,
        "purged_files": files,
        "failures": failures,
        **recovery,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Purge expired soft-deleted report assets safely")
    parser.add_argument("--data-dir", default=os.environ.get("CSDH_DATA_DIR") or os.environ.get("MITRE_CSDH_DATA_DIR") or "data")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--apply", action="store_true", help="perform deletion; omit for a dry-run summary")
    args = parser.parse_args()
    result = purge_expired_deletions(data_dir=args.data_dir, apply=args.apply, limit=args.limit)
    mode = "applied" if args.apply else "dry run"
    print(f"Retention {mode}: {result}")
    if result["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
