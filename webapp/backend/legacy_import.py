"""Import loose historical report pairs as explicitly read-only legacy records.

Old ``reports/CONSOL-Txxxx.{md,json}`` files have no durable run, artifact,
candidate, or path provenance.  This importer preserves them for discovery and
controlled deletion without presenting them as new evidence-first reports.
Use ``--apply`` deliberately; normal web startup never imports mutable legacy
files on its own.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from .db import LifecycleRepository
from .workspace import RunWorkspace


LEGACY_NAMESPACE = uuid.UUID("7d583e41-c3a5-4e7c-b3e8-d9ff2e7d9ad9")
TECHNIQUE_RE = re.compile(r"T\d{4}(?:[-.]\d{3})?", re.IGNORECASE)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _report_data(json_path: Path | None, markdown_path: Path | None, stem: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if json_path and json_path.is_file():
        try:
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {"legacy_import_warning": "Historical JSON could not be parsed."}
    data.setdefault("report_id", stem)
    data.setdefault("schema_version", "legacy")
    data["legacy"] = {
        "read_only": True,
        "provenance_complete": False,
        "message": "Imported historical output; reprocess its original artifact to obtain durable evidence and validated mapping paths.",
        "source_markdown": str(markdown_path) if markdown_path else None,
        "source_json": str(json_path) if json_path else None,
    }
    return data


def import_legacy_reports(*, source_dir: str | Path, data_dir: str | Path, apply: bool = False) -> dict[str, int]:
    source = Path(source_dir).resolve()
    data = Path(data_dir).resolve()
    # Build the pair table without relying on filenames as report identities.
    pairs: dict[str, dict[str, Path | None]] = {}
    for path in sorted([*source.glob("*.json"), *source.glob("*.md")]):
        pairs.setdefault(path.stem, {"json": None, "markdown": None})
        pairs[path.stem]["json" if path.suffix == ".json" else "markdown"] = path
    if not pairs:
        return {"discovered": 0, "imported": 0, "skipped": 0}
    if not apply:
        # A real dry run intentionally avoids even creating SQLite/workspace
        # directories; it only reports the report pairs it discovered.
        return {"discovered": len(pairs), "imported": len(pairs), "skipped": 0}

    repository = LifecycleRepository(data / "csdh.sqlite3")
    repository.initialize()
    run_id = str(uuid.uuid5(LEGACY_NAMESPACE, f"legacy-run:{source}"))
    workspace = RunWorkspace.create(data / "runs", run_id)
    if repository.get_run(run_id) is None:
        repository.create_run(
            run_id=run_id,
            workspace_path=str(workspace.path),
            requested_provider="legacy",
            policy_version="legacy-import-v1",
            status="completed",
        )

    imported = 0
    skipped = 0
    for stem, pair in pairs.items():
        report_id = str(uuid.uuid5(LEGACY_NAMESPACE, f"legacy-report:{source / stem}"))
        if repository.get_report(report_id) is not None:
            skipped += 1
            continue
        markdown_path = pair.get("markdown")
        json_path = pair.get("json")
        payload = _report_data(json_path, markdown_path, stem)
        technique_id = str(payload.get("technique_id") or "")
        if not technique_id:
            match = TECHNIQUE_RE.search(stem)
            technique_id = match.group(0).replace("-", ".").upper() if match else "LEGACY"
        technique_name = str(payload.get("technique_name") or "Historical report")
        artifact_id = str(uuid.uuid5(LEGACY_NAMESPACE, f"legacy-artifact:{source / stem}"))
        source_asset = json_path or markdown_path
        if source_asset is None:
            skipped += 1
            continue
        stored_source = workspace.atomic_copy(source_asset, workspace.uploads_dir / f"legacy-{report_id}{source_asset.suffix}")
        repository.create_artifact(
            artifact_id=artifact_id,
            run_id=run_id,
            original_name=source_asset.name,
            media_type="application/json" if source_asset.suffix == ".json" else "text/markdown",
            extension=source_asset.suffix,
            sha256=_sha256(source_asset),
            storage_key=workspace.relative(stored_source),
            byte_size=source_asset.stat().st_size,
            kind="legacy_report",
            parse_status="legacy",
            metadata={"legacy_source_dir": str(source), "provenance_complete": False},
        )
        staging_md = workspace.pipeline_dir / f"{report_id}.md"
        staging_json = workspace.pipeline_dir / f"{report_id}.json"
        if markdown_path:
            workspace.atomic_copy(markdown_path, staging_md)
        if json_path:
            workspace.atomic_copy(json_path, staging_json)
        elif not staging_json.exists():
            workspace.atomic_write_bytes(staging_json, json.dumps(payload, indent=2).encode("utf-8"))
        assets = workspace.publish_report_assets(report_id=report_id, markdown_source=staging_md if staging_md.is_file() else None, json_source=staging_json)
        revision_id = str(uuid.uuid4())
        repository.create_report_with_revision(
            report_id=report_id,
            revision_id=revision_id,
            run_id=run_id,
            artifact_id=artifact_id,
            display_id=str(payload.get("report_id") or stem),
            aggregate_key=technique_id,
            technique_id=technique_id,
            technique_name=technique_name,
            finding_count=int(payload.get("finding_count") or len(payload.get("affected_hosts") if isinstance(payload.get("affected_hosts"), list) else [])),
            severity_breakdown=payload.get("severity_breakdown") if isinstance(payload.get("severity_breakdown"), dict) else {},
            qa_verdict="LEGACY",
            lifecycle_state="legacy",
            report_data=payload,
            narrative={},
            markdown_path=assets["markdown_path"],
            json_path=assets["json_path"],
            markdown_sha256=RunWorkspace.sha256_file(workspace.resolve_relative(assets["markdown_path"])) if assets["markdown_path"] else None,
            json_sha256=RunWorkspace.sha256_file(workspace.resolve_relative(assets["json_path"])) if assets["json_path"] else None,
            qa_state="legacy",
            metadata={"legacy": True, "provenance_complete": False},
            created_by="legacy-import",
        )
        imported += 1
    repository.recompute_run_completion(run_id)
    return {"discovered": len(pairs), "imported": imported, "skipped": skipped}


def main() -> None:
    parser = argparse.ArgumentParser(description="Import loose report files as read-only legacy records")
    parser.add_argument("--source-dir", default="reports")
    parser.add_argument("--data-dir", default=os.environ.get("CSDH_DATA_DIR") or os.environ.get("MITRE_CSDH_DATA_DIR") or "data")
    parser.add_argument("--apply", action="store_true", help="perform import; omit to list what would be imported")
    args = parser.parse_args()
    result = import_legacy_reports(source_dir=args.source_dir, data_dir=args.data_dir, apply=args.apply)
    print(f"Legacy import {'applied' if args.apply else 'dry run'}: {result}")


if __name__ == "__main__":
    main()
