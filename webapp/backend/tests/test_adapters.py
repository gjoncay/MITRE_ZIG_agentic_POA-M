"""Artifact-adapter tests that do not require a model or a running server."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pandas as pd

from webapp.backend import pipeline_adapter
from webapp.backend.pipeline_adapter import NormalizationError, normalize_artifact
from webapp.backend.legacy_import import import_legacy_reports
from webapp.backend.db import LifecycleRepository
from webapp.backend.workspace import RunWorkspace


def test_stix_bundle_keeps_each_object_locator_and_attack_id_context(tmp_path: Path) -> None:
    artifact = tmp_path / "bundle.json"
    artifact.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--example",
        "objects": [
            {"type": "attack-pattern", "id": "attack-pattern--one", "name": "Phishing", "description": "Observed T1566.", "external_references": [{"external_id": "T1566"}]},
            {"type": "attack-pattern", "id": "attack-pattern--two", "name": "Network Service Scanning", "description": "Observed T1046.", "external_references": [{"external_id": "T1046"}]},
        ],
    }), encoding="utf-8")
    workspace = RunWorkspace.create(tmp_path / "runs", str(uuid.uuid4()))

    normalized = normalize_artifact(artifact_path=artifact, extension=".json", workspace=workspace)

    assert [item["source_locator"]["object_id"] for item in normalized.observations] == [
        "attack-pattern--one", "attack-pattern--two",
    ]
    assert [item["source_locator"]["kind"] for item in normalized.observations] == ["stix_object", "stix_object"]
    assert [item["explicit_ids"] for item in normalized.observations] == [["T1566"], ["T1046"]]
    assert normalized.metadata["normalization_limits"]["normalized_observations"] == pipeline_adapter.MAX_NORMALIZED_OBSERVATIONS
    frame = pd.read_csv(normalized.input_csv)
    assert set(frame["_source_row"].astype(str)) == {"attack-pattern--one", "attack-pattern--two"}


def test_normalizer_enforces_tabular_row_sheet_and_text_chunk_limits(tmp_path: Path) -> None:
    csv_artifact = tmp_path / "too-many.csv"
    csv_artifact.write_text("Finding\nT1003 first\nT1059 second\nT1046 third\n", encoding="utf-8")
    text_artifact = tmp_path / "too-many.txt"
    text_artifact.write_text("First finding. Second finding. Third finding.", encoding="utf-8")
    workbook_artifact = tmp_path / "too-many-sheets.xlsx"
    with pd.ExcelWriter(workbook_artifact) as writer:
        pd.DataFrame({"Finding": ["T1003"]}).to_excel(writer, index=False, sheet_name="One")
        pd.DataFrame({"Finding": ["T1059"]}).to_excel(writer, index=False, sheet_name="Two")

    original_row_limit = pipeline_adapter.MAX_TABULAR_ROWS_PER_SHEET
    original_sheet_limit = pipeline_adapter.MAX_TABULAR_SHEETS
    original_chunk_limit = pipeline_adapter.MAX_TEXT_CHUNKS
    try:
        pipeline_adapter.MAX_TABULAR_ROWS_PER_SHEET = 2
        workspace = RunWorkspace.create(tmp_path / "runs", str(uuid.uuid4()))
        try:
            normalize_artifact(artifact_path=csv_artifact, extension=".csv", workspace=workspace)
        except NormalizationError as exc:
            assert "row limit" in str(exc)
        else:
            raise AssertionError("CSV above the normalized-row limit was accepted")

        pipeline_adapter.MAX_TABULAR_SHEETS = 1
        workspace = RunWorkspace.create(tmp_path / "runs", str(uuid.uuid4()))
        try:
            normalize_artifact(artifact_path=workbook_artifact, extension=".xlsx", workspace=workspace)
        except NormalizationError as exc:
            assert "sheets" in str(exc)
        else:
            raise AssertionError("Workbook above the sheet limit was accepted")

        pipeline_adapter.MAX_TEXT_CHUNKS = 2
        workspace = RunWorkspace.create(tmp_path / "runs", str(uuid.uuid4()))
        try:
            normalize_artifact(artifact_path=text_artifact, extension=".txt", workspace=workspace)
        except NormalizationError as exc:
            assert "chunk limit" in str(exc)
        else:
            raise AssertionError("Text above the normalized-chunk limit was accepted")
    finally:
        pipeline_adapter.MAX_TABULAR_ROWS_PER_SHEET = original_row_limit
        pipeline_adapter.MAX_TABULAR_SHEETS = original_sheet_limit
        pipeline_adapter.MAX_TEXT_CHUNKS = original_chunk_limit


def test_workspace_purge_only_removes_expired_trash_manifest_assets(tmp_path: Path) -> None:
    workspace = RunWorkspace.create(tmp_path / "runs", str(uuid.uuid4()))
    trashed = workspace.trash_dir / "report" / "revision" / "report.md"
    workspace.atomic_write_bytes(trashed, b"deleted report")
    manifest = {"files": [{"kind": "markdown_path", "trash": workspace.relative(trashed), "original": "reports/report/report.md"}]}

    removed = workspace.purge_trash_manifest(manifest)

    assert removed == 1
    assert not trashed.exists()


def test_legacy_report_import_is_explicit_and_marks_records_read_only(tmp_path: Path) -> None:
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "CONSOL-T1003.md").write_text("# Historical report\n", encoding="utf-8")
    (source / "CONSOL-T1003.json").write_text(json.dumps({"report_id": "CONSOL-T1003", "technique_id": "T1003", "technique_name": "OS Credential Dumping"}), encoding="utf-8")
    data_dir = tmp_path / "data"

    dry_run = import_legacy_reports(source_dir=source, data_dir=data_dir, apply=False)
    assert dry_run == {"discovered": 1, "imported": 1, "skipped": 0}
    assert not data_dir.exists()

    applied = import_legacy_reports(source_dir=source, data_dir=data_dir, apply=True)
    assert applied["imported"] == 1
    repository = LifecycleRepository(data_dir / "csdh.sqlite3")
    reports, _ = repository.list_reports(include_deleted=True)
    assert reports[0]["lifecycle_state"] == "legacy"
    assert reports[0]["metadata"]["legacy"] is True
