"""Run-scoped normalization and compatibility adapter for the analyst pipeline.

The legacy ingestion helper writes fixed filenames in the repository root.  The
web path must not call it.  This module normalizes supported artifacts directly
into a run workspace, then invokes ``run_pipeline`` with explicit input and
output paths.  It accepts both the original string progress callback and the
structured event callback introduced by the durable lifecycle.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import pandas as pd

from .workspace import RunWorkspace


class NormalizationError(ValueError):
    pass


class RunCanceled(RuntimeError):
    pass


@dataclass(frozen=True)
class NormalizedArtifact:
    input_csv: Path
    observations: list[dict[str, Any]]
    metadata: dict[str, Any]


ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Upload-byte limits prevent huge files, but they do not bound the number of
# work items produced by a compressed spreadsheet, a dense CSV, or sentence
# splitting.  These ceilings keep one artifact from monopolizing the worker or
# holding the SQLite writer lock while every normalized observation is stored.
HEADER_SCAN_ROWS = 50
MAX_TABULAR_SHEETS = 20
MAX_TABULAR_ROWS_PER_SHEET = 5_000
MAX_TABULAR_ROWS_TOTAL = 10_000
MAX_TEXT_CHUNKS = 10_000
MAX_TEXT_CHUNK_CHARACTERS = 20_000
MAX_JSON_OBSERVATIONS = 10_000
MAX_JSON_NODES = 50_000
MAX_JSON_NESTING = 64
MAX_NORMALIZED_OBSERVATIONS = 10_000


def _first_value(row: Mapping[str, Any], names: Iterable[str]) -> str | None:
    lower = {str(key).strip().lower(): value for key, value in row.items()}
    for name in names:
        value = lower.get(name.lower())
        if value is not None and str(value).strip() and str(value).lower() != "nan":
            return str(value).strip()
    return None


def _split_text(text: str) -> list[str]:
    chunks: list[str] = []
    for raw_line in re.split(r"\n+", text):
        line = raw_line.strip(" -*•\t")
        if not line:
            continue
        for raw_sentence in re.split(r"(?<=[.!?])\s+", line):
            sentence = raw_sentence.strip()
            if not sentence:
                continue
            if len(sentence) > MAX_TEXT_CHUNK_CHARACTERS:
                raise NormalizationError(
                    f"Text artifact contains a chunk longer than {MAX_TEXT_CHUNK_CHARACTERS:,} characters; split it into smaller findings."
                )
            if len(chunks) >= MAX_TEXT_CHUNKS:
                raise NormalizationError(
                    f"Text artifact exceeds the {MAX_TEXT_CHUNKS:,} normalized-chunk limit."
                )
            chunks.append(sentence)
    if chunks:
        return chunks
    fallback = text.strip()
    if fallback and len(fallback) > MAX_TEXT_CHUNK_CHARACTERS:
        raise NormalizationError(
            f"Text artifact contains a chunk longer than {MAX_TEXT_CHUNK_CHARACTERS:,} characters; split it into smaller findings."
        )
    return [fallback] if fallback else []


def _rows_from_dataframe(
    frame: pd.DataFrame,
    *,
    sheet_name: str,
    header_offset: int = 0,
    max_rows: int = MAX_TABULAR_ROWS_PER_SHEET,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for row_number, (_, series) in enumerate(frame.iterrows(), start=header_offset + 1):
        values = {
            str(column): str(value).strip()
            for column, value in series.items()
            if pd.notna(value) and str(value).strip() and str(value).strip().lower() != "nan"
        }
        if not values:
            continue
        behavior = _first_value(values, ("Finding", "Description", "Vulnerability", "Observation", "Details", "Title"))
        if not behavior:
            behavior = " | ".join(f"{key}: {value}" for key, value in values.items())
        if len(rows) >= max_rows:
            raise NormalizationError(
                f"Sheet '{sheet_name}' exceeds the {max_rows:,} normalized-row limit."
            )
        normalized = dict(values)
        normalized.setdefault("Finding", behavior)
        normalized.setdefault("Severity", _first_value(values, ("Severity", "Risk", "Priority")) or "Unknown")
        normalized.setdefault("IP", _first_value(values, ("IP", "IP Address", "Address")) or "N/A")
        normalized.setdefault("Hostname", _first_value(values, ("Hostname", "Host", "Asset", "Device")) or "N/A")
        normalized["_sheet"] = sheet_name
        normalized["_source_row"] = str(row_number)
        rows.append(normalized)
        observations.append(
            {
                "source_locator": {"kind": "tabular_row", "sheet": sheet_name, "row": row_number},
                "raw_text_hash": hashlib.sha256(behavior.encode("utf-8")).hexdigest(),
                "normalized_text": behavior,
                "context_text": " | ".join(f"{key}: {value}" for key, value in values.items()),
                "asset": {"ip": normalized["IP"], "hostname": normalized["Hostname"]},
                "severity": normalized["Severity"],
                "explicit_ids": sorted({match.upper() for match in ATTACK_ID_RE.findall(behavior)}),
                "metadata": {"sheet": sheet_name, "row": row_number},
            }
        )
    return rows, observations


def _tabular_rows(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    if path.suffix.lower() == ".csv":
        try:
            # Read one extra row so the normalizer can reject a CSV over the
            # ceiling without materializing the rest of an untrusted file.
            frame = pd.read_csv(path, nrows=MAX_TABULAR_ROWS_PER_SHEET + 1)
        except Exception as exc:  # pandas exceptions vary by parser/version
            raise NormalizationError(f"Could not parse CSV artifact: {exc}") from exc
        if len(frame) > MAX_TABULAR_ROWS_PER_SHEET:
            raise NormalizationError(
                f"CSV artifact exceeds the {MAX_TABULAR_ROWS_PER_SHEET:,} row limit."
            )
        data, obs = _rows_from_dataframe(frame, sheet_name="Sheet1", header_offset=1)
        return data, obs, {
            "sheets": 1,
            "row_limit_per_sheet": MAX_TABULAR_ROWS_PER_SHEET,
            "row_limit_total": MAX_TABULAR_ROWS_TOTAL,
        }

    try:
        with pd.ExcelFile(path) as workbook:
            sheet_names = list(workbook.sheet_names)
            if len(sheet_names) > MAX_TABULAR_SHEETS:
                raise NormalizationError(
                    f"Spreadsheet contains {len(sheet_names):,} sheets; the normalizer limit is {MAX_TABULAR_SHEETS:,}."
                )
            for sheet_name in sheet_names:
                # Probe only the header-search range, then read at most one
                # additional data row past the per-sheet ceiling.
                raw_header = pd.read_excel(
                    workbook,
                    sheet_name=sheet_name,
                    header=None,
                    nrows=HEADER_SCAN_ROWS,
                )
                max_non_null = 0
                header_index = 0
                for index, series in raw_header.iterrows():
                    populated = int(series.notna().sum())
                    if populated > max_non_null:
                        max_non_null = populated
                        header_index = int(index)
                if max_non_null == 0:
                    continue

                raw_frame = pd.read_excel(
                    workbook,
                    sheet_name=sheet_name,
                    header=None,
                    skiprows=header_index + 1,
                    nrows=MAX_TABULAR_ROWS_PER_SHEET + 1,
                )
                if len(raw_frame) > MAX_TABULAR_ROWS_PER_SHEET:
                    raise NormalizationError(
                        f"Sheet '{sheet_name}' exceeds the {MAX_TABULAR_ROWS_PER_SHEET:,} row limit."
                    )
                frame = raw_frame.dropna(how="all")
                header_values = list(raw_header.iloc[header_index])
                column_count = max(len(header_values), int(frame.shape[1]))
                header = [
                    str(header_values[index])
                    if index < len(header_values) and pd.notna(header_values[index]) and str(header_values[index]) != "nan"
                    else f"Unnamed_{index}"
                    for index in range(column_count)
                ]
                frame = frame.reindex(columns=range(column_count))
                frame.columns = header
                data, obs = _rows_from_dataframe(
                    frame,
                    sheet_name=str(sheet_name),
                    header_offset=header_index + 1,
                )
                if len(rows) + len(data) > MAX_TABULAR_ROWS_TOTAL:
                    raise NormalizationError(
                        f"Spreadsheet exceeds the {MAX_TABULAR_ROWS_TOTAL:,} total normalized-row limit."
                    )
                rows.extend(data)
                observations.extend(obs)
    except Exception as exc:
        if isinstance(exc, NormalizationError):
            raise
        raise NormalizationError(f"Could not parse spreadsheet artifact: {exc}") from exc
    return rows, observations, {
        "sheets": len(sheet_names),
        "row_limit_per_sheet": MAX_TABULAR_ROWS_PER_SHEET,
        "row_limit_total": MAX_TABULAR_ROWS_TOTAL,
    }


def _text_rows(text: str, *, source_kind: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for index, chunk in enumerate(_split_text(text), start=1):
        rows.append({"_sheet": source_kind, "_source_row": str(index), "IP": "N/A", "Hostname": "N/A", "Finding": chunk, "Severity": "Unknown"})
        observations.append(
            {
                "source_locator": {"kind": source_kind, "chunk": index},
                "raw_text_hash": hashlib.sha256(chunk.encode("utf-8")).hexdigest(),
                "normalized_text": chunk,
                "context_text": chunk,
                "asset": {"ip": "N/A", "hostname": "N/A"},
                "severity": "Unknown",
                "explicit_ids": sorted({match.upper() for match in ATTACK_ID_RE.findall(chunk)}),
                "metadata": {"chunk": index},
            }
        )
    return rows, observations


def _json_text(value: Mapping[str, Any]) -> str:
    """Return behavior-bearing text while retaining the full object as context.

    STIX objects frequently use ``description``/``name``/``pattern`` while
    vulnerability feeds tend to use ``title``/``finding``/``cve``.  This is a
    named adapter boundary, not a claim that every JSON key is behavior.
    """
    preferred = ("description", "name", "pattern", "value", "title", "finding", "vulnerability", "summary")
    parts = [str(value[key]).strip() for key in preferred if isinstance(value.get(key), str) and str(value[key]).strip()]
    return "\n".join(dict.fromkeys(parts))


def _json_rows(raw: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize JSON/STIX objects without losing an object-level locator.

    The former implementation flattened every description to anonymous text
    chunks.  A STIX bundle containing six attack-pattern objects therefore
    lost which object supplied each TTP.  This adapter emits one observation
    per meaningful object and retains its STIX/generic object ID, JSON pointer,
    full context, and exact source text.
    """
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    visited_nodes = 0

    def visit(value: Any, pointer: str, depth: int = 0) -> None:
        nonlocal visited_nodes
        visited_nodes += 1
        if visited_nodes > MAX_JSON_NODES:
            raise NormalizationError(
                f"JSON artifact exceeds the {MAX_JSON_NODES:,} traversable-value limit."
            )
        if depth > MAX_JSON_NESTING:
            raise NormalizationError(
                f"JSON artifact exceeds the {MAX_JSON_NESTING}-level nesting limit."
            )
        if isinstance(value, Mapping):
            object_type = str(value.get("type") or "json_object")
            object_id = str(value.get("id") or value.get("uuid") or pointer or "root")
            # Common feed/container envelopes are metadata, not a finding.  A
            # title on a STIX bundle or vulnerability export must not suppress
            # the individual objects nested below it.
            child_collections = [
                (key, child)
                for key, child in value.items()
                if key in {"objects", "items", "results", "data", "findings", "vulnerabilities"}
                and isinstance(child, list)
            ]
            if child_collections and (pointer == "" or object_type == "bundle"):
                for key, child in child_collections:
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    visit(child, f"{pointer}/{escaped}", depth + 1)
                return
            behavior = _json_text(value)
            if behavior:
                kind = "stix_object" if object_type != "json_object" or pointer.startswith("/objects/") else "json_object"
                identity = (kind, object_id)
                if identity not in seen:
                    if len(observations) >= MAX_JSON_OBSERVATIONS:
                        raise NormalizationError(
                            f"JSON artifact exceeds the {MAX_JSON_OBSERVATIONS:,} normalized-observation limit."
                        )
                    seen.add(identity)
                    context = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
                    source_row = object_id
                    rows.append({
                        "_sheet": kind,
                        "_source_row": source_row,
                        "IP": "N/A",
                        "Hostname": "N/A",
                        "Finding": behavior,
                        "Context": context,
                        "Severity": str(value.get("severity") or value.get("x_mitre_version") or "Unknown"),
                    })
                    evidence_text = f"{behavior}\n{context}"
                    observations.append({
                        "source_locator": {"kind": kind, "object_id": object_id, "pointer": pointer or "/", "object_type": object_type},
                        "raw_text_hash": hashlib.sha256(evidence_text.encode("utf-8")).hexdigest(),
                        "normalized_text": behavior,
                        "context_text": context,
                        "asset": {"ip": "N/A", "hostname": "N/A"},
                        "severity": str(value.get("severity") or "Unknown"),
                        "explicit_ids": sorted({match.upper() for match in ATTACK_ID_RE.findall(evidence_text)}),
                        "metadata": {"json_pointer": pointer or "/", "object_id": object_id, "object_type": object_type},
                    })
                # A meaningful object is the traceable unit.  Nested metadata
                # is context for that unit, not a second anonymous finding.
                return
            for key, child in value.items():
                if isinstance(child, (Mapping, list)):
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    visit(child, f"{pointer}/{escaped}", depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{pointer}/{index}", depth + 1)

    visit(raw, "")
    return rows, observations


def normalize_artifact(
    *,
    artifact_path: str | Path,
    extension: str,
    workspace: RunWorkspace,
) -> NormalizedArtifact:
    """Normalize one immutable artifact into its run-local pipeline CSV."""
    source = Path(artifact_path)
    extension = extension.lower()
    if extension in {".csv", ".xlsx", ".xls"}:
        rows, observations, metadata = _tabular_rows(source)
    elif extension in {".txt", ".md"}:
        rows, observations = _text_rows(source.read_text(encoding="utf-8"), source_kind="text_chunk")
        metadata = {"source": "text"}
    elif extension == ".json":
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NormalizationError(f"Could not parse JSON artifact: {exc}") from exc
        rows, observations = _json_rows(raw)
        metadata = {"source": "json", "json_type": raw.get("type") if isinstance(raw, Mapping) else type(raw).__name__}
    else:
        raise NormalizationError(f"No normalizer is registered for '{extension}'.")
    if not rows:
        raise NormalizationError("Artifact did not contain any analyzable observations.")
    if len(observations) > MAX_NORMALIZED_OBSERVATIONS:
        raise NormalizationError(
            f"Artifact exceeds the {MAX_NORMALIZED_OBSERVATIONS:,} normalized-observation limit."
        )
    # The CSV is independently written for every run and never triggers the
    # unused global assessment-embedding side effects in ingest_assessment.py.
    pd.DataFrame(rows).to_csv(workspace.normalized_csv_path, index=False)
    metadata["observation_count"] = len(observations)
    metadata["normalization_limits"] = {
        "tabular_sheets": MAX_TABULAR_SHEETS,
        "tabular_rows_per_sheet": MAX_TABULAR_ROWS_PER_SHEET,
        "tabular_rows_total": MAX_TABULAR_ROWS_TOTAL,
        "text_chunks": MAX_TEXT_CHUNKS,
        "normalized_observations": MAX_NORMALIZED_OBSERVATIONS,
    }
    return NormalizedArtifact(workspace.normalized_csv_path, observations, metadata)


def invoke_pipeline(
    *,
    engine: Any,
    input_csv: Path,
    output_dir: Path,
    provider_name: str | None,
    progress_cb: Callable[[Any], None],
    cancel_cb: Callable[[], bool],
    report_id_factory: Callable[[str, int], str] | None = None,
    run_id: str | None = None,
    runner: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """Invoke legacy or upgraded ``run_pipeline`` without global paths.

    The target contract is documented in ``main.py`` and supports a structured
    callback plus optional ``cancel_cb``.  Signature inspection keeps current
    deployments working while the pipeline is upgraded in a separate module.
    """
    if runner is None:
        from run_analyst_pipeline import run_pipeline as runner  # local import avoids graph/pipeline startup side effects

    output_dir.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {"provider_name": provider_name, "progress_cb": progress_cb}
    try:
        parameters = inspect.signature(runner).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "cancel_cb" in parameters:
        kwargs["cancel_cb"] = cancel_cb
    if "report_id_factory" in parameters and report_id_factory is not None:
        kwargs["report_id_factory"] = report_id_factory
    if "run_id" in parameters and run_id is not None:
        kwargs["run_id"] = run_id
    if cancel_cb():
        raise RunCanceled("Run was canceled before pipeline execution.")
    try:
        result = runner(engine, str(input_csv), str(output_dir), **kwargs)
    except SystemExit as exc:
        # Older library code calls sys.exit for malformed inputs.  A worker
        # must turn that into a durable failure rather than die silently.
        raise NormalizationError(f"Pipeline stopped unexpectedly (exit code {exc.code}).") from exc
    except Exception as exc:
        # The upgraded pipeline uses PipelineCanceled while the adapter keeps a
        # local exception so the web worker does not import pipeline internals.
        if cancel_cb() or type(exc).__name__ in {"PipelineCanceled", "RunCanceled"}:
            raise RunCanceled(str(exc) or "Run was canceled.") from exc
        raise
    if cancel_cb():
        raise RunCanceled("Run was canceled during pipeline execution.")
    if result is None:
        return []
    return [dict(item) for item in result]


def resolve_pipeline_asset(output_dir: Path, result: Mapping[str, Any], kind: str) -> Path | None:
    """Resolve a pipeline result asset only if it remains in pipeline staging."""
    explicit_key = f"{kind}_path"
    candidate_value = result.get(explicit_key)
    if candidate_value:
        candidate = Path(str(candidate_value))
        if not candidate.is_absolute():
            candidate = output_dir / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(output_dir.resolve())
        except ValueError:
            return None
        if candidate.is_file():
            return candidate
    report_key = str(result.get("report_key") or result.get("report_id") or "")
    if report_key:
        extension = ".md" if kind == "markdown" else ".json"
        candidate = (output_dir / f"{report_key}{extension}").resolve()
        try:
            candidate.relative_to(output_dir.resolve())
        except ValueError:
            return None
        if candidate.is_file():
            return candidate
    return None
