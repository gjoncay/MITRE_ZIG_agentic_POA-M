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
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Renderer-only report refresh
# ---------------------------------------------------------------------------
# This intentionally lives beside the durable pipeline adapter rather than in
# a route handler.  API requests and an operator-approved maintenance/backfill
# command can therefore call exactly the same evidence/graph/render path.  It
# never imports or constructs an LLM provider and never calls ``run_pipeline``.


def _locator_fingerprint(locator: Any) -> str:
    """Return a stable source-locator key for durable evidence matching."""
    return json.dumps(dict(locator), sort_keys=True, separators=(",", ":"), default=str) if isinstance(locator, Mapping) else ""


def _observation_to_report_host(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Adapt one durable observation to the consolidated report host shape."""
    asset = observation.get("asset") if isinstance(observation.get("asset"), Mapping) else {}
    return {
        "ip": str(asset.get("ip") or "N/A"),
        "hostname": str(asset.get("hostname") or "N/A"),
        "finding_text": str(observation.get("normalized_text") or "N/A"),
        "severity": str(observation.get("severity") or "Unknown"),
        "source_locator": dict(observation.get("source_locator") or {}),
        "explicit_ids": list(observation.get("explicit_ids") or []),
    }


def _historical_hosts(report_data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Use retained report evidence only as a narrow compatibility fallback.

    A current durable run has source-linked candidates and therefore never
    needs this path.  It exists for early lifecycle rows that retained an
    immutable JSON report before per-observation candidate persistence was
    complete.  It never broadens a multi-technique report to every artifact
    observation.
    """
    values = report_data.get("affected_hosts")
    if not isinstance(values, list):
        return []
    hosts: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping):
            continue
        hosts.append(
            {
                "ip": str(value.get("ip") or "N/A"),
                "hostname": str(value.get("hostname") or "N/A"),
                "finding_text": str(value.get("finding_text") or value.get("finding") or "N/A"),
                "severity": str(value.get("severity") or "Unknown"),
                "source_locator": dict(value.get("source_locator") or {}),
                "explicit_ids": list(value.get("explicit_ids") or []),
            }
        )
    return hosts


def _select_report_observations(
    repository: Any,
    *,
    report: Mapping[str, Any],
    report_data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return only source observations attributable to this report.

    Candidate-to-observation links are the authoritative scope boundary for a
    technique report.  If an older row lacks those links, exact retained
    source locators (then the prior report's own retained observation list)
    provide a conservative compatibility path.  We intentionally do not use
    all artifact observations as a fallback: one threat-intel item may map to
    multiple technique reports and that would cross-contaminate revisions.
    """
    artifact_id = report.get("artifact_id")
    if not artifact_id:
        raise NormalizationError("This report has no retained source artifact and cannot be re-rendered.")
    observations = repository.list_observations(str(artifact_id))
    candidates = repository.list_candidates(
        artifact_id=str(artifact_id), technique_id=report.get("technique_id")
    )
    candidate_observation_ids = {
        str(candidate.get("observation_id"))
        for candidate in candidates
        if candidate.get("observation_id")
    }
    if candidate_observation_ids:
        selected = [
            _observation_to_report_host(observation)
            for observation in observations
            if str(observation.get("id")) in candidate_observation_ids
        ]
        if selected:
            return selected, {
                "selection": "durable_candidate_links",
                "candidate_count": len(candidates),
                "observation_count": len(selected),
            }

    historical = _historical_hosts(report_data)
    historical_locators = {
        _locator_fingerprint(host.get("source_locator"))
        for host in historical
        if _locator_fingerprint(host.get("source_locator"))
    }
    if historical_locators:
        matched = [
            _observation_to_report_host(observation)
            for observation in observations
            if _locator_fingerprint(observation.get("source_locator")) in historical_locators
        ]
        if matched:
            return matched, {
                "selection": "retained_source_locator_match",
                "candidate_count": len(candidates),
                "observation_count": len(matched),
            }
    if historical:
        return historical, {
            "selection": "retained_prior_revision_evidence",
            "candidate_count": len(candidates),
            "observation_count": len(historical),
        }
    raise NormalizationError(
        "No source observations can be attributed to this report; retry the retained source run instead."
    )


def _severity_breakdown(hosts: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for host in hosts:
        severity = str(host.get("severity") or "Unknown")
        result[severity] = result.get(severity, 0) + 1
    return result


def _preserved_narrative(
    prior_narrative: Mapping[str, Any], report_data: Mapping[str, Any]
) -> dict[str, str]:
    """Keep stored analyst prose; a renderer refresh must not draft prose."""
    fallbacks = {
        "exploitation_scenario": report_data.get("exploitation_scenario"),
        "business_impact": report_data.get("business_impact"),
        "csa_impact_summary": report_data.get("csa_impact_summary"),
        "architectural_recommendation": report_data.get("cref_recommendation"),
        "immediate_action": report_data.get("immediate_action"),
        "short_term_action": report_data.get("short_term_action"),
        "long_term_action": report_data.get("long_term_action"),
    }
    return {
        key: str(prior_narrative.get(key) or fallbacks[key] or "")
        for key in fallbacks
    }


def _render_unmapped_triage(
    *,
    report: Mapping[str, Any],
    report_data: Mapping[str, Any],
    hosts: list[dict[str, Any]],
    generated_date: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Rebuild an UNMAPPED triage revision without pretending it has a TTP."""
    # Keep untrusted source text inside a Markdown table so it remains visible
    # to the reviewer while pipes/newlines cannot alter the document shape.
    def cell(value: Any) -> str:
        return str(value if value is not None else "N/A").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    table = ["| Source Excerpt | Severity |", "|---|---|"]
    for host in hosts:
        table.append(f"| {cell(host.get('finding_text'))} | {cell(host.get('severity'))} |")
    display_id = str(report.get("display_id") or report.get("id"))
    markdown = (
        f"# {display_id}\n\n"
        "## Analyst triage required\n\n"
        f"{len(hosts)} observation(s) did not retain a validated ATT&CK candidate. "
        "Review the source evidence, record a decision, or retry the complete source run after classification.\n\n"
        "## Source Observations\n\n"
        + "\n".join(table)
        + "\n"
    )
    qa_result = {
        "verdict": "MANUAL_REVIEW_REQUIRED",
        "notes": "Re-rendered with the current renderer; no LLM/provider or new ATT&CK classification was run.",
    }
    report_json = {
        **dict(report_data),
        "schema_version": "unmapped-triage-v1",
        "report_id": report.get("id"),
        "display_id": display_id,
        "generated_date": generated_date,
        "technique_id": "UNMAPPED",
        "finding_count": len(hosts),
        "severity_breakdown": _severity_breakdown(hosts),
        "affected_hosts": [{**host, "finding": host.get("finding_text", "N/A")} for host in hosts],
        "evidence_preview": [
            {
                "source_locator": host.get("source_locator", {}),
                "severity": host.get("severity"),
                "explicit_ids": host.get("explicit_ids", []),
                "text_excerpt": host.get("finding_text", ""),
            }
            for host in hosts
        ],
        "evidence_preview_omitted": 0,
        "qa_verdict": qa_result["verdict"],
        "qa_notes": qa_result["notes"],
        "lifecycle_state": "manual_review_required",
        "requires_review": True,
    }
    return markdown, report_json, qa_result


def rerender_report_from_durable_evidence(
    *,
    repository: Any,
    runs_dir: str | Path,
    engine: Any,
    report_id: str,
    actor_id: str,
    reason: str = "Re-rendered with current renderer",
) -> dict[str, Any]:
    """Append a no-provider report revision from retained evidence/current graph.

    The function is intentionally synchronous so an API route can run it in a
    worker thread and a maintenance/backfill command can invoke it directly.
    It performs no model/provider operation: it selects durable source-linked
    observations, crawls the currently loaded read-only graph, preserves the
    prior analyst narrative, and renders a new immutable asset pair.
    """
    report = repository.get_report(report_id, include_deleted=True)
    if report is None:
        raise NormalizationError(f"Report '{report_id}' was not found.")
    if report.get("lifecycle_state") in {"deleted", "deleting", "restoring"}:
        raise NormalizationError("A deleted, deleting, or restoring report cannot be re-rendered.")
    if report.get("lifecycle_state") == "legacy":
        raise NormalizationError(
            "Legacy reports do not retain durable source observations and cannot be re-rendered."
        )
    prior_revision = repository.get_current_revision(str(report["id"]))
    if prior_revision is None:
        raise NormalizationError("Report has no current revision to re-render.")
    report_data = prior_revision.get("report_data") if isinstance(prior_revision.get("report_data"), Mapping) else {}
    prior_narrative = prior_revision.get("narrative") if isinstance(prior_revision.get("narrative"), Mapping) else {}
    workspace = RunWorkspace.open(runs_dir, str(report["run_id"]))
    revision_id = str(uuid.uuid4())
    generated_date = datetime.now(timezone.utc).date().isoformat()
    hosts, source_metadata = _select_report_observations(
        repository, report=report, report_data=report_data
    )
    technique_id = str(report.get("technique_id") or report_data.get("technique_id") or "")
    template_path = Path(__file__).resolve().parents[2] / "assessment_template_consolidated.md"
    template_str = template_path.read_text(encoding="utf-8")
    template_sha256 = hashlib.sha256(template_str.encode("utf-8")).hexdigest()

    if technique_id == "UNMAPPED":
        markdown, report_json, qa_result = _render_unmapped_triage(
            report=report,
            report_data=report_data,
            hosts=hosts,
            generated_date=generated_date,
        )
        mapping_bundle: Mapping[str, Any] = report_json.get("framework_mappings") if isinstance(report_json.get("framework_mappings"), Mapping) else {}
        narrative = dict(prior_narrative)
    else:
        # Imports stay local: ordinary adapter use and tests that only
        # normalize artifacts do not pay for report renderer imports.
        from scripts.consolidate_findings import build_context, crawl_correlation
        from scripts.report_schema import build_report_json, render_markdown
        from run_analyst_pipeline import _adapt_context_for_render, _build_render_narrative

        node = engine.query_node(technique_id) if technique_id else None
        if not isinstance(node, Mapping) or node.get("type") not in {None, "attack_technique"}:
            raise NormalizationError(
                "The report technique no longer exists as an ATT&CK technique in the current graph; retry the source run instead."
            )
        group_data = {
            "technique_name": node.get("name") or report.get("technique_name") or report_data.get("technique_name") or technique_id,
            "technique_description": node.get("description") or report_data.get("technique_description") or "Unknown",
            "affected_hosts": hosts,
            "severity_breakdown": _severity_breakdown(hosts),
            "requires_review": True,
        }
        correlation = crawl_correlation(engine, technique_id)
        context = build_context(technique_id, group_data, correlation)
        narrative = _preserved_narrative(prior_narrative, report_data)
        render_context = _adapt_context_for_render(context, narrative)
        render_narrative = _build_render_narrative(
            technique_id,
            render_context,
            narrative,
            full_affected_hosts=hosts,
        )
        qa_result = {
            "verdict": "MANUAL_REVIEW_REQUIRED",
            "notes": "Re-rendered with the current graph and template; no LLM/provider or new QA pass was run. Review this revision before acceptance.",
        }
        markdown = render_markdown(
            template_str,
            str(report.get("display_id") or report.get("id")),
            generated_date,
            technique_id,
            render_context,
            render_narrative,
            qa_result,
        )
        report_json = build_report_json(technique_id, render_context, render_narrative, qa_result)
        mapping_bundle = context.get("framework_mappings") if isinstance(context.get("framework_mappings"), Mapping) else {}
        report_json.update(
            {
                "report_id": report.get("id"),
                "display_id": report.get("display_id"),
                "generated_date": generated_date,
                "schema_version": "2.1",
                "pipeline_version": "renderer-refresh",
                "run_id": report.get("run_id"),
                "lifecycle_state": "manual_review_required",
                "requires_review": True,
                "mapping_confidence": {
                    "requires_review": True,
                    "rerendered_without_provider": True,
                },
                # Preserve historical provider provenance without implying a
                # provider participated in this renderer-only revision.
                "provider": report_data.get("provider"),
                "llm_graph_tool_crawl": {
                    "status": "not_run",
                    "reason": "Renderer-only revision; no LLM/provider graph crawl was performed.",
                    "selected": [],
                    "audit": {"calls": []},
                },
                "llm_graph_tool_validation_required": False,
                "model_input_policy": report_data.get("model_input_policy"),
                "affected_hosts": [
                    {**host, "finding": host.get("finding_text", host.get("finding", "N/A"))}
                    for host in hosts
                ],
            }
        )

    mapping_snapshot_hash = hashlib.sha256(
        json.dumps(mapping_bundle, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    rerender_metadata = {
        "operation": "renderer_refresh",
        "reason": reason,
        "rerendered_by": actor_id,
        "rerendered_from_revision_id": prior_revision.get("id"),
        "rerendered_from_revision_number": prior_revision.get("revision_number"),
        "source_observations": source_metadata,
        "template": {
            "path": template_path.name,
            "sha256": template_sha256,
        },
        "graph_snapshot_id": mapping_bundle.get("graph_snapshot_id") if isinstance(mapping_bundle, Mapping) else None,
        "mapping_matrix_version": mapping_bundle.get("mapping_matrix_version") if isinstance(mapping_bundle, Mapping) else None,
        "provider_calls": {"made": False, "reason": "renderer_only"},
    }
    report_json["rerender"] = {
        **rerender_metadata,
        "revision_id": revision_id,
    }
    report_json["mapping_snapshot_hash"] = mapping_snapshot_hash
    report_json["qa_verdict"] = qa_result["verdict"]
    report_json["qa_notes"] = qa_result["notes"]
    report_json["lifecycle_state"] = "manual_review_required"
    report_json["requires_review"] = True

    assets = workspace.publish_rendered_revision_assets(
        report_id=str(report["id"]),
        revision_id=revision_id,
        markdown=markdown,
        report_json=json.dumps(report_json, indent=2, ensure_ascii=False, default=str),
    )
    markdown_path = workspace.resolve_relative(assets["markdown_path"])
    json_path = workspace.resolve_relative(assets["json_path"])
    try:
        updated = repository.append_rerendered_revision(
            report_id=str(report["id"]),
            revision_id=revision_id,
            expected_report_version=int(report["version"]),
            expected_current_revision_id=str(prior_revision["id"]),
            report_data=report_json,
            narrative=narrative,
            markdown_path=assets["markdown_path"],
            json_path=assets["json_path"],
            markdown_sha256=RunWorkspace.sha256_file(markdown_path) or "",
            json_sha256=RunWorkspace.sha256_file(json_path) or "",
            mapping_snapshot_hash=mapping_snapshot_hash,
            created_by=actor_id,
            metadata=rerender_metadata,
            finding_count=len(hosts),
            severity_breakdown=_severity_breakdown(hosts),
        )
    except BaseException:
        # The assets are in a newly generated UUID directory and no revision
        # row references them when the append transaction fails. Compensate
        # this exact uncommitted directory without ever touching revision 1
        # or any older immutable asset.
        try:
            workspace.discard_uncommitted_rendered_revision_assets(
                report_id=str(report["id"]), revision_id=revision_id
            )
        except Exception:
            # The DB conflict/error remains the useful caller-facing failure;
            # an orphaned unique directory is harmless and can be inspected.
            pass
        raise
    return {
        "report": updated,
        "revision_id": revision_id,
        "source_observation_count": len(hosts),
        "mapping_snapshot_hash": mapping_snapshot_hash,
    }
