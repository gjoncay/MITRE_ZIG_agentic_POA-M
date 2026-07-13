"""Input validation shared by submission and retry paths."""

from __future__ import annotations

import json
import mimetypes
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final


ALLOWED_EXTENSIONS: Final[dict[str, str]] = {
    ".csv": "tabular",
    ".xlsx": "tabular",
    ".xls": "tabular",
    ".txt": "text",
    ".md": "text",
    ".json": "threat_intel",
}

MAX_XLSX_UNCOMPRESSED_BYTES: Final[int] = 200 * 1024 * 1024
MAX_XLSX_MEMBERS: Final[int] = 10_000
MAX_COMPRESSION_RATIO: Final[int] = 100


class ArtifactValidationError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class ArtifactInspection:
    extension: str
    kind: str
    media_type: str | None
    metadata: dict[str, object]


def _decode_utf8_sample(path: Path) -> None:
    try:
        with path.open("rb") as handle:
            handle.read(128 * 1024).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactValidationError(
            "invalid_text_encoding",
            "Text, CSV, Markdown, and JSON artifacts must be UTF-8 encoded.",
            status_code=415,
        ) from exc


def _inspect_xlsx(path: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_XLSX_MEMBERS:
                raise ArtifactValidationError("xlsx_too_many_members", "Spreadsheet archive contains too many files.", status_code=413)
            total_uncompressed = sum(info.file_size for info in infos)
            if total_uncompressed > MAX_XLSX_UNCOMPRESSED_BYTES:
                raise ArtifactValidationError("xlsx_expansion_limit", "Spreadsheet expands beyond the permitted size.", status_code=413)
            for info in infos:
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    raise ArtifactValidationError("xlsx_compression_ratio", "Spreadsheet archive has an unsafe compression ratio.", status_code=413)
            names = {info.filename for info in infos}
            if "[Content_Types].xml" not in names:
                raise ArtifactValidationError("invalid_xlsx", "Upload does not appear to be a valid XLSX workbook.", status_code=415)
            return {"archive_members": len(infos), "uncompressed_bytes": total_uncompressed}
    except zipfile.BadZipFile as exc:
        raise ArtifactValidationError("invalid_xlsx", "Upload does not appear to be a valid XLSX workbook.", status_code=415) from exc


def inspect_artifact(path: str | Path, *, filename: str, content_type: str | None = None) -> ArtifactInspection:
    """Validate an already-streamed artifact without trusting client MIME type."""
    candidate = Path(path)
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise ArtifactValidationError("unsupported_file_type", f"Unsupported artifact type '{extension or 'none'}'. Allowed: {allowed}.", status_code=415)
    if not candidate.is_file() or candidate.stat().st_size == 0:
        raise ArtifactValidationError("empty_upload", "Upload is empty.")

    kind = ALLOWED_EXTENSIONS[extension]
    metadata: dict[str, object] = {}
    if extension == ".xlsx":
        metadata.update(_inspect_xlsx(candidate))
    elif extension == ".xls":
        # Legacy XLS is an OLE Compound File.  This is a lightweight type
        # check, not a promise that every legacy workbook parser is safe.
        with candidate.open("rb") as handle:
            magic = handle.read(8)
        if magic != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise ArtifactValidationError("invalid_xls", "Upload does not appear to be a valid XLS workbook.", status_code=415)
    elif extension in {".csv", ".txt", ".md", ".json"}:
        _decode_utf8_sample(candidate)
        if extension == ".json":
            try:
                with candidate.open("r", encoding="utf-8") as handle:
                    parsed = json.load(handle)
                metadata["json_kind"] = parsed.get("type") if isinstance(parsed, dict) else type(parsed).__name__
            except json.JSONDecodeError as exc:
                raise ArtifactValidationError("invalid_json", "Threat-intelligence JSON is not valid JSON.", status_code=415) from exc

    guessed_type = mimetypes.guess_type(filename)[0]
    # Keep the supplied MIME for audit, but use our validated extension for
    # routing.  Browsers commonly send application/octet-stream for XLSX.
    if content_type:
        metadata["client_media_type"] = content_type
    return ArtifactInspection(
        extension=extension,
        kind=kind,
        media_type=guessed_type or content_type,
        metadata=metadata,
    )


def validate_text_artifact(text: str | None, *, max_characters: int) -> str:
    value = (text or "").strip()
    if not value:
        raise ArtifactValidationError("empty_text", "Provide either a file or non-empty text.")
    if len(value) > max_characters:
        raise ArtifactValidationError(
            "text_too_large",
            f"Pasted text exceeds the {max_characters} character limit.",
            status_code=413,
        )
    return value
