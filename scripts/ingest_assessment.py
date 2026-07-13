import sys
import os
import re
import json
import argparse
from pathlib import Path
import pandas as pd

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False
    print("Warning: Machine Learning libraries (sentence-transformers, numpy) not found. Will only output flattened CSV.")


class IngestionError(ValueError):
    """A recoverable artifact-ingestion failure.

    This module is used by both the CLI and the web worker. Library code must
    raise a normal exception rather than calling ``sys.exit()``, otherwise a
    background web job can remain forever marked as running.
    """


def _default_output_path() -> Path:
    return Path(__file__).resolve().parent.parent / "processed_assessment.csv"

def ingest_file(filepath, output_csv=None, *, generate_embeddings=False, embedding_dir=None):
    """Flatten a CSV/XLS/XLSX artifact into a run-scoped normalized CSV.

    Args:
        filepath: source artifact.
        output_csv: explicit destination. The legacy repository-root path is
            retained only when omitted for CLI compatibility.
        generate_embeddings: opt-in because the consolidated pipeline does not
            consume assessment embeddings. Web jobs should leave this false.
        embedding_dir: directory for optional run-scoped embedding artifacts.

    Returns the flattened DataFrame. Raises :class:`IngestionError` for a
    recoverable user-input failure.
    """
    source_path = Path(filepath)
    destination = Path(output_csv) if output_csv else _default_output_path()
    print(f"Ingesting {source_path}...")

    # Check if excel or csv
    suffix = source_path.suffix.lower()
    if suffix in {'.xlsx', '.xls'}:
        # Read without headers initially to deal with admin metadata/spanned cells
        sheets = pd.read_excel(source_path, sheet_name=None, header=None)
    elif suffix == '.csv':
        sheets = {"Sheet1": pd.read_csv(source_path, header=None)}
    else:
        raise IngestionError("Unsupported file format. Please provide a .csv, .xls, or .xlsx file.")

    all_findings = []

    # Process each sheet
    for sheet_name, raw_df in sheets.items():
        print(f"Processing sheet: {sheet_name} ({len(raw_df)} raw rows)")

        # Heuristic: The real header row is usually the one in the top 50 rows
        # with the most non-null columns (ignoring the admin metadata on top)
        max_non_nulls = 0
        header_idx = 0

        for idx, row in raw_df.head(50).iterrows():
            # Count cells that aren't empty/NaN
            non_null_count = row.notna().sum()
            if non_null_count > max_non_nulls:
                max_non_nulls = non_null_count
                header_idx = idx

        if max_non_nulls == 0:
            print(f"  Skipping {sheet_name}: Appears empty.")
            continue

        print(f"  Found logical header at row {header_idx + 1}. Extracting admin metadata above it...")

        # Extract all text from rows above the header to preserve context
        metadata_parts = []
        for i in range(header_idx):
            row_vals = raw_df.iloc[i].dropna().astype(str).tolist()
            for val in row_vals:
                if val.strip() and val.strip() != 'nan':
                    metadata_parts.append(val.strip())
        sheet_metadata = " | ".join(metadata_parts)

        # Extract the real header and slice the dataframe
        header_row = raw_df.iloc[header_idx].astype(str)
        # Handle empty column names
        header_row = [str(val) if str(val) != 'nan' else f"Unnamed_{i}" for i, val in enumerate(header_row)]

        df = raw_df.iloc[header_idx + 1:].copy()
        df.columns = header_row

        df = df.dropna(how='all')

        # Iterate over rows
        for idx, row in df.iterrows():
            finding_text_parts = []
            row_data = {"_sheet": str(sheet_name), "_source_row": int(idx) + 1}

            # Stringify row based on whatever random schema columns exist
            for col_name, value in row.items():
                if pd.notna(value) and str(value).strip() != "" and str(value).strip() != "nan":
                    finding_text_parts.append(f"{col_name}: {str(value).strip()}")
                    row_data[str(col_name)] = str(value).strip()

            if sheet_metadata:
                # Preserve administrative sheet context for a reviewer, but do
                # not feed it into behavioral TTP matching.  A technique in a
                # sheet title must not make every row look like that technique.
                row_data["_sheet_context"] = sheet_metadata

            if finding_text_parts:
                full_text = " | ".join(finding_text_parts)
                row_data["_semantic_text"] = full_text
                all_findings.append(row_data)

    # Save flattened CSV
    if not all_findings:
        raise IngestionError("No non-empty findings were found in the artifact.")

    flattened_df = pd.DataFrame(all_findings)
    # Reorder so _semantic_text is first for easy reading, drop it from final CSV
    csv_out = flattened_df.drop(columns=['_semantic_text'])
    destination.parent.mkdir(parents=True, exist_ok=True)
    csv_out.to_csv(destination, index=False)
    print(f"\nSaved flattened raw data to {destination} ({len(flattened_df)} total rows).")

    # Generate Embeddings
    if generate_embeddings and SEMANTIC_ENABLED:
        print("\nGenerating semantic embeddings for the assessment findings...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts_to_embed = flattened_df['_semantic_text'].tolist()

        embeddings = model.encode(texts_to_embed, show_progress_bar=True)

        artifacts_dir = Path(embedding_dir) if embedding_dir else destination.parent
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        npz_path = artifacts_dir / "assessment_embeddings.npz"
        np.savez(npz_path, embeddings=embeddings)

        # Save metadata mapping index to the text
        meta_path = artifacts_dir / "assessment_metadata.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump({"findings": texts_to_embed, "source_csv": str(destination)}, f)
        print(f"Successfully saved {len(embeddings)} embeddings to {npz_path}")
        print(f"Agents can now semantically search this raw dataset!")

    return csv_out

def _split_into_chunks(text, min_chunk_len=15):
    """Splits freeform pasted text into sentence/line-level chunks.

    A CTI narrative describing a threat actor typically covers MANY distinct
    techniques ("established persistence via valid accounts... exploited a
    public-facing application... used phishing for initial access"). Treating
    the whole paste as a single semantic-search query collapses all of that
    down to whichever single technique scores highest, silently discarding
    every other technique the text describes. Splitting into per-sentence
    chunks lets each behavior get its own resolution attempt downstream in
    consolidate_findings.py, so multiple techniques can actually surface.

    A single short finding with no sentence punctuation (e.g. "Weak
    administrative password set") splits into exactly one chunk -- unchanged
    behavior for that existing use case.
    """
    lines = [ln.strip(" -*•\t") for ln in re.split(r'\n+', text) if ln.strip()]
    chunks = []
    for line in lines:
        for sentence in re.split(r'(?<=[.!?])\s+', line):
            sentence = sentence.strip()
            if len(sentence) >= min_chunk_len:
                chunks.append(sentence)
    return chunks


def ingest_text(text, output_csv=None):
    """Ingests a pasted string of unstructured threat-intel text.

    Splits it into per-sentence/per-line chunks (see _split_into_chunks) and
    writes one row per chunk, each compatible with the same schema
    first_present() expects elsewhere in this codebase (consolidate_findings.py
    / agent_batch_processor.py look for columns named IP/Hostname/Finding/
    Severity among their candidate lists), so freeform-pasted text -- whether
    a one-line finding or a multi-paragraph threat-actor profile -- flows
    through the same downstream pipeline as spreadsheet-derived rows.
    """
    stripped = text.strip() if text else ""
    if not stripped:
        raise IngestionError("Pasted threat-intelligence text is empty.")
    chunks = _split_into_chunks(stripped) if stripped else []
    if not chunks and stripped:
        # No sentence boundaries found (a short one-line finding) -- keep the
        # whole thing as a single chunk rather than dropping it.
        chunks = [stripped]

    rows = [
        {
            "_sheet": "pasted",
            "_source_row": index,
            "IP": "N/A",
            "Hostname": "N/A",
            # Preserve full evidence. Context-window truncation belongs in the
            # mapping/provider layer, where it can retain an explicit span.
            "Finding": chunk,
            "Severity": "Unknown",
        }
        for index, chunk in enumerate(chunks, start=1)
    ]
    if not rows:
        rows = [{"_sheet": "pasted", "_source_row": 1, "IP": "N/A", "Hostname": "N/A", "Finding": stripped, "Severity": "Unknown"}]

    flattened_df = pd.DataFrame(rows)
    destination = Path(output_csv) if output_csv else _default_output_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    flattened_df.to_csv(destination, index=False)
    print(f"Saved pasted text as {len(flattened_df)} chunk(s) to {destination}.")
    return flattened_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and optionally embed assessment reports (Excel/CSV)")
    parser.add_argument("filepath", help="Path to the .xlsx or .csv file")
    parser.add_argument("--output", help="Destination CSV (default: repository processed_assessment.csv)")
    parser.add_argument("--embed", action="store_true", help="Generate optional assessment embeddings")
    args = parser.parse_args()

    try:
        ingest_file(args.filepath, args.output, generate_embeddings=args.embed)
    except IngestionError as exc:
        print(f"Ingestion failed: {exc}", file=sys.stderr)
        sys.exit(2)
