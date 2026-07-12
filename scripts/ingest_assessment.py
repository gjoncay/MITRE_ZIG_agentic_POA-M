import sys
import os
import re
import json
import argparse
import pandas as pd

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    SEMANTIC_ENABLED = True
except ImportError:
    SEMANTIC_ENABLED = False
    print("Warning: Machine Learning libraries (sentence-transformers, numpy) not found. Will only output flattened CSV.")

def ingest_file(filepath):
    print(f"Ingesting {filepath}...")
    
    # Check if excel or csv
    if filepath.endswith('.xlsx') or filepath.endswith('.xls'):
        # Read without headers initially to deal with admin metadata/spanned cells
        sheets = pd.read_excel(filepath, sheet_name=None, header=None)
    elif filepath.endswith('.csv'):
        sheets = {"Sheet1": pd.read_csv(filepath, header=None)}
    else:
        print("Unsupported file format. Please provide a .csv or .xlsx file.")
        sys.exit(1)
        
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
            row_data = {"_sheet": sheet_name}
            
            # Stringify row based on whatever random schema columns exist
            for col_name, value in row.items():
                if pd.notna(value) and str(value).strip() != "" and str(value).strip() != "nan":
                    finding_text_parts.append(f"{col_name}: {str(value).strip()}")
                    row_data[str(col_name)] = str(value).strip()
            
            if sheet_metadata:
                row_data["Sheet Context"] = sheet_metadata
                # Prepend the sheet context to the semantic text
                finding_text_parts.insert(0, f"Sheet Context: {sheet_metadata}")
            
            if finding_text_parts:
                full_text = " | ".join(finding_text_parts)
                row_data["_semantic_text"] = full_text
                all_findings.append(row_data)
                
    # Save flattened CSV
    if not all_findings:
        print("No data found to process.")
        return
        
    flattened_df = pd.DataFrame(all_findings)
    # Reorder so _semantic_text is first for easy reading, drop it from final CSV
    csv_out = flattened_df.drop(columns=['_semantic_text'])
    csv_path = "processed_assessment.csv"
    csv_out.to_csv(csv_path, index=False)
    print(f"\nSaved flattened raw data to {csv_path} ({len(flattened_df)} total rows).")
    
    # Generate Embeddings
    if SEMANTIC_ENABLED:
        print("\nGenerating semantic embeddings for the assessment findings...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        texts_to_embed = flattened_df['_semantic_text'].tolist()
        
        embeddings = model.encode(texts_to_embed, show_progress_bar=True)
        
        npz_path = "assessment_embeddings.npz"
        np.savez(npz_path, embeddings=embeddings)
        
        # Save metadata mapping index to the text
        meta_path = "assessment_metadata.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump({"findings": texts_to_embed}, f)
            
        print(f"Successfully saved {len(embeddings)} embeddings to {npz_path}")
        print(f"Agents can now semantically search this raw dataset!")

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


def ingest_text(text, output_csv="processed_assessment.csv"):
    """Ingests a pasted string of unstructured threat-intel text.

    Splits it into per-sentence/per-line chunks (see _split_into_chunks) and
    writes one row per chunk, each compatible with the same schema
    first_present() expects elsewhere in this codebase (consolidate_findings.py
    / agent_batch_processor.py look for columns named IP/Hostname/Finding/
    Severity among their candidate lists), so freeform-pasted text -- whether
    a one-line finding or a multi-paragraph threat-actor profile -- flows
    through the same downstream pipeline as spreadsheet-derived rows.
    """
    MAX_CHUNK_CHARS = 500

    stripped = text.strip() if text else ""
    chunks = _split_into_chunks(stripped) if stripped else []
    if not chunks and stripped:
        # No sentence boundaries found (a short one-line finding) -- keep the
        # whole thing as a single chunk rather than dropping it.
        chunks = [stripped]

    rows = [
        {
            "_sheet": "pasted",
            "IP": "N/A",
            "Hostname": "N/A",
            "Finding": chunk if len(chunk) <= MAX_CHUNK_CHARS else chunk[:MAX_CHUNK_CHARS],
            "Severity": "Unknown",
        }
        for chunk in chunks
    ]
    if not rows:
        rows = [{"_sheet": "pasted", "IP": "N/A", "Hostname": "N/A", "Finding": stripped, "Severity": "Unknown"}]

    flattened_df = pd.DataFrame(rows)
    flattened_df.to_csv(output_csv, index=False)
    print(f"Saved pasted text as {len(flattened_df)} chunk(s) to {output_csv}.")
    return flattened_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest and optionally embed assessment reports (Excel/CSV)")
    parser.add_argument("filepath", help="Path to the .xlsx or .csv file")
    args = parser.parse_args()

    ingest_file(args.filepath)
