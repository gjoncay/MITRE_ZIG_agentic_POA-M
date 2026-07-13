"""Build or validate the graph embedding index.

The metadata written beside ``graph_embeddings.npz`` binds vector row order to
one exact graph snapshot.  A stale index is rejected by ``KnowledgeGraphEngine``
instead of being searched against changed node IDs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from graph_engine import (
    BASE_DIR,
    EMBEDDING_FILENAME,
    EMBEDDING_METADATA_FILENAME,
    EMBEDDING_MODEL_NAME,
    KnowledgeGraphEngine,
)

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError as exc:  # pragma: no cover - exercised in deployment setup
    raise SystemExit("sentence-transformers and numpy are required to generate embeddings") from exc


def _ordered_embedding_nodes(engine: KnowledgeGraphEngine) -> tuple[list[str], list[str]]:
    """Return a stable graph order.  Never serialize an unordered set here."""
    node_ids: list[str] = []
    texts: list[str] = []
    for node_id, data in engine.repository.iter_nodes():
        name = str(data.get("name", ""))
        description = str(data.get("description", ""))
        if not name and not description:
            continue
        node_ids.append(node_id)
        texts.append(f"{name}. {description}")
    return node_ids, texts


def embed_graph_nodes(base_dir: str | Path = BASE_DIR) -> dict:
    """Generate a deterministic vector index and its compatibility manifest."""
    engine = KnowledgeGraphEngine(base_dir, load_embeddings=False)
    node_ids, texts = _ordered_embedding_nodes(engine)
    print(f"Loading embedding model ({EMBEDDING_MODEL_NAME})...")
    # Generation may intentionally download on a connected build host; runtime
    # loading remains local-files-only in graph_engine.py.
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    print(f"Generating embeddings for {len(node_ids)} nodes...")
    embeddings = model.encode(texts, show_progress_bar=True)

    target_dir = Path(base_dir)
    npz_path = target_dir / EMBEDDING_FILENAME
    np.savez(npz_path, embeddings=embeddings)
    metadata = engine.write_embedding_manifest(
        node_ids=node_ids,
        embeddings=embeddings,
        model_name=EMBEDDING_MODEL_NAME,
        npz_path=npz_path,
        metadata_path=target_dir / EMBEDDING_METADATA_FILENAME,
    )
    print(f"Saved {npz_path.name} and validated metadata for {metadata['graph_snapshot_id']}")
    return metadata


def refresh_embedding_metadata(base_dir: str | Path = BASE_DIR) -> dict:
    """Bind an existing index to the current snapshot without re-encoding.

    This is useful for the repository's previously generated index.  It is
    deliberately strict: the old metadata must still provide the exact node
    order so no row is guessed or reordered.
    """
    target_dir = Path(base_dir)
    engine = KnowledgeGraphEngine(target_dir, load_embeddings=False)
    npz_path = target_dir / EMBEDDING_FILENAME
    old_metadata_path = target_dir / EMBEDDING_METADATA_FILENAME
    if not npz_path.is_file() or not old_metadata_path.is_file():
        raise FileNotFoundError("Existing graph_embeddings.npz and embedding_metadata.json are required")
    old_metadata = json.loads(old_metadata_path.read_text(encoding="utf-8"))
    node_ids = old_metadata.get("node_ids")
    if not isinstance(node_ids, list) or not all(isinstance(node_id, str) for node_id in node_ids):
        raise ValueError("Existing embedding metadata does not contain a valid node_ids list")
    embeddings = np.load(npz_path, allow_pickle=False)["embeddings"]
    metadata = engine.write_embedding_manifest(
        node_ids=node_ids,
        embeddings=embeddings,
        model_name=old_metadata.get("model_name", EMBEDDING_MODEL_NAME),
        npz_path=npz_path,
        metadata_path=old_metadata_path,
    )
    print(f"Refreshed {EMBEDDING_METADATA_FILENAME} for {metadata['graph_snapshot_id']}")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Build/validate graph embeddings")
    parser.add_argument(
        "--refresh-metadata",
        action="store_true",
        help="write a snapshot-bound manifest for an existing vector index without re-encoding",
    )
    args = parser.parse_args()
    if args.refresh_metadata:
        refresh_embedding_metadata()
    else:
        embed_graph_nodes()


if __name__ == "__main__":
    main()
