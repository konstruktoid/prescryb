"""Semantic (RAG-style) search over local reference documents.

Reads Markdown, text, and PDF files from a local, gitignored directory
(`LOCAL_DOCS_DIR`, default `local_docs/`) holding material the
network-backed tools can't see: runbooks, policy, prior remediation notes.
Embeddings are computed locally with a `sentence-transformers` model, so no
document content or query text leaves the machine; the model itself is
fetched from Hugging Face on first use (see README "Local documents"). The
chunk index is rebuilt only when file mtimes or sizes change.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

_DEFAULT_DOCS_DIR = "local_docs"
_DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_SUPPORTED_SUFFIXES = {".md", ".markdown", ".txt", ".pdf"}
_CHUNK_SIZE = 1000
_CHUNK_OVERLAP = 150
MAX_RESULTS = 20
# Caps bound a LOCAL_DOCS_DIR misconfigured at, say, a home directory.
_MAX_INDEXED_FILES = 500
_MAX_FILE_BYTES = 20 * 1024 * 1024


@dataclass
class DocChunk:
    """One chunk of a local document; `source` is relative to the docs dir."""

    source: str
    chunk_index: int
    text: str


@dataclass
class _IndexEntry:
    chunk: DocChunk
    embedding: list[float]


# Searches can run in separate threads; reentrant for _build_index()'s _get_model().
_index_lock = threading.RLock()
_model: SentenceTransformer | None = None
_index_cache: list[_IndexEntry] = []
_skipped_cache: list[dict[str, str]] = []
_truncated_cache: bool = False
_index_signature: tuple[tuple[str, int, int], ...] | None = None


def docs_dir() -> Path:
    """Resolve the configured local-docs directory (LOCAL_DOCS_DIR env var)."""
    raw = os.environ.get("LOCAL_DOCS_DIR", _DEFAULT_DOCS_DIR)
    return Path(raw).expanduser().resolve()


def _iter_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            # A symlink resolving outside the docs dir is not ours to index.
            continue
        files.append(path)
    return files


def _extract_pdf_text(path: Path) -> str:
    from pypdf import PdfReader  # noqa: PLC0415 - skip pypdf's import cost when unused

    reader = PdfReader(str(path))
    return "\n\n".join(page.extract_text() or "" for page in reader.pages)


def _extract_text(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        return _extract_pdf_text(path)
    return path.read_text(encoding="utf-8", errors="replace")


def _chunk_text(text: str) -> list[str]:
    """Split `text` into ~_CHUNK_SIZE-char chunks, preferring paragraph breaks."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if current and len(current) + len(para) + 2 > _CHUNK_SIZE:
            chunks.append(current)
            current = current[-_CHUNK_OVERLAP:]
        current = f"{current}\n\n{para}" if current else para
        while len(current) > _CHUNK_SIZE:
            chunks.append(current[:_CHUNK_SIZE])
            current = current[_CHUNK_SIZE - _CHUNK_OVERLAP :]
    if current:
        chunks.append(current)
    return chunks


def _get_model() -> SentenceTransformer:
    global _model  # noqa: PLW0603 - lazy singleton, weights load once
    with _index_lock:
        if _model is not None:
            return _model
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        model_name = os.environ.get("LOCAL_DOCS_MODEL", _DEFAULT_MODEL)
        # Pinned explicitly: LOCAL_DOCS_MODEL can name any Hub repo, and custom
        # model code runs only under trust_remote_code=True.
        _model = SentenceTransformer(model_name, trust_remote_code=False)
    return _model


def _empty_reason(path: Path) -> str:
    """Explain why a file yielded no text; a scanned PDF is the common case."""
    if path.suffix.lower() == ".pdf":
        return "no extractable text; a scanned or image-only PDF needs OCR first"
    return "file contains no text"


def _signature(files: list[Path]) -> tuple[tuple[str, int, int], ...]:
    return tuple(
        sorted((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    )


def _capped(files: list[Path]) -> tuple[list[Path], bool]:
    """Cap `files` at _MAX_INDEXED_FILES; second value is whether it was cut down."""
    return files[:_MAX_INDEXED_FILES], len(files) > _MAX_INDEXED_FILES


def _build_index() -> tuple[list[_IndexEntry], list[dict[str, str]], bool]:
    global _index_cache, _index_signature, _skipped_cache, _truncated_cache
    with _index_lock:
        root = docs_dir()
        files, truncated = _capped(_iter_files(root))
        signature = _signature(files)
        if signature == _index_signature:
            return _index_cache, _skipped_cache, _truncated_cache

        chunks: list[DocChunk] = []
        skipped: list[dict[str, str]] = []
        for path in files:
            rel = str(path.relative_to(root))
            if path.stat().st_size > _MAX_FILE_BYTES:
                limit_mb = _MAX_FILE_BYTES // (1024 * 1024)
                reason = f"file exceeds the {limit_mb} MB size limit"
                skipped.append({"path": rel, "reason": reason})
                continue
            try:
                text = _extract_text(path)
            except Exception as exc:  # noqa: BLE001 - one bad file must not fail the index
                skipped.append({"path": rel, "reason": str(exc)})
                continue
            if not text.strip():
                skipped.append({"path": rel, "reason": _empty_reason(path)})
                continue
            chunks.extend(
                DocChunk(source=rel, chunk_index=i, text=chunk)
                for i, chunk in enumerate(_chunk_text(text))
            )

        entries: list[_IndexEntry] = []
        if chunks:
            model = _get_model()
            embeddings = model.encode(
                [c.text for c in chunks], normalize_embeddings=True
            )
            entries = [
                _IndexEntry(chunk=chunk, embedding=embedding.tolist())
                for chunk, embedding in zip(chunks, embeddings, strict=True)
            ]

        _index_cache, _index_signature, _skipped_cache, _truncated_cache = (
            entries,
            signature,
            skipped,
            truncated,
        )
        return entries, skipped, truncated


def _cosine_sim(a: list[float], b: list[float]) -> float:
    """Dot product of two already-L2-normalized embedding vectors."""
    return sum(x * y for x, y in zip(a, b, strict=True))


def list_documents() -> tuple[list[dict[str, object]], list[dict[str, str]], bool]:
    """List indexed files, any skipped file, and whether more exist than the cap."""
    with _index_lock:
        root = docs_dir()
        files, truncated = _capped(_iter_files(root))
        _, skipped, _ = _build_index()
        documents: list[dict[str, object]] = [
            {"path": str(f.relative_to(root)), "size_bytes": f.stat().st_size}
            for f in files
        ]
        return documents, skipped, truncated


def search(query: str, top_k: int = 5) -> tuple[list[dict[str, object]], bool]:
    """Return the top_k chunks most similar to `query`.

    Second value is whether the index was capped (see _MAX_INDEXED_FILES).
    """
    entries, _, truncated = _build_index()
    if not entries or not query.strip():
        return [], truncated

    query_vec = _get_model().encode([query], normalize_embeddings=True)[0].tolist()
    scored = sorted(
        ((entry, _cosine_sim(entry.embedding, query_vec)) for entry in entries),
        key=lambda pair: pair[1],
        reverse=True,
    )
    limit = max(1, min(top_k, MAX_RESULTS))
    results: list[dict[str, object]] = [
        {
            "source": entry.chunk.source,
            "chunk_index": entry.chunk.chunk_index,
            "text": entry.chunk.text,
            "score": score,
        }
        for entry, score in scored[:limit]
    ]
    return results, truncated
