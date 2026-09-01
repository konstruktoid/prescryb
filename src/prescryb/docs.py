"""Semantic (RAG-style) search over local reference documents.

Reads Markdown, text, and PDF files from a local, gitignored directory
(`LOCAL_DOCS_DIR`, default `local_docs/`) holding material the
network-backed tools can't see: runbooks, policy, prior remediation notes.
Embeddings are computed locally with a `sentence-transformers` model, so
indexing and ranking need no network; matched chunks are still returned to
the connected MCP client like any other tool result. The model itself is
fetched from Hugging Face on first use (see README "Local documents"). The
chunk index is rebuilt only when file mtimes or sizes change.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

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
# A per-file cap alone still admits 500 files of that size, so bound the index too.
_MAX_INDEXED_CHUNKS = 5000
_ENCODE_BATCH = 256


@dataclass
class DocChunk:
    """One chunk of a local document; `source` is relative to the docs dir."""

    source: str
    chunk_index: int
    text: str


@dataclass
class _IndexEntry:
    """One indexed chunk paired with its L2-normalized embedding."""

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


def _has_symlink_component(root: Path, path: Path) -> bool:
    """Report whether any component of `path` below `root` is a symlink."""
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _iter_files(root: Path) -> list[Path]:
    """List the indexable files under `root`, sorted by path."""
    if not root.is_dir():
        return []
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        # A symlink can be repointed out of the docs dir after any check here,
        # so indexing declines to traverse one at all; see _open_within().
        if _has_symlink_component(root, path):
            continue
        files.append(path)
    return files


def _open_within(root: Path, path: Path) -> BinaryIO:
    """Open `path` under `root` for reading, traversing no symlink on the way."""
    parts = path.relative_to(root).parts
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
            )
            os.close(dir_fd)
            dir_fd = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    return os.fdopen(fd, "rb")


def _extract_pdf_text(stream: BinaryIO) -> str:
    """Extract the text of every page of an open PDF stream."""
    from pypdf import PdfReader  # noqa: PLC0415 - skip pypdf's import cost when unused

    reader = PdfReader(stream)
    return "\n\n".join(page.extract_text() or "" for page in reader.pages)


def _extract_text(stream: BinaryIO, suffix: str) -> str:
    """Extract text from an open document stream, dispatching on its suffix."""
    if suffix == ".pdf":
        return _extract_pdf_text(stream)
    return stream.read().decode("utf-8", errors="replace")


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
    """Load the configured sentence-transformers model once, on first use."""
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


def _stat_within(root: Path, path: Path) -> os.stat_result | None:
    """Stat `path` through a descriptor opened under `root`; None if unopenable."""
    try:
        with _open_within(root, path) as stream:
            return os.fstat(stream.fileno())
    except OSError:
        return None


def _signature(root: Path, files: list[Path]) -> tuple[tuple[str, int, int], ...]:
    """Fingerprint `files` by path, mtime, and size, to detect index staleness.

    An unopenable file keeps a sentinel entry, so the index is rebuilt once it
    becomes readable again.
    """
    fingerprints = []
    for path in files:
        stat = _stat_within(root, path)
        mtime_ns, size = (stat.st_mtime_ns, stat.st_size) if stat else (-1, -1)
        fingerprints.append((str(path), mtime_ns, size))
    return tuple(sorted(fingerprints))


def _capped(files: list[Path]) -> tuple[list[Path], bool]:
    """Cap `files` at _MAX_INDEXED_FILES; second value is whether it was cut down."""
    return files[:_MAX_INDEXED_FILES], len(files) > _MAX_INDEXED_FILES


def _read_document(root: Path, path: Path) -> tuple[str, str | None]:
    """Read one document's text, or return the reason it has to be skipped."""
    try:
        with _open_within(root, path) as stream:
            if os.fstat(stream.fileno()).st_size > _MAX_FILE_BYTES:
                limit_mb = _MAX_FILE_BYTES // (1024 * 1024)
                return "", f"file exceeds the {limit_mb} MB size limit"
            text = _extract_text(stream, path.suffix.lower())
    except Exception as exc:  # noqa: BLE001 - one bad file must not fail the index
        return "", str(exc)
    if not text.strip():
        return "", _empty_reason(path)
    return text, None


def _collect_chunks(
    root: Path, files: list[Path]
) -> tuple[list[DocChunk], list[dict[str, str]], bool]:
    """Chunk every readable file up to _MAX_INDEXED_CHUNKS, reporting the rest."""
    chunks: list[DocChunk] = []
    skipped: list[dict[str, str]] = []
    truncated = False
    for path in files:
        rel = str(path.relative_to(root))
        text, reason = _read_document(root, path)
        if reason is not None:
            skipped.append({"path": rel, "reason": reason})
            continue
        room = _MAX_INDEXED_CHUNKS - len(chunks)
        file_chunks = _chunk_text(text)
        if len(file_chunks) > room:
            file_chunks = file_chunks[:room]
            truncated = True
        chunks.extend(
            DocChunk(source=rel, chunk_index=i, text=chunk)
            for i, chunk in enumerate(file_chunks)
        )
        if len(chunks) >= _MAX_INDEXED_CHUNKS:
            truncated = True
            break
    return chunks, skipped, truncated


def _embed(chunks: list[DocChunk]) -> list[_IndexEntry]:
    """Embed `chunks` in bounded batches so peak memory stays predictable."""
    model = _get_model()
    entries: list[_IndexEntry] = []
    for start in range(0, len(chunks), _ENCODE_BATCH):
        batch = chunks[start : start + _ENCODE_BATCH]
        embeddings = model.encode([c.text for c in batch], normalize_embeddings=True)
        entries.extend(
            _IndexEntry(chunk=chunk, embedding=embedding.tolist())
            for chunk, embedding in zip(batch, embeddings, strict=True)
        )
    return entries


def _build_index() -> tuple[list[_IndexEntry], list[dict[str, str]], bool]:
    """Return the cached chunk index, rebuilding it when the files changed."""
    global _index_cache, _index_signature, _skipped_cache, _truncated_cache
    with _index_lock:
        root = docs_dir()
        files, truncated = _capped(_iter_files(root))
        signature = _signature(root, files)
        if signature == _index_signature:
            return _index_cache, _skipped_cache, _truncated_cache

        chunks, skipped, chunks_truncated = _collect_chunks(root, files)
        truncated = truncated or chunks_truncated
        entries = _embed(chunks) if chunks else []

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
    """List indexed files, any skipped file, and whether a cap left content out."""
    with _index_lock:
        root = docs_dir()
        files, _ = _capped(_iter_files(root))
        _, skipped, truncated = _build_index()
        documents: list[dict[str, object]] = []
        for path in files:
            stat = _stat_within(root, path)
            documents.append(
                {
                    "path": str(path.relative_to(root)),
                    "size_bytes": stat.st_size if stat else 0,
                }
            )
        return documents, skipped, truncated


def search(query: str, top_k: int = 5) -> tuple[list[dict[str, object]], bool]:
    """Return the top_k chunks most similar to `query`.

    Second value is whether the index was capped (see _MAX_INDEXED_FILES
    and _MAX_INDEXED_CHUNKS).
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
