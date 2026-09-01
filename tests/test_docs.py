"""Tests for prescryb.docs: file discovery, chunking, and search ranking.

The sentence-transformers model is stubbed throughout, so no test needs
network access or downloaded weights.
"""

from __future__ import annotations

import threading
from pathlib import Path

import numpy as np
import pytest

from prescryb import docs


class _FakeModel:
    """Deterministic stand-in for SentenceTransformer, matching encode()'s return shape.

    Each input maps to a fixed 2D vector by whether it mentions "ssh" or
    "kernel", making search ranking verifiable without a real model.
    """

    def encode(self, texts: list[str], *, normalize_embeddings: bool) -> np.ndarray:
        assert normalize_embeddings
        return np.array([self._vector(t) for t in texts])

    @staticmethod
    def _vector(text: str) -> list[float]:
        text = text.lower()
        if "ssh" in text:
            return [1.0, 0.0]
        if "kernel" in text:
            return [0.0, 1.0]
        return [0.7071, 0.7071]


@pytest.fixture(autouse=True)
def _reset_index_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test gets a fresh in-memory index and a stubbed embedding model."""
    monkeypatch.setattr(docs, "_index_cache", [])
    monkeypatch.setattr(docs, "_index_signature", None)
    monkeypatch.setattr(docs, "_skipped_cache", [])
    monkeypatch.setattr(docs, "_truncated_cache", False)
    monkeypatch.setattr(docs, "_get_model", _FakeModel)


def test_docs_dir_reads_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path / "notes"))
    assert docs.docs_dir() == (tmp_path / "notes").resolve()


def test_docs_dir_defaults_to_local_docs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCAL_DOCS_DIR", raising=False)
    assert docs.docs_dir().name == "local_docs"


def test_iter_files_missing_dir_is_empty(tmp_path: Path) -> None:
    assert docs._iter_files(tmp_path / "does-not-exist") == []


def test_iter_files_finds_nested_supported_files(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "notes.md").write_text("hello")
    (tmp_path / "sub" / "raw.txt").write_text("world")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")  # unsupported suffix

    found = {p.relative_to(tmp_path) for p in docs._iter_files(tmp_path)}
    assert found == {Path("notes.md"), Path("sub/raw.txt")}


def test_iter_files_skips_dotfiles_and_dotdirs(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.md").write_text("secret")
    (tmp_path / ".hidden.md").write_text("secret")
    (tmp_path / "visible.md").write_text("hello")

    found = {p.relative_to(tmp_path) for p in docs._iter_files(tmp_path)}
    assert found == {Path("visible.md")}


def test_iter_files_excludes_symlink_escaping_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("do not index")
    root = tmp_path / "root"
    root.mkdir()
    (root / "escape.md").symlink_to(outside / "secret.md")

    assert docs._iter_files(root) == []


def test_chunk_text_empty_input() -> None:
    assert docs._chunk_text("") == []
    assert docs._chunk_text("   \n\n  ") == []


def test_chunk_text_short_text_is_one_chunk() -> None:
    text = "Disable root login.\n\nUse key-based auth only."
    chunks = docs._chunk_text(text)
    assert len(chunks) == 1
    assert chunks[0] == text


def test_chunk_text_splits_long_text() -> None:
    paragraph = "x" * 700
    text = "\n\n".join([paragraph] * 4)
    chunks = docs._chunk_text(text)
    assert len(chunks) > 1
    assert all(len(c) <= docs._CHUNK_SIZE for c in chunks)


def _write_pdf(path: Path, text: str = "") -> None:
    """Write a minimal one-page PDF; empty `text` mimics a scanned, image-only page."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii") if text else b""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(stream)).encode()
        + b" >>\nstream\n"
        + stream
        + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n"
    ).encode()
    path.write_bytes(bytes(out))


def test_extract_pdf_text_reads_page_text(tmp_path: Path) -> None:
    pdf = tmp_path / "runbook.pdf"
    _write_pdf(pdf, "Rotate all SSH host keys quarterly")

    assert "Rotate all SSH host keys quarterly" in docs._extract_pdf_text(pdf)


def test_extract_pdf_text_empty_for_page_without_text(tmp_path: Path) -> None:
    pdf = tmp_path / "scan.pdf"
    _write_pdf(pdf)

    assert docs._extract_pdf_text(pdf).strip() == ""


def test_list_documents_skips_pdf_without_extractable_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_pdf(tmp_path / "scan.pdf")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    documents, skipped, _ = docs.list_documents()

    reason = "no extractable text; a scanned or image-only PDF needs OCR first"
    assert [d["path"] for d in documents] == ["scan.pdf"]
    assert skipped == [{"path": "scan.pdf", "reason": reason}]


def test_list_documents_skips_whitespace_only_text_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "blank.md").write_text("   \n\n\t\n")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    _, skipped, _ = docs.list_documents()

    assert skipped == [{"path": "blank.md", "reason": "file contains no text"}]


def test_search_excludes_pdf_without_extractable_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _write_pdf(tmp_path / "scan.pdf")
    (tmp_path / "ssh.md").write_text("SSH hardening notes")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    results, _ = docs.search("ssh", top_k=5)

    assert [r["source"] for r in results] == ["ssh.md"]


def test_list_documents_reports_files_and_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "ssh.md").write_text("SSH hardening notes")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    documents, skipped, truncated = docs.list_documents()

    assert documents == [{"path": "ssh.md", "size_bytes": len("SSH hardening notes")}]
    assert skipped == []
    assert truncated is False


def test_list_documents_records_unreadable_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bad_pdf = tmp_path / "broken.pdf"
    bad_pdf.write_bytes(b"not a real pdf")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    documents, skipped, _ = docs.list_documents()

    assert documents == [{"path": "broken.pdf", "size_bytes": bad_pdf.stat().st_size}]
    assert len(skipped) == 1
    assert skipped[0]["path"] == "broken.pdf"


def test_list_documents_skips_oversized_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(docs, "_MAX_FILE_BYTES", 10)
    (tmp_path / "big.md").write_text("x" * 11)
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    documents, skipped, _ = docs.list_documents()

    assert documents == [{"path": "big.md", "size_bytes": 11}]
    assert skipped == [{"path": "big.md", "reason": "file exceeds the 0 MB size limit"}]


def test_list_documents_truncates_at_file_count_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cap = 2
    monkeypatch.setattr(docs, "_MAX_INDEXED_FILES", cap)
    for i in range(cap + 1):
        (tmp_path / f"doc{i}.md").write_text(f"note {i}")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    documents, _, truncated = docs.list_documents()

    assert len(documents) == cap
    assert truncated is True


def test_search_ranks_by_similarity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "ssh.md").write_text("SSH hardening runbook: disable root login.")
    (tmp_path / "kernel.md").write_text("Kernel sysctl hardening notes.")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    results, truncated = docs.search("ssh root login policy", top_k=5)

    assert results
    assert truncated is False
    assert results[0]["source"] == "ssh.md"
    top_score, bottom_score = results[0]["score"], results[-1]["score"]
    assert isinstance(top_score, float)
    assert isinstance(bottom_score, float)
    assert top_score > bottom_score


def test_search_empty_query_returns_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "ssh.md").write_text("SSH hardening notes")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    assert docs.search("   ", top_k=5) == ([], False)


def test_search_empty_docs_dir_returns_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))
    assert docs.search("anything", top_k=5) == ([], False)


def test_search_clamps_top_k_to_max_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for i in range(3):
        (tmp_path / f"doc{i}.md").write_text(f"SSH note number {i}")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    results, _ = docs.search("ssh", top_k=1000)
    assert len(results) <= docs.MAX_RESULTS


def test_search_reports_truncated_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(docs, "_MAX_INDEXED_FILES", 1)
    (tmp_path / "ssh.md").write_text("SSH hardening notes")
    (tmp_path / "kernel.md").write_text("Kernel hardening notes")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    _, truncated = docs.search("hardening", top_k=5)
    assert truncated is True


def test_concurrent_searches_return_consistent_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "ssh.md").write_text("SSH hardening runbook: disable root login.")
    (tmp_path / "kernel.md").write_text("Kernel sysctl hardening notes.")
    monkeypatch.setenv("LOCAL_DOCS_DIR", str(tmp_path))

    workers = 4
    results: list[list[str]] = []
    barrier = threading.Barrier(workers)

    def run() -> None:
        barrier.wait()
        matches, _ = docs.search("ssh root login policy", top_k=5)
        results.append([str(m["source"]) for m in matches])

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == workers
    assert all(sources == results[0] for sources in results)
    assert results[0][0] == "ssh.md"
