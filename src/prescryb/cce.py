"""Look up NIST Common Configuration Enumeration (CCE) entries.

CCE (https://ncp.nist.gov/cce) assigns a unique identifier to individual
system configuration checks - distinct from CIS/DISA STIG rule numbers (see
compliance.py), which require a licensed benchmark document. NIST only
publishes CCE as spreadsheets, so this module reads the pre-converted JSON
exports hosted by the community project
https://github.com/konstruktoid/cce-web instead of parsing Excel here.

Coverage is per-platform (e.g. "rhel8", "SLES15-DISA-STIG"), not per-topic:
of this project's target distros, only RHEL-family and SUSE have any CCE
data upstream at all - Debian, Ubuntu, Alpine, and Arch have none. Several
of the older cce-web exports also lost their column headers in the
Excel-to-JSON conversion; those are reported as unsupported rather than
returning garbled fields.
"""

from __future__ import annotations

import html
import os
import re

import httpx

from prescryb.models import CCERef

_DEFAULT_REPO = "konstruktoid/cce-web"
CCE_REPO = os.environ.get("CCE_REPO", _DEFAULT_REPO)
_GITHUB_API = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"

MAX_RESULTS = 25

# Exports with this key are a direct, well-formed conversion of the USGCB-style
# spreadsheet columns (most Linux/Apple/Office/browser targets).
_USGCB_ID_KEY = "CCE ID v5"
# Exports with these keys use the SLES DISA-STIG/PCI-DSS benchmark columns.
_SLES_ID_KEY = "CCE"
_SLES_TITLE_KEY = "Name"


def _clean(value: object) -> str:
    if value is None:
        return ""
    text = html.unescape(str(value)).strip()
    return "" if text.lower() == "none" else text


def _html_url(target: str) -> str:
    return f"https://konstruktoid.github.io/cce-web/cce_html/{target}.html"


def _repo_file_url(target: str) -> str:
    return f"https://github.com/{CCE_REPO}/blob/main/cce_json/{target}.json"


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def unsupported_reason(target: str) -> str:
    """Explain why `target`'s export can't be normalized (see module docstring)."""
    return (
        f"{target}.json in {CCE_REPO} lost its column headers in the upstream "
        f"Excel-to-JSON conversion and can't be reliably parsed - see "
        f"{_repo_file_url(target)} directly."
    )


def _rows(data: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    first_col = next(iter(data.values()))
    return [{col: data[col].get(str(i)) for col in data} for i in range(len(first_col))]


def _normalize_usgcb(rows: list[dict[str, object]], target: str) -> list[CCERef]:
    source_url = _html_url(target)
    return [
        CCERef(
            cce_id=_clean(row.get(_USGCB_ID_KEY)),
            title=_clean(row.get("CCE Title")),
            target=target,
            description=_clean(row.get("Configuration Details")),
            rationale=_clean(row.get("Rationale")),
            severity=_clean(row.get("Impact")),
            group=_clean(row.get("Configuration Group")),
            cis=_clean(row.get("Center for Internet Security")) or None,
            disa_srg=_clean(
                row.get(
                    "Defense Information Systems Agency Security "
                    "Security Requirements Guide"
                )
            )
            or None,
            source_url=source_url,
        )
        for row in rows
        if _clean(row.get(_USGCB_ID_KEY))
    ]


def _normalize_sles(rows: list[dict[str, object]], target: str) -> list[CCERef]:
    source_url = _html_url(target)
    return [
        CCERef(
            cce_id=_clean(row.get(_SLES_ID_KEY)),
            title=_clean(row.get(_SLES_TITLE_KEY)),
            target=target,
            description=_clean(row.get("Check_Fix")),
            rationale=_clean(row.get("Rationale")),
            severity=_clean(row.get("Severity")),
            group=_clean(row.get("SLE")),
            cis=_clean(row.get("CIS")) or None,
            disa_srg=_clean(row.get("SRG")) or None,
            source_url=source_url,
        )
        for row in rows
        if _clean(row.get(_SLES_ID_KEY))
    ]


def _normalize(data: dict[str, dict[str, object]], target: str) -> list[CCERef] | None:
    rows = _rows(data)
    if _USGCB_ID_KEY in data:
        return _normalize_usgcb(rows, target)
    if _SLES_ID_KEY in data and _SLES_TITLE_KEY in data:
        return _normalize_sles(rows, target)
    return None


async def list_targets() -> list[str]:
    """List cce-web export names, e.g. 'rhel8', 'SLES15-DISA-STIG', 'firefox'."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{_GITHUB_API}/repos/{CCE_REPO}/contents/cce_json",
            headers=_github_headers(),
            timeout=15.0,
        )
        resp.raise_for_status()
        entries = resp.json()
    return sorted(
        entry["name"].removesuffix(".json")
        for entry in entries
        if entry["type"] == "file" and entry["name"].endswith(".json")
    )


def _normalize_hint(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _match_targets(hint: str, targets: list[str]) -> list[str]:
    hint_norm = _normalize_hint(hint)
    exact = [t for t in targets if _normalize_hint(t) == hint_norm]
    if exact:
        return exact
    return [
        t
        for t in targets
        if hint_norm in _normalize_hint(t) or _normalize_hint(t) in hint_norm
    ]


async def resolve_target(hint: str) -> tuple[str | None, list[str]]:
    """Resolve free text (e.g. 'rhel8', 'sles15') to one cce-web target.

    Returns (target, candidates). `target` is None unless exactly one target
    matches - ambiguous or absent matches are surfaced via `candidates`
    (the partial matches, or every published target if none matched at all)
    rather than guessing.
    """
    targets = await list_targets()
    matches = _match_targets(hint, targets)
    if len(matches) == 1:
        return matches[0], []
    return None, (matches or targets)


async def fetch_target(target: str) -> list[CCERef] | None:
    """Fetch and normalize one cce-web export; None if its schema is unsupported."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{_RAW_BASE}/{CCE_REPO}/main/cce_json/{target}.json", timeout=30.0
        )
        resp.raise_for_status()
        data = resp.json()
    return _normalize(data, target)


def search(entries: list[CCERef], keyword: str = "", cce_id: str = "") -> list[CCERef]:
    """Filter `entries` by exact `cce_id` or a case-insensitive `keyword`."""
    if cce_id:
        needle = cce_id.strip().upper()
        return [e for e in entries if e.cce_id.upper() == needle]
    if keyword:
        needle = keyword.lower()
        return [
            e
            for e in entries
            if needle in e.title.lower()
            or needle in e.description.lower()
            or needle in e.rationale.lower()
            or needle in e.group.lower()
        ]
    return entries
