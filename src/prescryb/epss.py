"""EPSS (Exploit Prediction Scoring System) lookups against the FIRST.org API.

See https://www.first.org/epss/api. No API key required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from prescryb.models import CVEMatch

_EPSS_BASE = "https://api.first.org/data/v1/epss"
_BATCH_SIZE = 100


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Return {cve_id: (epss_score, percentile)}.

    Unscored CVEs are absent, not an error.
    """
    unique_ids = sorted({c.upper() for c in cve_ids if c})
    if not unique_ids:
        return {}

    scores: dict[str, tuple[float, float]] = {}
    async with httpx.AsyncClient() as client:
        for batch in _chunks(unique_ids, _BATCH_SIZE):
            resp = await client.get(
                _EPSS_BASE,
                params={"cve": ",".join(batch), "limit": len(batch)},
                timeout=30.0,
            )
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                scores[entry["cve"]] = (
                    float(entry["epss"]),
                    float(entry["percentile"]),
                )
    return scores


async def annotate_matches(matches: list[CVEMatch]) -> str | None:
    """Attach epss_score/epss_percentile to `matches` in place.

    Returns a warning on failure instead of raising.
    """
    if not matches:
        return None
    try:
        scores = await fetch_epss_scores([m.cve_id for m in matches])
    except httpx.HTTPError as exc:
        return f"EPSS lookup failed ({exc}); epss_score/epss_percentile left unset."

    for match in matches:
        score = scores.get(match.cve_id.upper())
        if score is not None:
            match.epss_score, match.epss_percentile = score
    return None
