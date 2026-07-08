"""Live authoritative advisory lookups for a specific, already-identified CVE.

This is the "up-to-date news/documentation" leg of the workflow: given a CVE
ID (from check_cves, or one the caller already knows about e.g. via web
search), fetch the current NVD record - description, CVSS, CWE weaknesses,
and references - at call time, rather than relying on anything cached or
baked into the model's training data.
"""

from __future__ import annotations

import os

import httpx

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVENotFoundError(RuntimeError):
    """Raised when NVD has no record for the requested CVE ID."""


def _best_metric(cve: dict) -> dict | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]
    return None


async def fetch_advisory(cve_id: str) -> dict:
    """Fetch the current NVD record for `cve_id`: description, CVSS, CWEs, refs."""
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            _NVD_BASE, params={"cveId": cve_id}, headers=headers, timeout=30.0
        )
        resp.raise_for_status()
        payload = resp.json()

    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        msg = f"{cve_id} not found in NVD"
        raise CVENotFoundError(msg)

    cve = vulns[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    metric = _best_metric(cve)
    cwes = [
        desc["value"]
        for weakness in cve.get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc.get("lang") == "en"
    ]

    return {
        "cve_id": cve_id,
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_base_score": (metric or {}).get("cvssData", {}).get("baseScore"),
        "cvss_severity": (metric or {}).get("cvssData", {}).get("baseSeverity")
        or (metric or {}).get("baseSeverity"),
        "cwe_ids": cwes,
        "references": [ref["url"] for ref in cve.get("references", [])],
    }
