"""CVE lookup against OSV.dev.

OSV.dev is used as the sole matching source (rather than raw NVD/CPE matching)
because it does the ecosystem-aware version comparison for OS packages
server-side: we send `{name, ecosystem, version}` and it tells us which
vulnerabilities apply to that *exact installed version*, avoiding the
false positives that naive "any CVE mentioning this package name" matching
produces. NVD is used separately (see advisories.py) to enrich a specific,
already-identified CVE with authoritative CVSS/description/references.

Ecosystem coverage varies by distro family - see _ECOSYSTEM_BUILDERS. Debian,
Ubuntu, and Alpine have mature OSV coverage. RHEL-family (AlmaLinux, Rocky,
RHEL itself) and SUSE-family coverage is newer/thinner in OSV; treat a lack
of findings there as "nothing found", not "confirmed clean".
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

import httpx

from prescryb import epss
from prescryb.models import CVEMatch, Package, SystemInfo

if TYPE_CHECKING:
    from collections.abc import Iterator

_OSV_BASE = "https://api.osv.dev/v1"
_BATCH_SIZE = 500
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_MIN_PARTS_FOR_MAJOR_MINOR = 2


def _debian_ecosystem(system: SystemInfo) -> str:
    major = system.distro_version.split(".")[0]
    return f"Debian:{major}"


def _alpine_ecosystem(system: SystemInfo) -> str:
    parts = system.distro_version.split(".")
    has_minor = len(parts) >= _MIN_PARTS_FOR_MAJOR_MINOR
    major_minor = ".".join(parts[:2]) if has_minor else system.distro_version
    return f"Alpine:v{major_minor}"


_ECOSYSTEM_BUILDERS = {
    "ubuntu": lambda s: f"Ubuntu:{s.distro_version}",
    "debian": _debian_ecosystem,
    "alpine": _alpine_ecosystem,
    "almalinux": lambda s: f"AlmaLinux:{s.distro_version.split('.')[0]}",
    "rocky": lambda s: f"Rocky Linux:{s.distro_version.split('.')[0]}",
    "opensuse-leap": lambda s: f"openSUSE:Leap:{s.distro_version}",
}

_WELL_COVERED = {"ubuntu", "debian", "alpine"}


def resolve_ecosystem(system: SystemInfo) -> str | None:
    """Map a SystemInfo's distro to its OSV ecosystem string, or None if unmapped."""
    builder = _ECOSYSTEM_BUILDERS.get(system.distro_id)
    if builder is None:
        return None
    return builder(system)


def _chunks(items: list, size: int) -> Iterator[list]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


async def query_osv_batch(
    client: httpx.AsyncClient, ecosystem: str, packages: list[Package]
) -> dict[str, list[str]]:
    """Return {package_name: [osv_vuln_id, ...]} for packages with a match."""
    matches: dict[str, list[str]] = {}
    for batch in _chunks(packages, _BATCH_SIZE):
        body = {
            "queries": [
                {
                    "package": {"name": pkg.name, "ecosystem": ecosystem},
                    "version": pkg.version,
                }
                for pkg in batch
            ]
        }
        resp = await client.post(f"{_OSV_BASE}/querybatch", json=body, timeout=30.0)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        for pkg, result in zip(batch, results, strict=True):
            vulns = result.get("vulns", [])
            if vulns:
                matches[pkg.name] = [v["id"] for v in vulns]
    return matches


async def fetch_vuln_details(client: httpx.AsyncClient, vuln_id: str) -> dict:
    """Fetch the full OSV record for a single vulnerability id."""
    resp = await client.get(f"{_OSV_BASE}/vulns/{vuln_id}", timeout=30.0)
    resp.raise_for_status()
    return resp.json()


def _extract_cve_id(vuln: dict) -> str:
    """Pull the CVE id out of an OSV record; OSV ids aren't always bare CVE ids.

    Debian entries look like 'DEBIAN-CVE-2023-5363', security-advisory ids
    like 'DSA-5764-1' or 'USN-1234-1' carry the CVE only in `aliases` (or not
    at all, for multi-CVE advisories - the first alias is reported then).
    """
    match = _CVE_RE.search(vuln["id"])
    if match:
        return match.group(0)
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln["id"]


def _extract_fixed_version(vuln: dict, package_name: str, ecosystem: str) -> str | None:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package_name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            fixed_events = [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
            if fixed_events:
                return fixed_events[-1]
    return None


def _extract_severity(vuln: dict) -> tuple[str, str | None]:
    db_specific = vuln.get("database_specific", {}) or {}
    severity = db_specific.get("severity")
    vector = None
    for entry in vuln.get("severity", []):
        if entry.get("type", "").startswith("CVSS"):
            vector = entry.get("score")
    if not severity and vector:
        severity = "UNKNOWN"
    return (severity or "UNKNOWN").upper(), vector


async def check_cves(
    system: SystemInfo, packages: list[Package]
) -> tuple[list[CVEMatch], str | None]:
    """Query OSV for every package, then enrich matches with EPSS scores.

    Returns (matches, warning) - warning covers unmapped/low-confidence
    ecosystems or a failed EPSS lookup.
    """
    ecosystem = resolve_ecosystem(system)
    if ecosystem is None:
        return [], (
            f"No OSV ecosystem mapping for distro '{system.distro_id}'. "
            "Skipping automated CVE matching for this host; use fetch_advisory with "
            "specific CVE IDs (e.g. found via web search) instead."
        )

    warning = None
    if system.distro_id not in _WELL_COVERED:
        warning = (
            f"OSV coverage for ecosystem '{ecosystem}' is newer/thinner than "
            "Debian/Ubuntu/Alpine. Treat an empty result as inconclusive, not as "
            "confirmation the host is unaffected."
        )

    async with httpx.AsyncClient() as client:
        pkg_to_vulns = await query_osv_batch(client, ecosystem, packages)
        packages_by_name = {p.name: p for p in packages}

        unique_vuln_ids = sorted({vid for ids in pkg_to_vulns.values() for vid in ids})
        details = await asyncio.gather(
            *(fetch_vuln_details(client, vid) for vid in unique_vuln_ids)
        )
        details_by_id = dict(zip(unique_vuln_ids, details, strict=True))

    matches: list[CVEMatch] = []
    for pkg_name, vuln_ids in pkg_to_vulns.items():
        pkg = packages_by_name[pkg_name]
        for vid in vuln_ids:
            vuln = details_by_id[vid]
            severity, vector = _extract_severity(vuln)
            matches.append(
                CVEMatch(
                    cve_id=_extract_cve_id(vuln),
                    package=pkg_name,
                    installed_version=pkg.version,
                    fixed_version=_extract_fixed_version(vuln, pkg_name, ecosystem),
                    severity=severity,
                    cvss_vector=vector,
                    summary=(vuln.get("summary") or vuln.get("details") or "")[:500],
                    references=[
                        r["url"] for r in vuln.get("references", []) if "url" in r
                    ][:5],
                    source="osv",
                )
            )

    epss_warning = await epss.annotate_matches(matches)
    if epss_warning:
        warning = f"{warning} {epss_warning}" if warning else epss_warning

    return matches, warning
