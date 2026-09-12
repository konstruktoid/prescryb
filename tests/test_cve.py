"""Tests for prescryb.cve's pure helpers: ecosystem resolution and OSV extraction."""

from __future__ import annotations

from prescryb import cve
from prescryb.models import SystemInfo


def _system(
    distro_id: str, distro_version: str, os_family: str = "debian"
) -> SystemInfo:
    return SystemInfo(
        hostname="h",
        os_family=os_family,
        distro_id=distro_id,
        distro_version=distro_version,
        package_manager="dpkg",
    )


def test_resolve_ecosystem_ubuntu() -> None:
    system = _system("ubuntu", "24.04")
    assert cve.resolve_ecosystem(system) == "Ubuntu:24.04"


def test_resolve_ecosystem_debian_uses_major_version() -> None:
    system = _system("debian", "12.4")
    assert cve.resolve_ecosystem(system) == "Debian:12"


def test_resolve_ecosystem_alpine_uses_major_minor() -> None:
    system = _system("alpine", "3.19.1", os_family="alpine")
    assert cve.resolve_ecosystem(system) == "Alpine:v3.19"


def test_resolve_ecosystem_alpine_without_minor_version() -> None:
    system = _system("alpine", "3", os_family="alpine")
    assert cve.resolve_ecosystem(system) == "Alpine:v3"


def test_resolve_ecosystem_unmapped_distro_returns_none() -> None:
    system = _system("arch", "", os_family="arch")
    assert cve.resolve_ecosystem(system) is None


def test_extract_cve_id_from_bare_id() -> None:
    assert cve._extract_cve_id({"id": "CVE-2023-12345"}) == "CVE-2023-12345"


def test_extract_cve_id_embedded_in_distro_advisory_id() -> None:
    assert cve._extract_cve_id({"id": "DEBIAN-CVE-2023-5363"}) == "CVE-2023-5363"


def test_extract_cve_id_falls_back_to_alias() -> None:
    vuln = {"id": "DSA-5764-1", "aliases": ["CVE-2024-0001", "GHSA-xxxx"]}
    assert cve._extract_cve_id(vuln) == "CVE-2024-0001"


def test_extract_cve_id_falls_back_to_raw_id_without_any_cve() -> None:
    vuln = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": []}
    assert cve._extract_cve_id(vuln) == "GHSA-aaaa-bbbb-cccc"


def test_extract_fixed_version_returns_last_fixed_event() -> None:
    vuln = {
        "affected": [
            {
                "package": {"name": "curl", "ecosystem": "Debian:12"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "7.88.1-1"},
                            {"fixed": "7.88.1-2"},
                        ]
                    }
                ],
            }
        ]
    }
    assert cve._extract_fixed_version(vuln, "curl", "Debian:12") == "7.88.1-2"


def test_extract_fixed_version_none_when_package_mismatch() -> None:
    vuln = {
        "affected": [
            {"package": {"name": "other", "ecosystem": "Debian:12"}, "ranges": []}
        ]
    }
    assert cve._extract_fixed_version(vuln, "curl", "Debian:12") is None


def test_extract_fixed_version_none_when_no_fixed_event() -> None:
    vuln = {
        "affected": [
            {
                "package": {"name": "curl", "ecosystem": "Debian:12"},
                "ranges": [{"events": [{"introduced": "0"}]}],
            }
        ]
    }
    assert cve._extract_fixed_version(vuln, "curl", "Debian:12") is None


def test_extract_severity_prefers_database_specific_field() -> None:
    vuln = {
        "database_specific": {"severity": "high"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
    }
    severity, vector = cve._extract_severity(vuln)
    assert severity == "HIGH"
    assert vector == "CVSS:3.1/AV:N/AC:L"


def test_extract_severity_unknown_with_vector_when_no_database_severity() -> None:
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]}
    severity, vector = cve._extract_severity(vuln)
    assert severity == "UNKNOWN"
    assert vector == "CVSS:3.1/AV:N/AC:L"


def test_extract_severity_unknown_with_no_data_at_all() -> None:
    assert cve._extract_severity({}) == ("UNKNOWN", None)


def test_chunks_splits_into_expected_batch_sizes() -> None:
    items = list(range(7))
    assert list(cve._chunks(items, 3)) == [[0, 1, 2], [3, 4, 5], [6]]


def test_chunks_empty_input_yields_no_batches() -> None:
    assert list(cve._chunks([], 5)) == []
