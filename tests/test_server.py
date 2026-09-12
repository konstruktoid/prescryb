"""Tests for prescryb.server: dict<->dataclass round-trip helpers and tool wiring."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import TYPE_CHECKING

from prescryb import server
from prescryb.models import ComplianceRef, CVEMatch, SystemInfo

if TYPE_CHECKING:
    import pytest


def test_system_from_dict_round_trips_asdict_output() -> None:
    system = SystemInfo(
        hostname="db1",
        os_family="debian",
        distro_id="debian",
        distro_version="12",
        package_manager="dpkg",
        kernel="6.1.0",
    )
    assert server._system_from_dict(asdict(system)) == system


def test_system_from_dict_defaults_missing_kernel() -> None:
    d = {
        "hostname": "h",
        "os_family": "debian",
        "distro_id": "debian",
        "distro_version": "12",
        "package_manager": "dpkg",
    }
    assert server._system_from_dict(d).kernel == ""


def test_cve_from_dict_round_trips_asdict_output() -> None:
    match = CVEMatch(
        cve_id="CVE-2024-0001",
        package="curl",
        installed_version="7.1",
        fixed_version="7.2",
        severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N",
        summary="desc",
        references=["https://example.com/adv"],
        source="osv",
        epss_score=0.5,
        epss_percentile=0.9,
    )
    assert server._cve_from_dict(asdict(match)) == match


def test_cve_from_dict_applies_defaults_for_optional_fields() -> None:
    d = {"cve_id": "CVE-2024-0002", "package": "bash", "installed_version": "5.0"}
    rebuilt = server._cve_from_dict(d)
    assert rebuilt.fixed_version is None
    assert rebuilt.severity == "UNKNOWN"
    assert rebuilt.references == []
    assert rebuilt.source == "osv"
    assert rebuilt.epss_score is None
    assert rebuilt.epss_percentile is None


def test_generate_playbook_builds_cve_and_compliance_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_map_finding(area: str) -> list[ComplianceRef]:
        del area
        return [
            ComplianceRef(
                framework="CIS",
                topic="SSH Server Configuration",
                role="ssh",
                role_path=None,
                note="not found",
            )
        ]

    def fake_attack_map_finding(area: str) -> list:
        del area
        return []

    monkeypatch.setattr(server.compliance, "map_finding", fake_map_finding)
    monkeypatch.setattr(server.attack, "map_finding", fake_attack_map_finding)

    system = {
        "hostname": "h",
        "os_family": "debian",
        "distro_id": "debian",
        "distro_version": "12",
        "package_manager": "dpkg",
    }
    cve_matches = [
        {
            "cve_id": "CVE-2024-0001",
            "package": "curl",
            "installed_version": "7.1",
            "fixed_version": "7.2",
        }
    ]

    output = asyncio.run(
        server.generate_playbook(
            system, cve_matches=cve_matches, compliance_areas=["ssh"]
        )
    )

    assert "CVE-2024-0001" in output
    assert "konstruktoid.hardening.ssh" in output
