"""Tests for prescryb.server: dict<->dataclass round-trip helpers and tool wiring."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

from prescryb import server
from prescryb.models import ComplianceRef, CVEMatch, Package, SystemInfo

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


def test_inventory_host_logs_connection_and_result(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    system = SystemInfo(
        hostname="db1",
        os_family="debian",
        distro_id="debian",
        distro_version="12",
        package_manager="dpkg",
        kernel="6.1.0",
    )
    packages = [Package(name="curl", version="7.1", arch="amd64")]

    class FakeSession:
        def close(self) -> None:
            pass

    monkeypatch.setattr(server.ssh, "connect", lambda *_args, **_kwargs: FakeSession())
    monkeypatch.setattr(server.ssh, "detect_system", lambda _session: system)
    monkeypatch.setattr(
        server.ssh, "inventory_packages", lambda _session, _sys_info: packages
    )

    with caplog.at_level(logging.INFO, logger="prescryb.server"):
        result = server.inventory_host("db1", user="ops")

    assert result["package_count"] == 1
    messages = [record.message for record in caplog.records]
    assert any("connecting host='db1' user='ops'" in m for m in messages)
    assert any(
        "inventoried host='db1' distro=debian package_count=1" in m for m in messages
    )


def test_inventory_host_logs_and_reraises_connect_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fake_connect(*_args: object, **_kwargs: object) -> None:
        msg = "boom"
        raise RuntimeError(msg)

    monkeypatch.setattr(server.ssh, "connect", fake_connect)

    with caplog.at_level(logging.INFO, logger="prescryb.server"):
        try:
            server.inventory_host("db1")
        except RuntimeError:
            pass
        else:
            msg = "expected RuntimeError to propagate"
            raise AssertionError(msg)

    assert any(
        "connect failed host='db1'" in record.message for record in caplog.records
    )


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
