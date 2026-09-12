"""Tests for prescryb.playbook: suggest-only Ansible playbook rendering."""

from __future__ import annotations

from prescryb import playbook
from prescryb.models import AttackRef, ComplianceRef, CVEMatch, Finding, SystemInfo


def _system(
    os_family: str = "debian",
    distro_id: str = "debian",
    distro_version: str = "12",
    hostname: str = "db1",
) -> SystemInfo:
    return SystemInfo(
        hostname=hostname,
        os_family=os_family,
        distro_id=distro_id,
        distro_version=distro_version,
        package_manager="dpkg",
    )


def _cve_match(
    cve_id: str = "CVE-2024-0001",
    package: str = "curl",
    fixed_version: str | None = "7.88.1-2",
    epss_score: float | None = None,
    epss_percentile: float | None = None,
) -> CVEMatch:
    return CVEMatch(
        cve_id=cve_id,
        package=package,
        installed_version="7.88.1-1",
        fixed_version=fixed_version,
        severity="HIGH",
        cvss_vector=None,
        summary="buffer overflow",
        references=["https://example.com/adv"],
        epss_score=epss_score,
        epss_percentile=epss_percentile,
    )


def test_build_playbook_no_findings_reports_nothing_actionable() -> None:
    output = playbook.build_playbook(_system(), [])
    assert "No actionable findings" in output
    assert "tasks:" not in output


def test_build_playbook_cve_finding_creates_upgrade_task() -> None:
    match = _cve_match()
    finding = Finding(
        kind="cve",
        title="CVE-2024-0001 in curl",
        detail="buffer overflow",
        package="curl",
        cve=match,
    )
    output = playbook.build_playbook(_system(), [finding], hosts_alias="dbservers")

    assert "hosts: dbservers" in output
    assert "curl=7.88.1-2" in output
    assert "CVE-2024-0001" in output
    assert "ansible.builtin.apt" in output


def test_build_playbook_uses_os_family_specific_package_module() -> None:
    system = _system(os_family="redhat", distro_id="almalinux", distro_version="9")
    match = _cve_match(cve_id="CVE-2024-0002", package="openssl", fixed_version="3.0.2")
    finding = Finding(kind="cve", title="x", detail="", package="openssl", cve=match)

    output = playbook.build_playbook(system, [finding])

    assert "ansible.builtin.dnf" in output
    assert "openssl-3.0.2" in output


def test_build_playbook_config_finding_references_hardening_role() -> None:
    ref = ComplianceRef(
        framework="CIS",
        topic="SSH Server Configuration",
        role="ssh",
        role_path="https://github.com/example/roles/ssh",
        note="found",
    )
    finding = Finding(
        kind="config", title="ssh hardening", detail="SSH", compliance=[ref]
    )

    output = playbook.build_playbook(_system(), [finding])

    assert "konstruktoid.hardening.ssh" in output
    assert "roles:" in output


def test_build_playbook_includes_attack_mapping_in_header() -> None:
    ref = AttackRef(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        technique_url="https://attack.mitre.org/techniques/T1110/",
        mitigation_id="M1032",
        mitigation_name="Multi-factor Authentication",
    )
    finding = Finding(kind="config", title="pam hardening", detail="pam", attack=[ref])

    output = playbook.build_playbook(_system(), [finding])

    assert "T1110 Brute Force" in output
    assert "M1032 Multi-factor Authentication" in output


def test_build_playbook_epss_suffix_included_when_scored() -> None:
    match = _cve_match(
        cve_id="CVE-2024-0003",
        package="bash",
        fixed_version="5.2.1",
        epss_score=0.734,
        epss_percentile=0.912,
    )
    finding = Finding(kind="cve", title="x", detail="", package="bash", cve=match)

    output = playbook.build_playbook(_system(), [finding])

    assert "EPSS 0.73, 91%ile" in output


def test_build_playbook_omits_epss_suffix_when_unscored() -> None:
    match = _cve_match()
    finding = Finding(kind="cve", title="x", detail="", package="curl", cve=match)

    output = playbook.build_playbook(_system(), [finding])

    assert "EPSS" not in output


def test_blank_line_between_tasks_inserts_blank_before_each_task_but_first() -> None:
    body = "tasks:\n  - name: first\n    foo: bar\n  - name: second\n    foo: baz\n"

    result = playbook._blank_line_between_tasks(body)

    lines = result.splitlines()
    assert lines[0] == "tasks:"
    assert lines[1] == "  - name: first"
    second_idx = lines.index("  - name: second")
    assert lines[second_idx - 1] == ""
