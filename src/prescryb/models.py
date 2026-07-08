"""Shared data models for prescryb."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SystemInfo:
    """Identity of the inspected host: package manager and CVE ecosystem selection."""

    hostname: str
    os_family: str  # "debian", "redhat", "alpine", "suse", "arch", "unknown"
    distro_id: str  # e.g. "ubuntu", "debian", "almalinux"
    distro_version: str  # e.g. "24.04", "12", "10"
    package_manager: str  # "dpkg", "rpm", "apk", "pacman"
    kernel: str = ""


@dataclass
class Package:
    """An installed package as reported by the host's package manager."""

    name: str
    version: str
    arch: str = ""
    source: str = ""  # source package name, if different from binary package name


@dataclass
class CVEMatch:
    """A known vulnerability matched against an installed package version."""

    cve_id: str
    package: str
    installed_version: str
    fixed_version: str | None
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    cvss_vector: str | None
    summary: str
    references: list[str] = field(default_factory=list)
    source: str = "osv"  # "osv" | "nvd"


@dataclass
class ComplianceRef:
    """A CIS/DISA STIG topic area, optionally mapped to a hardening-collection role."""

    framework: str  # "CIS" | "DISA STIG"
    topic: str  # human-readable topic area, e.g. "SSH Server Configuration"
    role: str | None = None  # matching role name in konstruktoid.hardening, if any
    role_path: str | None = None  # GitHub URL to the role, if found
    galaxy_tags: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class AttackRef:
    """A MITRE ATT&CK technique (and mitigation, if applicable) a finding relates to."""

    technique_id: str  # e.g. "T1110" or "T1021.004" for a sub-technique
    technique_name: str
    tactic: str  # e.g. "Credential Access"; comma-separated if it spans several
    technique_url: str
    mitigation_id: str | None = None  # e.g. "M1032"
    mitigation_name: str | None = None
    mitigation_url: str | None = None


@dataclass
class CCERef:
    """A NIST Common Configuration Enumeration entry for one target platform.

    Sourced from the community JSON conversion at
    https://github.com/konstruktoid/cce-web (NIST itself only publishes CCE
    as spreadsheets) - see cce.py.
    """

    cce_id: str  # e.g. "CCE-80876-6"
    title: str
    target: str  # cce-web export name, e.g. "rhel8", "SLES15-DISA-STIG"
    description: str = ""
    rationale: str = ""
    severity: str = ""
    group: str = ""  # e.g. Configuration Group / applicable SLE version
    cis: str | None = None
    disa_srg: str | None = None
    source_url: str = ""


@dataclass
class Finding:
    """A single remediation-worthy finding: a vulnerable package or config gap."""

    kind: str  # "cve" | "config"
    title: str
    detail: str
    package: str | None = None
    cve: CVEMatch | None = None
    compliance: list[ComplianceRef] = field(default_factory=list)
    attack: list[AttackRef] = field(default_factory=list)
