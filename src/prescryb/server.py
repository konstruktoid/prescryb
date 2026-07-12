"""prescryb MCP server.

Exposes composable remediation-orchestration primitives; the calling model
(Claude, or any MCP client) chains them and does the synthesis: decide which
packages look suspicious, which CVEs matter, and which compliance areas to
check. prescryb itself never mutates the target host or applies a playbook -
every tool here is read-only against the host, or pure text/data generation.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from mcp.server.fastmcp import FastMCP

from prescryb import advisories, attack, cce, compliance, epss, ssh
from prescryb import cve as cve_mod
from prescryb import playbook as playbook_mod
from prescryb.models import CVEMatch, Finding, Package, SystemInfo

mcp = FastMCP(
    "prescryb",
    instructions=(
        "Remediation orchestrator. Typical flow: 1) inventory_host to SSH in and "
        "list packages, 2) check_cves to match installed versions against known "
        "vulnerabilities (each match includes an EPSS exploitation-probability "
        "score alongside severity, so findings can be sorted/filtered by either), "
        "3) fetch_advisory for authoritative up-to-date detail on "
        "a specific CVE you want to discuss (or fetch_epss for EPSS scores on "
        "CVE IDs from elsewhere), 4) map_compliance to see which "
        "CIS/DISA STIG topic areas and hardening-collection roles relate to an "
        "area (e.g. 'ssh', 'sudo', 'kernel'), plus the MITRE ATT&CK techniques and "
        "mitigations it addresses, 5) lookup_cce for NIST Common Configuration "
        "Enumeration entries on a specific platform (e.g. 'rhel8'), 6) "
        "generate_playbook to produce a suggest-only Ansible playbook for human "
        "review. This tool never applies changes to the target host itself."
    ),
)


def _system_from_dict(d: dict[str, Any]) -> SystemInfo:
    return SystemInfo(
        hostname=d["hostname"],
        os_family=d["os_family"],
        distro_id=d["distro_id"],
        distro_version=d["distro_version"],
        package_manager=d["package_manager"],
        kernel=d.get("kernel", ""),
    )


def _cve_from_dict(d: dict[str, Any]) -> CVEMatch:
    return CVEMatch(
        cve_id=d["cve_id"],
        package=d["package"],
        installed_version=d["installed_version"],
        fixed_version=d.get("fixed_version"),
        severity=d.get("severity", "UNKNOWN"),
        cvss_vector=d.get("cvss_vector"),
        summary=d.get("summary", ""),
        references=d.get("references", []),
        source=d.get("source", "osv"),
        epss_score=d.get("epss_score"),
        epss_percentile=d.get("epss_percentile"),
    )


@mcp.tool()
def inventory_host(
    host: str,
    user: str = "",
    port: int = 22,
    hostname: str = "",
    identity_file: str = "",
    *,
    trust_unknown_host: bool = False,
) -> dict[str, Any]:
    """SSH into `host` and inventory installed packages.

    Auth uses ~/.ssh/config, an SSH agent, and default identity files - the
    same as running `ssh host` yourself. No password argument is accepted:
    credentials must never flow through MCP tool-call arguments. Unknown
    host keys are rejected unless trust_unknown_host=True; prefer connecting
    with `ssh host` once yourself to pin the key instead.

    `hostname`/`identity_file` override the resolved address and key path
    without editing ~/.ssh/config - handy for e.g. a local molecule/vagrant
    instance. Only a path is passed, never key contents.
    """
    session = ssh.connect(
        host,
        user=user or None,
        port=port,
        hostname=hostname or None,
        identity_file=identity_file or None,
        trust_unknown_host=trust_unknown_host,
    )
    try:
        system = ssh.detect_system(session)
        packages = ssh.inventory_packages(session, system)
    finally:
        session.close()

    return {
        "system": asdict(system),
        "packages": [asdict(p) for p in packages],
        "package_count": len(packages),
    }


@mcp.tool()
async def check_cves(
    system: dict[str, Any], packages: list[dict[str, Any]]
) -> dict[str, Any]:
    """Match installed package versions against known CVEs via OSV.dev.

    `system` and `packages` are the objects returned by inventory_host (or a
    filtered subset of `packages`). Matches are enriched with
    `epss_score`/`epss_percentile` (see fetch_epss); a FIRST.org outage
    degrades to unset EPSS fields plus a `warning`, not a failed match.
    """
    sys_obj = _system_from_dict(system)
    pkg_objs = [
        Package(name=p["name"], version=p["version"], arch=p.get("arch", ""))
        for p in packages
    ]
    matches, warning = await cve_mod.check_cves(sys_obj, pkg_objs)
    return {
        "matches": [asdict(m) for m in matches],
        "warning": warning,
        "match_count": len(matches),
    }


@mcp.tool()
async def fetch_advisory(cve_id: str) -> dict[str, Any]:
    """Fetch the current, authoritative NVD record for a specific CVE ID.

    Use this to get an up-to-date description, CVSS score/severity, CWE
    weakness classification, and reference links for a CVE surfaced by
    check_cves (or one you already know about), rather than relying on
    potentially stale training data.
    """
    return await advisories.fetch_advisory(cve_id)


@mcp.tool()
async def fetch_epss(cve_ids: list[str]) -> dict[str, Any]:
    """Fetch EPSS scores for CVE IDs not already scored by check_cves.

    Unscored CVE IDs (too new, reserved, rejected) are absent from
    `scores`, not an error.
    """
    scores = await epss.fetch_epss_scores(cve_ids)
    return {
        "scores": {
            cve_id: {"epss_score": score, "epss_percentile": percentile}
            for cve_id, (score, percentile) in scores.items()
        },
        "not_found": sorted({c.upper() for c in cve_ids if c} - scores.keys()),
    }


@mcp.tool()
async def map_compliance(area: str) -> dict[str, Any]:
    """Map a free-text topic to CIS Benchmark / DISA STIG topic areas and ATT&CK.

    `area` examples: 'ssh', 'sudo', 'kernel modules', 'password policy'. If a
    matching role is found in the konstruktoid.hardening GitHub repo, it is
    returned too. Also returns the MITRE ATT&CK techniques (and, where
    defined, the ATT&CK mitigation) that hardening this area addresses.

    Only topic-area mapping is returned for CIS/DISA STIG, never fabricated
    specific rule IDs (e.g. "CIS 5.2.1") - those require the licensed
    benchmark text. Consult the referenced role's own docs/tags for exactly
    what it covers. ATT&CK technique/mitigation IDs, by contrast, are
    MITRE's own public catalog (attack.mitre.org), so they're cited directly.
    """
    refs = await compliance.map_finding(area)
    attack_refs = attack.map_finding(area)
    return {
        "area": area,
        "matches": [asdict(r) for r in refs],
        "attack": [asdict(r) for r in attack_refs],
        "collection_available_on_github": await compliance.collection_available(),
    }


@mcp.tool()
async def list_cce_targets() -> list[str]:
    """List platform names lookup_cce can query (e.g. 'rhel8', 'firefox').

    Sourced live from https://github.com/konstruktoid/cce-web, the community
    JSON conversion of NIST's CCE spreadsheets. Coverage of this project's
    target distros is thin: only RHEL-family ('rhel6'/'rhel7'/'rhel8') and
    SUSE ('SLES12-DISA-STIG'/'SLES15-DISA-STIG'/'SLES15-PCI-DSS') are
    usable - Debian, Ubuntu, Alpine, and Arch have no CCE data upstream.
    """
    return await cce.list_targets()


@mcp.tool()
async def lookup_cce(
    target: str, keyword: str = "", cce_id: str = ""
) -> dict[str, Any]:
    """Look up NIST Common Configuration Enumeration entries for a platform.

    `target`: free text naming a platform, resolved against the export
    names published by https://github.com/konstruktoid/cce-web (NIST itself
    only publishes CCE as spreadsheets). For a host from inventory_host, use
    'rhel<major version>' for any RHEL-family distro_id (rhel, almalinux,
    rocky - CCE only tracks the upstream RHEL number) or
    'SLES<major version>-DISA-STIG' for suse; Debian, Ubuntu, Alpine, and
    Arch have no CCE coverage upstream at all. Call list_cce_targets to see
    every published platform (also covers e.g. 'firefox', 'apache-httpd2.2',
    'win2k8r2').

    Pass `keyword` (matched against title/description/rationale/config
    group) or `cce_id` (exact ID, e.g. 'CCE-80876-6') to filter results.
    Without either, only the platform's config-group categories and entry
    count are returned - dumping an entire platform (hundreds of entries)
    isn't useful; narrow with a keyword first.
    """
    target_name, candidates = await cce.resolve_target(target)
    if target_name is None:
        return {"target": target, "available": False, "candidates": candidates}

    entries = await cce.fetch_target(target_name)
    if entries is None:
        return {
            "target": target_name,
            "available": False,
            "note": cce.unsupported_reason(target_name),
        }

    if not keyword and not cce_id:
        return {
            "target": target_name,
            "available": True,
            "total_entries": len(entries),
            "configuration_groups": sorted({e.group for e in entries if e.group}),
            "note": "Pass keyword or cce_id to search within this platform.",
        }

    matches = cce.search(entries, keyword=keyword, cce_id=cce_id)
    return {
        "target": target_name,
        "available": True,
        "total_matches": len(matches),
        "truncated": len(matches) > cce.MAX_RESULTS,
        "matches": [asdict(m) for m in matches[: cce.MAX_RESULTS]],
    }


@mcp.tool()
async def generate_playbook(
    system: dict[str, Any],
    cve_matches: list[dict[str, Any]] | None = None,
    compliance_areas: list[str] | None = None,
    hosts_alias: str = "",
) -> str:
    """Generate a suggest-only Ansible playbook from findings. Does NOT run it.

    `system`: object from inventory_host. `cve_matches`: entries from
    check_cves you want remediated (each becomes a package-upgrade task
    citing the CVE). `compliance_areas`: topic hints (e.g. ["ssh", "sudo"])
    - each resolved via map_compliance and, where a matching
    konstruktoid.hardening role exists, referenced in the playbook's
    `roles:` list instead of reimplemented. The header also cites the MITRE
    ATT&CK techniques/mitigations each area addresses. Always review the
    output with `ansible-playbook --check --diff` before applying.
    """
    sys_obj = _system_from_dict(system)
    findings: list[Finding] = []

    for m in cve_matches or []:
        match = _cve_from_dict(m)
        findings.append(
            Finding(
                kind="cve",
                title=f"{match.cve_id} in {match.package}",
                detail=match.summary,
                package=match.package,
                cve=match,
            )
        )

    for area in compliance_areas or []:
        refs = await compliance.map_finding(area)
        attack_refs = attack.map_finding(area)
        if refs or attack_refs:
            findings.append(
                Finding(
                    kind="config",
                    title=f"{area} hardening",
                    detail=refs[0].topic if refs else area,
                    compliance=refs,
                    attack=attack_refs,
                )
            )

    return playbook_mod.build_playbook(
        sys_obj, findings, hosts_alias=hosts_alias or None
    )


def main() -> None:
    """Run the prescryb MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
