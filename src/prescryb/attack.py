"""Map findings to relevant MITRE ATT&CK techniques and mitigations.

Unlike CIS/DISA STIG rule numbers (see `compliance.py`), ATT&CK technique,
tactic, and mitigation IDs are MITRE's own freely published catalog at
https://attack.mitre.org - there's no licensed-benchmark concern with citing
them directly. This module reuses the same topic slugs as `compliance.py`
(via `compliance.match_topic`) so a single free-text hint (e.g. "ssh",
"sudo") yields a consistent view across both frameworks plus ATT&CK.
"""

from __future__ import annotations

from prescryb import compliance
from prescryb.models import AttackRef

_BASE_URL = "https://attack.mitre.org"

# topic slug (same slugs as compliance._TOPICS) -> ATT&CK techniques that
# hardening this topic area mitigates.
_ATTACK: dict[str, list[dict]] = {
    "ssh": [
        {
            "technique_id": "T1021.004",
            "technique_name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "mitigation_id": "M1042",
            "mitigation_name": "Disable or Remove Feature or Program",
        },
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "mitigation_id": "M1032",
            "mitigation_name": "Multi-factor Authentication",
        },
    ],
    "sudo": [
        {
            "technique_id": "T1548.003",
            "technique_name": (
                "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
            ),
            "tactic": "Privilege Escalation, Defense Evasion",
            "mitigation_id": "M1026",
            "mitigation_name": "Privileged Account Management",
        },
    ],
    "pam_auth": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "mitigation_id": "M1027",
            "mitigation_name": "Password Policies",
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": (
                "Defense Evasion, Persistence, Privilege Escalation, Initial Access"
            ),
            "mitigation_id": "M1032",
            "mitigation_name": "Multi-factor Authentication",
        },
    ],
    "audit": [
        {
            "technique_id": "T1070",
            "technique_name": "Indicator Removal",
            "tactic": "Defense Evasion",
            "mitigation_id": "M1022",
            "mitigation_name": "Restrict File and Directory Permissions",
        },
    ],
    "firewall": [
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "mitigation_id": "M1030",
            "mitigation_name": "Network Segmentation",
        },
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "mitigation_id": "M1037",
            "mitigation_name": "Filter Network Traffic",
        },
    ],
    "kernel": [
        {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "mitigation_id": "M1050",
            "mitigation_name": "Exploit Protection",
        },
        {
            "technique_id": "T1547.006",
            "technique_name": (
                "Boot or Logon Autostart Execution: Kernel Modules and Extensions"
            ),
            "tactic": "Persistence, Privilege Escalation",
            "mitigation_id": "M1047",
            "mitigation_name": "Audit",
        },
    ],
    "mount": [
        {
            "technique_id": "T1611",
            "technique_name": "Escape to Host",
            "tactic": "Privilege Escalation",
            "mitigation_id": "M1048",
            "mitigation_name": "Application Isolation and Sandboxing",
        },
    ],
    "package_mgmt": [
        {
            "technique_id": "T1195",
            "technique_name": "Supply Chain Compromise",
            "tactic": "Initial Access",
            "mitigation_id": "M1051",
            "mitigation_name": "Update Software",
        },
        {
            "technique_id": "T1210",
            "technique_name": "Exploitation of Remote Services",
            "tactic": "Lateral Movement",
            "mitigation_id": "M1051",
            "mitigation_name": "Update Software",
        },
    ],
    "time": [
        {
            "technique_id": "T1070.006",
            "technique_name": "Indicator Removal: Timestomp",
            "tactic": "Defense Evasion",
            "mitigation_id": "M1047",
            "mitigation_name": "Audit",
        },
    ],
    "mac": [
        {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "mitigation_id": "M1038",
            "mitigation_name": "Execution Prevention",
        },
    ],
    "usb": [
        {
            "technique_id": "T1091",
            "technique_name": "Replication Through Removable Media",
            "tactic": "Lateral Movement, Initial Access",
            "mitigation_id": "M1034",
            "mitigation_name": "Limit Hardware Installation",
        },
    ],
    "root_access": [
        {
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": (
                "Defense Evasion, Persistence, Privilege Escalation, Initial Access"
            ),
            "mitigation_id": "M1026",
            "mitigation_name": "Privileged Account Management",
        },
    ],
    "users": [
        {
            "technique_id": "T1136",
            "technique_name": "Create Account",
            "tactic": "Persistence",
            "mitigation_id": "M1018",
            "mitigation_name": "User Account Management",
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": (
                "Defense Evasion, Persistence, Privilege Escalation, Initial Access"
            ),
            "mitigation_id": "M1028",
            "mitigation_name": "Operating System Configuration",
        },
    ],
    "mail": [
        {
            "technique_id": "T1071.003",
            "technique_name": "Application Layer Protocol: Mail Protocols",
            "tactic": "Command and Control",
            "mitigation_id": "M1037",
            "mitigation_name": "Filter Network Traffic",
        },
    ],
    "network_stack": [
        {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Credential Access, Discovery",
            "mitigation_id": "M1037",
            "mitigation_name": "Filter Network Traffic",
        },
    ],
    "integrity": [
        {
            "technique_id": "T1565",
            "technique_name": "Data Manipulation",
            "tactic": "Impact",
            "mitigation_id": "M1022",
            "mitigation_name": "Restrict File and Directory Permissions",
        },
        {
            "technique_id": "T1070",
            "technique_name": "Indicator Removal",
            "tactic": "Defense Evasion",
            "mitigation_id": "M1053",
            "mitigation_name": "Data Backup",
        },
    ],
}


def _technique_url(technique_id: str) -> str:
    return f"{_BASE_URL}/techniques/{technique_id.replace('.', '/')}/"


def _mitigation_url(mitigation_id: str) -> str:
    return f"{_BASE_URL}/mitigations/{mitigation_id}/"


def map_finding(area: str) -> list[AttackRef]:
    """area: same free-text topic hint accepted by compliance.map_finding."""
    slug = compliance.match_topic(area)
    if slug is None or slug not in _ATTACK:
        return []

    refs = []
    for entry in _ATTACK[slug]:
        mitigation_id = entry.get("mitigation_id")
        refs.append(
            AttackRef(
                technique_id=entry["technique_id"],
                technique_name=entry["technique_name"],
                tactic=entry["tactic"],
                technique_url=_technique_url(entry["technique_id"]),
                mitigation_id=mitigation_id,
                mitigation_name=entry.get("mitigation_name"),
                mitigation_url=(
                    _mitigation_url(mitigation_id) if mitigation_id else None
                ),
            )
        )
    return refs
