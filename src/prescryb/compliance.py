"""Map findings to CIS/DISA STIG topic areas and, where available, roles.

Roles come from the `konstruktoid.hardening` Ansible collection on GitHub.
This deliberately does not cite specific CIS/STIG rule numbers (e.g. "CIS
5.2.1"): those come from licensed benchmark documents this tool doesn't have
access to, and fabricating them would be worse than not citing them at all.
Instead it names the topic area and, when the collection's GitHub repo has a
matching role, links it - the role's own tags/README are the source of truth
for exactly what it does.
"""

from __future__ import annotations

import os

import httpx

from prescryb.models import ComplianceRef

_DEFAULT_COLLECTION_REPO = "konstruktoid/ansible-collection-hardening"
_COLLECTION_REPO = os.environ.get("HARDENING_COLLECTION_REPO", _DEFAULT_COLLECTION_REPO)
_GITHUB_API = "https://api.github.com"


# topic slug -> (human label, [role names], extra keyword aliases matching this topic)
_TOPICS: dict[str, dict] = {
    "ssh": {
        "label": "SSH Server Configuration",
        "roles": ["ssh"],
        "aliases": ["sshd", "openssh"],
    },
    "sudo": {"label": "Privilege Escalation (sudo)", "roles": ["sudo"], "aliases": []},
    "pam_auth": {
        "label": "Authentication / PAM / Password Policy",
        "roles": ["password_management", "login_defs", "pam"],
        "aliases": ["pam", "password", "login.defs", "authentication"],
    },
    "audit": {
        "label": "Audit Logging",
        "roles": ["auditd", "journald"],
        "aliases": ["auditing", "logging"],
    },
    "firewall": {
        "label": "Host Firewall / Network Filtering",
        "roles": ["ufw"],
        "aliases": ["iptables", "nftables", "netfilter"],
    },
    "kernel": {
        "label": "Kernel Hardening / sysctl",
        "roles": ["sysctl", "kernel", "kernel_modules"],
        "aliases": ["sysctl", "modprobe"],
    },
    "mount": {
        "label": "Filesystem Mount Options",
        "roles": ["mount"],
        "aliases": ["filesystem", "fstab", "partition"],
    },
    "package_mgmt": {
        "label": "Package Management / Software Updates",
        "roles": ["package_management", "packages", "automatic_updates"],
        "aliases": ["apt", "dnf", "yum", "update", "patch", "upgrade"],
    },
    "time": {
        "label": "Time Synchronization",
        "roles": ["timesyncd"],
        "aliases": ["ntp", "chrony"],
    },
    "mac": {
        "label": "Mandatory Access Control",
        "roles": ["apparmor"],
        "aliases": ["selinux", "apparmor"],
    },
    "usb": {
        "label": "Removable Media / USB Control",
        "roles": ["usbguard"],
        "aliases": ["removable media"],
    },
    "root_access": {
        "label": "Root Account Access Control",
        "roles": ["root_access", "lock_root"],
        "aliases": ["root login", "root account"],
    },
    "users": {
        "label": "User Account Management",
        "roles": ["adduser", "delete_users"],
        "aliases": ["accounts", "unused accounts"],
    },
    "mail": {
        "label": "Mail Transfer Agent Hardening",
        "roles": ["postfix"],
        "aliases": ["smtp", "mta"],
    },
    "network_stack": {
        "label": "Network Stack / IPv6 / Wireless",
        "roles": ["disable_ipv6", "disable_wireless", "netplan"],
        "aliases": ["ipv6", "wireless", "wifi"],
    },
    "integrity": {
        "label": "File Integrity Monitoring",
        "roles": ["aide"],
        "aliases": ["fim", "file integrity"],
    },
}

_FRAMEWORKS = ("CIS", "DISA STIG")


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _role_url(role: str) -> str:
    return f"https://github.com/{_COLLECTION_REPO}/tree/main/roles/{role}"


async def _role_exists(client: httpx.AsyncClient, role: str) -> bool:
    resp = await client.get(
        f"{_GITHUB_API}/repos/{_COLLECTION_REPO}/contents/roles/{role}",
        headers=_github_headers(),
        timeout=15.0,
    )
    return resp.status_code == httpx.codes.OK


def match_topic(area: str) -> str | None:
    """Resolve a free-text topic hint to one of this module's topic slugs.

    Shared with `attack.py` so ATT&CK mapping stays keyed to the same topic
    areas as the CIS/DISA STIG mapping below.
    """
    area_lower = area.lower()
    for slug, info in _TOPICS.items():
        haystack = [slug, info["label"].lower(), *info["roles"], *info["aliases"]]
        if any(term in area_lower or area_lower in term for term in haystack):
            return slug
    return None


async def map_finding(area: str) -> list[ComplianceRef]:
    """area: a free-text topic hint, e.g. 'ssh', 'password policy', 'kernel_modules'."""
    slug = match_topic(area)
    if slug is None:
        return []

    info = _TOPICS[slug]
    role_paths: dict[str, str | None] = {}
    async with httpx.AsyncClient() as client:
        for role in info["roles"]:
            role_paths[role] = (
                _role_url(role) if await _role_exists(client, role) else None
            )

    refs = []
    for framework in _FRAMEWORKS:
        for role in info["roles"]:
            role_path = role_paths[role]
            refs.append(
                ComplianceRef(
                    framework=framework,
                    topic=info["label"],
                    role=role,
                    role_path=role_path,
                    galaxy_tags=["cis", "disa", role],
                    note=(
                        f"konstruktoid.hardening role '{role}' found at {role_path}"
                        if role_path
                        else f"konstruktoid.hardening role '{role}' not found in "
                        f"{_COLLECTION_REPO}; install via "
                        "`ansible-galaxy collection install konstruktoid.hardening`."
                    ),
                )
            )
    return refs


async def collection_available() -> bool:
    """Check whether the configured hardening-collection repo exists on GitHub."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{_GITHUB_API}/repos/{_COLLECTION_REPO}",
            headers=_github_headers(),
            timeout=15.0,
        )
        return resp.status_code == httpx.codes.OK
