"""SSH connectivity and package inventory collection.

Deliberately does not accept passwords as tool arguments: MCP tool call
arguments can be logged by clients/servers and are visible to the LLM
orchestrating the call, so credentials must never flow through them.
Auth relies on the same mechanisms `ssh` itself uses: ~/.ssh/config,
an SSH agent, and default identity files. Unknown host keys are
rejected by default, mirroring StrictHostKeyChecking.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import paramiko

from prescryb.models import Package, SystemInfo

_SSH_CONFIG_PATH = Path("~/.ssh/config").expanduser()
_KNOWN_HOSTS_PATH = Path("~/.ssh/known_hosts").expanduser()


class HostKeyUnknownError(RuntimeError):
    """Raised when the target host key isn't in known_hosts and trust wasn't granted."""


class RemoteCommandError(RuntimeError):
    """Raised when a remote command exits non-zero."""


@dataclass
class RemoteSession:
    """An open SSH connection to a single target host."""

    client: paramiko.SSHClient
    hostname: str

    def run(self, command: str, timeout: float = 30.0) -> str:
        """Run `command` on the remote host and return its stdout."""
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if exit_code != 0:
            msg = f"`{command}` on {self.hostname} exited {exit_code}: {err.strip()}"
            raise RemoteCommandError(msg)
        return out

    def close(self) -> None:
        """Close the underlying SSH connection."""
        self.client.close()


def _resolve_ssh_config(host: str) -> dict:
    if not _SSH_CONFIG_PATH.exists():
        return {"hostname": host}
    config = paramiko.SSHConfig()
    with _SSH_CONFIG_PATH.open() as f:
        config.parse(f)
    return config.lookup(host)


def connect(
    host: str,
    user: str | None = None,
    port: int | None = None,
    hostname: str | None = None,
    identity_file: str | None = None,
    *,
    trust_unknown_host: bool = False,
    connect_timeout: float = 10.0,
) -> RemoteSession:
    """Open an SSH session via ~/.ssh/config + agent/default keys, like `ssh` itself.

    `hostname`/`identity_file` let a caller override the resolved address and
    key path directly (e.g. a molecule/vagrant instance not in ~/.ssh/config)
    without editing that file - only paths, never key material, ever flow
    through these.
    """
    cfg = _resolve_ssh_config(host)
    real_hostname = hostname or cfg.get("hostname", host)
    resolved_user = user or cfg.get("user") or os.environ.get("USER", "root")
    resolved_port = port or int(cfg.get("port", 22))
    identity_files = (
        [str(Path(identity_file).expanduser())]
        if identity_file
        else cfg.get("identityfile", [])
    )

    client = paramiko.SSHClient()
    if _KNOWN_HOSTS_PATH.exists():
        client.load_host_keys(str(_KNOWN_HOSTS_PATH))
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy() if trust_unknown_host else paramiko.RejectPolicy()
    )

    try:
        client.connect(
            hostname=real_hostname,
            port=resolved_port,
            username=resolved_user,
            key_filename=identity_files or None,
            timeout=connect_timeout,
            allow_agent=True,
            look_for_keys=True,
        )
    except paramiko.SSHException as exc:
        if "not found in known_hosts" in str(exc) or isinstance(
            exc, paramiko.BadHostKeyException
        ):
            msg = (
                f"Host key for {real_hostname} is not in known_hosts. Connect once "
                f"with trust_unknown_host=True, or `ssh {host}` manually, to pin it."
            )
            raise HostKeyUnknownError(msg) from exc
        raise

    return RemoteSession(client=client, hostname=real_hostname)


_OS_RELEASE_CMD = "cat /etc/os-release 2>/dev/null && echo '---KERNEL---' && uname -r"


def _parse_os_release(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip('"')
    return fields


_FAMILY_BY_ID_LIKE = {
    "debian": "debian",
    "rhel": "redhat",
    "fedora": "redhat",
    "suse": "suse",
    "opensuse": "suse",
    "arch": "arch",
    "alpine": "alpine",
}
_PACKAGE_MANAGER_BY_FAMILY = {
    "debian": "dpkg",
    "redhat": "rpm",
    "suse": "rpm",
    "arch": "pacman",
    "alpine": "apk",
}


def detect_system(session: RemoteSession) -> SystemInfo:
    """Inspect /etc/os-release and `uname -r` to identify OS family and package mgr."""
    output = session.run(_OS_RELEASE_CMD)
    os_release_text, _, kernel_section = output.partition("---KERNEL---")
    fields = _parse_os_release(os_release_text)

    distro_id = fields.get("ID", "unknown").lower()
    id_like = fields.get("ID_LIKE", "").lower().split()
    candidates = [distro_id, *id_like]

    family = "unknown"
    for candidate in candidates:
        if candidate in _FAMILY_BY_ID_LIKE:
            family = _FAMILY_BY_ID_LIKE[candidate]
            break
        if candidate == "debian":
            family = "debian"
            break

    package_manager = _PACKAGE_MANAGER_BY_FAMILY.get(family, "unknown")

    return SystemInfo(
        hostname=session.hostname,
        os_family=family,
        distro_id=distro_id,
        distro_version=fields.get("VERSION_ID", ""),
        package_manager=package_manager,
        kernel=kernel_section.strip(),
    )


_DPKG_FORMAT = "${Package}\\t${Version}\\t${Architecture}\\t${Source}\\n"
_RPM_FORMAT = "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t\\n"
_INVENTORY_COMMANDS = {
    "dpkg": f"dpkg-query -W -f='{_DPKG_FORMAT}'",
    "rpm": f"rpm -qa --qf '{_RPM_FORMAT}'",
    "pacman": "pacman -Q",
    "apk": "apk info -v",
}

_APK_VERSION_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[^-]*(?:-r\d+)?)$")

# Field counts in tab-separated `dpkg-query`/`rpm` output: name and version
# are always present; arch and source (dpkg only) are appended if available.
_FIELDS_WITH_ARCH = 3
_FIELDS_WITH_SOURCE = 4


def _parse_dpkg(output: str) -> list[Package]:
    packages = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name, version = parts[0], parts[1]
        arch = parts[2] if len(parts) >= _FIELDS_WITH_ARCH else ""
        has_source = len(parts) >= _FIELDS_WITH_SOURCE and parts[3]
        source = parts[3] if has_source else name
        packages.append(Package(name=name, version=version, arch=arch, source=source))
    return packages


def _parse_rpm(output: str) -> list[Package]:
    packages = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name, version = parts[0], parts[1]
        arch = parts[2] if len(parts) >= _FIELDS_WITH_ARCH else ""
        packages.append(Package(name=name, version=version, arch=arch, source=name))
    return packages


def _parse_pacman(output: str) -> list[Package]:
    packages = []
    for line in output.splitlines():
        if not line.strip():
            continue
        name, _, version = line.partition(" ")
        packages.append(Package(name=name, version=version.strip(), source=name))
    return packages


def _parse_apk(output: str) -> list[Package]:
    packages = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _APK_VERSION_RE.match(line)
        if match:
            name = match["name"]
            packages.append(Package(name=name, version=match["version"], source=name))
        else:
            packages.append(Package(name=line, version="", source=line))
    return packages


_PARSERS = {
    "dpkg": _parse_dpkg,
    "rpm": _parse_rpm,
    "pacman": _parse_pacman,
    "apk": _parse_apk,
}


def inventory_packages(session: RemoteSession, system: SystemInfo) -> list[Package]:
    """Run the OS-appropriate listing command and parse it into `Package` objects."""
    command = _INVENTORY_COMMANDS.get(system.package_manager)
    if command is None:
        msg = f"Unsupported package manager: {system.package_manager}"
        raise RemoteCommandError(msg)
    output = session.run(command)
    return _PARSERS[system.package_manager](output)
