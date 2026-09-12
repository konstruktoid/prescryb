"""Tests for prescryb.ssh: config resolution, connect() logic, and package parsers.

paramiko.SSHClient is faked throughout so no test opens a real network socket.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import paramiko
import pytest

from prescryb import ssh
from prescryb.models import Package

if TYPE_CHECKING:
    from pathlib import Path

_DEFAULT_SSH_PORT = 22
_OVERRIDE_PORT = 2201


class _FakeParamikoClient:
    """Stand-in for paramiko.SSHClient recording what connect() passed it."""

    def __init__(self, *, connect_exception: Exception | None = None) -> None:
        self._connect_exception = connect_exception
        self.host_keys_path: str | None = None
        self.missing_host_key_policy: object = None
        self.connect_kwargs: dict[str, object] | None = None
        self.closed = False

    def load_host_keys(self, path: str) -> None:
        self.host_keys_path = path

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.missing_host_key_policy = policy

    def connect(self, **kwargs: object) -> None:
        self.connect_kwargs = kwargs
        if self._connect_exception is not None:
            raise self._connect_exception

    def close(self) -> None:
        self.closed = True


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeStream:
    def __init__(self, data: bytes, channel: _FakeChannel | None = None) -> None:
        self._data = data
        self.channel = channel

    def read(self) -> bytes:
        return self._data


class _FakeExecClient:
    """Stand-in for paramiko.SSHClient.exec_command's three-tuple return."""

    def __init__(
        self, exit_status: int, stdout: bytes = b"", stderr: bytes = b""
    ) -> None:
        self._exit_status = exit_status
        self._stdout = stdout
        self._stderr = stderr

    def exec_command(
        self, command: str, timeout: float | None = None
    ) -> tuple[None, _FakeStream, _FakeStream]:
        del command, timeout
        stdout = _FakeStream(self._stdout, channel=_FakeChannel(self._exit_status))
        stderr = _FakeStream(self._stderr)
        return None, stdout, stderr


class _FakeSession:
    """Stand-in for RemoteSession exposing a scripted `run()`."""

    def __init__(self, output: str, hostname: str = "host") -> None:
        self._output = output
        self.hostname = hostname

    def run(self, command: str, timeout: float = 30.0) -> str:
        del command, timeout
        return self._output


def test_run_returns_stdout_on_success() -> None:
    client = cast("paramiko.SSHClient", _FakeExecClient(0, stdout=b"hello\n"))
    session = ssh.RemoteSession(client=client, hostname="h")
    assert session.run("echo hello") == "hello\n"


def test_run_raises_remote_command_error_on_nonzero_exit() -> None:
    client = cast("paramiko.SSHClient", _FakeExecClient(1, stderr=b"boom"))
    session = ssh.RemoteSession(client=client, hostname="h")
    with pytest.raises(ssh.RemoteCommandError, match="boom"):
        session.run("false")


def test_resolve_ssh_config_parses_matching_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config"
    config_path.write_text(
        "Host myhost\n    HostName 10.0.0.5\n    User admin\n    Port 2222\n"
    )
    monkeypatch.setattr(ssh, "_SSH_CONFIG_PATH", config_path)

    cfg = ssh._resolve_ssh_config("myhost")

    assert cfg["hostname"] == "10.0.0.5"
    assert cfg["user"] == "admin"
    assert cfg["port"] == "2222"


def test_resolve_ssh_config_missing_file_returns_hostname_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "_SSH_CONFIG_PATH", tmp_path / "does-not-exist")
    assert ssh._resolve_ssh_config("myhost") == {"hostname": "myhost"}


def test_connect_resolves_defaults_without_ssh_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssh, "_resolve_ssh_config", lambda _host: {})
    monkeypatch.setenv("USER", "alice")
    fake = _FakeParamikoClient()
    monkeypatch.setattr(ssh.paramiko, "SSHClient", lambda: fake)

    session = ssh.connect("myhost")

    assert session.hostname == "myhost"
    assert fake.connect_kwargs is not None
    assert fake.connect_kwargs["hostname"] == "myhost"
    assert fake.connect_kwargs["username"] == "alice"
    assert fake.connect_kwargs["port"] == _DEFAULT_SSH_PORT
    assert isinstance(fake.missing_host_key_policy, paramiko.RejectPolicy)


def test_connect_explicit_args_override_ssh_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ssh,
        "_resolve_ssh_config",
        lambda _host: {"hostname": "cfg-host", "user": "cfguser", "port": 2200},
    )
    fake = _FakeParamikoClient()
    monkeypatch.setattr(ssh.paramiko, "SSHClient", lambda: fake)
    identity = tmp_path / "id_rsa"
    identity.write_text("fake key material")

    session = ssh.connect(
        "alias",
        user="override",
        port=_OVERRIDE_PORT,
        hostname="explicit-host",
        identity_file=str(identity),
    )

    assert session.hostname == "explicit-host"
    assert fake.connect_kwargs is not None
    assert fake.connect_kwargs["username"] == "override"
    assert fake.connect_kwargs["port"] == _OVERRIDE_PORT
    assert fake.connect_kwargs["key_filename"] == [str(identity)]


def test_connect_trust_unknown_host_uses_auto_add_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssh, "_resolve_ssh_config", lambda _host: {})
    fake = _FakeParamikoClient()
    monkeypatch.setattr(ssh.paramiko, "SSHClient", lambda: fake)

    ssh.connect("host", trust_unknown_host=True)

    assert isinstance(fake.missing_host_key_policy, paramiko.AutoAddPolicy)


def test_connect_raises_host_key_unknown_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssh, "_resolve_ssh_config", lambda _host: {})
    fake = _FakeParamikoClient(
        connect_exception=paramiko.SSHException(
            "Server 'host' not found in known_hosts"
        )
    )
    monkeypatch.setattr(ssh.paramiko, "SSHClient", lambda: fake)

    with pytest.raises(ssh.HostKeyUnknownError):
        ssh.connect("host")


def test_connect_reraises_unrelated_ssh_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssh, "_resolve_ssh_config", lambda _host: {})
    fake = _FakeParamikoClient(connect_exception=paramiko.SSHException("auth failed"))
    monkeypatch.setattr(ssh.paramiko, "SSHClient", lambda: fake)

    with pytest.raises(paramiko.SSHException, match="auth failed"):
        ssh.connect("host")


def test_detect_system_maps_id_like_to_family() -> None:
    output = (
        'ID=almalinux\nID_LIKE="rhel fedora"\nVERSION_ID="9.3"\n---KERNEL---\n5.14.0\n'
    )
    system = ssh.detect_system(cast("ssh.RemoteSession", _FakeSession(output)))
    assert system.os_family == "redhat"
    assert system.distro_id == "almalinux"
    assert system.distro_version == "9.3"
    assert system.package_manager == "rpm"
    assert system.kernel == "5.14.0"


def test_detect_system_falls_back_to_debian_id_like() -> None:
    output = "ID=raspbian\nID_LIKE=debian\nVERSION_ID=12\n---KERNEL---\n6.1.0\n"
    system = ssh.detect_system(cast("ssh.RemoteSession", _FakeSession(output)))
    assert system.os_family == "debian"
    assert system.package_manager == "dpkg"


def test_detect_system_unknown_family_when_unmapped() -> None:
    output = "ID=unknownos\n---KERNEL---\n1.0\n"
    system = ssh.detect_system(cast("ssh.RemoteSession", _FakeSession(output)))
    assert system.os_family == "unknown"
    assert system.package_manager == "unknown"


def test_parse_dpkg_with_all_fields() -> None:
    output = "curl\t7.88.1-10\tamd64\tcurl\nbash\t5.2.15-2\tamd64\tbash\n"
    assert ssh._parse_dpkg(output) == [
        Package(name="curl", version="7.88.1-10", arch="amd64", source="curl"),
        Package(name="bash", version="5.2.15-2", arch="amd64", source="bash"),
    ]


def test_parse_dpkg_missing_source_falls_back_to_name() -> None:
    output = "libfoo\t1.0\tamd64\t\n"
    packages = ssh._parse_dpkg(output)
    assert packages[0].source == "libfoo"


def test_parse_dpkg_skips_blank_lines() -> None:
    output = "curl\t7.88.1-10\tamd64\tcurl\n\n"
    assert len(ssh._parse_dpkg(output)) == 1


def test_parse_rpm() -> None:
    output = "bash\t5.2.15-1.fc39\tx86_64\t\n"
    assert ssh._parse_rpm(output) == [
        Package(name="bash", version="5.2.15-1.fc39", arch="x86_64", source="bash")
    ]


def test_parse_pacman() -> None:
    output = "linux 6.6.8.arch1-1\nvim 9.1.0004-1\n"
    assert ssh._parse_pacman(output) == [
        Package(name="linux", version="6.6.8.arch1-1", source="linux"),
        Package(name="vim", version="9.1.0004-1", source="vim"),
    ]


def test_parse_apk_with_release_suffix() -> None:
    output = "openssl-3.1.4-r1\n"
    assert ssh._parse_apk(output) == [
        Package(name="openssl", version="3.1.4-r1", source="openssl")
    ]


def test_parse_apk_falls_back_when_unmatched() -> None:
    output = "abc-def\n"
    assert ssh._parse_apk(output) == [
        Package(name="abc-def", version="", source="abc-def")
    ]
