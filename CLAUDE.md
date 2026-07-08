# prescryb

MCP server for CVE/config remediation orchestration: SSH inventory, OSV/NVD
lookups, CIS/DISA STIG-mapped Ansible playbook suggestions. Suggest-only —
`prescryb` never mutates the target host; every tool is read-only or pure
text/data generation. See `README.md` for the full tool list and design
rationale before making behavioral changes.

## Layout

- `src/prescryb/server.py` — MCP server entrypoint, tool registration.
- `src/prescryb/ssh.py` — SSH inventory (paramiko), no password args ever.
- `src/prescryb/cve.py` — OSV.dev matching.
- `src/prescryb/advisories.py` — NVD lookups.
- `src/prescryb/compliance.py` — CIS/DISA STIG topic mapping via GitHub API.
- `src/prescryb/attack.py` — MITRE ATT&CK technique/mitigation mapping,
  keyed to the same topic slugs as `compliance.py`.
- `src/prescryb/playbook.py` — Ansible playbook rendering.
- `src/prescryb/models.py` — shared data models.

## Required checks

Every change to `src/` must pass both of these before you consider the work
done — run them yourself, don't just describe them:

```console
uv run ruff check .
uv run ty check
```

Fix reported issues in the code rather than suppressing them (`# noqa`,
`# type: ignore` or ty equivalents) unless the suppression is narrowly
justified with a one-line comment explaining why the check is a false
positive. Do not weaken `pyproject.toml` lint/type config to make a failure
go away.

## Conventions

- Python >=3.12, managed with `uv` (`uv sync`, `uv run ...`).
- No secrets/passwords ever flow through MCP tool arguments (see README
  "SSH auth model") — keep new tools consistent with that.
- Keep `prescryb` suggest-only: new tools must not execute or apply anything
  on the target host.
