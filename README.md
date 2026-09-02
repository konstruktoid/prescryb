# prescryb - A remediation orchestrator

See [`OVERVIEW.md`](OVERVIEW.md) for a high-level description of the
repository's purpose, components, and scope before making behavioral
changes.

A remediation orchestrator, exposed as an MCP server. Connect an MCP client
(Claude Desktop, Claude Code, or similar) and submit a natural-language
request, for example:

> Log into host a.b.c, check installed packages, find CVEs, and suggest a
> fix - Ansible if possible, and tell me what compliance controls it maps to.

`prescryb` supplies the primitives (SSH inventory, CVE matching, live advisory
lookups, compliance-topic mapping, Ansible playbook rendering). The
connected model does the reasoning: which findings matter, which CVEs to
dig into, which playbook to generate. `prescryb` never applies anything to the
target host - every tool is read-only against it, or pure text/data
generation.

## How it works

| Tool | What it does |
| --- | --- |
| `inventory_host(host, user="", port=22, hostname="", identity_file="", trust_unknown_host=False)` | SSH in, detect the distro, list installed packages with versions. |
| `check_cves(system, packages)` | Batch-match package versions against [OSV.dev](https://osv.dev) using its ecosystem-aware version comparison (not name-only matching). Each match is enriched with an EPSS exploitation-probability score. |
| `fetch_advisory(cve_id)` | Fetch the current NVD record for one CVE - description, CVSS, CWE, references - live, not from training data. |
| `fetch_epss(cve_ids)` | Batch-fetch [EPSS](https://www.first.org/epss/api) exploitation-probability scores for CVE IDs not already covered by `check_cves` (e.g. from `fetch_advisory` or a web search). |
| `map_compliance(area)` | Map a free-text topic (`"ssh"`, `"sudo"`, `"kernel modules"`, ...) to CIS/DISA STIG topic areas and, if present in the `konstruktoid.hardening` GitHub repo, the matching role - plus the MITRE ATT&CK techniques and mitigations that area addresses. |
| `lookup_cce(target, keyword, cve_id)` | Look up [NIST CCE](https://ncp.nist.gov/cce) (Common Configuration Enumeration) entries for a platform (e.g. `"rhel8"`), sourced from the community JSON conversion at [`konstruktoid/cce-web`](https://github.com/konstruktoid/cce-web). |
| `list_cce_targets()` | List every platform `lookup_cce` can query. |
| `list_local_docs()` | List documents (Markdown/text/PDF) found under the local, gitignored `LOCAL_DOCS_DIR`. |
| `search_local_docs(query, top_k=5)` | RAG-style semantic search over those local documents, embedded entirely on-machine. |
| `generate_playbook(system, cve_matches, compliance_areas, hosts_alias)` | Render a **suggest-only** Ansible playbook: CVE fixes become package-upgrade tasks, compliance areas become `roles:` references. |

Typical flow: `inventory_host`, then `check_cves` on the returned packages,
then optionally `fetch_advisory` on interesting CVEs, then `map_compliance`
(and `lookup_cce`) for any insecure-config areas noticed, then optionally
`search_local_docs` for relevant internal runbook/policy context, then
`generate_playbook` to produce something to review.

## Install

```console
uv sync
```

### Register with an MCP client

Claude Code:

```console
claude mcp add prescryb -- uv --directory /path/to/prescryb run prescryb
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "prescryb": {
      "command": "uv",
      "args": ["--directory", "/path/to/prescryb", "run", "prescryb"]
    }
  }
}
```

## SSH auth model

`inventory_host` never accepts a password argument. MCP tool-call arguments
can be logged by clients and are visible to the connected model, so
credentials must never flow through them. Auth works exactly like running
`ssh host` yourself:

- Host/user/port/identity files are resolved from `~/.ssh/config`.
- Keys come from an SSH agent or the default identity files.
- `inventory_host`'s `hostname`/`identity_file` arguments override the
  resolved address/key path directly, for hosts you do not want to add to
  `~/.ssh/config` (only a path is passed, never key contents).
- Unknown host keys are **rejected** unless you pass `trust_unknown_host=True`
  - prefer running `ssh host` manually once to pin the key instead.

## Example: running claude against the repository Vagrant VM

```console
claude 'run vagrant up, connect to the created VM, check any vulnerabilities
and suggest a fix, include compliance mapping if possible,
write the playbook suggestion to /tmp/ and print the file location'
```

## Example: checking a regular host

For a host already reachable via `ssh` (resolved through `~/.ssh/config`,
an agent key, or the default identity file), specify the hostname
directly; no port or identity-file configuration is required:

> Inventory prod-web-01, check installed packages, find CVEs, and suggest a
> fix - Ansible if possible, and tell me what compliance controls it maps to.

If the host is not in `~/.ssh/config` yet, either add a `Host` block or pass
`user`/`port`/`hostname`/`identity_file` straight to `inventory_host` for a
one-off connection - same as the molecule example below.

## Example: inspecting a molecule test instance

```console
molecule converge -s default
```

Find the `ssh_port`/`ssh_user` from that scenario's `molecule.yml` platform
entry (e.g. `ssh_port: 22201`, `ssh_user: almalinux` for the `almalinux10`
platform) and the private key `molecule login` uses to connect - either add
a `Host` block to `~/.ssh/config`, or skip the file entirely and pass them
straight to `inventory_host` for a one-off, ephemeral connection:

> Inventory 127.0.0.1, port 22201, user almalinux, identity_file
> /path/to/molecule's/generated/key, check installed packages, find CVEs,
> and suggest a fix - Ansible if possible, and tell me what compliance
> controls it maps to.

Run `molecule destroy -s default` when finished; `prescryb` will not do it
for you, and will not touch the instance beyond reading it.

## Compliance mapping

`map_compliance` names topic areas (e.g. "SSH Server Configuration") and, if
found in the [`konstruktoid/ansible-collection-hardening`](https://github.com/konstruktoid/ansible-collection-hardening) GitHub repository, a link to the
Ansible role that implements it.

By default it queries the GitHub API against
[`konstruktoid/ansible-collection-hardening`](https://github.com/konstruktoid/ansible-collection-hardening).
Override with:

```console
export HARDENING_COLLECTION_REPO=owner/repo
```

Set `GITHUB_TOKEN` to raise the (otherwise low) unauthenticated GitHub API
rate limit. If a role is not found in the repo, `map_compliance` still
returns the topic/framework/role name so you know what to install
(`ansible-galaxy collection install konstruktoid.hardening`).

## CCE lookup

`lookup_cce` looks up [NIST Common Configuration Enumeration](https://ncp.nist.gov/cce)
entries - unique identifiers for individual configuration checks, distinct
from the topic-area CIS/DISA STIG mapping above. NIST only publishes CCE as
spreadsheets, so this reads the pre-converted JSON exports hosted by the
community project [`konstruktoid/cce-web`](https://github.com/konstruktoid/cce-web)
instead of parsing Excel.

Coverage is per-platform, not per-topic, and thin for this project's target
distros: only RHEL-family (`rhel6`/`rhel7`/`rhel8` - AlmaLinux/Rocky use the
matching upstream RHEL number) and SUSE
(`SLES12-DISA-STIG`/`SLES15-DISA-STIG`/`SLES15-PCI-DSS`) have usable data.
Debian, Ubuntu, Alpine, and Arch have no CCE data upstream at all. A few
older `cce-web` exports (e.g. `rhel4`, `rhel5`, `apache-httpd2.2`) lost
their column headers in the upstream Excel-to-JSON conversion; those are
reported as unsupported rather than returning garbled fields. Call
`list_cce_targets` to see every published platform, including non-Linux
ones (`firefox`, `win2k8r2`, ...).

Override the source repo with:

```console
export CCE_REPO=owner/repo
```

## MITRE ATT&CK mapping

Alongside CIS/DISA STIG, `map_compliance` and `generate_playbook` also cite
the [MITRE ATT&CK](https://attack.mitre.org) technique(s) mitigated by a
topic area's hardening (e.g. "ssh" maps to `T1110` Brute Force and
`T1021.004` Remote Services: SSH) and, where ATT&CK defines one, the
corresponding mitigation (e.g. `M1032` Multi-factor Authentication) with a
link to attack.mitre.org. Unlike CIS/DISA STIG rule numbers, ATT&CK
technique and mitigation IDs are MITRE's own public catalog, so they are
cited directly rather than needing a licensed benchmark lookup. This mapping
is static (built into `attack.py`), not fetched live.

## CVE data sources and their limits

- **OSV.dev** is the sole CVE-matching source. It resolves `{name, ecosystem,
  version}` server-side against the ecosystem's actual version ordering, so
  a match reflects the exact installed version rather than "any CVE that
  mentions this package name." Coverage is mature for **Debian, Ubuntu,
  Alpine**; thinner for RHEL-family (AlmaLinux, Rocky) and SUSE. `check_cves`
  returns a `warning` field flagging thinner-coverage ecosystems, and
  returns nothing (rather than a guess) for distros with no ecosystem
  mapping at all - an empty result there means "not checked," not "clean."
- **NVD** (`fetch_advisory`) is used only to enrich a CVE you already have
  the ID for. Set `NVD_API_KEY` to raise the (otherwise low) unauthenticated
  rate limit.
- **EPSS** (`epss_score`/`epss_percentile` on every `check_cves` match, or
  `fetch_epss` for CVE IDs from elsewhere) estimates the probability of
  exploitation in the next 30 days - independent of, and a useful
  complement to, CVSS/severity: a LOW-severity CVE can carry a high EPSS
  score, and vice versa. This lets findings be sorted/filtered by `cve_id`,
  `severity`, or `epss_score`. No API key needed. CVEs with no EPSS record
  (very new, reserved, or rejected IDs) simply have `epss_score` unset -
  not an error. A FIRST.org outage surfaces as a `warning` on `check_cves`
  rather than failing the CVE match itself.
- Severity: OSV gives a raw CVSS vector string (`cvss_vector`), not a
  precomputed label, for most OS-package entries. `severity` is only
  populated when the source explicitly labels it; otherwise it is
  `"UNKNOWN"` and the vector is left for you (or the model) to interpret,
  rather than guessing.

## Local documents

`search_local_docs` and `list_local_docs` are a RAG-style complement to the
network-backed tools above: semantic search over documents an operator
places in a local directory (default `local_docs/`, override with
`LOCAL_DOCS_DIR`) - internal runbooks, hardening policy, past remediation
notes - that no public source knows about. Supported formats: Markdown
(`.md`/`.markdown`), plain text (`.txt`), and PDF (`.pdf`); dotfiles,
dotdirs (e.g. `.git/`), and symlinks are skipped.

```console
mkdir local_docs
cp ~/ssh-hardening-runbook.pdf local_docs/
```

`local_docs/` is already listed in `.gitignore` - these are operator-supplied
and machine-local, never committed to this repository.

Documents are split into paragraph-preferring chunks and embedded locally
with [`sentence-transformers`](https://sbert.net) (default model
`sentence-transformers/all-MiniLM-L6-v2`, override with `LOCAL_DOCS_MODEL`).
**Embedding and ranking happen entirely on this machine** - the only network
access this feature needs is downloading the model weights from Hugging Face
the first time it runs; after that first run indexing and search are fully
offline (set `HF_HUB_OFFLINE=1` to force it, once the model is cached). That
is a claim about `prescryb`, not about the client: `search_local_docs`
returns the matched chunks as its tool result, so the query and those chunks
reach the connected MCP client and whatever model it is driving, exactly
like every other tool's output. Put nothing in `LOCAL_DOCS_DIR` you would
not send to that client. The chunk index is rebuilt in memory whenever a file under
`LOCAL_DOCS_DIR` is added, removed, or modified, and reused otherwise.

A file that can't be read (e.g. a corrupt PDF), yields no extractable text
(e.g. a scanned, image-only PDF that would need OCR first), or exceeds the
20 MB per-file limit, is skipped rather than failing the whole index;
`list_local_docs`'s `skipped` field names it and why. A skipped file still
appears in `documents` - it is listed, but none of its content is
searchable. Indexing is also capped at 500 files: `LOCAL_DOCS_DIR` should
point at a directory dedicated to this purpose, not something broad like a
home directory - both caps exist to bound indexing cost and to stop an
overbroad directory from pulling unrelated local files into search results.
Indexing stops at 5000 chunks overall, whichever files that spans, so a few
very large documents cannot exhaust memory on their own. Both tools'
`truncated` field is `true` if either cap left content out of the index.

### Requirements

- `uv sync` installs `sentence-transformers` and `pypdf`; this pulls in
  `torch`, so the sync is noticeably larger than the rest of this project's
  dependencies.
- Outbound HTTPS to `huggingface.co` the first time `search_local_docs` (or
  `list_local_docs`, which also builds the index) runs, to download the
  embedding model - about 90 MB for the default model, cached under
  `~/.cache/huggingface` (override with `HF_HOME`) so later runs, including
  after a restart, need no network. No connectivity is required beyond that:
  `prescryb` itself sends document content and queries nowhere, though search
  results do go back to the connected MCP client as tool output.
- At least one file under `LOCAL_DOCS_DIR` - the tools return an empty
  result, not an error, if the directory is missing or empty.

### Example: grounding a fix in an internal runbook

> Check host db-01 for CVEs, and see if our internal runbooks say anything
> relevant before you suggest a fix.

This drives `inventory_host` and `check_cves` as usual, then
`search_local_docs` against whatever's in `local_docs/` (e.g. an internal
Postgres patching runbook) so the connected model can fold that guidance
into its suggestion alongside the CVE data. The runbook is never uploaded
anywhere for indexing; the matched excerpts do reach that model, since
answering with them is the point.

## Playbook generation

Output is always a full playbook as text, prefixed with a comment header
citing every CVE/compliance source used. It is never executed by `prescryb`.
Review it - `ansible-playbook --syntax-check`, then `--check --diff` - before
running it anywhere.

Package-upgrade tasks use the module for the target's package manager
(`ansible.builtin.apt`/`dnf`/`zypper`/`community.general.apk`). Version pins
are only applied where the module supports them; Arch/pacman targets get
`state: latest` since pacman does not support the same pinning syntax.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `HARDENING_COLLECTION_REPO` | `konstruktoid/ansible-collection-hardening` | GitHub `owner/repo` queried for compliance-mapped Ansible roles. |
| `CCE_REPO` | `konstruktoid/cce-web` | GitHub `owner/repo` queried for CCE JSON exports by `lookup_cce`/`list_cce_targets`. |
| `GITHUB_TOKEN` | unset | Raises GitHub API rate limits for `map_compliance`, `lookup_cce`, and `list_cce_targets`. |
| `NVD_API_KEY` | unset | Raises NVD API rate limits for `fetch_advisory`. |
| `LOCAL_DOCS_DIR` | `local_docs` | Directory `search_local_docs`/`list_local_docs` read from. |
| `LOCAL_DOCS_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Hugging Face model ID used to embed local documents. |

## What this deliberately does not do

- Does not apply playbooks or otherwise mutate the target host.
- Does not accept passwords as tool arguments.
- Does not fabricate CIS/DISA STIG rule numbers.
- Does not guess CVEs for ecosystems OSV does not cover; it reports that
  instead.
