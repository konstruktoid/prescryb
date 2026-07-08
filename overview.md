# prescryb — Repository Overview

## What is this repository?

`prescryb` is an [MCP](https://modelcontextprotocol.io) (Model Context
Protocol) server that acts as a **remediation orchestrator** for Linux
hosts. It is not a scanner, not an agent, and not a patch-management
system in its own right. Instead, it is a small set of read-only tools
that an MCP client — Claude Code, Claude Desktop, or any other MCP-aware
model runtime — can call conversationally to go from "what's running on
this box?" to "here is a reviewable Ansible playbook that would fix it,
and here is the compliance/ATT&CK context for why it matters."

A typical session looks like a sentence, not a script:

> Log into host a.b.c, check installed packages, find CVEs, and suggest a
> fix — Ansible if possible, and tell me what compliance controls it maps
> to.

`prescryb` supplies the primitives — SSH inventory, CVE matching against
live data, advisory enrichment, compliance-topic mapping, ATT&CK mapping,
and playbook rendering. The connected model supplies the reasoning: which
findings actually matter, which CVEs are worth digging into, which
playbook shape makes sense for the situation. The split is deliberate —
`prescryb` never decides *what to do*, it only fetches and formats grounded
facts the model can decide with.

## Why does it exist?

Vulnerability and hardening data is scattered across sources that don't
talk to each other and don't talk to a live host: OSV.dev knows package
vulnerabilities, NVD knows CVE detail, CIS/DISA STIG benchmarks know
compliance controls, NIST CCE knows configuration-check identifiers,
MITRE ATT&CK knows adversary techniques and mitigations, and the actual
answer to "what's installed on this host, right now" only lives on the
host itself over SSH.

Large language models are good at synthesizing this kind of information
into a coherent remediation story, but they are unreliable at the
*retrieval* step — they'll happily fabricate a CVE ID, a CIS rule number,
or a package version if left to their training data alone. `prescryb`
exists to close that gap: it does the retrieval against real, current
sources and hands the model verified facts to reason over, rather than
letting the model guess. Nothing it returns is synthesized from training
data — every fact is either read live off the target host or fetched from
a named upstream source at call time.

## What security philosophy does it follow?

`prescryb` is built around one hard rule, stated in its own `CLAUDE.md`
and enforced by design: **it is suggest-only.** Every tool is either
strictly read-only against the target host or pure text/data generation
that touches nothing. It never applies a patch, never runs a config
change, and never executes the playbooks it generates — a human (or the
operator driving the model) is expected to review and run them
separately, with the standard Ansible safety net (`--syntax-check`, then
`--check --diff`) in between.

That philosophy extends to how it handles credentials and claims:

- **No passwords ever flow through MCP tool arguments.** Because tool-call
  arguments can be logged by MCP clients and are visible to the connected
  model, `inventory_host` accepts no password parameter at all. Auth
  works exactly like running `ssh host` yourself — resolved through
  `~/.ssh/config`, an SSH agent, or default identity files. Only a path
  to a key file can be passed explicitly, never key contents.
- **Unknown host keys are rejected by default.** `trust_unknown_host` must
  be explicitly set to bypass host-key verification; the safer path is
  pinning the key with a manual `ssh` connection first.
- **No fabricated compliance data.** `map_compliance` and `lookup_cce`
  only return CIS/DISA STIG topic areas, role names, and CCE identifiers
  that are actually present in the upstream sources they query. If a role
  isn't found, the tool says so and tells you what to install, rather
  than inventing a plausible-looking rule number.
- **No guessed CVEs.** `check_cves` relies solely on OSV.dev's
  ecosystem-aware version resolution — matching is based on the *actual*
  installed version against the ecosystem's real version ordering, not
  name-only matching. For distros with no ecosystem mapping in OSV, it
  returns nothing rather than a guess, and documents that an empty result
  there means "not checked," not "clean." Thinner-coverage ecosystems
  (RHEL-family, SUSE) get an explicit warning field.
- **Sourced, not asserted.** Every generated playbook is prefixed with a
  comment header citing every CVE and compliance source used to produce
  it, so the provenance of each task is traceable.

## What are its major components?

- `src/prescryb/server.py` — the MCP server entrypoint; registers every
  tool (`inventory_host`, `check_cves`, `fetch_advisory`,
  `map_compliance`, `lookup_cce`, `list_cce_targets`,
  `generate_playbook`) and exposes the typical-flow guidance to clients.
- `src/prescryb/ssh.py` — SSH inventory via `paramiko`. Connects using the
  same resolution order as the `ssh` CLI, detects the distro, and lists
  installed packages with versions. Never accepts a password argument.
- `src/prescryb/cve.py` — batch-matches installed `{name, ecosystem,
  version}` tuples against OSV.dev, the sole CVE-matching data source.
- `src/prescryb/advisories.py` — fetches a single CVE's current NVD
  record (description, CVSS, CWE, references) live, for enrichment once
  a CVE ID is already known.
- `src/prescryb/compliance.py` — maps a free-text topic (e.g. "ssh",
  "sudo", "kernel modules") to CIS/DISA STIG topic areas and, where one
  exists, the matching Ansible role in the `konstruktoid.hardening`
  collection, queried live via the GitHub API.
- `src/prescryb/cce.py` — looks up NIST Common Configuration Enumeration
  entries per target platform (e.g. `rhel8`) from the community JSON
  conversion hosted at `konstruktoid/cce-web`, since NIST only publishes
  CCE as spreadsheets.
- `src/prescryb/attack.py` — a static, hand-built mapping from the same
  topic slugs used in `compliance.py` to MITRE ATT&CK techniques and,
  where ATT&CK defines one, the corresponding mitigation. This is the one
  component that isn't fetched live, because ATT&CK IDs are a stable
  public catalog rather than a licensed benchmark.
- `src/prescryb/playbook.py` — renders the suggest-only Ansible playbook:
  CVE fixes become package-upgrade tasks (using the correct module per
  package manager, with version pins where the module supports them),
  compliance areas become `roles:` references.
- `src/prescryb/models.py` — shared data models used across the above.

## What does it not try to do?

`prescryb` deliberately stays narrow. It does not apply playbooks or
otherwise mutate the target host under any circumstance — that step is
always left to the operator, outside of `prescryb`'s own tool surface. It
does not accept passwords as tool arguments, does not fabricate CIS/DISA
STIG rule numbers or CCE identifiers when a lookup comes up empty, and
does not guess at CVEs for package ecosystems that OSV.dev doesn't cover
— it reports the gap instead of papering over it. It is not a general
vulnerability scanner, asset-management system, or SIEM, and it does not
attempt continuous monitoring; every tool call is a single, explicit,
on-demand lookup driven by the conversation. Compliance mapping is
scoped to CIS/DISA STIG-flavored hardening via one open-source
collection and MITRE ATT&CK's public catalog — it is not a substitute
for a licensed benchmark subscription or a formal compliance audit tool.
