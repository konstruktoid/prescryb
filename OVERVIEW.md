# prescryb: Repository Overview

## Introduction

`prescryb` is a server implementing the Model Context Protocol (MCP) that
functions as a remediation orchestrator for Linux hosts.

The repository is intended for security engineers, system administrators,
and platform teams who want vulnerability triage and hardening guidance
without adopting a full scanning or configuration-management platform. It
assumes familiarity with SSH-accessible Linux hosts, package management,
and basic Ansible concepts, but does not require deep expertise in any
single vulnerability database or compliance framework.

## Purpose

Vulnerability and hardening information is scattered across sources that
do not communicate with one another and that have no direct visibility
into a live host. Package vulnerability data, CVE detail, CIS and DISA
STIG compliance controls, NIST Common Configuration Enumeration (CCE)
identifiers, and MITRE ATT&CK technique and mitigation data each live in
separate systems. The only authoritative answer to "what is installed on
this host right now" exists on the host itself.

The guiding principle behind the repository is separation of concerns.
`prescryb` decides nothing about what remediation is appropriate; it only
retrieves and formats grounded data. The connected model decides which
findings matter, which vulnerabilities warrant closer inspection, and what
shape a remediation playbook should take. This separation keeps the
repository small, auditable, and free of the judgment calls that are
better made by the model or by a human reviewer.

## Major Components

The repository is organized around a small number of conceptual
components that together support one end-to-end workflow.

**Host inventory** establishes a read-only connection to a target host
over SSH, identifies its Linux distribution, and lists installed packages
with their versions. It never accepts a password as an argument, relying
instead on the same credential resolution an interactive `ssh` session
would use.

**Vulnerability matching** takes the packages returned by host inventory
and checks their versions against a vulnerability database, using
ecosystem-aware version comparison so that a match reflects the exact
installed version rather than a name-only correspondence.

**Advisory enrichment** retrieves the current public record for a single,
already-identified vulnerability, providing description, severity scoring,
weakness classification, and reference material beyond what the matching
step returns.

**Compliance mapping** translates a free-text topic, such as SSH
configuration or sudo policy, into the corresponding CIS and DISA STIG
topic areas and, where one is published, the hardening automation that
implements it.

**Configuration-identifier lookup** provides platform-specific NIST CCE
entries, a complementary and more granular identifier system than the
topic-level compliance mapping.

**Adversary-technique mapping** connects the same topic areas used for
compliance mapping to the MITRE ATT&CK techniques they mitigate, and to
the corresponding named mitigations where ATT&CK defines one. Unlike the
other components, this mapping is maintained statically within the
repository rather than queried live, because ATT&CK identifiers form a
stable public catalog rather than a licensed, changing benchmark.

**Playbook rendering** assembles the outputs of the preceding components
into a single Ansible playbook: vulnerability findings become
package-upgrade tasks, and compliance areas become role references. The
rendered playbook is text for human review, never something the repository
executes itself.

These components are independent and composable. A client typically calls
them in sequence, but each can also be invoked on its own, for example to
enrich a single CVE that was reported through another channel.

## Scope

`prescryb` is scoped to read-only observation of a target host and
generation of remediation artifacts for human review.

## Out of Scope

`prescryb` does not apply the playbooks it generates, and it does not
otherwise modify a target host under any circumstance. Every tool is
either strictly read-only against the host or pure text and data
generation; execution of any remediation is left entirely to the operator,
outside of the repository's own tool surface.

The repository does not accept passwords through tool arguments, since
tool-call arguments can be visible to logging and to the connected model.
Credential handling instead mirrors the resolution order of an interactive
SSH client.

`prescryb` does not fabricate compliance rule numbers, configuration
identifiers, or CVE matches when a lookup returns no result; it reports
the absence explicitly rather than approximating an answer. It is not a
general-purpose vulnerability scanner, asset-management system, or
security information and event management (SIEM) platform, and it
performs no continuous monitoring: every tool call is a single, explicit,
on-demand lookup driven by the conversation. Its compliance coverage is
limited to CIS and DISA STIG-flavored controls available through one
open-source hardening collection and to MITRE ATT&CK's public catalog; it
is not a substitute for a licensed compliance benchmark subscription or a
formal audit.

## Architecture Summary

`prescryb` sits between an MCP client and a set of external data sources.
The client, driven by its connected model, calls the repository's tools
in whatever sequence the conversation requires; a typical sequence begins
with host inventory, proceeds through vulnerability matching and optional
advisory enrichment, adds compliance and adversary-technique context for
any configuration concerns identified, and ends with playbook rendering.
