# Security Policy

OpenMalLab is a security tool that processes hostile input. We take its own security seriously.

## Supported versions

OpenMalLab is pre-release and moving fast. Security fixes land on `main`; there is no long-term support branch yet. Build from `main` for the latest fixes, and pin a commit for reproducibility.

## Reporting a vulnerability
**Do not open a public issue for a security vulnerability.** Report it privately via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Include a description, reproduction, and impact. We aim to acknowledge within a
few business days.

## Never attach live malware
Do **not** attach live malware samples, or unencrypted samples of any kind, to issues, PRs, or reports.
Reference samples by hash (SHA-256). If a proof-of-concept requires a sample, coordinate privately.

## Scope
The most safety-critical properties are: the credential-less / empty-netns worker isolation, the
bounded-schema result boundary and its sub-process broker, and the fail-closed verdict fabric
(see the security-critical cores and invariants in `docs/PHASE1-TECHNICAL-DESIGN.md`, and `docs/THREAT-MODEL.md`).
Findings against these are highest priority.

## Dependency and supply chain
Every push runs `govulncheck` over the whole Go module in CI (`deploy/security/vulncheck.sh`).
It fails the build on any vulnerability reachable from our code, except a small set of advisories
accepted in `deploy/security/govulncheck-allow.txt`. An advisory is accepted only when it is
unfixed upstream **and** outside our threat model, and every entry carries a dated reason. When an
upstream fix lands we bump the dependency and drop the entry; the gate warns if an accepted entry
is no longer reachable. The current set is the Moby SDK daemon advisories that only the trusted
orchestrator could ever reach (no jail has a docker socket or a network), with the per-advisory
reasoning written out in that file.
