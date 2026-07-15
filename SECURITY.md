# Security Policy

OpenMalLab is a security tool that processes hostile input. We take its own security seriously.

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
