# YARA rules

Everything under this directory is compiled into the mal-static-yara worker at
build time, so the image digest pins the exact rule set. Rules are loaded
per-file: a file that fails to compile under YARA-X is skipped, not fatal, so
adding a pack cannot break the build.

## Layout

- `first-party/`: rules we wrote, licensed **Apache-2.0** like the core. Each
  rule is self-describing through its `meta`: the worker reads `verdict`
  (`BENIGN` | `UNKNOWN` | `SUSPICIOUS` | `MALICIOUS`) and `attck` (a MITRE
  ATT&CK technique id) instead of hardcoding them. A matched rule with no
  `verdict` meta defaults to SUSPICIOUS, never benign.
- `community/`: a slot for vetted third-party packs (for example YARA-Forge,
  or your own internal rules) dropped in for an offline build. It is empty in
  the core repo on purpose: we do not vendor third-party rule content into an
  Apache-2.0 codebase, because those packs carry their own licenses (GPL, the
  Detection Rule License, Elastic License, and others) and mixing them into the
  core would violate the bidirectional license gate.

## Adding rules for a deployment

Drop `.yar` files into `community/` (or mount them) before building the worker.
Give each rule a `verdict` and, where it applies, an `attck` meta. Track the
license of every pack you add; the CI license gate is meant to fail the build
if an incompatible license reaches the core. Test new rules against a goodware
set first: a false positive here floors a benign file to a bad verdict.

## Writing low-false-positive rules

The first-party rules deliberately match attacker *idioms* (a request
superglobal fed into `eval`, a PowerShell download-and-execute cradle, packer
section markers) rather than bare language features (`eval`, `UPX`), so they do
not fire on legitimate code. Hold new rules to the same bar.
