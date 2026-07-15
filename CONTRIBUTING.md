# Contributing to OpenMalLab

Governance is still being worked out (foundation, trademark, DCO vs CLA, the open-core boundary). Until that lands, contributions go in under the Developer Certificate of Origin. Sign your commits with `git commit -s`.

## The one rule we will not bend

Build the hostile boundary first. Any code that touches sample-derived bytes runs in a single-use, credential-less worker in an empty network namespace. Results cross the bounded AnalyzeResult schema and get decoded by the orchestrator-side sub-process broker, never parsed in a trusted process. Every failure path fails closed (suspicious or unknown, never clean by omission). If a change weakens that, it does not go in, no matter what else it does.

## Building

Dependencies resolve through the project's configured registries (Go GOPROXY, Cargo, npm, PyPI). See deploy/ and the per-service READMEs. The static wedge builds and runs on macOS or Linux. The worker's kernel-isolation posture (empty netns, seccomp, cgroups) is validated on Linux, either native or a container-runtime Linux VM.

Never run live malware on a shared or work machine. Use an isolated, air-gapped host. Reference samples by hash, never commit them.

## Tests are the teeth

Every invariant and residual (see docs/PHASE1-TECHNICAL-DESIGN.md) needs a linked test, and CI fails the build if one does not have it. Any new hostile-input surface joins the continuous fuzzing set.
