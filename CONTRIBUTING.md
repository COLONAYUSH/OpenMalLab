# Contributing to OpenMalLab

Thanks for being here. OpenMalLab is built in the open, and good contributions are welcome, whether that is a new detection rule, an engine integration, a bug fix, a doc, or a hard question about the threat model.

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first. By contributing you agree to abide by it.

## The one rule we will not bend

Build the hostile boundary first, and never weaken it.

Any code that touches sample-derived bytes runs in a single-use, credential-less worker jail: no network, all capabilities dropped, read-only root, non-root user, and exactly one file mounted read-only. Its output crosses a bounded schema and is validated by the jailed broker before any trusted process decodes it. Every failure path fails closed (suspicious or unknown, never clean by omission).

If a change weakens that, it does not merge, no matter what else it does. The boundary proof (`deploy/proof/boundary-proof.sh`) runs in CI and has to stay green.

## Getting set up

You need Docker with the Compose plugin. For the native Go and Rust tests you need Go 1.26+ and a recent stable Rust; the Python engine (capa) builds inside its image.

```bash
git clone https://github.com/COLONAYUSH/OpenMalLab
cd OpenMalLab

# build the jailed engine images and bring up the control node
docker compose -f deploy/compose.yaml --profile build build
docker compose -f deploy/compose.yaml up -d
```

Behind a private package index, export `MAL_PIP_CONF=~/.pip/pip.conf` before building so the capa image can install; on a clean network it uses public PyPI.

## Running the checks

Everything here runs in CI, so run it locally before you open a PR.

```bash
# Go: build, vet, unit tests (the lattice, the broker contract, the jail conformance)
go build ./... && go vet ./... && go test ./...

# the broker fuzz target (the trust boundary)
go test -fuzz=FuzzValidate -fuzztime=60s ./services/mal-broker/

# Rust workspace (the hostile-input workers)
cargo test --workspace

# the two proofs (need the images built first)
deploy/proof/boundary-proof.sh   # 48 checks that the jail holds
deploy/proof/e2e.sh              # a real submission round-trips to a verdict
```

Format before committing: `gofmt -w .` and `cargo fmt`.

## Adding an engine

New analysis engines follow the same shape, so a new engine cannot invent a weaker boundary:

1. A worker that reads exactly one file and writes one bounded JSON report to stdout (see `services/mal-static-yara` for the pure-Rust pattern, `services/mal-capa` for a heavier runtime).
2. It runs through the shared `runWorkerThroughBroker` path in the orchestrator, so its raw output is validated by the broker before anything trusts it.
3. Findings map to the verdict lattice; confidence is assigned by control-plane policy, never by the worker.
4. Rules and models are vendored into the image and pinned by hash. Nothing is fetched at run time.
5. Extend the boundary proof if the engine needs any new jail capability, and add unit tests.

## Rules and detection content

First-party YARA rules live in `services/mal-static-yara/rules/first-party/` under Apache-2.0. They must be self-describing (a `verdict` and, where it applies, an `attck` in their meta) and must not fire on the goodware set. Third-party packs go in the `community/` slot with their license tracked; we do not vendor incompatible licenses into the Apache core.

## Samples: never commit them

Never run live malware on a shared or work machine. Use an isolated host. Reference samples by SHA-256, never commit them, and never attach them to an issue or PR. The test corpus is synthetic (EICAR and hand-built fixtures), never live.

## Pull requests

- Keep PRs focused. One concern per PR.
- Sign your commits under the Developer Certificate of Origin: `git commit -s`.
- Write commit messages that say what changed and why, in plain prose.
- Make sure `go test ./...`, `cargo test --workspace`, and both proofs pass.
- If you touched a hostile-input surface, say how you tested it.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
