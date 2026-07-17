<!-- Thanks for the contribution. Keep PRs focused: one concern per PR. -->

## What this changes

<!-- What does this PR do, and why? -->

## How it was tested

<!-- Commands you ran, and what you saw. If you touched a hostile-input surface, say how you exercised it. -->

## Checklist

- [ ] `go build ./... && go vet ./... && go test ./...` pass
- [ ] `cargo test --workspace` passes (if Rust changed)
- [ ] `deploy/proof/boundary-proof.sh` is green (if the jail or a worker changed)
- [ ] `deploy/proof/e2e.sh` is green (if the pipeline changed)
- [ ] Code is formatted (`gofmt -w .`, `cargo fmt`)
- [ ] Commits are signed off (`git commit -s`, per the DCO)

## Containment

- [ ] This change does not weaken the worker jail or the broker boundary
- [ ] Any new hostile-input surface is jailed and its output is broker-validated
- [ ] Failure paths fail closed (suspicious or unknown, never clean by omission)

## Samples

- [ ] No live malware or unencrypted samples are attached; anything referenced is by SHA-256
