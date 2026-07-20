# Proving dynamic analysis on your laptop

Phase 2 slice 0 (the `mal-detonate` worker) is built, wired, and committed. Its
code, wiring, and pure logic are verified in CI, but the one thing a firewalled
corporate build sandbox cannot do is build the worker *image*: that step installs
`qemu-user-static` + a second-arch libc via apt, and some proxies block apt egress
from the BuildKit sandbox even though `docker run` reaches the mirror fine. The
Dockerfile is correct and builds normally on an unfiltered network. This guide runs
the live detonation proof on a clean network (your personal laptop).

## What you are proving

That a Linux ELF submitted with detonation requested is actually run - as *data*,
under a trusted `qemu-<arch>-static` emulator that never grants the sample execute
permission - and that the behavior the emulator observes (process/exec, file writes,
network-connect intent, persistence, evasive sleeps) comes back as brokered findings
that are contained: capped at SUSPICIOUS, never MALICIOUS on the detonation's word,
and fail-closed on timeout or error.

## Prerequisites

- A machine on an unfiltered network (apt + docker pulls reach the internet).
- Docker with compose v2, plus `curl` and `python3`.
- The repo: `git clone git@github.com:COLONAYUSH/OpenMalLab.git` (or `git pull` if
  you already have it), then `cd OpenMalLab`.

## Run it (one command)

    deploy/proof/detonate-proof.sh

It builds the worker, brings the stack up, stages a benign stock ELF, submits it
with `detonate=true`, and asserts the detonation ran and stayed contained. On
success it prints:

    DETONATION PROOF PASSED
      sub-... -> detonated under the jailed emulator, behavior reported + contained.

Set `KEEP_UP=1` to leave the stack running afterward.

## If your build sandbox is also firewalled

If the build fails on `apt-get ... Could not connect to deb.debian.org`, your
BuildKit sandbox is filtered too. Two workarounds (the Dockerfile is unchanged):

- Legacy builder (its RUN steps use the same network `docker run` does):

      DOCKER_BUILDKIT=0 docker build -f services/mal-detonate/Dockerfile \
        -t openmallab/mal-detonate:m0 .

- Or install into a `docker run` container and commit it:

      docker run --name db debian:12 sh -c 'dpkg --add-architecture amd64 && \
        apt-get update && apt-get install -y --no-install-recommends \
        python3 qemu-user-static libc6:amd64'
      docker cp services/mal-detonate/wrapper.py db:/wrapper.py
      docker commit --change 'USER 65534:65534' \
        --change 'ENTRYPOINT ["python3","/wrapper.py"]' db openmallab/mal-detonate:m0
      docker rm db

Then re-run `deploy/proof/detonate-proof.sh` (it will reuse the built image).

## What to report back

Paste the tail of the run (the `DETONATION PROOF PASSED` line, or the `FAIL:` line
and the JSON it printed). If it failed, the submission id + that JSON is enough to
diagnose it here.

## After it passes

- Try a richer sample: a dynamically-linked binary that opens a socket or writes a
  file shows `net-connect` / `persistence` findings (still contained, `--network
  none`, so a connect is captured as *intent*).
- The next slice is the detonation-jail boundary proof: extend
  `deploy/proof/boundary-proof.sh` with a detonation section (net none, CapEff=0,
  no writable+executable mount, sample stays read-only, a looping sample is killed
  and floors incomplete). See docs/DYNAMIC-ANALYSIS-V1.md for the full roadmap
  (sinkhole, dropped-file recursion, auto-gating, and the segregated node).
