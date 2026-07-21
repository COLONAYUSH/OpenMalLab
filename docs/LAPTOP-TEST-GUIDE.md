# OpenMalLab: clean-network laptop test guide

This is the single checklist for everything that has to be proven on a real,
clean-network machine (a personal laptop), because the build box this was written
on sits behind a corporate proxy that firewalls image builds and model pulls.
Everything here is code-complete and CI-green on `main`; what is left is running it
live on a network that can actually pull packages and model weights.

**How to use this.** Work top to bottom. Each test says what it proves, the exact
command, the exact success line to look for, and what to copy back. When you paste
the results back, I can confirm the end-to-end behavior from here.

**This is a living document.** As more things get built that can only be proven on
a clean network, they get appended here (see "Future additions" at the bottom), so
this stays the one place you check before a laptop testing session.

---

## 0. Prerequisites (once)

- **Docker with the Compose v2 plugin.** Docker Desktop (Mac/Windows), or Docker
  Engine + `docker compose` on Linux. Colima works too. Check:
  ```
  docker version && docker compose version
  ```
- **git, curl, python3** (python3 is only used by the proof scripts).
- **~10 GB free disk** (~6 GB images, ~2 GB for the local model) and **8 GB+ RAM**
  free is comfortable. First build takes a few minutes; later runs are cached.
- **Ports 8080 (API) and 8090 (console)** must be free.
- **Clean home network:** leave all the corporate knobs UNSET. `MAL_PIP_CONF`,
  `MAL_MODEL_URL`, `MAL_ALLOW_CLOUD` are for proxied/corporate machines only; unset
  is the sovereign clean-network path.

**Get the code:**
```
git clone https://github.com/COLONAYUSH/OpenMalLab.git
cd OpenMalLab
cp .env.example .env        # optional; the defaults already point at the local model
```

**One-shot for the impatient** (runs tests 1, then 3, then 2):
```
deploy/proof/e2e.sh                                             # test 1
make live && make e2e-live                                      # test 3 (local LLM)
docker compose -f deploy/compose.yaml --profile build build \
  && deploy/proof/boundary-proof.sh                             # test 2
```
Then tests 4 (detonation) and 5 (DIE) need their one-time image steps below.

---

## Test 1 - Base pipeline (deterministic core)

**Proves:** submit -> identify -> scan -> recursively unpack -> capability + string
analysis -> fail-closed verdict, across 5 samples (EICAR, benign text, EICAR buried
two zips deep, an ELF, a PE). This is the whole static engine lineup end to end.

**Run** (one command; it builds and brings up the base stack itself):
```
deploy/proof/e2e.sh
```

**Expect** (the last block; look for the header):
```
E2E PROOF PASSED
  eicar:      sub-... -> MALICIOUS (yara: eicar_test_file, T1204; magika: ...)
  benign:     sub-... -> UNKNOWN (magika: ...)
  nested zip: sub-... -> MALICIOUS (recursive extract found the buried eicar)
  executable: sub-... -> capa surfaced ATT&CK-mapped capabilities
  pe:         sub-... -> FLOSS strings + capa capabilities, complete (magika: pebin)
```

**Send me:** the `E2E PROOF PASSED` block, or the `FAIL: ...` line if it stops.

---

## Test 2 - Containment / boundary proof (the security guarantee)

**Proves:** every engine really runs under the locked jail (no network, all caps
dropped, read-only rootfs, non-root, seccomp, noexec scratch, memory/pid caps) and
the broker rejects malformed worker output. This is the claim the whole platform
stakes its safety on.

**Run** (build the images first, then prove - same two commands CI runs):
```
docker compose -f deploy/compose.yaml --profile build build
deploy/proof/boundary-proof.sh
```

**Expect:**
```
BOUNDARY PROOF: all <N> checks passed.
worker image: openmallab/mal-static-yara:m0
broker image: openmallab/mal-broker:m0
```
(You will see `PASS 1: ...`, `PASS 2: ...` scroll by first; `<N>` is around 48.)

**Send me:** the `BOUNDARY PROOF: all N checks passed.` line, or the first `FAIL:`.

---

## Test 3 - Sovereign LOCAL LLM + full AI plane (the headline)

> **Status: already proven on the build box (2026-07-21)** - this exact loop passed there
> against a local `llama3.2:1b` imported from a HuggingFace GGUF (`E2E-LIVE PROOF PASSED`).
> Run it on your machine for the real model, but know the path is verified, not theoretical.
>
> **If you are behind a proxy that blocks the ollama model registry** (the `bootstrap-model`
> pull times out or EOFs on the 2 GB blob, as it did on the build box), skip it and use the
> HuggingFace-import workaround - HF's CDN is usually reachable where the ollama registry is not:
> ```
> # 1) on the host, download a GGUF (3B matches the default MAL_MODEL_NAME)
> curl -L -o model.gguf \
>   https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf
> # 2) import it OFFLINE into the model volume (it mounts at /root/.ollama)
> docker run --rm -v openmallab-models:/root/.ollama -v "$PWD":/gguf:ro --entrypoint sh \
>   ollama/ollama:latest -c 'ollama serve & sleep 3; printf "FROM /gguf/model.gguf\n" >/tmp/M; ollama create llama3.2:3b -f /tmp/M'
> # 3) bring up + prove (no bootstrap-model needed)
> make up && make e2e-live
> ```
> On a clean home network none of this is needed - plain `make live` pulls the model normally.

**Proves:** the whole platform live with a local, air-gapped model - submit ->
deterministic verdict -> async AI enrichment by the caged agent roster -> the
human-in-the-loop review relay -> and that the AI is contained (it can never push a
verdict above SUSPICIOUS on its own). This is the sovereign-local path that could
not be pulled behind the proxy here.

**Run:**
```
make live        # build -> pull the local model -> bring the full stack up
make e2e-live    # prove the full submit -> verdict -> enrich -> HITL loop
```
`make live` runs three ordered steps you can also run one at a time:
```
make build            # build all images
make bootstrap-model  # pull the local model (llama3.2:3b) into its volume - NEEDS INTERNET, one time
make up               # bring the stack up
```

**Expect** (from `make e2e-live`):
```
E2E-LIVE PROOF PASSED
  sub-... -> deterministic=<VERDICT>, AI enrichment completed + contained, HITL relay verified.
```
You can also open the console at **http://localhost:8090** and the API at
**http://localhost:8080** to click around.

**Read this before you run it:**
- **The model pull is the one step that needs the internet**, and only once. The
  bootstrap pulls `llama3.2:3b` (~2 GB) into a named volume on an egress-capable
  network; after that the runtime model server runs on a sealed, no-egress network
  and never reaches out. If you skip the pull, `mal-agents` never goes healthy and
  `make e2e-live` fails with "is the model bootstrapped?".
- **Enrichment can take minutes** on a CPU model (the proof waits up to 6 minutes,
  `ENRICH_TIMEOUT=360`). That is normal, not a hang.
- To try a bigger/smarter model: `MAL_MODEL_NAME=qwen2.5:7b make live` (slower on
  CPU). Default `llama3.2:3b` is the fast one.

**Send me:** the `E2E-LIVE PROOF PASSED` line. If it fails, also send the tail of
`make logs` (or `docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml logs --tail=80 mal-agents ollama orchestrator`).

**(Optional) guarded-cloud path** instead of a local model - I already proved this
one here, so it is optional for you. It points the roster at a cloud model with an
explicit egress opt-in:
```
make build
MAL_MODEL_URL=<endpoint> MAL_MODEL_NAME=<model> MAL_MODEL_KEY=<key> MAL_ALLOW_CLOUD=1 \
  docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml -f deploy/compose.cloud.yaml up -d
MAL_MODEL_URL=<endpoint> MAL_MODEL_KEY=<key> MAL_ALLOW_CLOUD=1 EXTRA_COMPOSE=compose.cloud.yaml make e2e-live
```

---

## Test 4 - Detonation / dynamic analysis (Phase 2 slice 0)

**Proves:** a benign ELF is detonated *as data* under a jailed `qemu-user` emulator,
its syscall trace mined into behavioral findings, and the result stays contained
(capped at SUSPICIOUS, verdict never inflated by detonation alone).

**Run** (one command; builds all engines + brings up the stack itself):
```
deploy/proof/detonate-proof.sh
```
- First build is heavy (several GB). The worker image installs `qemu-user-static`
  via apt, which is exactly what the proxy blocked here - on your laptop it just
  works.
- Detonation can take a while under emulation; the proof waits up to 5 minutes
  (`DETONATE_TIMEOUT=300`).

**Expect:**
```
DETONATION PROOF PASSED
  sub-... -> detonated under the jailed emulator, behavior reported + contained (capped at SUSPICIOUS).
```

**If the image build still fails** on your network (unlikely on a clean one), the
legacy-builder workaround from `docs/DETONATE-HANDOFF.md`:
```
DOCKER_BUILDKIT=0 docker build -f services/mal-detonate/Dockerfile -t openmallab/mal-detonate:m0 .
```

**Send me:** the `DETONATION PROOF PASSED` line, or the `FAIL:` line.

---

## Test 5 - DIE engine (Phase 1's last engine)

**Proves:** Detect It Easy fingerprints packers/compilers/crypto, and the
packed/unanalyzed gate works (a packed sample floors to SUSPICIOUS + incomplete).
This one has a one-time pin step because the DIE image fetches Detect It Easy from a
GitHub release.

**One-time setup** (from `docs/DIE-HANDOFF.md`, ~5 minutes):
1. Pick the Debian amd64 `.deb` from https://github.com/horsicq/DIE-engine/releases,
   download it, and get its hash:
   ```
   curl -fsSL -o die.deb <the .deb url>
   sha256sum die.deb
   ```
2. In `services/mal-static-die/Dockerfile`, set `DIE_DEB_URL` to that url and
   `DIE_SHA256` to that hash.
3. Build the DIE image (its own profile) and run the proof:
   ```
   docker compose -f deploy/compose.yaml --profile build-die build
   deploy/proof/die-proof.sh
   ```
   (`die-proof.sh` sets `MAL_DIE_IMAGE` for you.)

**Expect:**
```
DIE PROOF PASSED
  sub-... -> Detect It Easy ran under the jail, reported provenance, and stayed contained.
```

**Bonus - prove the packed gate:** `upx -9` a benign binary and submit it; expect
SUSPICIOUS + a `packed-unanalyzed` finding + the artifact marked incomplete.

**Send me:** the `DIE PROOF PASSED` line, plus (if you did the bonus) the packed
sample's verdict.

---

## Teardown

```
make down                                                                # stop, keep data + model
docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml down -v   # also drop volumes
docker volume rm openmallab-models                                       # remove the ~2 GB local model
```

---

## What to send me (report template)

Copy this back filled in - a PASS line per test is enough; paste the `FAIL:` line
and a log tail for anything that breaks.

```
Test 1 base e2e:        PASS / FAIL   ->  <the E2E PROOF PASSED block, or FAIL line>
Test 2 boundary:        PASS / FAIL   ->  <the "all N checks passed" line, or FAIL>
Test 3 local LLM live:  PASS / FAIL   ->  <the E2E-LIVE PROOF PASSED line, or FAIL + logs>
Test 4 detonation:      PASS / FAIL   ->  <the DETONATION PROOF PASSED line, or FAIL>
Test 5 DIE:             PASS / FAIL   ->  <the DIE PROOF PASSED line, or FAIL>
machine: <os + chip>, docker: <version>
```

Handy while testing: `make ps` (status), `make logs` (follow logs).

---

## Future additions (appended as more clean-network-only work lands)

These are not ready yet; they will get full steps here when they are:

- **Detonation + DIE jail sections in the boundary proof** - extend
  `deploy/proof/boundary-proof.sh` to assert the qemu and DIE jails once those
  images exist on a clean box.
- **MACO config extraction** - the final Phase 1 residual engine (not built yet).
- **Phase 2 slices 1-5** - detonation fidelity, a contained network sinkhole,
  dropped-artifact recursion, auto-gating with a budget, native-exec fidelity.
- **Phase 3 production detonation range** - full-system guests, needs dedicated
  hardware.

Deeper references: [`LIVE-GUIDE.md`](LIVE-GUIDE.md) (full sovereign walkthrough),
[`../deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) (quick reference),
[`DETONATE-HANDOFF.md`](DETONATE-HANDOFF.md), [`DIE-HANDOFF.md`](DIE-HANDOFF.md).
