# mal-static-die: clean-network handoff

`mal-static-die` is the Detect It Easy engine: it fingerprints packers,
protectors, compilers, linkers and crypto on executables, and it is the
**packed/unanalyzed gate** - when a sample is packed or protected, the static
engines (yara, capa) cannot read the real payload, so DIE floors that artifact to
SUSPICIOUS and marks it incomplete (fail-closed: packed-and-unread is never
benign; it wants dynamic analysis).

## What is already done (on `main`, CI-green)

- The worker (`services/mal-static-die/wrapper.py`) and its build-time `--selftest`
  (the DIE-json -> findings mapping is verified without needing a sample).
- The orchestrator wiring: `DieActivity`, the dispatch gate (runs on every
  executable, same surface as capa), the confidence policy, and the config.
- A unit test pinning the config-gate no-op (`die_test.go`).
- The compose build service, in the **`build-die`** profile.

## Why the image is not built here

The worker image fetches Detect It Easy from its GitHub release at build time.
A corporate proxy that firewalls the build sandbox cannot do that, and this repo
was built on such a box, so the image build (and the live proof) is a clean-network
step. Everything except the actual DIE binary is verified in CI. The engine is
therefore shipped **wired but dormant**: `DieActivity` is a no-op that reports an
empty UNKNOWN until `MAL_DIE_IMAGE` is set, so it can never floor or pollute a
submission (including your ELF detonation tests) until you turn it on here.

## Turning it on (clean network, ~5 minutes)

1. **Pin the DIE release.** In `services/mal-static-die/Dockerfile`, set
   `DIE_DEB_URL` and `DIE_SHA256` to the Debian amd64 `.deb` you want from
   https://github.com/horsicq/DIE-engine/releases (download it, `sha256sum` it,
   paste the hash). The sha pin is mandatory: an air-gapped platform does not run
   an unverified download.

2. **Confirm two DIE facts against that release** (they are stable across recent
   DIE, but verify once):
   - the console prints JSON with `diec -j <file>` (the worker's `die_argv`), and
   - its JSON has `detects[].values[]` rows with a `type` field ("Packer",
     "Compiler", "Crypto", ...) and a human `string`. The worker's `map_die_doc`
     parses exactly that; if a DIE version differs, adjust `map_die_doc` (it is a
     pure function with a synthetic `--selftest`, so iterate offline).

3. **Build the image** (only this profile pulls DIE):
   ```bash
   docker compose -f deploy/compose.yaml --profile build-die build
   ```

4. **Enable the engine.** Uncomment `MAL_DIE_IMAGE: openmallab/mal-static-die:m0`
   in the orchestrator env in `deploy/compose.yaml` (or export
   `MAL_DIE_IMAGE=openmallab/mal-static-die:m0`), then bring the stack up.

5. **Prove it end to end:**
   ```bash
   deploy/proof/die-proof.sh
   ```
   It builds the base engines + the DIE image, submits a benign ELF, and asserts a
   `mal-static-die` finding came back and stayed contained (DIE alone never drives
   the verdict above SUSPICIOUS). To exercise the packed/unanalyzed gate, pack a
   benign binary (`upx -9 ./sample`) and resubmit: expect a `packed-unanalyzed`
   finding, SUSPICIOUS, and the artifact marked incomplete.

## Containment

DIE runs under the exact same single-use jail as every engine (network none, all
caps dropped, read-only rootfs, non-root 65534, seccomp, bounded wall-clock and
memory), and its output crosses the broker like any other engine's. It does no
emulation, so it takes the default light jail (no raised memory/scratch). Adding it
to `deploy/proof/boundary-proof.sh`'s jail assertions is a good follow-up once the
image exists.
