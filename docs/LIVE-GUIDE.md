# OpenMalLab - Run It Live: a basic-to-end guide

This walks you from an empty machine to a **fully live OpenMalLab**: submit a file,
get a verdict in the browser, and watch the AI analyst enrich it and ask you to
review its findings. No prior knowledge of the project is assumed.

At the end you will have, on one machine:
- the deterministic engine pipeline (YARA, capa, FLOSS, content-ID, unpacking),
- the multi-agent **AI analyst plane** connected to a model,
- a web console at <http://localhost:8090> and an API at <http://localhost:8080>.

The AI **enriches**; it never overrules the deterministic verdict, and it can only
raise a finding to "suspicious" or ask a human - never mark anything safe.

---

## 0. Two ways to connect a model (pick one)

The AI plane needs a language model. You have two options; you can switch later.

| | **A. Sovereign local** (recommended) | **B. Guarded cloud** |
|---|---|---|
| Model runs | on your machine, in a container | on a remote API you point at |
| Network | fully air-gapped, zero egress | the analyst reaches the internet |
| Quality | good (small local model) | higher (large hosted model) |
| Needs | ~2 GB disk for the model | an OpenAI-compatible endpoint + API key |
| Best for | the sovereign promise, offline use | a fast demo / best analysis |

Follow **Step 2A** for local, or **Step 2B** for cloud. Everything else is shared.

---

## 1. Prerequisites

1. **Docker** with Compose v2 (Docker Desktop on Mac/Windows, or Docker Engine +
   `docker compose` on Linux). Verify:
   ```
   docker version && docker compose version
   ```
2. **git**, **curl**, **python3** (python3 is only used by the proof script).
3. **Disk/RAM**: ~6 GB for images, ~2 GB more if you use a local model, and 8 GB+
   RAM free is comfortable.
4. That's it. On a normal home/personal network no extra setup is needed. (On a
   corporate network with a TLS-inspecting proxy, see the Appendix first.)

---

## 2. Get the code

```
git clone https://github.com/COLONAYUSH/OpenMalLab.git
cd OpenMalLab
cp .env.example .env        # your local settings; edit as the steps below say
```

---

## 2A. Sovereign local model (recommended)

Nothing to configure - the defaults already point the AI at a local model
(`llama3.2:3b`) served air-gapped. If you want a different/bigger local model, set
it in `.env`:
```
MAL_MODEL_NAME=llama3.2:3b      # or e.g. qwen2.5:7b, gpt-oss:20b (bigger = slower on CPU)
```
Now jump to **Step 3**.

## 2B. Guarded cloud model (alternative)

Point the analyst at any OpenAI-compatible endpoint and give it your key. Put these
in `.env` (never commit real keys):
```
MAL_MODEL_URL=https://your-endpoint         # e.g. https://ollama.com , an OpenAI-compatible URL
MAL_MODEL_NAME=gpt-oss:120b                 # a model that endpoint serves
MAL_MODEL_KEY=<your-api-key>                # your key for that endpoint
MAL_ALLOW_CLOUD=1                           # explicit acknowledgement that evidence may egress
```
The platform minimizes what it sends off-box (it drops the file hash and any file
paths, sending only the analytical signal), and it refuses a public endpoint unless
`MAL_ALLOW_CLOUD=1` is set. Now jump to **Step 3**, then use the **cloud** commands
in Step 4.

---

## 3. Build the images

```
make build
```
On a clean network this pulls base images and compiles everything (a few minutes
the first time, cached after). On a corporate pip index, see the Appendix.

---

## 4. Bring it live

### If you chose A (sovereign local):
```
make live
```
`make live` does three things in order: `build`, then **`bootstrap-model`** (a
one-time download of the model into a local volume - the only step that touches the
network, because the runtime model server is air-gapped and cannot pull), then
`up`. When it finishes you will see the console + API URLs.

> You can also run the steps separately: `make bootstrap-model` then `make up`.

### If you chose B (guarded cloud):
No model download. Bring the stack up with the cloud overlay:
```
make build
docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml -f deploy/compose.cloud.yaml up -d
```
(The cloud overlay gives the analyst egress to reach your endpoint and skips the
local model server.)

Check everything is up:
```
docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml ps
```

---

## 5. Open the console and submit a file

Open <http://localhost:8090> in a browser - the triage console.

Submit a sample from the command line (use any file; here a harmless EICAR test
string, the industry-standard "am I wired up?" test):
```
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
curl -s -F "file=@/tmp/eicar.com" http://localhost:8080/v1/submissions
# -> {"submission_id":"sub-....","sha256":"...","status":"accepted"}
```
Within seconds the console shows a ranked verdict (EICAR -> MALICIOUS).

For something the AI can reason about, submit a real executable, e.g. a stock
system binary:
```
curl -s -F "file=@/bin/ls" http://localhost:8080/v1/submissions
```

---

## 6. Watch the AI enrich it, and review

1. The **deterministic verdict** appears first (seconds).
2. The **AI plane** then works asynchronously (with a local CPU model this can take
   a minute or two; it never blocks the verdict). Refresh the submission in the
   console.
3. If the evidence is groundable, you will see a **`mal-ai` enrichment finding**
   (capped at "suspicious") and, when the gate escalates, a **"needs review"** panel
   with a question and options.
4. Click **Approve + curate** or **Reject**. Approving records a "gold label" that
   curates the analysis facts - the same action that resolves the case teaches the
   system.

---

## 7. Prove the whole loop end to end (optional)

```
make e2e-live
```
This submits a sample, waits for the deterministic verdict, waits for the async AI
enrichment to complete, asserts it stayed contained (the AI never reaches
"malicious"), and round-trips a human review through the API. A green
`E2E-LIVE PROOF PASSED` means the full Phase-1 loop is live.

---

## 8. How the connection works (the short version)

```
you --> gateway --> deterministic engines (jailed) --> verdict (durable, instant)
                             |
                             +--> AI plane (async, caged): the roster reasons with
                                  the MODEL you connected, the Go "confidence gate"
                                  re-checks every claim against a knowledge base,
                                  and only grounded, verified findings enrich the
                                  result - capped at "suspicious", escalated to you
                                  when unsure.
```
The model is reached at `MAL_MODEL_URL`. Locally that is a container
(`http://ollama:11434`) on a no-egress network; in cloud mode it is your endpoint,
reached only because you set `MAL_ALLOW_CLOUD=1`.

---

## 9. Changing the model later

- **Local**: set `MAL_MODEL_NAME` in `.env`, run `make bootstrap-model` (pulls the
  new one), then `make up`. Bigger models reason better but are slower on CPU.
- **Cloud**: change `MAL_MODEL_URL` / `MAL_MODEL_NAME` / `MAL_MODEL_KEY` in `.env`
  and re-run the cloud `up` command.

---

## 10. Security and sovereignty

- **Local mode is air-gapped.** The model and the analyst sit on a Docker network
  with `internal: true` - no route off the box. Nothing about your sample leaves.
- **Cloud mode is an explicit opt-in.** It only works with `MAL_ALLOW_CLOUD=1`, it
  gives the analyst container egress (the trade-off you accept), and evidence is
  minimized before it is sent (hash + file paths dropped).
- **The AI is caged either way.** It cannot change or lower the deterministic
  verdict, cannot mark anything safe, and every claim it makes is re-validated by
  the trusted Go gate before it can enrich a result.

---

## 11. Troubleshooting

- **`make e2e-live` says the model is not provisioned / `mal-agents` never becomes
  healthy (local mode).** Run `make bootstrap-model` first. The model server is only
  "healthy" once the model is actually present, and the analyst waits for it, so the
  stack will not come up half-provisioned.
- **A Python image fails to build with an SSL error.** You are on a proxied network
  - see the Appendix (set `MAL_PIP_CONF`).
- **Enrichment never appears (local mode).** A small CPU model is slow; give it a
  couple of minutes. Check logs: `make logs`. The deterministic verdict is unaffected.
- **Cloud mode: the analyst errors reaching the model.** Confirm `MAL_ALLOW_CLOUD=1`,
  the URL is OpenAI-compatible, the key is valid, and you used the `compose.cloud.yaml`
  overlay in the `up` command.
- **Port already in use (8080/8090).** Stop whatever is using it, or change the
  published ports in `deploy/compose.yaml`.

---

## 12. Stop / clean up

```
make down                                  # stop the stack (keeps data + the model)
docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml down -v   # also drop volumes
docker volume rm openmallab-models         # remove the downloaded local model (~2 GB)
```

---

## Appendix: corporate network (TLS proxy + private pip index)

If your machine is behind a TLS-inspecting proxy (e.g. Zscaler) and/or installs
Python packages from a private index (e.g. Artifactory):

1. **CA certificate** - export your proxy's root CA so the image builds trust it:
   ```
   # macOS example:
   security find-certificate -a -c "Zscaler" -p /Library/Keychains/System.keychain \
     > deploy/certs/corp-tls-ca.pem
   ```
   (The `deploy/certs/*.pem` files are git-ignored and used only during builds; the
   runtime images are minimal and carry none of this.)
2. **Private pip index** - point at your credentialed `pip.conf` so the Python
   images (mal-agents, capa, floss) install:
   ```
   export MAL_PIP_CONF="$HOME/.pip/pip.conf"
   make build      # picks it up as a build secret (never baked into a layer)
   ```
On a clean home network you need neither of these.
