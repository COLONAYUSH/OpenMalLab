# Extra build-time trust roots

Some corporate networks intercept TLS. Inside a docker build stage that shows
up as "server certificate not trusted" when cargo, go, or apk try to fetch
dependencies, because the interception CA lives in the host keychain but not
in the build container.

Fix: export that root CA and drop it here as one or more `*.pem` files. Every
build stage appends whatever is in this directory to its system trust bundle
before fetching anything.

Rules:

- `*.pem` is gitignored. Never commit a CA bundle, corporate or otherwise.
- This affects BUILD stages only. Runtime images are scratch: they carry no
  trust bundle and no network. Nothing from this directory reaches a shipped
  layer.
- On a clean network this directory holds only this file and the build steps
  are a no-op.
- Air-gapped builds do not use this at all; they pull vendored dependencies
  from the local mirror.
