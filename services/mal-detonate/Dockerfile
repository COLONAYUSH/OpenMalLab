# mal-detonate: the dynamic-analysis worker. It detonates a Linux ELF by running it
# AS DATA under a trusted qemu-user emulator and mining the emulator's own syscall
# trace into behavioral findings. Same "jail is the containment" model as mal-capa /
# mal-floss: a debian base (it needs the emulator plus a second libc userland to
# serve as the qemu sysroot), with every containment guarantee enforced by the jail,
# never by image minimalism. The sample is never made executable; only the trusted
# emulator on this read-only rootfs ever runs.
#
# Build context is the REPO ROOT (compose sets context: ..), so source paths are
# repo-relative, matching the capa/floss/extract workers. debian:12 (not -slim) is
# used because it is already present on constrained/proxied networks; the apt step
# adds only python3 + the emulator + a second libc, so the size delta is minor.
FROM debian:12

# optional corporate TLS-interception CA (deploy/certs/*.pem, git-ignored); empty on
# a clean network -> a harmless no-op. lets apt over a proxied mirror trust the chain.
COPY deploy/certs/ /tmp/extra-certs/
RUN cat /tmp/extra-certs/*.pem >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

# the emulator (ships every guest arch) + a SECOND libc userland so a dynamically
# linked FOREIGN-arch ELF resolves its loader under qemu's "-L /" sysroot. On this
# arm64 build the native libc serves aarch64 guests and libc6:amd64 serves x86-64
# guests. python3 is stdlib-only here (no pip), so there is no venv and no build
# stage. apt is retried to ride out a flaky/throttling proxy.
RUN dpkg --add-architecture amd64 && \
    n=0; until apt-get update && apt-get install -y --no-install-recommends \
        python3 qemu-user-static libc6:amd64; do \
      n=$((n+1)); [ "$n" -ge 5 ] && echo "apt failed after 5 tries" && exit 1; \
      echo "apt retry $n"; sleep 3; done && \
    rm -rf /var/lib/apt/lists/* /tmp/extra-certs

COPY services/mal-detonate/wrapper.py /wrapper.py

# build-time self-check: both emulators are present and runnable, the emulator
# command is well-formed (argv only, no shell), and the syscall -> finding -> verdict
# mapping is correct (behavioral evidence caps at SUSPICIOUS, a clean run stays
# UNKNOWN not BENIGN). Fails the build if the containment or verdict policy regresses.
RUN python3 /wrapper.py --selftest

# non-root in the image too (the jail also enforces uid 65534). the analysis path is
# argv only; the jail supplies network-none, caps-dropped, read-only rootfs, seccomp.
USER 65534:65534
ENTRYPOINT ["python3", "/wrapper.py"]
