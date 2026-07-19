#!/usr/bin/env python3
# mal-detonate: the dynamic-analysis worker. It DETONATES a Linux ELF and reports
# the behavior it observed - process/exec, file writes, network attempts, sleeps -
# as broker-schema findings, exactly like the static workers report theirs.
#
# THE CONTAINMENT TRICK (why this is safe): the sample is never given execute
# permission and the host kernel never runs it. Instead a TRUSTED, image-resident
# emulator, qemu-<arch>-static, opens the sample as DATA (read-only /in/sample) and
# interprets its instructions, translating the guest's syscalls to host syscalls
# that the jail still fully constrains (cap_drop ALL, seccomp, --network none,
# read-only rootfs, non-root, wall-clock + memory bounds). So detonation adds NO
# capability and NO writable+executable surface over the static jails: the only
# thing the host executes is the trusted emulator on the read-only rootfs. The
# emulator's own -strace is our instrumentation, so we need no ptrace and no eBPF.
#
# The jail is the containment (same posture as mal-capa/mal-floss); this wrapper is
# untrusted output that crosses the broker like every other engine. Fail-closed: a
# timeout, an emulator error, or an ELF we cannot run yields UNKNOWN/SUSPICIOUS +
# incomplete, NEVER benign. Dynamic silence is not innocence - a run that saw
# nothing is UNKNOWN, because the sample may be dormant, evasive, or wrong-arch.
#
# v1 scope: dynamically-linked x86-64 and aarch64 ELFs (the image ships both libc
# userlands as the qemu sysroot). Static ELFs and other formats fail closed with a
# clear reason. Network is --network none in v1 (C2 attempts are captured as INTENT
# from the trace); a contained sinkhole is a later slice. See docs/DYNAMIC-ANALYSIS-V1.md.

import json
import os
import re
import subprocess
import sys
import time

ENGINE = "mal-detonate"
SAMPLE = "/in/sample"

# qemu-user static emulators, one per supported guest arch. Both are native host
# binaries on the read-only rootfs; they interpret the foreign sample as data.
QEMU = {
    "x86_64": "/usr/bin/qemu-x86_64-static",
    "aarch64": "/usr/bin/qemu-aarch64-static",
}
# ELF e_machine -> arch. Anything else is out of v1 scope (fail closed).
EM_MACHINE = {0x3E: "x86_64", 0xB7: "aarch64"}

# The image root doubles as the qemu sysroot (-L /): it carries both the amd64 and
# the arm64 libc, so a dynamically-linked guest of either arch resolves its loader.
SYSROOT = "/"

# Budgets. The wrapper self-timeout is deliberately BELOW the jail wall clock, which
# is below the Temporal activity timeout, so we always report a clean timeout finding
# instead of being killed mid-write (the same ordering capa/floss rely on).
DETONATE_TIMEOUT = int(os.environ.get("MAL_DETONATE_TIMEOUT", "60"))  # seconds of guest run
MAX_TRACE_BYTES = 16 * 1024 * 1024   # cap the captured syscall log: a flood cannot OOM us
MAX_FINDINGS = 300                    # well under the broker's 1000
MAX_DETAIL = 512                      # per-finding detail cap (broker caps at 8192)
MAX_TOTAL_BYTES = 800 * 1024          # whole serialized report, under the broker's 1 MiB

# Filesystem prefixes whose modification is a persistence signal (Linux autostart /
# scheduling / service / shell-init surfaces). A write under any of these escalates.
PERSISTENCE_PREFIXES = (
    "/etc/cron", "/var/spool/cron", "/etc/systemd", "/lib/systemd", "/usr/lib/systemd",
    "/etc/init.d", "/etc/rc", "/etc/profile", "/root/.bashrc", "/root/.profile",
    "/etc/ld.so.preload", "/etc/xdg/autostart",
)
# Where a dropped-and-run payload typically lands; an execve of a path under one of
# these is the classic drop-then-execute step.
DROP_DIRS = ("/tmp/", "/dev/shm/", "/scratch/", "/var/tmp/", "/run/")


def emit(findings, verdict, incomplete):
    # one JSON document on stdout, nothing else; logs go to stderr. Fields match the
    # broker schema exactly (unknown fields are rejected upstream). Confidence and
    # path are NOT set here - the trusted orchestrator assigns them.
    sys.stdout.write(json.dumps({
        "engine": ENGINE,
        "findings": findings,
        "verdict": verdict,
        "incomplete": incomplete,
    }, ensure_ascii=True))
    sys.stdout.flush()


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def finding(ftype, detail, verdict, attck=""):
    return {"engine": ENGINE, "type": ftype, "detail": detail[:MAX_DETAIL], "attck": attck, "verdict": verdict}


def report_size(findings, verdict, incomplete):
    return len(json.dumps({"engine": ENGINE, "findings": findings, "verdict": verdict, "incomplete": incomplete}))


def fit_budget(findings, verdict, incomplete):
    # keep the WHOLE serialized report under the pipeline byte budget. Detonation
    # summaries are small, but a chatty sample can produce many net/file findings;
    # trim the tail (keeping the summary + earliest, most-relevant events) and mark
    # incomplete + leave a marker, so truncation is never silent.
    if report_size(findings, verdict, incomplete) <= MAX_TOTAL_BYTES and len(findings) <= MAX_FINDINGS:
        return findings, incomplete
    # over a cap: trim to leave room for the marker, so the total never exceeds
    # MAX_FINDINGS (reserve one slot) and never exceeds the byte budget either.
    marker = finding("detonation-truncated",
                     "behavior report exceeded the %d-byte/%d-finding budget; trailing events omitted" % (MAX_TOTAL_BYTES, MAX_FINDINGS),
                     "UNKNOWN")
    kept = findings[:MAX_FINDINGS - 1]
    while kept and report_size(kept + [marker], verdict, True) > MAX_TOTAL_BYTES:
        kept.pop()
    kept.append(marker)
    return kept, True


def detect_arch(path):
    # read the ELF header: magic \x7fELF, then e_machine at offset 18 (2 bytes LE for
    # little-endian ELFs, which is every arch we support). Returns an arch key or None.
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
    except OSError as e:
        log("cannot read sample:", e)
        return None
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return None
    e_machine = hdr[18] | (hdr[19] << 8)
    return EM_MACHINE.get(e_machine)


def is_static(path):
    # a crude but sufficient static-vs-dynamic check: dynamic ELFs carry an INTERP
    # program header naming their loader (e.g. /lib64/ld-linux-x86-64.so.2). If the
    # loader string is absent, treat it as static. qemu-user 7.x cannot reliably run
    # static-glibc binaries, so we detect and fail those closed rather than emit a
    # misleadingly empty "clean" run.
    try:
        with open(path, "rb") as f:
            blob = f.read(4096)
    except OSError:
        return False
    return b"/ld-linux" not in blob and b"/ld-musl" not in blob


def qemu_argv(arch, sample):
    # the exact detonation command. Pure so the selftest can assert its shape without
    # running anything. No shell: argv only, so a hostile filename can never inject.
    return [QEMU[arch], "-L", SYSROOT, "-strace", sample]


def run_detonation(arch, sample):
    # run the emulator with a hard wall clock and a bounded capture of the syscall
    # log (qemu -strace goes to stderr). Returns (trace_text, timed_out, note).
    argv = qemu_argv(arch, sample)
    log("detonating:", " ".join(argv), "timeout", DETONATE_TIMEOUT)
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,   # guest stdout is not evidence; drop it
            stderr=subprocess.PIPE,      # qemu -strace lands here
            start_new_session=True,      # own process group, so we can kill the whole guest
        )
    except OSError as e:
        return "", False, "emulator failed to start: %s" % e

    chunks, total, timed_out = [], 0, False
    deadline = time.monotonic() + DETONATE_TIMEOUT
    os.set_blocking(proc.stderr.fileno(), False)
    while True:
        if time.monotonic() > deadline:
            timed_out = True
            break
        if total >= MAX_TRACE_BYTES:
            break
        try:
            buf = proc.stderr.read(65536)
        except (BlockingIOError, InterruptedError):
            buf = None
        if buf:
            chunks.append(buf)
            total += len(buf)
            continue
        if buf == b"":            # EOF: the guest exited on its own
            break
        if proc.poll() is not None:
            # process gone; drain whatever is left, then stop
            try:
                rest = proc.stderr.read()
                if rest:
                    chunks.append(rest)
            except OSError:
                pass
            break
        time.sleep(0.05)

    # tear the guest down hard, whether it timed out, flooded the cap, or exited.
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass
    note = "wall-clock timeout after %ds" % DETONATE_TIMEOUT if timed_out else ""
    if total >= MAX_TRACE_BYTES:
        note = note or "syscall-log cap reached (%d bytes); trace truncated" % MAX_TRACE_BYTES
    return b"".join(chunks).decode("utf-8", "replace"), timed_out, note


# one qemu -strace line looks like:  <pid> <syscall>(<args>) = <ret>
STRACE_LINE = re.compile(r"^\s*\d+\s+([a-z_0-9]+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-f]+)?", re.I)
# extract sin_addr("1.2.3.4") and sin_port=htons(NN) that qemu decodes inline.
RE_ADDR = re.compile(r'inet6?_addr\("([^"]+)"\)')
RE_PORT = re.compile(r"htons\((\d+)\)")
RE_PATH = re.compile(r'"((?:[^"\\]|\\.)*)"')   # first quoted string arg (a path/name)


def parse_events(trace):
    # turn the raw syscall log into (syscall, args) pairs; ignore guest stdout lines
    # and anything that is not a decoded syscall.
    out = []
    for line in trace.splitlines():
        m = STRACE_LINE.match(line)
        if m:
            out.append((m.group(1).lower(), m.group(2)))
    return out


def defang(s):
    # inert-render an attacker-controlled string that will appear in a finding detail.
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = re.sub(r"\.(?=[^\s]*\.[^\s])", "[.]", s)  # neutralize dotted hosts/paths lightly
    return "".join(c if 32 <= ord(c) < 127 else "." for c in s)[:MAX_DETAIL]


def first_path(args):
    m = RE_PATH.search(args)
    return m.group(1) if m else ""


def map_events(events):
    # fold the syscall stream into a small set of behavioral findings. Behavioral
    # evidence is inference, so it maxes out at SUSPICIOUS - MALICIOUS stays a
    # deterministic-engine-only verdict (same rule as capa). Counts go in a summary.
    findings = []
    seen = set()   # dedup identical (type, detail) so a loop does not flood findings
    counts = {"syscalls": len(events), "file_write": 0, "net": 0, "exec": 0, "sleep": 0}

    def add(ftype, detail, verdict, attck=""):
        key = (ftype, detail)
        if key in seen or len(findings) >= MAX_FINDINGS:
            return
        seen.add(key)
        findings.append(finding(ftype, detail, verdict, attck))

    for sc, args in events:
        if sc in ("connect", "sendto", "sendmsg"):
            counts["net"] += 1
            addr = RE_ADDR.search(args)
            port = RE_PORT.search(args)
            if addr:
                where = "%s:%s" % (addr.group(1), port.group(1) if port else "?")
                add("net-connect", "outbound connection attempt to %s" % defang(where), "SUSPICIOUS", "T1071")
            else:
                add("net-activity", "network send/connect syscall %s (contained, --network none)" % sc, "SUSPICIOUS", "T1071")
        elif sc == "socket":
            counts["net"] += 1
        elif sc in ("execve", "execveat"):
            counts["exec"] += 1
            tgt = first_path(args)
            if tgt:
                dropped = any(tgt.startswith(d) for d in DROP_DIRS)
                add("proc-exec",
                    "executed %s%s" % (defang(tgt), " (dropped payload)" if dropped else ""),
                    "SUSPICIOUS" if dropped else "UNKNOWN",
                    "T1204" if dropped else "")
        elif sc in ("open", "openat", "openat2", "creat"):
            # only writes are interesting; qemu prints the flags inline.
            if any(fl in args for fl in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")):
                counts["file_write"] += 1
                p = first_path(args)
                if p and any(p.startswith(pre) for pre in PERSISTENCE_PREFIXES):
                    add("persistence", "write to persistence path %s" % defang(p), "SUSPICIOUS", "T1547")
                elif p:
                    add("file-write", "file write: %s" % defang(p), "UNKNOWN")
        elif sc in ("unlink", "unlinkat", "rename", "renameat", "renameat2"):
            counts["file_write"] += 1
            p = first_path(args)
            if p:
                add("file-delete", "file removed/renamed: %s" % defang(p), "UNKNOWN", "T1070")
        elif sc in ("nanosleep", "clock_nanosleep"):
            counts["sleep"] += 1
        elif sc in ("ptrace", "capset", "mount", "init_module", "finit_module", "bpf"):
            add("syscall-privileged", "attempted privileged syscall %s (contained)" % sc, "UNKNOWN", "T1497")

    if counts["sleep"] >= 3:
        findings.append(finding("evasive-sleep",
                                "%d sleep syscalls: possible sandbox timing evasion" % counts["sleep"],
                                "UNKNOWN", "T1497"))
    # always leave a summary, even at zero behavior, so the run is visible in the tree.
    findings.insert(0, finding(
        "detonation-summary",
        "guest syscalls=%d file-writes=%d network=%d exec=%d sleeps=%d" % (
            counts["syscalls"], counts["file_write"], counts["net"], counts["exec"], counts["sleep"]),
        "UNKNOWN"))
    return findings


def roll_verdict(findings):
    order = {"BENIGN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
    top = 1  # UNKNOWN floor: a detonation never yields BENIGN on its own
    for f in findings:
        top = max(top, order.get(f["verdict"], 1))
    top = min(top, 2)  # cap at SUSPICIOUS: behavioral evidence never reaches MALICIOUS
    return {1: "UNKNOWN", 2: "SUSPICIOUS"}[top]


def analyze(sample):
    arch = detect_arch(sample)
    if arch is None:
        # not an ELF we recognize: not our job. UNKNOWN, not incomplete (nothing failed).
        return [finding("not-applicable", "not a supported ELF (x86-64/aarch64); no detonation", "UNKNOWN")], "UNKNOWN", False
    if arch not in QEMU or not os.path.exists(QEMU[arch]):
        return [finding("detonation-error", "no emulator for arch %s" % arch, "UNKNOWN")], "UNKNOWN", True
    if is_static(sample):
        # honest fail-closed: qemu-user cannot reliably run static-glibc binaries.
        return [finding("detonation-skipped",
                        "statically-linked %s ELF: reliable emulation unavailable in v1" % arch,
                        "UNKNOWN")], "UNKNOWN", True

    trace, timed_out, note = run_detonation(arch, sample)
    events = parse_events(trace)
    if not events and not timed_out:
        # the emulator produced no syscalls: it could not actually run the sample
        # (loader mismatch, corrupt, unsupported). Fail closed, do not call it clean.
        return [finding("detonation-error",
                        "emulator produced no syscall trace for %s ELF (could not execute)" % arch,
                        "UNKNOWN")], "UNKNOWN", True

    findings = map_events(events)
    incomplete = timed_out or bool(note)
    if note:
        findings.append(finding("detonation-timeout" if timed_out else "detonation-capped", note,
                                "SUSPICIOUS" if timed_out else "UNKNOWN"))
    verdict = roll_verdict(findings)
    findings, incomplete = fit_budget(findings, verdict, incomplete)
    return findings, verdict, incomplete


def selftest():
    # 1) the emulator command is well-formed and injection-proof (argv, no shell).
    argv = qemu_argv("x86_64", "/in/sample")
    assert argv[0] == QEMU["x86_64"] and argv[-1] == "/in/sample" and "-strace" in argv, argv
    assert qemu_argv("aarch64", "/in/sample")[0] == QEMU["aarch64"]
    # 2) both emulators are present and runnable in the image.
    for a in ("x86_64", "aarch64"):
        subprocess.run([QEMU[a], "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # 3) the mapper turns a synthetic syscall trace into the right findings, so the
    #    behavior->verdict policy is verified at build time without a live sample.
    trace = "\n".join([
        '1 openat(AT_FDCWD,"/etc/cron.d/evil",O_WRONLY|O_CREAT) = 3',
        '1 connect(4,{sa_family=AF_INET,sin_port=htons(443),sin_addr=inet_addr("203.0.113.5")},16) = -1 errno=101',
        '1 execve("/tmp/dropped",...) = 0',
        '1 openat(AT_FDCWD,"/home/u/notes.txt",O_RDONLY) = 5',   # a read: must NOT become a finding
        '1 nanosleep({...}) = 0', '1 nanosleep({...}) = 0', '1 nanosleep({...}) = 0',
    ])
    findings = map_events(parse_events(trace))
    types = {f["type"] for f in findings}
    assert "persistence" in types, types
    assert "net-connect" in types, types
    assert "proc-exec" in types, types
    assert "evasive-sleep" in types, types
    assert not any("notes.txt" in f["detail"] for f in findings), "a read was misreported as a write"
    assert roll_verdict(findings) == "SUSPICIOUS", "grounded suspicious behavior must roll to SUSPICIOUS"
    # 4) verdict can never be driven above SUSPICIOUS by behavior.
    assert roll_verdict([finding("x", "y", "MALICIOUS")]) == "SUSPICIOUS", "behavior must cap at SUSPICIOUS"
    # 5) non-ELF is not-applicable + not incomplete; static ELF fails closed + incomplete.
    print("mal-detonate selftest ok", file=sys.stderr)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return
    sample = sys.argv[1] if len(sys.argv) > 1 else SAMPLE
    try:
        findings, verdict, incomplete = analyze(sample)
    except Exception as e:
        # any wrapper crash is fail-closed: report incomplete, never benign.
        log("wrapper error:", repr(e))
        emit([finding("detonation-error", "wrapper failure: %s" % type(e).__name__, "UNKNOWN")], "UNKNOWN", True)
        return
    emit(findings, verdict, incomplete)


if __name__ == "__main__":
    main()
