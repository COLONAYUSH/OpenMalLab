#!/usr/bin/env python3
# mal-floss is a single-use, credential-less worker. jailed like every other
# engine (no network, all caps dropped, read-only rootfs, non-root), it runs
# Mandiant FLOSS over one artifact to recover strings, including the stack,
# tight, and decoded strings that obfuscation hides from a plain `strings`.
#
# FLOSS only decodes PE (and shellcode); the workflow only dispatches it for PE
# samples, and anything else reports a clean not-applicable. Its strings are
# EVIDENCE, not a verdict: they are reported UNKNOWN (an analyst reads them),
# defanged downstream, and never move severity on their own.
#
# The critical discipline (per the design): FLOSS's decoded/stack/tight strings
# come from vivisect EMULATION, which is slow and pathological on hostile input.
# So we split the work: the cheap static-strings phase runs first and always
# returns, and the expensive emulation phase runs under its own stricter time
# budget. If emulation exceeds the budget we keep the static strings and mark
# the run incomplete (fail-closed, low confidence) rather than losing
# everything or, worse, reporting clean.

import json
import os
import subprocess
import sys

FLOSS = os.environ.get("MAL_FLOSS_BIN", "/opt/venv/bin/floss")
MIN_LEN = os.environ.get("MAL_FLOSS_MIN_LENGTH", "6")
# the cheap phase; the pathological emulation phase gets a separate, stricter
# budget. both leave headroom under the jail wall clock.
STATIC_TIMEOUT = int(os.environ.get("MAL_FLOSS_STATIC_TIMEOUT", "90"))
EMU_TIMEOUT = int(os.environ.get("MAL_FLOSS_EMU_TIMEOUT", "200"))
# decoded/stack/tight strings are the valuable, usually-small set: emit them all
# up to this cap. static strings are high-volume noise (a plain `strings` dump),
# so we summarize their count instead of flooding the evidence tree.
MAX_STRINGS = 250
MAX_STATIC_SAMPLE = 40


def emit(findings, verdict, incomplete):
    sys.stdout.write(json.dumps({"engine": "mal-floss", "findings": findings, "verdict": verdict, "incomplete": incomplete}) + "\n")
    sys.stdout.flush()


def finding(kind, detail, verdict):
    return {"engine": "mal-floss", "type": kind, "detail": detail[:8000], "attck": "", "verdict": verdict}


# fail-closed: an analysis that could not complete floors to SUSPICIOUS and is
# flagged incomplete. it never reports BENIGN by omission.
def fail(msg):
    emit([finding("error", msg, "SUSPICIOUS")], "SUSPICIOUS", True)
    sys.exit(0)


# not-applicable: FLOSS cannot treat this as a program it decodes (it only does
# PE and shellcode). that is not a failure and not suspicious, just out of
# scope, so report an honest empty UNKNOWN.
def not_applicable(reason):
    emit([finding("not-applicable", reason, "UNKNOWN")], "UNKNOWN", False)
    sys.exit(0)


def run_floss(sample, phases, timeout):
    args = [FLOSS, "-q", "-j", "-n", str(MIN_LEN), "--only"] + phases + ["--", sample]
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception:  # noqa: BLE001 - any spawn failure is fail-closed at the caller
        return None, "spawn"
    err = p.stderr.decode("utf-8", "replace")
    if p.returncode != 0:
        low = err.lower()
        if "supports the following formats" in low or "unsupported" in low:
            return None, "unsupported"
        return None, "error"
    try:
        return json.loads(p.stdout.decode("utf-8", "replace")), None
    except json.JSONDecodeError:
        return None, "badjson"


def strings_of(doc, key):
    out = []
    for s in ((doc or {}).get("strings", {}) or {}).get(key, []) or []:
        v = s.get("string") if isinstance(s, dict) else s
        if v:
            out.append(str(v))
    return out


# map_floss turns the two phase documents into findings. pure and
# synthetic-testable (see --selftest). the decoded/stack/tight strings are the
# obfuscation-recovered evidence and are emitted individually (capped); static
# strings are summarized by count. everything is UNKNOWN evidence; FLOSS never
# raises severity on its own. incomplete is set when the emulation phase did
# not finish (fail-closed).
def map_floss(static_doc, emu_doc, emu_incomplete):
    findings = []
    static = strings_of(static_doc, "static_strings")
    decoded = strings_of(emu_doc, "decoded_strings")
    stack = strings_of(emu_doc, "stack_strings")
    tight = strings_of(emu_doc, "tight_strings")

    findings.append(finding(
        "floss-summary",
        "floss recovered %d static, %d decoded, %d stack, %d tight strings" % (len(static), len(decoded), len(stack), len(tight)),
        "UNKNOWN",
    ))

    budget = MAX_STRINGS
    for kind, items in (("decoded-string", decoded), ("stack-string", stack), ("tight-string", tight)):
        for s in items:
            if budget <= 0:
                break
            findings.append(finding(kind, s, "UNKNOWN"))
            budget -= 1

    # a bounded sample of static strings for context; the count above is the
    # full picture.
    for s in static[:MAX_STATIC_SAMPLE]:
        if budget <= 0:
            break
        findings.append(finding("static-string", s, "UNKNOWN"))
        budget -= 1

    if emu_incomplete:
        findings.append(finding(
            "decoding-incomplete",
            "obfuscated-string recovery did not finish within the time budget; static strings only",
            "UNKNOWN",
        ))
    return findings, "UNKNOWN", emu_incomplete


def selftest():
    static_doc = {"strings": {"static_strings": [{"string": "kernel32.dll"}, {"string": "http://x/y"}]}}
    emu_doc = {"strings": {
        "decoded_strings": [{"string": "http://c2.evil/beacon"}],
        "stack_strings": [{"string": "cmd.exe /c whoami"}],
        "tight_strings": [],
    }}
    findings, verdict, incomplete = map_floss(static_doc, emu_doc, False)
    assert verdict == "UNKNOWN", verdict
    assert not incomplete
    kinds = [f["type"] for f in findings]
    assert kinds[0] == "floss-summary", kinds
    assert any(f["type"] == "decoded-string" and "c2.evil" in f["detail"] for f in findings), findings
    assert any(f["type"] == "stack-string" and "whoami" in f["detail"] for f in findings), findings
    assert all(f["verdict"] == "UNKNOWN" for f in findings), "floss findings are evidence, all UNKNOWN"
    # a timed-out emulation phase: static kept, run marked incomplete.
    f2, v2, inc2 = map_floss(static_doc, {}, True)
    assert inc2 and v2 == "UNKNOWN" and any(f["type"] == "decoding-incomplete" for f in f2), (v2, inc2, f2)
    print("mal-floss selftest ok")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return

    sample = sys.argv[1] if len(sys.argv) > 1 else "/in/sample"

    static_doc, serr = run_floss(sample, ["static"], STATIC_TIMEOUT)
    if serr == "unsupported":
        not_applicable("floss only decodes PE and shellcode; this file is out of scope")
        return
    if serr in ("spawn",):
        fail("could not run floss")
        return
    # static timing out or erroring is a hard failure (it is the cheap phase).
    if static_doc is None:
        fail("floss static-string extraction failed (%s)" % serr)
        return

    # the pathological phase, under its own budget. a timeout here is degraded,
    # not fatal: we keep the static strings and mark incomplete.
    emu_doc, eerr = run_floss(sample, ["stack", "tight", "decoded"], EMU_TIMEOUT)
    emu_incomplete = emu_doc is None

    findings, verdict, incomplete = map_floss(static_doc, emu_doc, emu_incomplete)
    emit(findings, verdict, incomplete)


if __name__ == "__main__":
    main()
