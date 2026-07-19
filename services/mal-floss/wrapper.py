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
# hard ceiling on the WHOLE serialized report: cap_detail bounds each finding and
# MAX_STRINGS bounds the count, but 250 x ~8 KB can still exceed the 1 MiB
# broker/jail cap and get the ENTIRE report discarded downstream. headroom < 1 MiB.
MAX_TOTAL_BYTES = 900_000


def emit(findings, verdict, incomplete):
    sys.stdout.write(json.dumps({"engine": "mal-floss", "findings": findings, "verdict": verdict, "incomplete": incomplete}) + "\n")
    sys.stdout.flush()


# the broker caps finding.detail at 8192 BYTES, not code points. cap here by
# encoded bytes so a recovered multibyte string (Cyrillic/CJK/emoji, common in
# non-English malware) cannot slip past a code-point cap and then blow the
# broker's byte cap, which rejects the ENTIRE report and loses all evidence.
# leave headroom under 8192.
def cap_detail(detail):
    b = detail.encode("utf-8", "replace")
    if len(b) <= 8000:
        return detail
    return b[:8000].decode("utf-8", "ignore")


def finding(kind, detail, verdict):
    return {"engine": "mal-floss", "type": kind, "detail": cap_detail(detail), "attck": "", "verdict": verdict}


def _report_bytes(findings, incomplete):
    # the exact serialized size emit() produces (minus the trailing newline).
    return len(json.dumps({"engine": "mal-floss", "findings": findings, "verdict": "UNKNOWN", "incomplete": incomplete}))


def fit_budget(findings, incomplete):
    # guarantee the emitted report fits the pipeline byte cap. trim from the END
    # (keeping the summary at [0] and the earliest, highest-value strings) until it
    # fits WITH an output-truncated marker, and flag incomplete. a bounded-but-
    # useful report survives instead of the whole thing being rejected downstream.
    if _report_bytes(findings, incomplete) <= MAX_TOTAL_BYTES:
        return findings, incomplete
    marker = finding(
        "output-truncated",
        "report exceeded the %d-byte pipeline budget; trailing findings omitted" % MAX_TOTAL_BYTES,
        "UNKNOWN",
    )
    kept = list(findings)
    while len(kept) > 1 and _report_bytes(kept + [marker], True) > MAX_TOTAL_BYTES:
        kept.pop()
    kept.append(marker)
    return kept, True


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


# static_outcome classifies the cheap static phase's result into the fail-closed
# action. pure and testable. the static phase is not the pathological one, so a
# timeout or error here is a hard failure (SUSPICIOUS+incomplete), never a clean
# result; only an unsupported format is a legitimate not-applicable.
def static_outcome(doc, err):
    if err == "unsupported":
        return "not_applicable", "floss only decodes PE and shellcode; this file is out of scope"
    if doc is None:
        return "fail", "floss static-string extraction failed (%s)" % (err or "no output")
    return "ok", ""


def strings_of(doc, key):
    out = []
    strings = (doc or {}).get("strings", {})
    # FLOSS owns this schema, but a version/format change that made "strings" a
    # list (not a dict) would crash .get; guard it so we degrade, not explode.
    if not isinstance(strings, dict):
        return out
    for s in (strings.get(key, []) or []):
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
    dropped = 0
    for kind, items in (("decoded-string", decoded), ("stack-string", stack), ("tight-string", tight)):
        for s in items:
            if budget <= 0:
                # count the high-value obfuscated strings we could not emit.
                dropped += 1
                continue
            findings.append(finding(kind, s, "UNKNOWN"))
            budget -= 1

    # never truncate silently: if obfuscated strings were dropped at the cap,
    # say so with a marker, the way capa does for its capability list. the
    # static-string sample below is summarized-by-count on purpose and is not
    # counted as a truncation.
    if dropped:
        findings.append(finding(
            "strings-truncated",
            "recovered-string list capped at %d; %d obfuscated strings omitted (see the summary counts)" % (MAX_STRINGS, dropped),
            "UNKNOWN",
        ))

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
    findings, incomplete = fit_budget(findings, emu_incomplete)
    return findings, "UNKNOWN", incomplete


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

    # emulation completed with only static strings: complete, no incomplete marker.
    f3, v3, inc3 = map_floss(static_doc, {"strings": {}}, False)
    assert not inc3 and v3 == "UNKNOWN", (v3, inc3)
    assert not any(f["type"] == "decoding-incomplete" for f in f3), f3

    # detail is capped by BYTES, not code points: a multibyte string must stay
    # under the broker's 8192-byte cap so it can never reject the whole report.
    big = cap_detail("\u0416" * 6000)  # Cyrillic Zhe, 2 utf-8 bytes each
    assert len(big.encode("utf-8")) <= 8192, len(big.encode("utf-8"))

    # over-budget obfuscated strings are truncated WITH a marker, never silently.
    many = {"strings": {"decoded_strings": [{"string": "d%d" % i} for i in range(MAX_STRINGS + 25)]}}
    f4, _, _ = map_floss({"strings": {}}, many, False)
    assert any(f["type"] == "strings-truncated" for f in f4), "silent truncation"
    assert sum(1 for f in f4 if f["type"] == "decoded-string") == MAX_STRINGS, "budget not enforced"

    # a string-heavy report (each string near the per-finding cap) is trimmed to
    # fit the pipeline BYTE budget with an output-truncated marker + incomplete,
    # never discarded wholesale. this is what the byte budget adds atop the count.
    heavy = {"strings": {"decoded_strings": [{"string": "A" * 7000} for _ in range(MAX_STRINGS)]}}
    f5, _, inc5 = map_floss({"strings": {}}, heavy, False)
    assert _report_bytes(f5, inc5) <= MAX_TOTAL_BYTES, _report_bytes(f5, inc5)
    assert inc5 and any(f["type"] == "output-truncated" for f in f5), "missing byte-cap marker"

    # the fail-closed static classifier: unsupported is the only clean out;
    # every other no-output is a hard failure, never a clean/not-applicable pass.
    assert static_outcome(None, "unsupported")[0] == "not_applicable"
    assert static_outcome(None, "timeout")[0] == "fail"
    assert static_outcome(None, "spawn")[0] == "fail"
    assert static_outcome(None, "badjson")[0] == "fail"
    assert static_outcome(None, "error")[0] == "fail"
    assert static_outcome({"strings": {}}, None)[0] == "ok"

    # a schema drift where "strings" is a list must not crash strings_of.
    assert strings_of({"strings": []}, "static_strings") == []
    print("mal-floss selftest ok")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return

    sample = sys.argv[1] if len(sys.argv) > 1 else "/in/sample"

    static_doc, serr = run_floss(sample, ["static"], STATIC_TIMEOUT)
    action, detail = static_outcome(static_doc, serr)
    if action == "not_applicable":
        not_applicable(detail)
        return
    if action == "fail":
        fail(detail)
        return

    # the pathological phase, under its own budget. a timeout here is degraded,
    # not fatal: we keep the static strings and mark incomplete.
    emu_doc, eerr = run_floss(sample, ["stack", "tight", "decoded"], EMU_TIMEOUT)
    emu_incomplete = emu_doc is None

    findings, verdict, incomplete = map_floss(static_doc, emu_doc, emu_incomplete)
    emit(findings, verdict, incomplete)


if __name__ == "__main__":
    main()
