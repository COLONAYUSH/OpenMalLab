#!/usr/bin/env python3
# mal-static-die is a single-use, credential-less worker. jailed like every
# other engine (no network, all caps dropped, read-only rootfs, non-root), it
# runs Detect It Easy (the headless "diec" console) over one artifact and reports
# what packed, protected, compiled, or linked it, plus any crypto it recognized.
# DIE's signature database is vendored into the image and pinned, so nothing is
# fetched at run time.
#
# DIE identifies PROVENANCE, not maliciousness: "compiled by GCC" is a fact, not
# a verdict. so compiler / linker / library / installer / crypto rows are
# reported as UNKNOWN evidence (useful leads for the tree), and only a PACKER or
# PROTECTOR escalates. a packer is the "packed / unanalyzed" gate: packed code
# hides its real payload from the static engines (yara, capa), so we cannot clear
# it on static evidence alone. we floor that artifact to SUSPICIOUS and mark the
# report INCOMPLETE (fail-closed: packed-and-unread is never benign; it wants
# dynamic analysis). DIE alone never says MALICIOUS; the lattice owns that.
#
# the result is one bounded json line on stdout, the same schema every engine
# emits, which the isolated broker validates before any trusted process reads it.
# diec's own logs go to stderr and never touch stdout.

import json
import os
import subprocess
import sys

# the headless DIE console. vendored into the image; overridable for a direct run.
DIEC = os.environ.get("MAL_DIE_BIN", "/opt/die/diec")
# leave headroom under the jail wall clock so we report a clean timeout instead
# of being killed mid-write.
TIMEOUT = int(os.environ.get("MAL_DIE_TIMEOUT", "90"))
# stay well under the broker's finding cap and keep the result readable.
MAX_FINDINGS = 200
# hard ceiling on the WHOLE serialized report (see fit_budget): cap_detail bounds
# each finding and MAX_FINDINGS the count, but the sum can still exceed the 1 MiB
# broker/jail cap and get the ENTIRE report discarded. headroom < 1 MiB.
MAX_TOTAL_BYTES = 900_000

RANK = {"BENIGN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}

# DIE tags every detection with a "type". these two mean the real bytes are
# hidden from static analysis, so their presence is the packed/unanalyzed gate.
PACKED_TYPES = ("packer", "protector", "sfx")
# software packing maps to this ATT&CK technique; carried on packer/protector
# findings so the evidence tree shows why the artifact was floored.
PACKING_ATTCK = "T1027.002"


def emit(findings, verdict, incomplete):
    sys.stdout.write(
        json.dumps(
            {
                "engine": "mal-static-die",
                "findings": findings,
                "verdict": verdict,
                "incomplete": incomplete,
            }
        )
        + "\n"
    )
    sys.stdout.flush()


# the broker caps finding.detail at 8192 BYTES, not code points. cap by encoded
# bytes so a multibyte detail cannot pass this worker yet blow the broker's byte
# cap and get the WHOLE report rejected. DIE strings are usually ASCII but a
# version or info field could carry unicode.
def cap_detail(detail):
    b = detail.encode("utf-8", "replace")
    if len(b) <= 8000:
        return detail
    return b[:8000].decode("utf-8", "ignore")


def finding(kind, detail, attck, verdict):
    return {
        "engine": "mal-static-die",
        "type": kind,
        "detail": cap_detail(detail),
        "attck": attck[:64],
        "verdict": verdict,
    }


def _report_bytes(findings, incomplete):
    # conservative upper bound: assume the longest verdict token.
    return len(
        json.dumps(
            {"engine": "mal-static-die", "findings": findings, "verdict": "SUSPICIOUS", "incomplete": incomplete}
        )
    )


def fit_budget(findings, incomplete):
    # guarantee the emitted report fits the pipeline byte cap. cap_detail bounds
    # each finding and MAX_FINDINGS the count, but the sum can still exceed the
    # 1 MiB broker/jail cap and get the WHOLE report discarded. trim from the END
    # (keeping the summary at [0]) until it fits WITH a marker, and flag truncated -
    # a bounded-but-useful report survives instead of being rejected downstream.
    if _report_bytes(findings, incomplete) <= MAX_TOTAL_BYTES:
        return findings, incomplete
    marker = finding(
        "output-truncated",
        "report exceeded the %d-byte pipeline budget; trailing findings omitted" % MAX_TOTAL_BYTES,
        "",
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
    emit([finding("error", msg, "", "SUSPICIOUS")], "SUSPICIOUS", True)
    sys.exit(0)


# not-applicable: DIE could not treat this file as a binary it understands (magika
# mis-gated a non-executable). that is not a failure and not suspicious; it is
# simply outside DIE's scope, so report an honest empty UNKNOWN.
def not_applicable(reason):
    emit([finding("not-applicable", reason, "", "UNKNOWN")], "UNKNOWN", False)
    sys.exit(0)


# die_argv is the exact command. keeping it a pure function lets the selftest
# assert the wiring: "-j" is what makes diec emit the json this worker parses,
# and the sample must be the last operand.
def die_argv(sample):
    return [DIEC, "-j", sample]


# type_to_kind maps a DIE detection "type" onto our finding type + verdict +
# attck. pure and synthetic-testable. a packer/protector is the packed gate
# (SUSPICIOUS + T1027.002); everything else DIE identifies is UNKNOWN provenance
# evidence. an unrecognized type is surfaced (never silently dropped) as UNKNOWN.
def type_to_kind(die_type):
    t = (die_type or "").strip().lower()
    if t in PACKED_TYPES:
        kind = "protector" if t == "protector" else "packer"
        return kind, "SUSPICIOUS", PACKING_ATTCK
    known = {
        "compiler": "compiler",
        "linker": "linker",
        "library": "library",
        "installer": "installer",
        "tool": "tool",
        "compressor": "packer",  # a compressor over code is packing by another name
        "crypto": "crypto",
        "sign tool": "sign",
        "certificate": "sign",
        "format": "format",
        "operation system": "os",
        "language": "language",
    }
    if t in known:
        kind = known[t]
        verdict = "SUSPICIOUS" if kind == "packer" else "UNKNOWN"
        return kind, verdict, (PACKING_ATTCK if kind == "packer" else "")
    # unknown DIE type: keep it as evidence, never a verdict.
    return (t or "detection"), "UNKNOWN", ""


# detail_for renders one DIE detection into a readable one-liner. DIE gives a
# ready "string" (e.g. "Packer: UPX(4.24)[NRV,best]"); fall back to composing
# type/name/version when a build omits it.
def detail_for(value):
    s = value.get("string")
    if isinstance(s, str) and s.strip():
        return s.strip()
    parts = [p for p in (value.get("type"), value.get("name"), value.get("version"), value.get("info")) if p]
    return " ".join(str(p) for p in parts) if parts else "detection"


# map_die_doc turns a diec -j document into our findings. pure and synthetic-
# testable (see --selftest), so the mapping is verified at build time without
# depending on any particular sample. a summary is always emitted so DIE's run is
# visible in the tree even when nothing matched. if any packer/protector was
# seen, the report is floored SUSPICIOUS and marked incomplete: the packed
# payload is unread by the static engines, so the artifact is not-yet-analyzed.
def map_die_doc(doc):
    detects = doc.get("detects")
    if not isinstance(detects, list):
        detects = []
    findings = []
    worst = "UNKNOWN"
    packed = False
    truncated = False
    total = 0
    for det in detects:
        if not isinstance(det, dict):
            continue
        values = det.get("values")
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break
            kind, verdict, attck = type_to_kind(value.get("type"))
            findings.append(finding(kind, detail_for(value), attck, verdict))
            total += 1
            if kind == "packer" or kind == "protector":
                packed = True
            if RANK[verdict] > RANK[worst]:
                worst = verdict
        if truncated:
            break
    summary = finding("die-summary", "DIE identified %d signature(s)" % total, "", "UNKNOWN")
    findings.insert(0, summary)
    if packed:
        # the packed/unanalyzed gate: the real payload is hidden from the static
        # engines, so we cannot clear this artifact statically. floor + incomplete.
        findings.append(
            finding(
                "packed-unanalyzed",
                "packed or protected: the static engines cannot read the real payload; recommend dynamic analysis",
                PACKING_ATTCK,
                "SUSPICIOUS",
            )
        )
    if truncated:
        findings.append(
            finding("die-cap", "DIE detection list truncated at %d entries" % MAX_FINDINGS, "", "UNKNOWN")
        )
    incomplete = packed or truncated
    findings, incomplete = fit_budget(findings, incomplete)
    return findings, worst if not packed else "SUSPICIOUS", incomplete


# a synthetic DIE document exercising the mapping: a packer, a compiler, a crypto
# row, and an unknown type. run at build time (fails the build if broken).
def selftest():
    doc = {
        "detects": [
            {
                "filetype": "PE64",
                "values": [
                    {"type": "Packer", "name": "UPX", "version": "4.24", "info": "NRV,best",
                     "string": "Packer: UPX(4.24)[NRV,best]"},
                    {"type": "Compiler", "name": "MinGW", "version": "", "info": "",
                     "string": "Compiler: MinGW"},
                    {"type": "Crypto", "name": "CRC32", "version": "", "info": "",
                     "string": "Crypto: CRC32"},
                    {"type": "Frobnicator", "name": "X", "version": "", "info": "",
                     "string": "Frobnicator: X"},
                ],
            }
        ]
    }
    findings, worst, incomplete = map_die_doc(doc)
    assert worst == "SUSPICIOUS", worst
    assert incomplete, "a packer must mark the report incomplete (packed/unanalyzed gate)"
    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)
    assert "die-summary" in by_type, "summary missing"
    packer = by_type["packer"][0]
    assert packer["verdict"] == "SUSPICIOUS" and packer["attck"] == PACKING_ATTCK, packer
    assert by_type["compiler"][0]["verdict"] == "UNKNOWN", by_type["compiler"]
    assert by_type["crypto"][0]["verdict"] == "UNKNOWN", by_type["crypto"]
    # the packed/unanalyzed gate finding is emitted and carries the packing technique.
    assert "packed-unanalyzed" in by_type, "packed gate finding missing"
    assert by_type["packed-unanalyzed"][0]["attck"] == PACKING_ATTCK
    # an unknown DIE type is surfaced as UNKNOWN evidence, never dropped.
    assert "frobnicator" in by_type, by_type.keys()

    # a compiler-only doc is UNKNOWN and complete: provenance, not a verdict.
    f2, w2, i2 = map_die_doc({"detects": [{"values": [{"type": "Linker", "string": "Linker: GNU ld"}]}]})
    assert w2 == "UNKNOWN" and not i2, (w2, i2)
    assert any(f["type"] == "linker" for f in f2), f2

    # an empty doc -> just a summary, UNKNOWN, complete.
    f3, w3, i3 = map_die_doc({"detects": []})
    assert w3 == "UNKNOWN" and not i3 and len(f3) == 1 and f3[0]["type"] == "die-summary", (w3, i3, f3)

    # the "-j" json flag must be present and the sample last, or diec prints text
    # this worker cannot parse and every scan fails closed.
    argv = die_argv("/in/sample")
    assert "-j" in argv, argv
    assert argv[-1] == "/in/sample", argv
    assert argv[0] == DIEC, argv

    # detail is capped by BYTES so a multibyte string cannot blow the broker cap.
    assert len(cap_detail("\u4e2d" * 4000).encode("utf-8")) <= 8192

    # a detection-heavy report is trimmed to the pipeline BYTE budget with an
    # output-truncated marker, never discarded wholesale.
    heavy = {"detects": [{"values": [
        {"type": "Library", "string": "L" + "x" * 7000 + "%04d" % i} for i in range(MAX_FINDINGS + 5)
    ]}]}
    hf, _, htr = map_die_doc(heavy)
    assert _report_bytes(hf, htr) <= MAX_TOTAL_BYTES, _report_bytes(hf, htr)
    assert htr and any(f["type"] == "output-truncated" for f in hf), "missing byte-cap marker"
    print("mal-static-die selftest ok")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return
    sample = sys.argv[1] if len(sys.argv) > 1 else "/in/sample"
    try:
        proc = subprocess.run(
            die_argv(sample),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        fail("DIE analysis exceeded the time budget")
        return
    except Exception as e:  # noqa: BLE001 - any spawn failure is fail-closed
        fail("could not run DIE: %s" % type(e).__name__)
        return

    out = proc.stdout.decode("utf-8", "replace").strip()
    if not out:
        # diec emits json for any file it can open, so no output means it could not
        # process the file at all. fail closed rather than call it clean.
        fail("DIE produced no result (exit %d)" % proc.returncode)
        return

    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        fail("DIE output was not valid json")
        return
    if not isinstance(doc, dict):
        fail("DIE output was not a json object")
        return

    findings, worst, incomplete = map_die_doc(doc)
    emit(findings, worst, incomplete)


if __name__ == "__main__":
    main()
