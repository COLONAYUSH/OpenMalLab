#!/usr/bin/env python3
# mal-capa is a single-use, credential-less worker. jailed like every other
# engine (no network, all caps dropped, read-only rootfs, non-root), it runs
# Mandiant capa over one artifact and reports the capabilities capa found,
# mapped to MITRE ATT&CK / MBC. capa uses its bundled vivisect backend, so the
# worker needs no native disassembler and no Ghidra. rules are vendored into
# the image (hash-pinned), so nothing is fetched at run time.
#
# capa detects CAPABILITIES, not maliciousness: "communicate over HTTP" is a
# capability, not a verdict. so most capabilities are reported as UNKNOWN
# behavioral evidence (carrying their ATT&CK id for the evidence tree), and
# only genuinely suspicious namespaces (anti-analysis, injection, persistence,
# c2, credential access, impact) escalate to SUSPICIOUS. capa alone never says
# MALICIOUS; the lattice and the other engines own that. this keeps capa from
# flooring every analyzed binary.
#
# the result is one bounded json line on stdout, the same schema every engine
# emits, which the isolated broker validates before any trusted process reads
# it. capa's own logs and progress go to stderr and never touch stdout.

import json
import os
import subprocess
import sys

RULES = os.environ.get("MAL_CAPA_RULES", "/opt/capa/rules")
# FLIRT signatures. capa needs these to analyze PE (it raises OSError without
# them); ELF does not. vendored into the image next to the rules.
SIGS = os.environ.get("MAL_CAPA_SIGS", "/opt/capa/sigs")
CAPA = os.environ.get("MAL_CAPA_BIN", "/opt/venv/bin/capa")
# leave headroom under the jail wall clock so we report a clean timeout instead
# of being killed mid-write.
TIMEOUT = int(os.environ.get("MAL_CAPA_TIMEOUT", "210"))
# stay well under the broker's finding cap and keep the result readable.
MAX_FINDINGS = 400
# hard ceiling on the WHOLE serialized report (see fit_budget): cap_detail bounds
# each finding and MAX_FINDINGS the count, but 400 x ~8 KB can still exceed the
# 1 MiB broker/jail cap and get the ENTIRE report discarded. headroom < 1 MiB.
MAX_TOTAL_BYTES = 900_000

# capa namespaces whose mere presence is suspicious (behavior that benign
# software rarely needs). everything else is UNKNOWN behavioral evidence.
SUSPICIOUS_NS = (
    "anti-analysis",
    "host-interaction/process/inject",
    "host-interaction/bootkit",
    "host-interaction/firmware",
    "persistence",
    "communication/c2",
    "c2",
    "collection/credential",
    "collection/keylog",
    "collection/screenshot",
    "impact",
)

RANK = {"BENIGN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}


def emit(findings, verdict, incomplete):
    sys.stdout.write(
        json.dumps(
            {
                "engine": "mal-capa",
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
# cap and get the WHOLE report rejected. capa details are usually ASCII rule
# namespaces, but a rule name or match string could carry unicode.
def cap_detail(detail):
    b = detail.encode("utf-8", "replace")
    if len(b) <= 8000:
        return detail
    return b[:8000].decode("utf-8", "ignore")


def finding(kind, detail, attck, verdict):
    return {
        "engine": "mal-capa",
        "type": kind,
        "detail": cap_detail(detail),
        "attck": attck[:64],
        "verdict": verdict,
    }


def _report_bytes(findings, incomplete):
    # conservative upper bound: assume the longest verdict token.
    return len(json.dumps({"engine": "mal-capa", "findings": findings, "verdict": "SUSPICIOUS", "incomplete": incomplete}))


def fit_budget(findings, incomplete):
    # guarantee the emitted report fits the pipeline byte cap. cap_detail bounds
    # each finding and MAX_FINDINGS the count, but 400 x ~8 KB can still exceed the
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


# not-applicable: capa could not treat this file as a program (it was not a
# supported executable format). that is not a failure and not suspicious; it is
# simply outside capa's scope, so report an honest empty UNKNOWN.
def not_applicable(reason):
    emit([finding("not-applicable", reason, "", "UNKNOWN")], "UNKNOWN", False)
    sys.exit(0)


# capa_argv is the exact command. keeping it a pure function lets the selftest
# assert the sig/rule wiring: without -s SIGS capa raises OSError on every PE
# and fails closed (the regression that shipped once), so the flag must be here.
def capa_argv(sample):
    return [CAPA, "-q", "-j", "-r", RULES, "-s", SIGS, sample]


# phrases that specifically mean "capa does not support this file type" (magika
# mis-gated a non-executable). narrow and anchored ON PURPOSE: a bare "format"
# or "corrupt" also appears in genuine crash tracebacks, and treating a real
# analysis failure on a confirmed executable as not-applicable would report it
# UNKNOWN+complete, benign-by-omission. anything not matching here fails closed.
NOT_APPLICABLE_HINTS = (
    "not a pe, elf",  # capa: "input file does not appear to be a PE, ELF, or shellcode file"
    "does not appear to be a pe",
    "does not appear to be a supported",
    "input file does not appear",
    "not a supported file",
    "unsupported file type",  # deliberately "file type", NOT "format" (matches format-char errors)
)


# classify_no_output decides what an empty-stdout capa run means. pure and
# testable. only a narrow "unsupported file type" signal is a clean
# not-applicable; every other no-output (crash, timeout, parse abort on a real
# executable) is a hard failure that floors SUSPICIOUS+incomplete.
def classify_no_output(returncode, stderr):
    low = stderr.lower()
    if any(h in low for h in NOT_APPLICABLE_HINTS):
        return "not_applicable", "capa does not analyze this file type"
    return "fail", "capa produced no result (exit %d)" % returncode


# capa maps a capability to a FULL set of ATT&CK techniques plus MBC behaviors,
# and dropping all but the first throws away most of why an analyst runs capa.
# attck_ids returns them all (ATT&CK first, then MBC); attck_of keeps the single
# primary id for the finding's attck chip (the wire field is one string), and
# map_capa_doc appends the whole set to the detail so nothing is lost.
def attck_ids(meta):
    ids = []
    for key in ("attack", "mbc"):
        for item in (meta.get(key) or []):
            if isinstance(item, dict) and item.get("id"):
                ids.append(item["id"])
    return ids


def attck_of(meta):
    ids = attck_ids(meta)
    return ids[0] if ids else ""


def verdict_for(namespace):
    return "SUSPICIOUS" if namespace.startswith(SUSPICIOUS_NS) else "UNKNOWN"


# map_capa_doc turns a capa result document into our findings. pure and
# synthetic-testable (see --selftest), so the mapping is verified at build time
# without depending on any particular sample matching. capa reports behavioral
# capabilities, so most are UNKNOWN evidence carrying their ATT&CK id; only
# suspicious namespaces escalate. a summary finding is always emitted so capa's
# run is visible in the evidence tree even when nothing matched.
def map_capa_doc(doc):
    rules = doc.get("rules") or {}
    findings = []
    worst = "UNKNOWN"
    truncated = False
    for name, entry in rules.items():
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break
        meta = entry.get("meta") or {}
        namespace = meta.get("namespace") or ""
        verdict = verdict_for(namespace)
        detail = ("%s: %s" % (namespace, name)) if namespace else name
        ids = attck_ids(meta)
        # surface the full ATT&CK + MBC set (capa's whole point); the chip keeps
        # the primary id, the detail carries them all.
        if len(ids) > 1:
            detail = "%s [%s]" % (detail, ", ".join(ids))
        findings.append(finding("capability", detail, ids[0] if ids else "", verdict))
        if RANK[verdict] > RANK[worst]:
            worst = verdict
    summary = finding(
        "capa-summary", "capa matched %d capabilities" % len(rules), "", "UNKNOWN"
    )
    findings.insert(0, summary)
    if truncated:
        findings.append(
            finding("capa-cap", "capability list truncated at %d entries" % MAX_FINDINGS, "", "UNKNOWN")
        )
    findings, truncated = fit_budget(findings, truncated)
    return findings, worst, truncated


# a synthetic capa document exercising the mapping: a suspicious namespace, a
# benign one, and a capability with no namespace. run at build time.
def selftest():
    doc = {
        "rules": {
            "inject code into another process": {
                "meta": {"namespace": "host-interaction/process/inject", "attack": [{"id": "T1055"}]}
            },
            "encrypt data using RC4": {
                "meta": {"namespace": "data-manipulation/encryption/rc4", "mbc": [{"id": "C0027"}]}
            },
            "read file": {"meta": {"namespace": "host-interaction/file-system/read"}},
            "bare": {"meta": {}},
            "beacon over http": {
                "meta": {"namespace": "communication/c2",
                         "attack": [{"id": "T1071"}, {"id": "T1071.001"}], "mbc": [{"id": "C0002"}]}
            },
        }
    }
    findings, worst, truncated = map_capa_doc(doc)
    assert worst == "SUSPICIOUS", worst
    assert not truncated
    by_detail = {f["detail"]: f for f in findings}
    assert any(f["type"] == "capa-summary" for f in findings), "summary missing"
    inject = by_detail["host-interaction/process/inject: inject code into another process"]
    assert inject["verdict"] == "SUSPICIOUS" and inject["attck"] == "T1055", inject
    # the full ATT&CK + MBC set is surfaced: primary id on the chip, all ids in
    # the detail (this is capa's whole value, and we used to drop all but one).
    beacon = next(f for f in findings if f["type"] == "capability" and "beacon over http" in f["detail"])
    assert beacon["attck"] == "T1071", beacon
    assert "T1071.001" in beacon["detail"] and "C0002" in beacon["detail"], beacon
    rc4 = by_detail["data-manipulation/encryption/rc4: encrypt data using RC4"]
    assert rc4["verdict"] == "UNKNOWN" and rc4["attck"] == "C0027", rc4
    read = by_detail["host-interaction/file-system/read: read file"]
    assert read["verdict"] == "UNKNOWN", read
    # empty doc -> just a summary, UNKNOWN.
    f2, w2, _ = map_capa_doc({"rules": {}})
    assert w2 == "UNKNOWN" and len(f2) == 1 and f2[0]["type"] == "capa-summary", (w2, f2)

    # the sig/rule wiring must be present: without -s SIGS capa raises OSError on
    # every PE and fails closed. pin the flags and their operands' order.
    argv = capa_argv("/in/sample")
    assert "-s" in argv and argv[argv.index("-s") + 1] == SIGS, argv
    assert "-r" in argv and argv[argv.index("-r") + 1] == RULES, argv
    assert argv[-1] == "/in/sample", argv

    # the fail-closed no-output classifier: only anchored unsupported-format
    # phrases are not-applicable; a crash traceback mentioning "format" or an
    # empty stderr on a confirmed executable is a hard failure, never clean.
    assert classify_no_output(1, "Unsupported format: not a PE, ELF, or shellcode")[0] == "not_applicable"
    assert classify_no_output(1, "input file does not appear to be a PE file")[0] == "not_applicable"
    assert classify_no_output(1, "Traceback ... ValueError: unsupported format character in vivisect")[0] == "fail"
    assert classify_no_output(1, "corrupt section header")[0] == "fail"
    assert classify_no_output(2, "")[0] == "fail"

    # detail is capped by BYTES so a multibyte rule name cannot blow the broker cap.
    assert len(cap_detail("\u4e2d" * 4000).encode("utf-8")) <= 8192

    # a capability-heavy report is trimmed to the pipeline BYTE budget with an
    # output-truncated marker + truncated flag, never discarded wholesale. this is
    # what the byte budget adds atop the per-detail and count caps.
    heavy = {"rules": {("n%04d" % i) + "x" * 7000: {"meta": {"namespace": "communication/c2"}} for i in range(MAX_FINDINGS + 5)}}
    hf, _, htr = map_capa_doc(heavy)
    assert _report_bytes(hf, htr) <= MAX_TOTAL_BYTES, _report_bytes(hf, htr)
    assert htr and any(f["type"] == "output-truncated" for f in hf), "missing byte-cap marker"
    print("mal-capa selftest ok")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return
    sample = sys.argv[1] if len(sys.argv) > 1 else "/in/sample"
    try:
        proc = subprocess.run(
            capa_argv(sample),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        fail("capa analysis exceeded the time budget")
        return
    except Exception as e:  # noqa: BLE001 - any spawn failure is fail-closed
        fail("could not run capa: %s" % type(e).__name__)
        return

    out = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace")

    if not out:
        # no document: only a narrow "unsupported file type" signal is a clean
        # not-applicable; anything else (crash, aborted parse on a real
        # executable) fails closed. see classify_no_output.
        action, detail = classify_no_output(proc.returncode, err)
        if action == "not_applicable":
            not_applicable(detail)
        else:
            fail(detail)
        return

    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        fail("capa output was not valid json")
        return

    findings, worst, truncated = map_capa_doc(doc)
    emit(findings, worst, truncated)


if __name__ == "__main__":
    main()
