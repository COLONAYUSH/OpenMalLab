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
CAPA = os.environ.get("MAL_CAPA_BIN", "/opt/venv/bin/capa")
# leave headroom under the jail wall clock so we report a clean timeout instead
# of being killed mid-write.
TIMEOUT = int(os.environ.get("MAL_CAPA_TIMEOUT", "210"))
# stay well under the broker's finding cap and keep the result readable.
MAX_FINDINGS = 400

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


def finding(kind, detail, attck, verdict):
    return {
        "engine": "mal-capa",
        "type": kind,
        "detail": detail[:8000],
        "attck": attck[:64],
        "verdict": verdict,
    }


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


def attck_of(meta):
    for key in ("attack", "mbc"):
        items = meta.get(key) or []
        if items and isinstance(items[0], dict) and items[0].get("id"):
            return items[0]["id"]
    return ""


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
        findings.append(finding("capability", detail, attck_of(meta), verdict))
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
        }
    }
    findings, worst, truncated = map_capa_doc(doc)
    assert worst == "SUSPICIOUS", worst
    assert not truncated
    by_detail = {f["detail"]: f for f in findings}
    assert any(f["type"] == "capa-summary" for f in findings), "summary missing"
    inject = by_detail["host-interaction/process/inject: inject code into another process"]
    assert inject["verdict"] == "SUSPICIOUS" and inject["attck"] == "T1055", inject
    rc4 = by_detail["data-manipulation/encryption/rc4: encrypt data using RC4"]
    assert rc4["verdict"] == "UNKNOWN" and rc4["attck"] == "C0027", rc4
    read = by_detail["host-interaction/file-system/read: read file"]
    assert read["verdict"] == "UNKNOWN", read
    # empty doc -> just a summary, UNKNOWN.
    f2, w2, _ = map_capa_doc({"rules": {}})
    assert w2 == "UNKNOWN" and len(f2) == 1 and f2[0]["type"] == "capa-summary", (w2, f2)
    print("mal-capa selftest ok")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return
    sample = sys.argv[1] if len(sys.argv) > 1 else "/in/sample"
    try:
        proc = subprocess.run(
            [CAPA, "-q", "-j", "-r", RULES, sample],
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
        # no document: distinguish "not a program capa handles" from a real
        # failure using capa's stderr, and fail closed if unsure.
        low = err.lower()
        if any(k in low for k in ("unsupported", "not a supported", "invalid pe", "corrupt", "format")):
            not_applicable("capa does not analyze this file type")
        fail("capa produced no result (exit %d)" % proc.returncode)
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
