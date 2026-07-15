// mal-static-yara is a single-use, credential-less worker. in production it runs
// inside a locked-down container (empty netns, seccomp, cap-drop, read-only
// rootfs, tmpfs scratch) and scans exactly one artifact with YARA-X. the sample
// arrives read-only at /in/sample; the result leaves as one json line on stdout,
// which an isolated broker validates before any trusted process reads it. the
// worker holds no network and no store credential. see docs/M0-FIRST-COMMIT.md.
//
// YARA-X runs in-process here on purpose: the worker IS the sandbox, so parsing
// hostile bytes in it is exactly what it is for. rules are TRUSTED input baked
// into the image; the SAMPLE is the hostile input.

use std::fs;
use std::io::Write;

use serde::Serialize;

#[derive(Serialize)]
struct Finding {
    engine: String,
    #[serde(rename = "type")]
    kind: String,
    detail: String, // the rule that matched
    attck: String,
    verdict: String,
}

#[derive(Serialize)]
struct Report {
    engine: String,
    findings: Vec<Finding>,
    verdict: String, // worker-local rolled-up verdict; the orchestrator re-rolls
    incomplete: bool,
}

const RULES: &str = include_str!("../rules/eicar.yar");

// M0 maps a matched rule to (verdict, attck) in code. M1 reads this from the
// rule's own metadata so rules are self-describing.
fn classify(rule: &str) -> (&'static str, &'static str) {
    match rule {
        "eicar_test_file" => ("MALICIOUS", "T1204"),
        _ => ("SUSPICIOUS", ""),
    }
}

fn rank(v: &str) -> i32 {
    match v {
        "MALICIOUS" => 3,
        "SUSPICIOUS" => 2,
        "UNKNOWN" => 1,
        _ => 0, // BENIGN
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/in/sample".to_string());

    let rules = match yara_x::compile(RULES) {
        Ok(r) => r,
        Err(e) => return fail(&format!("rule compile failed: {e}")),
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => return fail(&format!("cannot read sample: {e}")),
    };
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(&data) {
        Ok(s) => s,
        Err(e) => return fail(&format!("scan failed: {e}")),
    };

    let mut findings = Vec::new();
    let mut worst = "UNKNOWN";
    for r in results.matching_rules() {
        let name = r.identifier().to_string();
        let (v, attck) = classify(&name);
        if rank(v) > rank(worst) {
            worst = v;
        }
        findings.push(Finding {
            engine: "mal-static-yara".into(),
            kind: "yara".into(),
            detail: name,
            attck: attck.into(),
            verdict: v.into(),
        });
    }

    emit(Report {
        engine: "mal-static-yara".into(),
        findings,
        verdict: worst.into(),
        incomplete: false,
    });
}

// fail-closed: if the worker cannot analyze, it reports SUSPICIOUS + incomplete.
// it never emits BENIGN by omission.
fn fail(msg: &str) {
    emit(Report {
        engine: "mal-static-yara".into(),
        findings: vec![Finding {
            engine: "mal-static-yara".into(),
            kind: "error".into(),
            detail: msg.to_string(),
            attck: String::new(),
            verdict: "SUSPICIOUS".into(),
        }],
        verdict: "SUSPICIOUS".into(),
        incomplete: true,
    });
}

fn emit(r: Report) {
    let mut out = std::io::stdout();
    let _ = serde_json::to_writer(&mut out, &r);
    let _ = out.write_all(b"\n");
}
