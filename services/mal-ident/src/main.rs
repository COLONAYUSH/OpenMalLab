// mal-ident identifies what a file really is, never trusting the extension.
// it is a single-use, credential-less worker: it runs jailed (no network, all
// caps dropped, read-only rootfs, nobody), reads exactly one artifact at
// /in/sample, and emits one bounded json line on stdout that an isolated
// broker validates before any trusted process reads it.
//
// identification is magika, google's content-type model, running in-process
// on the embedded model (pinned by the image digest). the worker IS the
// sandbox, so inferring over hostile bytes in here is exactly what it is for.
// identification is evidence, not judgment: findings carry UNKNOWN, and only
// a failure to analyze raises anything (fail-closed to SUSPICIOUS).

use std::io::Write;

use serde::Serialize;

// ensure_runtime makes the onnx runtime available before magika touches it.
// on linux the runtime is a shared library dlopen'd from a path baked into
// the image (default /opt/onnxruntime/libonnxruntime.so, overridable by
// MAL_ORT_DYLIB for out-of-jail use like ci); loading it here means the jail
// itself needs no environment at all. on macOS the runtime is statically
// linked, so this is a no-op and local dev needs no setup.
#[cfg(target_os = "linux")]
fn ensure_runtime() {
    let path = std::env::var("MAL_ORT_DYLIB")
        .unwrap_or_else(|_| "/opt/onnxruntime/libonnxruntime.so".to_string());
    // init_from loads the dylib; dropping the returned builder uncommitted is
    // fine, magika initializes its own environment against the loaded library.
    let _ = ort::init_from(path);
}

#[cfg(not(target_os = "linux"))]
fn ensure_runtime() {}

#[derive(Serialize)]
struct Finding {
    engine: String,
    #[serde(rename = "type")]
    kind: String,
    detail: String,
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

fn finding(kind: &str, detail: &str) -> Finding {
    Finding {
        engine: "mal-ident".into(),
        kind: kind.into(),
        detail: detail.into(),
        attck: String::new(),
        verdict: "UNKNOWN".into(),
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/in/sample".to_string());

    ensure_runtime();
    let mut session = match magika::Session::new() {
        Ok(s) => s,
        Err(e) => return fail(&format!("model init failed: {e}")),
    };
    let file_type = match session.identify_file_sync(&path) {
        Ok(t) => t,
        Err(e) => return fail(&format!("identify failed: {e}")),
    };

    let info = file_type.info();
    emit(Report {
        engine: "mal-ident".into(),
        findings: vec![
            finding("file-type", info.label),
            finding("mime-type", info.mime_type),
            finding("file-type-group", info.group),
        ],
        verdict: "UNKNOWN".into(),
        incomplete: false,
    });
}

// fail-closed: if the worker cannot analyze, it reports SUSPICIOUS + incomplete.
// it never emits BENIGN by omission.
fn fail(msg: &str) {
    emit(Report {
        engine: "mal-ident".into(),
        findings: vec![Finding {
            engine: "mal-ident".into(),
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
    fn info_of(data: &[u8]) -> &'static magika::TypeInfo {
        super::ensure_runtime();
        let mut s = magika::Session::new().expect("session");
        s.identify_content_sync(data).expect("identify").info()
    }

    #[test]
    fn shell_script_identifies() {
        assert_eq!(info_of(b"#!/bin/sh\necho hello\n").label, "shell");
    }

    #[test]
    fn python_identifies() {
        assert_eq!(
            info_of(b"import os\nfor i in range(10):\n    print(i)\n").label,
            "python"
        );
    }

    #[test]
    fn real_executable_identifies_by_content() {
        // a real system binary lands in the executable group from content
        // alone: elf on linux, mach-o on macos. read the whole file, since a
        // few header bytes are not enough signal for the model to commit.
        let bin = match std::fs::read("/bin/ls") {
            Ok(b) => b,
            Err(_) => return, // no system binary to sample in this environment
        };
        assert_eq!(info_of(&bin).group, "executable");
    }

    #[test]
    fn extension_means_nothing_content_wins() {
        // whatever a file claims to be, only bytes count. plain text stays in
        // the text group no matter what anyone named it.
        assert_eq!(
            info_of(b"just some ordinary notes, nothing else").group,
            "text"
        );
    }
}
