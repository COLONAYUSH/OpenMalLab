// mal-extract unpacks one level of an archive and hands the children back for
// the pipeline to recurse on. archives are the classic malware attack surface,
// so this worker is built to be hostile-input-safe from the first line:
//
//   - zip bombs go nowhere: every read is streamed and capped (per entry and
//     across the whole extraction), so a petabyte-expanding entry stops at the
//     cap and is flagged, never materialized.
//   - zip slip is structurally impossible: children are content-addressed by
//     sha256, so an entry named ../../etc/passwd is written as its hash and its
//     declared path is never touched. we still flag the traversal name as an
//     indicator.
//   - only regular files become children. symlinks, hardlinks, devices, and
//     directories are skipped and flagged; we never create them.
//   - recursion (a zip in a zip) is the orchestrator's job: this worker does
//     exactly one level and reports the children, so depth and total-artifact
//     caps live in the durable workflow, not in a jailed process.
//
// like mal-static-yara this is a pure-rust static binary: the sandbox makes
// parsing hostile bytes safe, and rust keeps our own first-touch code memory
// safe. formats we cannot decompress are skipped per entry and flagged, never
// guessed. it reads /in/sample and writes children into /out (both provided by
// the jail); the manifest leaves as one json line the broker validates.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

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
struct Child {
    sha256: String,
    size: u64,
    name: String,
}

#[derive(Serialize)]
struct Report {
    engine: String,
    findings: Vec<Finding>,
    children: Vec<Child>,
    verdict: String,
    incomplete: bool,
}

// Caps are the whole safety story for a hostile archive. Defaults are tuned for
// the M0 jail (512 MiB memory); tests override them to trigger the limits
// cheaply. Extraction is streamed, so these bound work regardless of what the
// archive's own headers claim their sizes to be.
#[derive(Clone, Copy)]
struct Caps {
    max_total: u64,      // summed child bytes across the whole extraction
    max_entry: u64,      // a single child
    max_entries: usize,  // entries examined (a header-count bomb guard)
    max_children: usize, // children emitted (matches the broker's finding cap)
    ratio_flag: u64,     // uncompressed:compressed ratio that reads as a bomb
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_total: 256 << 20,
            max_entry: 64 << 20,
            max_entries: 10_000,
            max_children: 1_000,
            ratio_flag: 100,
        }
    }
}

const MALICIOUS: &str = "MALICIOUS";
const SUSPICIOUS: &str = "SUSPICIOUS";
const UNKNOWN: &str = "UNKNOWN";

fn rank(v: &str) -> i32 {
    match v {
        MALICIOUS => 3,
        SUSPICIOUS => 2,
        UNKNOWN => 1,
        _ => 0,
    }
}

// why a capped copy stopped, so the caller can decide "skip this entry" (too
// big) versus "stop everything" (total budget spent, i.e. a bomb).
enum CapHit {
    Entry,
    Total,
}

struct Extractor {
    out: std::path::PathBuf,
    caps: Caps,
    input_size: u64,
    total_out: u64,
    seen: HashSet<String>,
    children: Vec<Child>,
    findings: Vec<Finding>,
    incomplete: bool,
    worst: &'static str,
}

impl Extractor {
    fn new(out: impl AsRef<Path>, caps: Caps, input_size: u64) -> Self {
        Extractor {
            out: out.as_ref().to_path_buf(),
            caps,
            input_size,
            total_out: 0,
            seen: HashSet::new(),
            children: Vec::new(),
            findings: Vec::new(),
            incomplete: false,
            worst: UNKNOWN,
        }
    }

    fn note(&mut self, kind: &str, detail: &str, verdict: &'static str) {
        if rank(verdict) > rank(self.worst) {
            self.worst = verdict;
        }
        self.findings.push(Finding {
            engine: "mal-extract".into(),
            kind: kind.into(),
            detail: sanitize(detail),
            attck: String::new(),
            verdict: verdict.into(),
        });
    }

    // stream a reader into a content-addressed child file, hashing as we go and
    // enforcing both the per-entry and the running-total caps. nothing is held
    // in memory beyond an 8 KiB chunk, so a bomb cannot exhaust ram before it
    // trips the cap.
    fn copy_capped<R: Read>(&mut self, mut r: R, tmp: &Path) -> Result<(u64, String), CapHit> {
        let mut f = match File::create(tmp) {
            Ok(f) => f,
            Err(_) => return Err(CapHit::Entry),
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut written: u64 = 0;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    let _ = std::fs::remove_file(tmp);
                    return Err(CapHit::Entry);
                }
            };
            if written + n as u64 > self.caps.max_entry {
                let _ = std::fs::remove_file(tmp);
                return Err(CapHit::Entry);
            }
            if self.total_out + written + n as u64 > self.caps.max_total {
                let _ = std::fs::remove_file(tmp);
                return Err(CapHit::Total);
            }
            if f.write_all(&buf[..n]).is_err() {
                let _ = std::fs::remove_file(tmp);
                return Err(CapHit::Entry);
            }
            hasher.update(&buf[..n]);
            written += n as u64;
        }
        let sha = hex(&hasher.finalize());
        Ok((written, sha))
    }

    // one regular-file entry -> one content-addressed child. returns false when
    // the total budget is spent and extraction must stop.
    fn take_entry<R: Read>(&mut self, raw_name: &str, reader: R) -> bool {
        if self.children.len() >= self.caps.max_children {
            self.incomplete = true;
            self.note(
                "extraction-cap-hit",
                "child count cap reached; remaining entries not extracted",
                SUSPICIOUS,
            );
            return false;
        }
        flag_traversal(self, raw_name);

        let tmp = self.out.join(format!(".partial-{}", self.children.len()));
        match self.copy_capped(reader, &tmp) {
            Ok((size, sha)) => {
                self.total_out += size;
                if self.seen.insert(sha.clone()) {
                    let dst = self.out.join(&sha);
                    if std::fs::rename(&tmp, &dst).is_err() {
                        let _ = std::fs::remove_file(&tmp);
                        self.incomplete = true;
                        self.note("extraction-error", "could not stage a child", SUSPICIOUS);
                        return true;
                    }
                } else {
                    // identical bytes already staged; drop the duplicate.
                    let _ = std::fs::remove_file(&tmp);
                }
                self.children.push(Child {
                    sha256: sha,
                    size,
                    name: sanitize(raw_name),
                });
                true
            }
            Err(CapHit::Entry) => {
                self.incomplete = true;
                self.note(
                    "entry-too-large",
                    &format!("entry '{}' exceeds the per-entry cap; skipped", raw_name),
                    SUSPICIOUS,
                );
                true
            }
            Err(CapHit::Total) => {
                self.incomplete = true;
                self.note(
                    "decompression-bomb",
                    "total extraction size cap reached; likely a decompression bomb",
                    SUSPICIOUS,
                );
                false
            }
        }
    }

    fn extract_zip(&mut self, path: &Path) {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return self.note("extraction-error", &format!("open: {e}"), SUSPICIOUS),
        };
        let mut zip = match zip::ZipArchive::new(file) {
            Ok(z) => z,
            Err(e) => return self.note("extraction-error", &format!("bad zip: {e}"), SUSPICIOUS),
        };
        self.note("archive", "zip", UNKNOWN);
        let count = zip.len().min(self.caps.max_entries);
        if zip.len() > self.caps.max_entries {
            self.incomplete = true;
            self.note(
                "entry-count-cap",
                "zip has more entries than the cap",
                SUSPICIOUS,
            );
        }
        for i in 0..count {
            let entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(_) => {
                    self.incomplete = true;
                    continue;
                }
            };
            let name = entry.name().to_string();
            if entry.is_dir() {
                continue;
            }
            if let Some(mode) = entry.unix_mode() {
                if mode & 0o170000 == 0o120000 {
                    self.note(
                        "skipped-symlink",
                        &format!("symlink entry '{name}' skipped"),
                        SUSPICIOUS,
                    );
                    continue;
                }
            }
            if !self.take_entry(&name, entry) {
                break;
            }
        }
    }

    fn extract_tar<R: Read>(&mut self, reader: R) {
        let mut ar = tar::Archive::new(reader);
        ar.set_ignore_zeros(true);
        let entries = match ar.entries() {
            Ok(e) => e,
            Err(e) => return self.note("extraction-error", &format!("bad tar: {e}"), SUSPICIOUS),
        };
        self.note("archive", "tar", UNKNOWN);
        let mut n = 0usize;
        for entry in entries {
            n += 1;
            if n > self.caps.max_entries {
                self.incomplete = true;
                self.note(
                    "entry-count-cap",
                    "tar has more entries than the cap",
                    SUSPICIOUS,
                );
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    self.incomplete = true;
                    continue;
                }
            };
            let etype = entry.header().entry_type();
            let name = entry
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            if etype.is_dir() {
                continue;
            }
            if etype.is_symlink() || etype.is_hard_link() {
                self.note(
                    "skipped-link",
                    &format!("link entry '{name}' skipped"),
                    SUSPICIOUS,
                );
                continue;
            }
            if !etype.is_file() {
                self.note(
                    "skipped-special",
                    &format!("non-regular entry '{name}' skipped"),
                    SUSPICIOUS,
                );
                continue;
            }
            if !self.take_entry(&name, entry) {
                break;
            }
        }
    }

    fn extract_gzip(&mut self, path: &Path) {
        // peek at the decompressed head: a gzip that wraps a tar is a tar.gz and
        // we stream its entries; anything else is a single gzipped member.
        let mut head = [0u8; 512];
        let n = File::open(path)
            .ok()
            .map(|f| flate2::read::GzDecoder::new(f))
            .and_then(|mut d| d.read(&mut head).ok())
            .unwrap_or(0);
        let is_tar = n >= 262 && &head[257..262] == b"ustar";

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return self.note("extraction-error", &format!("open: {e}"), SUSPICIOUS),
        };
        let gz = flate2::read::GzDecoder::new(file);
        if is_tar {
            self.note("archive", "tar.gz", UNKNOWN);
            self.extract_tar(gz);
        } else {
            self.note("archive", "gzip", UNKNOWN);
            self.take_entry("gunzipped", gz);
        }
    }

    fn into_report(self) -> Report {
        Report {
            engine: "mal-extract".into(),
            findings: self.findings,
            children: self.children,
            verdict: self.worst.into(),
            incomplete: self.incomplete,
        }
    }
}

// content-addressing means a hostile entry name is never used as a path; this
// only raises an indicator so analysts see the attempt.
fn flag_traversal(x: &mut Extractor, raw: &str) {
    let looks_bad = raw.contains("..")
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.chars().nth(1) == Some(':');
    if looks_bad {
        x.note(
            "path-traversal-name",
            &format!("entry name '{raw}' attempts path traversal (neutralized)"),
            SUSPICIOUS,
        );
    }
}

fn detect_and_extract(path: &Path, out: &Path, caps: Caps) -> Report {
    let input_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut head = [0u8; 264];
    let n = File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    let head = &head[..n];

    let mut x = Extractor::new(out, caps, input_size);

    let is_zip = head.len() >= 4
        && head[0] == 0x50
        && head[1] == 0x4b
        && (head[2..4] == [0x03, 0x04] || head[2..4] == [0x05, 0x06] || head[2..4] == [0x07, 0x08]);
    let is_gzip = head.len() >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    let is_tar = head.len() >= 262 && &head[257..262] == b"ustar";

    if is_zip {
        x.extract_zip(path);
    } else if is_gzip {
        x.extract_gzip(path);
    } else if is_tar {
        match File::open(path) {
            Ok(f) => x.extract_tar(f),
            Err(e) => x.note("extraction-error", &format!("open: {e}"), SUSPICIOUS),
        }
    } else {
        // not a container we handle: honest empty result, not a failure.
        x.note(
            "not-an-archive",
            "no supported container format detected",
            UNKNOWN,
        );
    }

    // a wildly high expansion ratio reads as a bomb even if we stayed under the
    // absolute cap.
    if x.input_size > 0
        && x.total_out / x.input_size.max(1) >= caps.ratio_flag
        && x.total_out > (1 << 20)
    {
        x.incomplete = true;
        x.note(
            "high-compression-ratio",
            "decompressed size dwarfs the input; likely a decompression bomb",
            SUSPICIOUS,
        );
    }
    x.into_report()
}

fn out_dir() -> std::path::PathBuf {
    std::env::var("MAL_OUT_DIR")
        .unwrap_or_else(|_| "/out".to_string())
        .into()
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/in/sample".to_string());
    let report = detect_and_extract(Path::new(&path), &out_dir(), Caps::default());
    emit(&report);
}

fn emit(r: &Report) {
    let mut out = std::io::stdout();
    let _ = serde_json::to_writer(&mut out, r);
    let _ = out.write_all(b"\n");
}

// neutralize hostile bytes in any string that will appear in the manifest:
// printable, bounded. the manifest crosses the broker, but defense in depth is
// free here.
fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    if out.len() > 256 {
        out.truncate(256);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    fn tmp_out() -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("malx-{}", std::process::id()));
        // unique per test via a counter folder
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let d = base.join(n.to_string());
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_sample(bytes: &[u8]) -> std::path::PathBuf {
        let d = tmp_out();
        let p = d.join("sample");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    // drive the real dispatch against a written sample, with children staged
    // into a per-test /out (passed explicitly, so tests are race-free).
    fn run(sample: &[u8], caps: Caps) -> (Report, std::path::PathBuf) {
        let p = write_sample(sample);
        let out = tmp_out();
        let rep = detect_and_extract(&p, &out, caps);
        (rep, out)
    }

    #[test]
    fn benign_zip_round_trips_to_children() {
        let z = zip_with(&[("a.txt", b"hello"), ("dir/b.txt", b"world")]);
        let (rep, out) = run(&z, Caps::default());
        assert_eq!(rep.verdict, "UNKNOWN");
        assert!(!rep.incomplete);
        assert_eq!(rep.children.len(), 2);
        for c in &rep.children {
            assert_eq!(c.sha256.len(), 64);
            assert!(out.join(&c.sha256).exists(), "child staged by hash");
        }
        // names are preserved for display but not used as paths.
        assert!(rep.children.iter().any(|c| c.name == "dir/b.txt"));
    }

    #[test]
    fn zip_slip_name_is_neutralized_and_flagged() {
        let z = zip_with(&[("../../etc/passwd", b"root:x:0:0")]);
        let (rep, out) = run(&z, Caps::default());
        // the child exists, but only under its hash, never at the evil path.
        assert_eq!(rep.children.len(), 1);
        assert!(out.join(&rep.children[0].sha256).exists());
        assert!(!Path::new("/etc/passwd_should_not_be_touched").exists());
        assert!(rep
            .findings
            .iter()
            .any(|f| f.kind == "path-traversal-name" && f.verdict == "SUSPICIOUS"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
    }

    #[test]
    fn decompression_bomb_hits_the_total_cap_and_is_flagged() {
        // one entry of highly compressible zeros, extracted under a tiny total
        // cap: it must stop and be called a bomb, never fully written.
        let z = zip_with(&[("bomb", &vec![0u8; 4 << 20])]); // 4 MiB of zeros, compresses tiny
        let caps = Caps {
            max_total: 1 << 20, // 1 MiB total budget
            max_entry: 64 << 20,
            ..Caps::default()
        };
        let (rep, _out) = run(&z, caps);
        assert!(rep.incomplete);
        assert!(rep
            .findings
            .iter()
            .any(|f| f.kind == "decompression-bomb" || f.kind == "high-compression-ratio"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
    }

    #[test]
    fn oversize_entry_is_skipped_not_fatal() {
        let z = zip_with(&[("small", b"ok"), ("big", &vec![7u8; 2 << 20])]);
        let caps = Caps {
            max_entry: 1 << 20, // 1 MiB per entry
            max_total: 256 << 20,
            ..Caps::default()
        };
        let (rep, out) = run(&z, caps);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "entry-too-large"));
        // the small entry still came through.
        assert!(rep.children.iter().any(|c| c.name == "small"));
        assert!(out.join(&rep.children[0].sha256).exists());
    }

    #[test]
    fn duplicate_entries_are_content_deduped() {
        let z = zip_with(&[("a", b"same-bytes"), ("b", b"same-bytes")]);
        let (rep, out) = run(&z, Caps::default());
        // two children reported (two names), one file on disk (one hash).
        assert_eq!(rep.children.len(), 2);
        assert_eq!(rep.children[0].sha256, rep.children[1].sha256);
        let staged: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().len() == 64)
            .collect();
        assert_eq!(staged.len(), 1, "identical children stored once");
    }

    #[test]
    fn gzip_single_member_becomes_one_child() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"just one gzipped blob").unwrap();
        let gz = enc.finish().unwrap();
        let (rep, out) = run(&gz, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].name, "gunzipped");
        assert!(out.join(&rep.children[0].sha256).exists());
    }

    #[test]
    fn not_an_archive_is_empty_not_an_error() {
        let (rep, _out) = run(
            b"just some plain text, definitely not an archive",
            Caps::default(),
        );
        assert_eq!(rep.verdict, "UNKNOWN");
        assert!(!rep.incomplete);
        assert!(rep.children.is_empty());
        assert!(rep.findings.iter().any(|f| f.kind == "not-an-archive"));
    }

    #[test]
    fn entry_count_cap_trips() {
        let entries: Vec<(String, Vec<u8>)> =
            (0..50).map(|i| (format!("f{i}"), vec![b'x'])).collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let z = zip_with(&refs);
        let caps = Caps {
            max_entries: 10,
            ..Caps::default()
        };
        let (rep, _out) = run(&z, caps);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "entry-count-cap"));
        assert!(rep.children.len() <= 10);
    }
}
