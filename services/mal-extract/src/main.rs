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
//   - the manifest itself is bounded: findings are capped below the broker's
//     limit, so an archive stuffed with thousands of flaggable entries cannot
//     inflate our own report past the trust boundary's caps and get the real
//     children thrown away along with it.
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

// the broker rejects any report with more than 1000 findings, so a hostile
// archive holding thousands of flaggable entries (symlinks, traversal names)
// must not be able to balloon our own manifest past the boundary's cap and get
// the whole report, real children included, thrown away. that would be a cheap
// honest-path evasion: bury the payload under a flag storm. keep one slot in
// reserve for the summary marker that says the list was cut.
const MAX_DETAIL_FINDINGS: usize = 999;

fn rank(v: &str) -> i32 {
    match v {
        MALICIOUS => 3,
        SUSPICIOUS => 2,
        UNKNOWN => 1,
        _ => 0,
    }
}

// why a capped copy stopped, so the caller can decide "skip this entry" (too
// big), "stop everything" (total budget spent, i.e. a bomb), or "this entry's
// stream is broken" (corrupt or truncated data, a failed stage write). the io
// case used to be folded into Entry, which reported a corrupt entry as
// "too large" - wrong telemetry for the analyst reading the findings.
enum CapHit {
    Entry,
    Total,
    Io,
}

struct Extractor {
    out: std::path::PathBuf,
    caps: Caps,
    input_size: u64,
    total_out: u64,
    seen: HashSet<String>,
    children: Vec<Child>,
    findings: Vec<Finding>,
    findings_capped: bool,
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
            findings_capped: false,
            incomplete: false,
            worst: UNKNOWN,
        }
    }

    fn note(&mut self, kind: &str, detail: &str, verdict: &'static str) {
        // the verdict always counts toward the lattice, even when the finding
        // list itself is full: suppressing text must never soften the verdict.
        if rank(verdict) > rank(self.worst) {
            self.worst = verdict;
        }
        if self.findings.len() < MAX_DETAIL_FINDINGS {
            self.findings.push(Finding {
                engine: "mal-extract".into(),
                kind: kind.into(),
                detail: sanitize(detail),
                attck: String::new(),
                verdict: verdict.into(),
            });
        } else if !self.findings_capped {
            self.findings_capped = true;
            self.incomplete = true;
            if rank(SUSPICIOUS) > rank(self.worst) {
                self.worst = SUSPICIOUS;
            }
            self.findings.push(Finding {
                engine: "mal-extract".into(),
                kind: "findings-cap-hit".into(),
                detail: "finding count cap reached; further indicators suppressed".into(),
                attck: String::new(),
                verdict: SUSPICIOUS.into(),
            });
        }
    }

    // stream a reader into a content-addressed child file, hashing as we go and
    // enforcing both the per-entry and the running-total caps. nothing is held
    // in memory beyond an 8 KiB chunk, so a bomb cannot exhaust ram before it
    // trips the cap.
    fn copy_capped<R: Read>(&mut self, mut r: R, tmp: &Path) -> Result<(u64, String), CapHit> {
        let mut f = match File::create(tmp) {
            Ok(f) => f,
            Err(_) => return Err(CapHit::Io),
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
                    return Err(CapHit::Io);
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
                return Err(CapHit::Io);
            }
            hasher.update(&buf[..n]);
            written += n as u64;
        }
        let sha = hex(&hasher.finalize());
        Ok((written, sha))
    }

    // one regular-file entry -> one content-addressed child. returns false when
    // the total budget is spent and extraction must stop. declared is the size
    // the archive header promised, when the format states one: a tar whose data
    // area ends early yields a silently short read (io::Take reports plain EOF),
    // so without this check a truncated archive would pass as a complete child.
    fn take_entry<R: Read>(&mut self, raw_name: &str, reader: R, declared: Option<u64>) -> bool {
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
                if let Some(d) = declared {
                    if size != d {
                        self.incomplete = true;
                        self.note(
                            "entry-truncated",
                            &format!("entry '{raw_name}' declared {d} bytes but yielded {size}"),
                            SUSPICIOUS,
                        );
                    }
                }
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
            Err(CapHit::Io) => {
                self.incomplete = true;
                self.note(
                    "entry-unreadable",
                    &format!(
                        "entry '{}' could not be read or staged (corrupt, truncated, or a failed write); skipped",
                        raw_name
                    ),
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
            Err(e) => {
                // fail closed: a container we could not even open is an
                // incomplete analysis, never a quiet no-op.
                self.incomplete = true;
                return self.note("extraction-error", &format!("open: {e}"), SUSPICIOUS);
            }
        };
        let mut zip = match zip::ZipArchive::new(file) {
            Ok(z) => z,
            Err(e) => {
                self.incomplete = true;
                return self.note("extraction-error", &format!("bad zip: {e}"), SUSPICIOUS);
            }
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
            match zip_kind(entry.unix_mode()) {
                ZipKind::Symlink => {
                    self.note(
                        "skipped-symlink",
                        &format!("symlink entry '{name}' skipped"),
                        SUSPICIOUS,
                    );
                    continue;
                }
                ZipKind::Special => {
                    self.note(
                        "skipped-special",
                        &format!("non-regular entry '{name}' skipped"),
                        SUSPICIOUS,
                    );
                    continue;
                }
                ZipKind::Regular => {}
            }
            // no declared size: the zip reader crc-checks the stream itself and
            // errors on short or corrupt data.
            if !self.take_entry(&name, entry, None) {
                break;
            }
        }
    }

    fn extract_tar<R: Read>(&mut self, reader: R) {
        let mut ar = tar::Archive::new(reader);
        ar.set_ignore_zeros(true);
        let entries = match ar.entries() {
            Ok(e) => e,
            Err(e) => {
                self.incomplete = true;
                return self.note("extraction-error", &format!("bad tar: {e}"), SUSPICIOUS);
            }
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
            // the header's declared size lets take_entry catch a truncated
            // data area, which tar reads as a silent early EOF.
            let declared = entry.size();
            if !self.take_entry(&name, entry, Some(declared)) {
                break;
            }
        }
    }

    fn extract_gzip(&mut self, path: &Path) {
        // peek at the decompressed head: a gzip that wraps a tar is a tar.gz and
        // we stream its entries; anything else is a single gzipped member.
        let mut head = [0u8; 512];
        let n = match File::open(path) {
            Ok(f) => read_head(flate2::read::GzDecoder::new(f), &mut head),
            Err(_) => 0,
        };
        let is_tar = n >= 262 && &head[257..262] == b"ustar";

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                self.incomplete = true;
                return self.note("extraction-error", &format!("open: {e}"), SUSPICIOUS);
            }
        };
        let gz = flate2::read::GzDecoder::new(file);
        if is_tar {
            self.note("archive", "tar.gz", UNKNOWN);
            self.extract_tar(gz);
        } else {
            self.note("archive", "gzip", UNKNOWN);
            self.take_entry("gunzipped", gz, None);
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

// read up to buf.len() head bytes, looping because a single read() call may
// legitimately return short (decompressors often do) and a short peek would
// misclassify a tar.gz as a plain gzip member.
fn read_head<R: Read>(mut r: R, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    n
}

// how a zip entry's unix mode bits say it should be handled. zip has no
// hardlinks; symlinks and the device/fifo/socket family are never followed or
// created, only flagged. absent, zero, or unrecognized mode bits read as a
// regular file, because plenty of real-world (windows-made) zips carry garbage
// there and their bytes are still worth extracting as inert data.
enum ZipKind {
    Regular,
    Symlink,
    Special,
}

fn zip_kind(mode: Option<u32>) -> ZipKind {
    match mode.map(|m| m & 0o170000) {
        Some(0o120000) => ZipKind::Symlink,
        Some(0o010000) | Some(0o020000) | Some(0o060000) | Some(0o140000) => ZipKind::Special,
        _ => ZipKind::Regular,
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
        .map(|f| read_head(f, &mut head))
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
//
// bound to 256 BYTES on a char boundary. entry names are attacker-controlled
// multibyte UTF-8, and String::truncate panics when the index is not a char
// boundary (a 300-byte multibyte name truncated at byte 256 lands mid-char and
// crashes the worker), so build the bounded string char by char and stop before
// a char would cross the budget. one crafted filename must never crash the
// extractor and blind the whole archive subtree.
fn sanitize(s: &str) -> String {
    const MAX_BYTES: usize = 256;
    let mut out = String::with_capacity(MAX_BYTES.min(s.len()));
    for c in s.chars() {
        let c = if c.is_control() || is_bidi_control(c) {
            '.'
        } else {
            c
        };
        if out.len() + c.len_utf8() > MAX_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

// bidi override and isolate characters reorder rendered text: the classic
// "invoice_exe.gpj" that displays as "invoice_gpj.exe". they are format (Cf)
// codepoints, so is_control() alone does not catch them, and a display-only
// entry name has no business steering the reader's text direction.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
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
    fn long_multibyte_entry_name_does_not_panic() {
        // sanitize() once truncated by BYTES, which panics off a char boundary;
        // one attacker-named entry (300 bytes of a 3-byte char) must not crash the
        // extractor and blind the whole archive subtree.
        let name = "\u{4e2d}".repeat(100); // 100 x U+4E2D = 300 utf-8 bytes
        let z = zip_with(&[(name.as_str(), b"payload")]);
        let (rep, out) = run(&z, Caps::default());
        assert_eq!(
            rep.children.len(),
            1,
            "the child must survive, not crash the worker"
        );
        assert!(out.join(&rep.children[0].sha256).exists());
        assert!(
            rep.children[0].name.len() <= 256,
            "display name byte-bounded"
        );
    }

    #[test]
    fn sanitize_is_byte_bounded_and_panic_free() {
        let s = "\u{4e2d}".repeat(100); // 300 bytes of a 3-byte char
        let out = sanitize(&s);
        // stops before crossing 256 bytes, on a char boundary: 85 chars = 255 bytes.
        assert_eq!(out.len(), 255);
        assert_eq!(out.chars().count(), 85);
        // control chars are neutralized, short strings pass through.
        assert_eq!(sanitize("a\u{0}b\u{1b}c"), "a.b.c");
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

    // ---- helpers for building hostile tars in memory ----

    fn tar_bytes(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        build(&mut b);
        b.into_inner().unwrap()
    }

    fn tar_file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        b.append_data(&mut h, name, data).unwrap();
    }

    fn tar_special(
        b: &mut tar::Builder<Vec<u8>>,
        t: tar::EntryType,
        name: &str,
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(t);
        h.set_size(0);
        h.set_mode(0o644);
        if let Some(l) = link {
            h.set_link_name(l).unwrap();
        }
        let _ = h.set_device_major(0);
        let _ = h.set_device_minor(0);
        b.append_data(&mut h, name, std::io::empty()).unwrap();
    }

    fn gz_bytes(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn sha_of(data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    // ---- nested bombs stay inert at this level ----

    #[test]
    fn nested_zip_bomb_is_not_expanded_at_this_level() {
        // a zip whose only child is itself a bomb zip: one level means the
        // inner archive crosses as an inert blob, so even a total cap far
        // smaller than the nested payload must not trip.
        let inner = zip_with(&[("zeros", &vec![0u8; 8 << 20])]);
        let outer = zip_with(&[("inner.zip", &inner)]);
        let caps = Caps {
            max_total: 1 << 20,
            ..Caps::default()
        };
        let (rep, out) = run(&outer, caps);
        assert_eq!(rep.children.len(), 1);
        assert!(
            !rep.incomplete,
            "level one must not expand the nested payload"
        );
        assert!(rep
            .findings
            .iter()
            .all(|f| f.kind != "decompression-bomb" && f.kind != "high-compression-ratio"));
        assert_eq!(rep.children[0].sha256, sha_of(&inner));
        assert_eq!(rep.children[0].size, inner.len() as u64);
        assert!(out.join(&rep.children[0].sha256).exists());
    }

    #[test]
    fn nested_gzip_member_is_extracted_one_level() {
        let inner_gz = gz_bytes(&vec![0u8; 4 << 20]);
        let outer_gz = gz_bytes(&inner_gz);
        let (rep, _out) = run(&outer_gz, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].sha256, sha_of(&inner_gz));
        assert!(rep
            .findings
            .iter()
            .all(|f| f.kind != "decompression-bomb" && f.kind != "high-compression-ratio"));
    }

    #[test]
    fn gzip_bomb_streams_into_the_entry_cap() {
        let gz = gz_bytes(&vec![0u8; 8 << 20]);
        let caps = Caps {
            max_entry: 256 << 10,
            ..Caps::default()
        };
        let (rep, out) = run(&gz, caps);
        assert!(rep.incomplete);
        assert!(rep.children.is_empty());
        assert!(rep.findings.iter().any(|f| f.kind == "entry-too-large"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
        // nothing materialized: the partial staging file is gone too.
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn compression_ratio_flag_fires_even_under_the_absolute_caps() {
        // 4 MiB of zeros deflates to a few KiB: the extraction finishes well
        // inside the absolute caps, but the expansion ratio alone must read as
        // a bomb indicator and mark the analysis incomplete.
        let z = zip_with(&[("zeros", &vec![0u8; 4 << 20])]);
        let (rep, _out) = run(&z, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert!(rep.incomplete);
        assert!(rep
            .findings
            .iter()
            .any(|f| f.kind == "high-compression-ratio" && f.verdict == "SUSPICIOUS"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
    }

    // ---- caps hold exactly at their boundaries ----

    #[test]
    fn per_entry_cap_boundary_exact_fits_one_over_skips() {
        let exact = vec![7u8; 4096];
        let over = vec![8u8; 4097];
        let z = zip_with(&[("exact", &exact), ("over", &over)]);
        let caps = Caps {
            max_entry: 4096,
            ..Caps::default()
        };
        let (rep, _out) = run(&z, caps);
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].name, "exact");
        assert_eq!(rep.children[0].size, 4096);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "entry-too-large"));
    }

    #[test]
    fn total_cap_boundary_exact_fits_one_more_byte_bombs() {
        let a = vec![1u8; 4096];
        let b_ok = vec![2u8; 4096];
        let b_over = vec![2u8; 4097];
        let caps = Caps {
            max_total: 8192,
            ..Caps::default()
        };
        let (rep, _out) = run(&zip_with(&[("a", &a), ("b", &b_ok)]), caps);
        assert_eq!(rep.children.len(), 2);
        assert!(!rep.incomplete, "summing exactly to the cap is not a bomb");
        let (rep, _out) = run(&zip_with(&[("a", &a), ("b", &b_over)]), caps);
        assert_eq!(rep.children.len(), 1);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "decompression-bomb"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
    }

    #[test]
    fn entry_count_cap_boundary_zip_and_tar() {
        let caps = Caps {
            max_entries: 3,
            ..Caps::default()
        };
        let z3 = zip_with(&[("a", b"1"), ("b", b"2"), ("c", b"3")]);
        let (rep, _out) = run(&z3, caps);
        assert!(!rep.incomplete, "exactly at the entry cap is complete");
        assert_eq!(rep.children.len(), 3);
        let z4 = zip_with(&[("a", b"1"), ("b", b"2"), ("c", b"3"), ("d", b"4")]);
        let (rep, _out) = run(&z4, caps);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "entry-count-cap"));
        assert!(rep.children.len() <= 3);

        let t3 = tar_bytes(|b| {
            tar_file(b, "a", b"1");
            tar_file(b, "b", b"2");
            tar_file(b, "c", b"3");
        });
        let (rep, _out) = run(&t3, caps);
        assert!(!rep.incomplete);
        assert_eq!(rep.children.len(), 3);
        let t4 = tar_bytes(|b| {
            tar_file(b, "a", b"1");
            tar_file(b, "b", b"2");
            tar_file(b, "c", b"3");
            tar_file(b, "d", b"4");
        });
        let (rep, _out) = run(&t4, caps);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "entry-count-cap"));
        assert!(rep.children.len() <= 3);
    }

    #[test]
    fn child_count_cap_boundary() {
        let caps = Caps {
            max_children: 2,
            ..Caps::default()
        };
        let (rep, _out) = run(&zip_with(&[("a", b"1"), ("b", b"2")]), caps);
        assert_eq!(rep.children.len(), 2);
        assert!(!rep.incomplete, "exactly at the child cap is complete");
        let (rep, _out) = run(&zip_with(&[("a", b"1"), ("b", b"2"), ("c", b"3")]), caps);
        assert_eq!(rep.children.len(), 2);
        assert!(rep.incomplete);
        assert!(rep.findings.iter().any(|f| f.kind == "extraction-cap-hit"));
    }

    // ---- special entries are flagged, skipped, never followed or created ----

    #[test]
    fn tar_special_entries_are_flagged_skipped_never_created() {
        let t = tar_bytes(|b| {
            tar_file(b, "real.bin", b"the only real child");
            tar_special(b, tar::EntryType::Symlink, "sym", Some("/etc/passwd"));
            tar_special(b, tar::EntryType::Link, "hard", Some("real.bin"));
            tar_special(b, tar::EntryType::Char, "cdev", None);
            tar_special(b, tar::EntryType::Block, "bdev", None);
            tar_special(b, tar::EntryType::Fifo, "pipe", None);
            tar_special(b, tar::EntryType::Directory, "d", None);
        });
        let (rep, out) = run(&t, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].name, "real.bin");
        let links = rep
            .findings
            .iter()
            .filter(|f| f.kind == "skipped-link")
            .count();
        assert_eq!(links, 2, "symlink and hardlink both flagged");
        let specials = rep
            .findings
            .iter()
            .filter(|f| f.kind == "skipped-special")
            .count();
        assert_eq!(specials, 3, "char, block, and fifo all flagged");
        assert_eq!(rep.verdict, "SUSPICIOUS");
        // on disk: exactly one staged file named by hash; no link, device, or
        // directory was ever created, let alone followed.
        let staged: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].file_name().to_string_lossy().len(), 64);
        let md = std::fs::symlink_metadata(staged[0].path()).unwrap();
        assert!(md.is_file() && !md.is_symlink());
        for name in ["sym", "hard", "cdev", "bdev", "pipe", "d"] {
            assert!(!out.join(name).exists(), "{name} must never be created");
        }
    }

    #[test]
    fn zip_symlink_entry_is_flagged_and_skipped() {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default();
            w.start_file("real.txt", opts).unwrap();
            w.write_all(b"real bytes").unwrap();
            w.add_symlink("innocent.txt", "/etc/shadow", opts).unwrap();
            w.finish().unwrap();
        }
        let (rep, out) = run(&buf, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].name, "real.txt");
        assert!(rep
            .findings
            .iter()
            .any(|f| f.kind == "skipped-symlink" && f.verdict == "SUSPICIOUS"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    }

    #[test]
    fn zip_kind_classifies_the_mode_family() {
        assert!(matches!(zip_kind(None), ZipKind::Regular));
        assert!(matches!(zip_kind(Some(0)), ZipKind::Regular));
        assert!(matches!(zip_kind(Some(0o644)), ZipKind::Regular));
        assert!(matches!(zip_kind(Some(0o100644)), ZipKind::Regular));
        assert!(matches!(zip_kind(Some(0o120777)), ZipKind::Symlink));
        assert!(matches!(zip_kind(Some(0o010644)), ZipKind::Special)); // fifo
        assert!(matches!(zip_kind(Some(0o020644)), ZipKind::Special)); // char dev
        assert!(matches!(zip_kind(Some(0o060644)), ZipKind::Special)); // block dev
        assert!(matches!(zip_kind(Some(0o140644)), ZipKind::Special)); // socket
    }

    // ---- truncated and corrupt archives fail closed, never panic ----

    #[test]
    fn truncated_zip_fails_closed() {
        let z = zip_with(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let cut = &z[..z.len() / 2];
        let (rep, _out) = run(cut, Caps::default());
        assert!(rep.children.is_empty());
        assert!(
            rep.incomplete,
            "a container we could not walk is incomplete"
        );
        assert!(rep.findings.iter().any(|f| f.kind == "extraction-error"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
    }

    #[test]
    fn corrupt_zip_entry_data_is_skipped_and_flagged() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            w.start_file("c", opts).unwrap();
            w.write_all(&payload).unwrap();
            w.finish().unwrap();
        }
        // flip a byte inside the stored payload, leaving headers and the
        // central directory intact: the crc check must catch it.
        buf[600] ^= 0xff;
        let (rep, out) = run(&buf, Caps::default());
        assert!(rep.incomplete);
        assert!(
            rep.findings.iter().any(|f| f.kind == "entry-unreadable"),
            "corrupt data must read as unreadable, not as too large: {:?}",
            rep.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
        );
        assert!(rep.children.is_empty());
        assert_eq!(rep.verdict, "SUSPICIOUS");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn truncated_tar_data_is_flagged_never_silently_short() {
        let t = tar_bytes(|b| tar_file(b, "big.bin", &vec![9u8; 4096]));
        let cut = &t[..700]; // header (512) plus 188 bytes of a 4096-byte body
        let (rep, _out) = run(cut, Caps::default());
        assert!(rep.incomplete);
        assert!(
            rep.findings
                .iter()
                .any(|f| f.kind == "entry-truncated" || f.kind == "entry-unreadable"),
            "truncation must surface: {:?}",
            rep.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
        );
        assert_eq!(rep.verdict, "SUSPICIOUS");
        // if the short bytes were kept as a child, the child must carry the
        // real (shorter) size, never the declared one.
        for c in &rep.children {
            assert!(c.size < 4096);
        }
    }

    #[test]
    fn truncated_gzip_fails_closed() {
        let gz = gz_bytes(&vec![7u8; 100_000]);
        let cut = &gz[..gz.len() / 2];
        let (rep, out) = run(cut, Caps::default());
        assert!(rep.incomplete);
        assert!(rep.children.is_empty());
        assert!(rep.findings.iter().any(|f| f.kind == "entry-unreadable"));
        assert_eq!(rep.verdict, "SUSPICIOUS");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn empty_zip_is_complete_and_childless() {
        let z = zip_with(&[]);
        let (rep, _out) = run(&z, Caps::default());
        assert!(rep.children.is_empty());
        assert!(!rep.incomplete);
        assert_eq!(rep.verdict, "UNKNOWN");
        assert!(rep.findings.iter().any(|f| f.kind == "archive"));
    }

    // ---- the manifest itself stays inside the broker's contract ----

    #[test]
    fn findings_are_capped_below_the_broker_limit() {
        // 1200 symlink entries would produce 1200 findings and get the whole
        // manifest, real children included, rejected at the trust boundary.
        let t = tar_bytes(|b| {
            tar_file(b, "real.bin", b"payload");
            for i in 0..1200 {
                tar_special(
                    b,
                    tar::EntryType::Symlink,
                    &format!("s{i}"),
                    Some("/etc/passwd"),
                );
            }
        });
        let (rep, _out) = run(&t, Caps::default());
        assert!(
            rep.findings.len() <= 1000,
            "got {} findings",
            rep.findings.len()
        );
        assert!(rep.findings.iter().any(|f| f.kind == "findings-cap-hit"));
        assert!(rep.incomplete);
        assert_eq!(
            rep.children.len(),
            1,
            "the real child must survive the flag storm"
        );
        assert_eq!(rep.verdict, "SUSPICIOUS");
        let manifest = serde_json::to_vec(&rep).unwrap();
        assert!(
            manifest.len() <= 1 << 20,
            "manifest must fit the broker's input cap, got {} bytes",
            manifest.len()
        );
    }

    #[test]
    fn worst_case_manifest_fits_the_broker_contract() {
        // the absolute worst report we can emit under our own caps: max
        // children with max-length names, max findings with max-length details.
        // it must fit the broker's 1 MiB input cap with room to spare.
        let name = "n".repeat(256);
        let detail = "d".repeat(256);
        let rep = Report {
            engine: "mal-extract".into(),
            findings: (0..1000)
                .map(|_| Finding {
                    engine: "mal-extract".into(),
                    kind: "path-traversal-name".into(),
                    detail: detail.clone(),
                    attck: String::new(),
                    verdict: SUSPICIOUS.into(),
                })
                .collect(),
            children: (0..1000)
                .map(|i| Child {
                    sha256: format!("{i:064x}"),
                    size: u64::MAX,
                    name: name.clone(),
                })
                .collect(),
            verdict: SUSPICIOUS.into(),
            incomplete: true,
        };
        let bytes = serde_json::to_vec(&rep).unwrap();
        assert!(
            bytes.len() <= 1 << 20,
            "worst-case manifest is {} bytes, past the broker cap",
            bytes.len()
        );
    }

    // ---- display-name sanitizing: bidi, boundaries ----

    #[test]
    fn sanitize_neutralizes_bidi_controls() {
        assert_eq!(sanitize("invoice\u{202e}gpj.exe"), "invoice.gpj.exe");
        assert_eq!(
            sanitize("a\u{202a}b\u{202b}c\u{202c}d\u{202d}e"),
            "a.b.c.d.e"
        );
        assert_eq!(sanitize("x\u{2066}y\u{2069}z"), "x.y.z");
        assert_eq!(sanitize("l\u{200e}r\u{200f}m\u{061c}n"), "l.r.m.n");
        // ordinary multibyte text is untouched.
        assert_eq!(sanitize("\u{4e2d}\u{6587}.exe"), "\u{4e2d}\u{6587}.exe");
        assert_eq!(sanitize("emoji\u{1f600}.bin"), "emoji\u{1f600}.bin");
    }

    #[test]
    fn sanitize_exact_byte_boundary_with_multibyte() {
        // 64 four-byte chars fill the 256-byte budget exactly.
        let exact = "\u{1f600}".repeat(64);
        let out = sanitize(&exact);
        assert_eq!(out.len(), 256);
        assert_eq!(out.chars().count(), 64);
        // one more char of any width must stop cleanly at the boundary.
        let over = "\u{1f600}".repeat(65);
        let out = sanitize(&over);
        assert_eq!(out.len(), 256);
        // ascii after 63 four-byte chars: 252 + 4 singles = 256, fifth breaks.
        let mixed = "\u{1f600}".repeat(63) + "abcde";
        let out = sanitize(&mixed);
        assert_eq!(out.len(), 256);
        assert!(out.ends_with("abcd"));
    }

    #[test]
    fn gzip_with_trailing_garbage_still_yields_the_member() {
        // a single-member gzip with junk appended: the decoder stops at the
        // member boundary and the child is the member, not the junk.
        let payload = b"member payload";
        let mut gz = gz_bytes(payload);
        gz.extend_from_slice(b"TRAILING GARBAGE");
        let (rep, _out) = run(&gz, Caps::default());
        assert_eq!(rep.children.len(), 1);
        assert_eq!(rep.children[0].sha256, sha_of(payload));
    }
}
