// mal-extract recursively unpacks archives and embedded objects. it rejects
// path traversal (.. , absolute paths, symlinks) and enforces entry-count,
// compression-ratio, and total-decompressed-size caps so a zip bomb or a
// slip goes nowhere. it wraps c libraries (libarchive, 7z, unrar); their
// unsafety is contained by the sandbox, not by the rust shell.
//
// M0 stub: proves the worker builds. the real unpack and the cap enforcement
// come next. see docs/M0-FIRST-COMMIT.md.

use std::env;

fn main() {
    let path = env::args().nth(1).unwrap_or_default();
    if path.is_empty() {
        eprintln!("usage: mal-extract <artifact-path>");
        std::process::exit(2);
    }
    // TODO(M0): recursive path-safe unpack with caps, emit children over the uds.
    println!("mal-extract stub: would unpack {path}");
}
