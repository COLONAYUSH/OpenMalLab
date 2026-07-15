// mal-ident identifies what a file really is, never trusting the extension.
// it runs as a single-use, credential-less worker in an empty network namespace:
// the artifact arrives as a read-only mounted fd, and the result leaves over a
// unix socket to the orchestrator broker. this M0 stub just proves the worker
// builds and runs; the magika model and the sandbox wiring come next.
// see docs/M0-FIRST-COMMIT.md.

use std::env;

fn main() {
    let path = env::args().nth(1).unwrap_or_default();
    if path.is_empty() {
        eprintln!("usage: mal-ident <artifact-path>");
        std::process::exit(2);
    }
    // TODO(M0): run magika over the mounted fd, emit an AnalyzeResult over the uds.
    println!("mal-ident stub: would identify {path}");
}
