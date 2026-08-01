//! Diagnostic command-line client for MAPI over HTTP.
//!
//! This binary exists for two reasons. It is the tool you reach for when a live server is
//! behaving unexpectedly and you need to see the bytes — and it *is* the fixture capture tool
//! driven by `scripts/Capture-Fixtures.ps1`, which means the capture path is exercised by real
//! diagnostic use rather than only by the capture script.
//!
//! Keeping it a separate crate keeps argument parsing, terminal formatting and hex dumping out of
//! the library dependency tree.
//!
//! # Status
//!
//! Pre-release scaffolding; no subcommands are implemented yet.

fn main() {
    // `print_stdout` is denied workspace-wide so that the *libraries* cannot print. A CLI whose
    // entire job is to write to the terminal is the one place that has to opt out, and doing it
    // with a scoped attribute keeps the deny in force for the rest of the file.
    #[expect(clippy::print_stdout, reason = "this binary's output is its purpose")]
    {
        println!(
            "mapi-cli {}: scaffolding, no subcommands yet",
            env!("CARGO_PKG_VERSION")
        );
    }
}
