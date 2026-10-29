//! Writes the committed test fixtures from the readable byte-builder in
//! `src/fixtures.rs`.
//!
//!     cargo run --example make_fixtures
//!
//! `tests/fixtures.rs` asserts that the committed files match what this
//! produces, so the `.wasm` files in the repository are never mystery
//! binaries: this program is their source.

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures".to_string())
        .into();
    std::fs::create_dir_all(&dir)?;
    for (filename, bytes) in wasm_capability_audit::fixtures::all() {
        let path = dir.join(filename);
        std::fs::write(&path, &bytes)?;
        println!("{} ({} bytes)", path.display(), bytes.len());
    }
    Ok(())
}
