# AGENTS.md

## Cursor Cloud specific instructions

`loglens` is a single-binary Rust terminal UI (TUI) app ("Grammarly for logs"). There is only one service: the CLI/TUI binary itself.

### Toolchain
- The crate uses `edition = "2024"` (see `Cargo.toml`), which requires Rust >= 1.85. The default `rustup` toolchain is set to `stable` (currently 1.97.x). Do not downgrade; the pre-1.85 toolchain fails to even parse the manifest (`feature edition2024 is required`).

### Build / lint / test / run
Standard commands (also documented in `README.md` "Development"):
- Build: `cargo build` / `cargo build --release`
- Lint: `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
- Test: `cargo test` (unit tests live inline in `src/*.rs`; must run from the crate root so `samples/` resolves)
- Run: `cargo run -- samples/bundle` (or any file/folder/.zip)
- Install smoke: `cargo install --path . --locked && loglens --version`

### Running the TUI (non-obvious)
- `loglens` is a full-screen interactive TUI using crossterm raw mode + alternate screen and mouse capture. It requires a real TTY; it does not run headless. To demo it in cloud, run it inside a terminal emulator via computer use, not by piping stdin.
- Useful sample data lives in `samples/` (`sample.log`, `big.log`, `network.log`, `bundle/`, `bundle.zip`).
- Key first moves once open: `S` scan for known-bad signatures, `a` add keyword highlight, `/` search, `f` filter, `?` help, `q` quit.
- CLI-only smoke checks that work without a TTY: `loglens --version` and `loglens --help`.
