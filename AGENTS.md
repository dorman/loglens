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
- Release: hold tagging/`cargo publish` until after merge + thorough testing
  (public release planned later). When ready: tag `v*` on `master` for GitHub
  Release binaries (`.github/workflows/release.yml`); publish to crates.io
  separately only when intentionally cutting that release.

### CI & release
- **PR/CI** (`.github/workflows/rust.yml`): push/PR to `master`; matrix
  `ubuntu-latest` / `macos-latest` / `windows-latest`; steps are
  `fmt --check`, `clippy -D warnings`, `cargo test`, release build, and
  (Unix only) `cargo install --path . --force --locked` + `--version`/`--help`.
- **Tagged release** (`.github/workflows/release.yml`): push `v*` (or
  `workflow_dispatch` with a tag). Builds
  `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`,
  `x86_64-pc-windows-msvc`; archives include the binary + `README.md` +
  `LICENSE`. CI does **not** publish to crates.io.
- **`scripts/install.sh`**: Linux/macOS helper that curls the latest GitHub
  Release asset into `PREFIX`/`BIN_DIR` (default `/usr/local/bin`). Needs a
  published release; not for Windows. Distinguishes HTTP 404 (no release yet)
  from other API failures; both point at source install as fallback.
  Maintainer tag steps live in `docs/USER_GUIDE.md` — do not duplicate them here.

### Code map
Startup wiring (`src/main.rs`): `Cli::parse` → `Theme::dark()` + `rules::build_rules`
→ `App::new` → enable mouse/bracketed paste → `event::run` ⇄ `ui::draw` →
restore terminal (panic hook also clears mouse/paste).

| Module | Role |
| ------ | ---- |
| `cli.rs` | clap: files, `-k`/`-r`/`-i` |
| `app.rs` | State: tabs/files, rules, search/filter, scan, status, open caps, hit-test regions |
| `event.rs` | Modes `Viewer` / `Browser` / `Input`; keys/mouse; scan chunking (`SCAN_CHUNK`); paste only in Input |
| `ui.rs` | Layout: tabs, log+gutter, legend, lean status, welcome / browser / findings / help / input |
| `ingest.rs` | Resolve file/dir/zip → `LoadTarget`s (+ temp dir for zips); collect caps |
| `rules.rs` | Compile keyword/regex highlights with size/nest budgets |
| `signatures.rs` | Built-in Medium–Critical scan library (no catch-all ERROR/WARN) |
| `theme.rs` | Dark palette + level-tint tokens; panel chrome (no theme cycling) |
| `browser.rs` | In-TUI filesystem browser (mark / open / recursive `O`) |
| `clipboard.rs` | OSC-52 yank helpers (`copy_text`) |
| `config.rs` | Tiny `~/.config/loglens` prefs (ignore-case persistence) |

Hot paths worth knowing:
- **Open** → `ingest::resolve` → `LogFile::load` / `rescan` → rebuild filtered view
- **Scan** → `begin_scan` then `scan_step` chunks so the UI stays responsive; cancel clears gutter dots

Safety/resource caps (50 MiB logs, zip extract budgets, 250k lines/file, 64
rules, 10k findings, …) are documented for operators in
`docs/USER_GUIDE.md` → "Limits & safety". Constants live beside the enforcing
code in `ingest.rs` / `app.rs` / `rules.rs` — prefer updating both together.

### Running the TUI (non-obvious)
- `loglens` is a full-screen interactive TUI using crossterm raw mode + alternate screen and mouse capture. It requires a real TTY; it does not run headless. To demo it in cloud, run it inside a terminal emulator via computer use, not by piping stdin.
- Useful sample data lives in `samples/` (`sample.log`, `big.log`, `network.log`, `bundle/`, `bundle.zip`).
- Key first moves once open: `S` scan for known-bad signatures, `a` add keyword highlight, `/` search, `f` filter, `:` go to line, `m` bookmark (`M` clear), `←`/`→` pan long lines, `y`/`Y` yank line/path, `e` export findings, `?` help, `q` quit.
- CLI-only smoke checks that work without a TTY: `loglens --version` and `loglens --help`.
