# loglens

**Grammarly for logs** — an interactive terminal UI that highlights, scans, and
triages diagnostic logs so you find what matters in seconds instead of
scrolling for minutes.

Built for support specialists, L2 engineers, and DevOps who get handed log
files or diagnostic bundles (AV support collections, Splunk exports, Docker
logs) and need to spot trouble fast.

```text
╭ agent.log ─────────────────────────────────────────────────╮╭ Highlights (click to jump) ─╮
│   3 │ 2026-07-22 10:00:05 WARN  Real-time protection module ││  ██ ERROR kw 4              │
│   4 │ 2026-07-22 10:00:07 ERROR Failed to connect to update ││  ██ WARN  kw 3              │
│   6 │ 2026-07-22 10:00:09 ERROR Certificate validation faile││                             │
│   8 │ 2026-07-22 10:01:03 WARN  Suspicious process detected:││                             │
╰────────────────────────────────────────────────────────────╯╰─────────────────────────────╯
 1/15 shown (15 total) · 7 hl · S scan  / search  f filter  n/N next  o open  a add  ? help
```

## Highlights

- **One-key scan (`S`)** — zero-config detection of known-bad signals (encoded
  PowerShell, cert failures, clock rollback, crashes, …), ranked by severity
  with plain-English explanations and jump-to-line
- **Keyword & regex highlighting** — every tracked term gets its own color;
  add/remove live from inside the TUI
- **Search & filter** — `/` to search, `f` to collapse a 10,000-line log down
  to only the lines that matter
- **Bundle-aware** — open a whole folder or `.zip` diagnostic collection;
  every log inside becomes a tab, binaries are skipped automatically
- **Full mouse support** — wheel scroll, click-drag scrollbar, click a
  highlight to jump through its matches

## Quick start

### 1. Install (pick one)

**Prebuilt binary** (no Rust toolchain required) — from
[GitHub Releases](https://github.com/dorman/loglens/releases):

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/dorman/loglens/master/scripts/install.sh | bash
loglens --version
```

Or download the archive for your platform from the latest release, unpack it,
and put `loglens` on your `PATH`.

**From crates.io** (requires Rust 1.85+):

```sh
cargo install loglens --locked
```

**From source**:

```sh
# Install Rust once: https://rustup.rs  (need 1.85+)
git clone https://github.com/dorman/loglens.git
cd loglens
cargo install --path . --locked
```

Teammates with repo access can also:

```sh
cargo install --git https://github.com/dorman/loglens --locked
```

### 2. Run it

```sh
loglens                      # opens the welcome screen — press o to browse
loglens agent.log            # open one file
loglens ./diag-bundle/       # open every log in a folder (recursive)
loglens support-logs.zip     # open every log inside a zip
```

First moves once you're in:

| Press | To |
| ----- | -- |
| `S`   | scan everything for known-bad signatures, ranked by severity |
| `a`   | add a keyword highlight (each gets its own color) |
| `/`   | search |
| `f`   | filter down to only matching lines |
| `?`   | full keybinding help |
| `q`   | quit |

Try it on the included samples:

```sh
loglens samples/bundle       # a fake AV diagnostic bundle — press S
```

## Documentation

The full guide — every feature, keybinding, workflow, and troubleshooting —
lives in **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**.

## Development

```sh
cargo build            # debug build
cargo test             # unit tests (run from the crate root)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run -- samples/bundle
```

Project layout: `src/app.rs` (state & logic), `src/ui.rs` (rendering),
`src/event.rs` (input), `src/ingest.rs` (file/folder/zip loading),
`src/signatures.rs` (the built-in detection library), `src/theme.rs` (colors).
