# loglens User Guide

loglens is an interactive terminal UI for reading logs: it highlights the
terms you care about, scans for known-bad patterns with zero configuration,
and collapses big files down to just the lines worth reading.

This guide covers everything. For a 2-minute intro, see the
[README](../README.md).

---

## Contents

1. [Installation](#installation)
2. [Opening logs](#opening-logs)
3. [The viewer](#the-viewer)
4. [Scan: automatic triage](#scan-automatic-triage)
5. [Highlights](#highlights)
6. [Search & filter](#search--filter)
7. [Mouse reference](#mouse-reference)
8. [Keybinding reference](#keybinding-reference)
9. [Command-line reference](#command-line-reference)
10. [Limits & safety](#limits--safety)
11. [Troubleshooting](#troubleshooting)

---

## Installation

loglens is in **pre-release**. Install from source today. Prebuilt GitHub
Release binaries and a crates.io publish are planned for a later public
release — do not treat those paths as live until a `v*` tag exists and the
crate has been published.

### From a clone (current)

Requires Rust **1.85+** (`edition = "2024"`):

```sh
# https://rustup.rs
git clone https://github.com/dorman/loglens.git
cd loglens
cargo install --path . --locked
```

### From GitHub (repo access required)

```sh
cargo install --git https://github.com/dorman/loglens --locked
```

`cargo install` places the binary in `$CARGO_HOME/bin` (usually
`~/.cargo/bin`), which rustup adds to your PATH. Open a new terminal (or
`source "$HOME/.cargo/env"`) and verify:

```sh
loglens --version
```

### Planned: prebuilt binary & crates.io

When the public release lands:

- Download OS/CPU archives from
  [GitHub Releases](https://github.com/dorman/loglens/releases), or run
  `scripts/install.sh` on Linux/macOS. Each release also ships a `SHA256SUMS`
  asset. The installer verifies the archive against it and **refuses to install**
  if the hash does not match, if the asset is not listed, if the release has no
  `SHA256SUMS`, or if no checksum tool is available — it never silently installs
  an unverified binary. Set `SKIP_VERIFY=1` to override that at your own risk.
  After a manual download, verify with `sha256sum -c SHA256SUMS`.
- Or: `cargo install loglens --locked` from crates.io.

### Publishing a release (maintainers — after testing)

Only after merge to `master` and thorough testing (target: later public
release). Then tag for GitHub Release binaries; publish to crates.io
separately when ready:

```sh
git checkout master
git pull
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions attaches Linux/macOS/Windows archives to the release.
# crates.io (optional, separate step — needs credentials):
#   cargo publish
```

### Updating

Re-run the same `cargo install` command with `--force`:

```sh
cargo install --path . --force --locked   # from a clone (after git pull)
```

### Uninstalling

```sh
cargo uninstall loglens
```

---

## Opening logs

### From the command line

```sh
loglens                          # no args: welcome screen
loglens agent.log                # a single file
loglens a.log b.log c.log        # several files -> tabs
loglens ./diagnostic-bundle/     # a folder: every text log inside, recursive
loglens support-collection.zip   # a zip: extracted and loaded the same way
```

Folders and zips are loaded recursively. Every text log becomes its own tab,
named by its relative path (`AV/agent.log`, `system/network.log`). Binary
files are detected and skipped automatically, so a bundle full of `.db` /
`.bin` files stays clean. Empty files, files over **50 MiB**, and files whose
first 8 KiB contain a NUL byte are skipped during collection; a direct open
of a file above 50 MiB is rejected too.

Zip archives are extracted to a temporary directory and hardened against
hostile input (path traversal / zip-slip, archive-size and extract-size
caps, entry-count limits). The extract directory is created fresh — never
reusing an existing path — and on Linux/macOS it is owner-only (`0700`), so
bundle contents are not readable by other users on a shared machine. It is
removed when loglens exits. Auto-collection never follows symlinks and stops
at depth 32 / 2,000 files per resolve — see [Limits & safety](#limits--safety).

### From inside the TUI (the file browser)

Press `o` anywhere to open the file browser popup. The browser reopens at the
last directory you visited (saved in `~/.config/loglens/config`) when that path
still exists; otherwise it starts in the process working directory.

| Key | Action |
| --- | ------ |
| `j` / `k` (or arrows) | move selection |
| `Enter` / `l` | enter a directory, or open the selected file |
| `h` / `Backspace` | go to the parent directory |
| `Space` | mark/unmark a file (mark several to open together) |
| `o` | open all marked files |
| `O` | open the selected folder or `.zip` recursively |
| `.` | show/hide hidden files |
| `q` / `Esc` | close the browser |

You can also click an entry to select it, and wheel-scroll the list.

### Managing open files

- `Tab` / `]` — next tab
- `Shift-Tab` / `[` — previous tab
- click a tab — switch to that file
- `w` — close the current file
- `o` — reopen the browser to add more

---

## The viewer

The main screen shows the current log with line numbers, your highlights
colored inline, and (after a scan) a severity dot in the gutter next to
flagged lines. Bookmarked lines show a diamond (`◆`) in the gutter (and keep
an accent-tinted line number even when a severity dot is also present).

Navigation:

| Key | Action |
| --- | ------ |
| `j` / `k`, `↓` / `↑` | one line down / up |
| `←` / `→` | pan left / right by 8 columns (long lines that clip at the edge) |
| `0` | reset horizontal scroll to column 1 |
| `Ctrl-d` / `Ctrl-u`, `Space` / `PgDn`, `PgUp` | one page down / up |
| `g` / `G`, `Home` / `End` | top / bottom |
| `:` | go to line number (1-based; clamps past the end) |
| `m` | toggle a bookmark on the current line |
| `M` | clear all bookmarks on the current file |
| `'` / `"` | next / previous bookmark (wraps; clears filter if the mark is hidden) |
| `y` | copy the cursor line to the system clipboard (OSC-52) |
| `Y` | copy the current file's path to the system clipboard (OSC-52) |
| `Enter` | jump to the first match (highlights, or search results while searching) |
| `n` / `N` | next / previous match (wraps; highlights, or search results while searching) |

The scrollbar on the right edge shows your position — click anywhere on it to
jump, or drag the thumb.

The status bar stays short on purpose: absolute line (`L42/1200`), highlight
count, filter/search state, truncation hint, ignore-case (`ic` when on),
bookmark count (when any), horizontal column (`col N` when panned), and
cached finding count (`N fd` after a scan) — full keybindings live behind
`?`. Press `:` to jump straight to a line number.

Log lines are soft-tinted by level tokens even before you add highlights
(`ERROR` / `ERR` / `FATAL` / `CRITICAL` / `CRIT`, `WARN` / `WARNING`,
`INFO`, `DEBUG` / `TRACE`). Matching is word-token based (so `TERROR` does
not tint), and the highest severity wins when several tokens appear on one
line.

---

## Scan: automatic triage

**A scan starts on its own.** Opening anything — a file from the command line,
a selection from the browser, a folder or `.zip` — runs every open file through
the built-in library of known-bad signatures and presents a **findings panel**
ranked by severity. No keywords, no setup, no keystroke.

While it runs, the progress bar is the report assembling: its length is real
progress and its color is the severity mix found so far, so a bar that stays
accent-blue means nothing has turned up yet. `Esc` cancels at any point.

Press **`S`** to rescan (after adding highlights, or on files opened with
`--no-scan`). Findings are global, so opening more files rescans the whole set
and keeps one complete report. Pass `--no-scan` when you want to open a large
bundle just to read it.

When a scan finds nothing, no panel opens — the status line reports what was
covered instead, e.g. `scan complete — nothing notable in 9004 lines across 3
files`.

What the library covers: security tampering (protection disabled), encoded
PowerShell commands, process injection, commonly-abused system binaries
(LOLBins), clock/time rollback, certificate-validation failures, corrupt
signature databases, crashes and fatal errors, resource exhaustion
(OOM / disk full), connection refusals, update failures, installer rollbacks,
and access-denied errors. Findings are **Medium severity and above** so a
noisy ERROR/WARN flood cannot bury real triage signals — use keyword
highlights (`a` / `-k ERROR,WARN`) when you want every error line.

In the findings panel:

- The **severity bar** across the top shows the crit/high/med/low/info mix at
  a glance.
- Each finding shows its severity badge, title, and `file:line`.
- The **detail box** explains *why the selected finding matters* in plain
  English, with the matched log line.
- `j`/`k` move · `Enter` (or click a row) jumps straight to that line ·
  `e` exports a markdown summary · `q`/`Esc` closes.

After a scan, flagged lines keep a colored **severity dot** in the gutter, so
trouble stays visible while you read normally. Press **`p`** / **`P`** to walk
next / previous finding in severity order without reopening the panel (wraps;
status shows `finding i/n · SEV · title · file:line`). Press **`s`** to reopen
the findings panel without rescanning (status bar shows `N fd` while findings
are cached). Press **`e`** anytime after a scan to write `loglens-findings.md`
in the current directory — a short triage dump with severity, location, why it
matters, and the matched line. An earlier export is never overwritten: if
`loglens-findings.md` already exists the next one becomes
`loglens-findings-2.md`, then `-3.md`, and the status line reports the exact
path written. The status shows the absolute path, since the export lands in the
directory loglens was started from, not necessarily where the logs came from.

Long scans (large bundles) show a live progress bar with a running findings
count — press `Esc` or `q` to cancel. Cancelling clears any partial severity
dots so the file does not look half-scanned. The findings panel itself caps
at 10,000 hits; if that ceiling is hit the status reads
`scan: N+ findings (capped)` while gutter severity dots still reflect every
matched line.

---

## Highlights

Highlights are your own tracked terms — like Grammarly underlines, but for
the strings you care about. Each rule gets a distinct color, shown in the
legend panel on the right with a live match count.

| Key | Action |
| --- | ------ |
| `a` | add a **keyword** highlight (literal text; type it, `Enter`) |
| `r` | add a **regex** highlight (e.g. `error \d{4}` or `powershell\.exe.*-enc`) |
| `x` | remove the most recently added highlight |
| `i` | toggle case-insensitive matching for **all** rules (saved to `~/.config/loglens/config`) |
| `l` | show/hide the legend panel (also saved to the same config file) |

Click a highlight in the legend to jump to its next match; keep clicking to
step through every occurrence (the active rule shows a ▸ marker).

You can also preload highlights from the command line — see
[Command-line reference](#command-line-reference). At most **64** highlight
rules can be active; regex patterns are capped at **512** bytes and compiled
with size/nest budgets so a pathological pattern cannot hang the TUI.

---

## Search & filter

| Key | Action |
| --- | ------ |
| `/` | search (case-insensitive, literal text). `Enter` jumps to the first hit; `n`/`N` walk results (wraps) |
| `f` | **filter mode** — collapse the view to only matching lines |
| `c` | clear search and filter together (one key) |
| `Esc` | clear search → clear filter → quit (peels one layer at a time) |

Filter mode is the biggest time-saver in the tool:

- With a search active, `f` shows **only lines matching the search**.
- With no search, `f` shows **only lines that hit one of your highlights**.

Either way, original line numbers are preserved, so a 10,000-line log
becomes the 40 lines worth reading without losing your place. If `f` hides
the line you were on, the status bar says so and the cursor moves to the
nearest remaining match. Press `f` again, `c` (clears search and filter
together), or `Esc` once search is cleared to restore the full view.

Search matches render with a bright white highlight, layered on top of any
keyword colors.

---

## Mouse reference

| Action | Result |
| ------ | ------ |
| Wheel over the log | scroll |
| Click a log line | move the cursor there |
| Click a file tab | switch to that file |
| Click the scrollbar track | jump to that position |
| Drag the scrollbar thumb | continuous scroll |
| Click a highlight in the legend | jump through that rule's matches |
| Click a row in the findings panel | jump to that finding's line |
| Click / wheel in the file browser | select entries |

Pasting into the terminal is safe: pasted text is only ever inserted into the
input prompt, never interpreted as keystrokes.

---

## Keybinding reference

Press `?` in the app for this list any time.

**Viewer** — `j`/`k` scroll · `←`/`→` pan · `0` reset pan ·
`Ctrl-d`/`Ctrl-u`/`Space`/`PgDn`/`PgUp` page · `g`/`G`/`Home`/`End`
top/bottom · `:` go to line · `m` bookmark · `M` clear bookmarks ·
`'`/`"` next/prev bookmark · `Enter` first match · `n`/`N` next/prev match
(wraps) · `Tab`/`]` next file · `Shift-Tab`/`[` prev file · `o` file browser ·
`w` close file · `y` copy cursor line · `Y` copy file path · `q` quit

**Scan** — `S` scan · `s` reopen findings · `p`/`P` next/prev finding (wraps) ·
`e` export markdown · in panel: `j`/`k` move, `Enter` jump, `e` export,
`q`/`Esc` close

**Search & filter** — `/` search · `f` filter · `Enter` first match ·
`n`/`N` walk matches (wraps) · `c` clear search+filter · `Esc` clear search →
clear filter → quit

**Highlights** — `a` keyword · `r` regex · `x` remove last · `i` case (persisted) ·
`l` legend

**File browser** — `Enter`/`l` open/enter · `h` parent · `Space` mark ·
`o` open marked · `O` open folder/zip · `.` hidden files · `q` close

---

## Command-line reference

```text
loglens [OPTIONS] [FILES]...
```

| Option | Meaning |
| ------ | ------- |
| `[FILES]...` | files, folders, or `.zip` archives to open (folders/zips recurse) |
| `-k, --keyword <KEYWORD>` | literal keyword highlight; repeatable or comma-separated (`-k "timeout,rollback"`) |
| `-r, --regex <PATTERN>` | regex highlight; repeatable |
| `-i, --ignore-case` | case-insensitive matching for all rules (this session; also OR'd with the saved `i` preference) |
| `--no-scan` | don't scan on open; press `S` when you want it |
| `--version` | print version |
| `--help` | print CLI help |

Preferences: pressing `i` / `l` in the TUI writes `ignore_case` and
`show_legend` (`true|false`) to `~/.config/loglens/config` (or
`$XDG_CONFIG_HOME/loglens/config` / `%APPDATA%\loglens\config` on Windows).
Navigating or leaving the file browser (`o`) also writes `browser_cwd` so the
next launch reopens there when the path still exists. Override the directory
with `LOGLENS_CONFIG_DIR`. The next launch restores those settings; `-i` still
forces ignore-case on for the session.

Example — open a bundle with a standing rule set:

```sh
loglens -i -k ERROR -k WARN -k "access denied" \
        -r 'powershell\.exe.*-enc' \
        ./diagnostic-bundle/
```

---

## Limits & safety

loglens is built to open untrusted diagnostic bundles without exhausting
memory or disk. Caps that most often matter:

| Area | Cap | What happens |
| ---- | --- | ------------ |
| Single log file | **50 MiB** | Skipped in folder/zip collect; direct open rejected |
| Zip archive (compressed) | **256 MiB** | Archive refused before extraction |
| Zip extract / file | **64 MiB** | Oversized entry skipped |
| Zip extract / total | **512 MiB** | Further entries skipped |
| Zip entries scanned | **10,000** | Remainder ignored |
| Dir depth / files per resolve | **32** / **2,000** | Deeper or extra files skipped |
| Symlinks (auto-collect) | never followed | Avoids cycles and escape from the bundle |
| Zip extract directory | fresh, `0700` on Unix | Not reused, not world-readable; removed on exit |
| Lines / file · bytes / line | **250,000** · **32 KiB** | Extra lines dropped; long lines truncated with `…` |
| Open tabs · session lines | **500** · **1,000,000** | Further opens skipped (`open cap reached…`) |
| Highlight rules · regex source | **64** · **512 B** | Add rejected with a status message |
| Scan findings panel | **10,000** (Medium+) | Status shows `… findings (capped)`; gutter still updates |
| Bookmarks / open file | **64** | Toggle rejected with a status message |
| Clipboard yank payload | **~12 KiB** | Longer lines copied truncated (OSC-52) |
| Input prompt (incl. paste) | **4,096** characters | Extra input ignored |

When a file hits the line/length caps the open status notes it was
**truncated**. These numbers live next to the code that enforces them
(`src/ingest.rs`, `src/app.rs`, `src/rules.rs`, `src/clipboard.rs`) — change
the constant and the behavior together.

---

## Troubleshooting

**`command not found: cargo` (or `loglens`)**
Your shell predates the Rust install. Run `source "$HOME/.cargo/env"` or open
a new terminal.

**A file won't open / "no log files found"**
Folders and zips only auto-collect non-empty text-looking files under
50 MiB. Empty files and files whose first 8 KiB contain a NUL are treated as
binary and skipped. Symlinks are never followed during collection. Open a
specific file directly (`loglens path/to/file`) to bypass folder collection
(direct open still rejects files over 50 MiB).

**Status says `open cap reached` or `… truncated`**
You hit the session file/line budget (500 tabs / 1M lines) or a single file
exceeded 250k lines / 32 KiB per line. Close tabs with `w`, or open a smaller
subset of the bundle.

**`highlight limit reached` / regex rejected**
At most 64 highlight rules; regex patterns max 512 bytes and must compile
under the size/nest budgets. Remove a rule with `x` and try a simpler pattern.

**Scan status shows `N+ findings (capped)`**
The findings panel stopped at 10k Medium+ hits. Gutter severity dots still
cover matched lines — jump via the legend/search, or filter with `f`.

**Log shows `�` characters**
The file contains non-UTF-8 bytes (common in real diagnostic logs). loglens
opens it anyway and replaces only the invalid bytes.

**Colors look wrong / washed out**
loglens uses 24-bit color. Use a truecolor-capable terminal (iTerm2, Windows
Terminal, most modern Linux terminals) and make sure `TERM` isn't forced to
an 8-color profile.

**Mouse clicks do nothing over SSH/tmux**
Ensure your terminal forwards mouse events (in tmux: `set -g mouse on`).

**The terminal is garbled after a crash**
loglens restores the terminal even on panics, but if a hard kill (`kill -9`)
leaves things broken, run `reset`.
