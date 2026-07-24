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
10. [Troubleshooting](#troubleshooting)

---

## Installation

### Prebuilt binary (recommended)

No Rust toolchain required. Download the archive for your OS/CPU from
[GitHub Releases](https://github.com/dorman/loglens/releases), or run:

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/dorman/loglens/master/scripts/install.sh | bash
loglens --version
```

Windows: download the `.zip` asset from the latest release, unpack it, and add
the folder containing `loglens.exe` to your `PATH` (Windows Terminal
recommended).

### From crates.io

Requires Rust **1.85+**:

```sh
cargo install loglens --locked
```

### From a clone

```sh
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

### Publishing a release (maintainers)

```sh
git tag v0.21.0
git push origin v0.21.0
# GitHub Actions builds Linux/macOS/Windows archives and attaches them
# to the release. Then, with crates.io credentials configured:
cargo publish
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
`.bin` files stays clean. Files over 50 MB are skipped.

Zip archives are extracted to a temporary directory and hardened against
hostile input (path traversal and zip-bomb protection built in).

### From inside the TUI (the file browser)

Press `o` anywhere to open the file browser popup:

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

- `Tab` / `Shift-Tab` — switch between tabs
- `w` — close the current file
- `o` — reopen the browser to add more

---

## The viewer

The main screen shows the current log with line numbers, your highlights
colored inline, and (after a scan) a severity dot in the gutter next to
flagged lines.

Navigation:

| Key | Action |
| --- | ------ |
| `j` / `k`, `↓` / `↑` | one line down / up |
| `Ctrl-d` / `Ctrl-u`, `PgDn` / `PgUp` | one page down / up |
| `g` / `G`, `Home` / `End` | top / bottom |
| `n` / `N` | next / previous match (highlights, or search results while searching) |

The scrollbar on the right edge shows your position — click anywhere on it to
jump, or drag the thumb.

The status bar shows `cursor/shown (total)` lines, the number of highlight
matches, and the most useful keys.

---

## Scan: automatic triage

Press **`S`**. loglens runs every open file through its built-in library of
known-bad signatures — no keywords or setup required — and presents a
**findings panel** ranked by severity.

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
  `q`/`Esc` closes.

After a scan, flagged lines keep a colored **severity dot** in the gutter, so
trouble stays visible while you read normally.

Long scans (large bundles) show a live progress bar with a running findings
count — press `Esc` to cancel. Cancelling clears any partial severity dots so
the file does not look half-scanned.

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
| `i` | toggle case-insensitive matching for **all** rules |
| `l` | show/hide the legend panel |

Click a highlight in the legend to jump to its next match; keep clicking to
step through every occurrence (the active rule shows a ▸ marker).

You can also preload highlights from the command line — see
[Command-line reference](#command-line-reference).

---

## Search & filter

| Key | Action |
| --- | ------ |
| `/` | search (case-insensitive, literal text). `n`/`N` walk results, `Esc` clears |
| `f` | **filter mode** — collapse the view to only matching lines |

Filter mode is the biggest time-saver in the tool:

- With a search active, `f` shows **only lines matching the search**.
- With no search, `f` shows **only lines that hit one of your highlights**.

Either way, original line numbers are preserved, so a 10,000-line log
becomes the 40 lines worth reading without losing your place. Press `f`
again to restore the full view.

Search matches render with a bright white highlight, layered on top of any
keyword colors.

---

## Mouse reference

| Action | Result |
| ------ | ------ |
| Wheel over the log | scroll |
| Click a log line | move the cursor there |
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

**Viewer** — `j`/`k` scroll · `Ctrl-d`/`Ctrl-u` page · `g`/`G` top/bottom ·
`n`/`N` next/prev match · `Tab`/`Shift-Tab` switch file · `o` file browser ·
`w` close file · `q` quit

**Scan** — `S` scan · in panel: `j`/`k` move, `Enter` jump, `q`/`Esc` close

**Search & filter** — `/` search · `f` filter · `Esc` clear search

**Highlights** — `a` keyword · `r` regex · `x` remove last · `i` case ·
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
| `-i, --ignore-case` | case-insensitive matching for all rules |
| `--version` | print version |
| `--help` | print CLI help |

Example — open a bundle with a standing rule set:

```sh
loglens -i -k ERROR -k WARN -k "access denied" \
        -r 'powershell\.exe.*-enc' \
        ./diagnostic-bundle/
```

---

## Troubleshooting

**`command not found: cargo` (or `loglens`)**
Your shell predates the Rust install. Run `source "$HOME/.cargo/env"` or open
a new terminal.

**A file won't open / "no log files found"**
Folders and zips only auto-collect files that look like text and are under
50 MB. Files whose first bytes contain NULs are treated as binary and
skipped. Open a specific file directly (`loglens path/to/file`) to bypass
folder collection.

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
