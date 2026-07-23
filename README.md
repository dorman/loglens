# loglens

A terminal UI that highlights the keywords and patterns you care about in log
files — think Grammarly, but for logs. Point it at diagnostic logs (Splunk
exports, Docker logs, support-tool bundles, etc.), tell it what to watch for,
and it highlights every match in a distinct color, lets you search and filter
down to just the lines that matter, and jumps you between hits so nothing gets
missed.

## Build

```
cargo build --release
```

The binary is at `target/release/loglens`. To put it on your PATH:

```
cargo install --path .
```

## Running it

Just launch it — no arguments required:

```
loglens
```

It opens a built-in **file browser** so you can import logs from inside the TUI.
You can also pass files, folders, or archives directly:

```
loglens agent.log                 # a single file
loglens ./diagnostic-bundle/      # every text log in a folder (recursive)
loglens support-collection.zip    # every text log inside a zip archive
loglens -k ERROR -i agent.log     # preload highlights via flags
```

### CLI options

- `-k, --keyword <KEYWORD>` — literal keyword/phrase to highlight. Repeatable,
  or comma-separated within one flag (`-k "timeout,rollback"`).
- `-r, --regex <PATTERN>` — regex pattern to highlight. Repeatable.
- `-i, --ignore-case` — case-insensitive matching for keywords and regexes.

Everything reachable from flags is also reachable live from inside the TUI —
add highlights with `a`/`r`, import more files with `o`, etc.

## Importing logs (file browser)

| Key             | Action                                        |
| --------------- | --------------------------------------------- |
| `j` / `k`       | move selection                                |
| `Enter` / `l`   | enter a directory, or open the selected file  |
| `h` / `Backspace`| go to the parent directory                   |
| `Space`         | mark / unmark a file                          |
| `o`             | open all marked files                         |
| `O`             | open the selected folder (or `.zip`) recursively |
| `.`             | show / hide hidden files                      |
| `q` / `Esc`     | close the browser                             |

A folder or `.zip` is loaded recursively; every text log inside becomes its own
tab (binary files are skipped automatically).

## Viewer

| Key                | Action                              |
| ------------------ | ----------------------------------- |
| `j` / `↓`, `k` / `↑`| scroll one line                     |
| `Ctrl-d` / `Ctrl-u`| scroll one page                     |
| `g` / `G`          | jump to top / bottom                |
| `n` / `N`          | next / previous match               |
| `Tab` / `Shift-Tab`| switch between open files           |
| `o`                | open the file browser (import more) |
| `w`                | close the current file              |
| `?`                | toggle help overlay                 |
| `q`                | quit                                |

## Scan — the fast lane

Press **`S`** and loglens scans every open file against a built-in library of
known-bad signatures — no keywords required. Large bundles show a **live
progress bar** (with a running findings count) and can be cancelled with `Esc`.
When it finishes you get a **findings panel** ranked by severity, topped with a
**severity distribution bar** that shows the crit/high/med/low/info mix at a
glance:

- Each finding shows its severity (`CRIT`/`HIGH`/`MED`/`LOW`/`INFO`), a title,
  and the `file:line` it was found on.
- The detail box explains *why it matters* in plain English and shows the
  matched line.
- `j`/`k` move, `Enter` (or click) jumps straight to that line, `q` closes.

After a scan, flagged lines get a colored severity dot in the gutter, so trouble
stands out even with the panel closed. The signature library covers signals such
as encoded PowerShell, process injection, living-off-the-land binaries, clock
rollback, certificate-validation failures, corrupt definition databases,
crashes, resource exhaustion, update/install failures, and access-denied errors.

## Mouse

| Action                         | Result                                        |
| ------------------------------ | --------------------------------------------- |
| wheel over the log             | scroll up / down                              |
| click a line                   | move the cursor to it                         |
| click a highlight in the legend| jump to that highlight's next match (repeat to step) |
| click / wheel in the browser popup | select an entry                          |

A scrollbar on the right of the log pane shows your position in the file.

## Search & filter

| Key   | Action                                                          |
| ----- | -------------------------------------------------------------- |
| `/`   | search (case-insensitive); `n`/`N` walk the results, `Esc` clears |
| `f`   | filter — collapse the view to only the lines that match         |

With a search active, `f` shows only lines matching the search. With no search,
`f` shows only lines that hit one of your highlights — turning a 10,000-line log
into just the handful worth reading. Original line numbers are preserved.

## Highlights

| Key   | Action                                          |
| ----- | ----------------------------------------------- |
| `a`   | add a keyword highlight (type it, `Enter`)      |
| `r`   | add a regex highlight                           |
| `x`   | remove the last highlight                       |
| `i`   | toggle case-insensitive matching for all rules  |
| `l`   | toggle the highlights legend                    |

Each rule gets its own color, shown in the legend panel with a live per-file
match count.

### Example

```
loglens -i -k ERROR -k WARN -k ALERT -r 'powershell\.exe.*-enc' ./bundle/
```
