# Product

<!-- impeccable:product-schema 1 -->

## Platform

terminal

<!--
Deliberately outside the `web | ios | android | adaptive` vocabulary: loglens is
a full-screen terminal UI (ratatui + crossterm, raw mode, alternate screen,
mouse capture). Treat it as non-native — no iOS or Android design guidance
applies — and never as a browser surface. The user made terminal-only binding
(see Capabilities and Constraints), so this field is not to be "corrected" to
`web`; tooling that does not recognize the value falls back to non-native, which
is the right behavior.
-->

## Users

Three audiences carry **equal weight** — the job is defined by the situation,
not the title: *someone holding a log file they did not write, under time
pressure, needing to name the problem.*

- **AV / endpoint support specialists** — handed a customer diagnostic
  collection (folder or `.zip`), highest volume, least log-tooling expertise,
  usually pasting evidence into a ticket.
- **L2 / escalation engineers** — deeper investigation on a hard case;
  correlating across files in one bundle to confirm or rule out a hypothesis
  before escalating.
- **DevOps / SRE** — their own service, container, or host logs during and
  after an incident; already fluent in `grep`, `less`, `lnav`.

No single workflow gets privileged when they conflict. A change that speeds up
one audience at the cost of another is a regression, not a tradeoff.

## Product Purpose

Turn a handed-over log file or diagnostic bundle into an answer in seconds
instead of minutes of scrolling. loglens opens logs, tints and highlights what
matters, scans for known-bad signals, and lets the reader jump straight to the
evidence — then copy or export it.

Success is the first ninety seconds: open the artifact, spot the trouble,
capture the proof. If the reader still has to scroll to find out whether
something is wrong, the product failed.

## Positioning

Three mechanisms a neighboring tool could not truthfully claim together:

1. **Fully local, no network.** A single binary; no HTTP client in the
   dependency tree (`anyhow`, `clap`, `crossterm`, `ratatui`, `regex`, `zip`).
   Nothing about a customer's logs leaves the machine — which is what makes it
   usable on customer data, in regulated environments, and air-gapped.
2. **Bundle-native ingestion.** Point at a file, a folder (recursive), or a
   `.zip` and every log inside becomes a tab; binaries are skipped and resource
   caps are enforced because the input is assumed untrusted. Not "open a file"
   — "open the collection somebody sent you."
3. **Terminal-speed on large logs.** Chunked scanning keeps the UI responsive
   while search, filter, and jump stay immediate at a quarter-million lines,
   where a GUI or web viewer would stall.

The `Grammarly for logs` tagline names the *posture* — proactive, inline,
explains itself — not a feature to defend.

## Operating Context

- Someone else produced the artifact; the reader has no prior context on the
  system that wrote it. Formats are heterogeneous (AV support collections,
  Splunk exports, Docker logs, plain app logs).
- The work happens over SSH, in a support console, or in a local terminal —
  frequently on a machine where installing a GUI tool is not an option.
- Output is destined for somewhere else: a ticket, a chat thread, a handoff
  note. Yank (`y` / `Y`) and export to `loglens-findings.md` are the exits.
- Requires a real TTY; it does not run headless. `--version` and `--help` are
  the only non-TTY smoke checks.
- A run is one sitting, not a persistent service. There is no server, account,
  telemetry, or shared state.

## Capabilities and Constraints

**Confirmed capabilities:** file / folder / zip ingestion into tabs; keyword and
regex highlights, each with its own color, editable live; level tint for
`ERROR` / `WARN` / `INFO` / `DEBUG` and aliases; search (`/`, `n` / `N`), filter
(`f`), go-to-line (`:`), bookmarks (`m`, `M`); a one-key severity scan (`S`)
with findings panel, severity filter tabs, next/previous finding, and
jump-to-line; export findings to Markdown; horizontal panning for long lines;
in-TUI filesystem browser; full mouse support (wheel, drag scrollbar, click a
highlight to walk its matches); OSC-52 clipboard yank.

**Hard constraints — all future work preserves these:**

- **Terminal-only, permanently.** No browser dashboard, no desktop wrapper, no
  GUI. The TUI is the product surface.
- **Keyboard-first; mouse is an accelerator.** Every action must be reachable by
  key. Mouse support stays strictly additive and never becomes required.
- **Cross-platform terminal parity.** Linux, macOS, and Windows behave the same.
  Nothing that works in only one terminal or on only one OS.
- **No config required to be useful.** First run on a raw log must pay off
  before any keyword, flag, or config file is added. Persisted prefs
  (`~/.config/loglens`: ignore-case, legend visibility, last browser directory)
  are conveniences layered on a good default, never prerequisites.

**Deliberately not positioning — free to change:** the built-in signature
library itself. Its detections, severity assignments, categories, and
plain-English wording are an *implementation* that may be replaced or
superseded. What is durable is the promise it currently keeps — zero setup, and
findings that explain themselves. (Current shape, for reference: `Medium`
through `Critical` only, with no catch-all `ERROR` / `WARN` rule, so a scan
result means something.)

**Technical constraints:** Rust, edition 2024, requires 1.85+; `ratatui` /
`crossterm`; dark palette only, no theme cycling. Resource caps exist because
bundles are untrusted input — 50 MiB per log, 250k lines per file, 1M lines
total, 500 open files, 64 highlight rules, 10k findings, and zip extract
budgets (256 MiB archive, 512 MiB total extracted, 10k entries). Cap constants
live beside the code that enforces them (`ingest.rs`, `app.rs`, `rules.rs`) and
are documented for operators in `docs/USER_GUIDE.md` → "Limits & safety";
update both together.

**Undecided / open:** public release timing. The crate is not on crates.io,
there are no GitHub Release assets, and `scripts/install.sh` is written against
a release that does not exist yet. Source install is the only real path today.
Do not describe binaries, published crates, or install commands as available.

## Brand Commitments

- Name is **loglens**, lowercase, including at the start of a sentence.
- Tagline: **"Grammarly for logs."**
- Voice: plain English, second person, imperative. Explains what a signal
  *means* rather than restating the pattern that matched. Terse over
  enthusiastic; no exclamation marks in product copy.
- Established vocabulary — reuse it, do not resynonymize: *highlight*
  (user-added keyword/regex term), *finding* (a scan hit), *signature* (a
  built-in detection), *scan*, *bundle*, *tab*, *filter*, *bookmark*, *legend*,
  *gutter*, *level tint*. Severity ladder is `CRIT` / `HIGH` / `MED` / `LOW` /
  `INFO`, always rendered as a text label alongside its color.
- MIT licensed. Repository `github.com/dorman/loglens`.

## Evidence on Hand

- `README.md` — features, quick start, first-moves table, ASCII screenshot.
- `docs/USER_GUIDE.md` — the complete guide: every feature, keybinding,
  workflow, limits, troubleshooting, maintainer release steps.
- `AGENTS.md` — code map, hot paths, CI and release workflows, TTY caveat.
- `samples/` — real demo data: `sample.log`, `network.log`, `big.log`, plus a
  fake AV diagnostic bundle as both `bundle/` and `bundle.zip`. `loglens
  samples/bundle` then `S` is the canonical demonstration.
- `loglens-findings.md` at the repo root — a genuine export artifact.
- Inline unit tests in `src/*.rs`; CI on Linux / macOS / Windows.

**Absences that must not be fabricated:** no users, customers, testimonials,
case studies, press, adoption numbers, download counts, or benchmark figures
exist. No logo or wordmark asset beyond the gradient ASCII logo in the welcome
screen. No pricing, no hosted service, no support commitment.

## Product Principles

1. **The reader arrives with no context.** Never assume knowledge of the system
   that produced the log. Anything surfaced explains itself in place.
2. **Value before setup.** The first keystroke on an unknown file has to pay
   off. Configuration is a reward for staying, never a toll for entering.
3. **Serve the situation, not the title.** Support, L2, and DevOps get equal
   weight; optimize the shared job of triaging someone else's log.
4. **Local by default, and that is a feature.** No network is not an omission
   to apologize for — it is what makes loglens safe to point at customer data.
5. **Findings must end somewhere.** Every discovery has a fast path out — jump,
   yank, or export — because the real deliverable is a ticket, not a session.
6. **Untrusted input, bounded behavior.** Bundles are hostile until proven
   otherwise; degrade with a visible cap rather than hanging or dying.

## Accessibility & Inclusion

No formal standard was established. Two product-specific requirements are
confirmed and binding:

- **Keyboard-complete.** Every action reachable without a mouse (see
  Constraints).
- **Color is never the sole carrier of meaning.** Severity always renders its
  text label (`CRIT` / `HIGH` / `MED` / `LOW` / `INFO`) next to its color, so a
  monochrome terminal, a colorblind reader, or a low-contrast theme loses
  nothing. Hold this line for any future signal, and remember the palette
  renders through the user's terminal, whose color fidelity is not ours to
  assume.
