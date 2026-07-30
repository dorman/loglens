---
name: loglens
description: A dark terminal lightbox where log anomalies glow and every finding explains itself.
colors:
  signal-blue: "#61AFEF"
  panel-graphite: "#454C5E"
  paper-white: "#CED3DE"
  slate-mute: "#7C8394"
  gutter-steel: "#5A6172"
  row-wash: "#2E3440"
  status-trench: "#1B1F27"
  status-quartz: "#ABB2BF"
  ink-black: "#14161B"
  search-magnesium: "#F5F5F5"
  logo-cobalt: "#5B84EF"
  logo-turquoise: "#3EE0D8"
  error-coral: "#E06C75"
  warn-amber: "#E5C07B"
  crit-alarm-red: "#FF5555"
  high-ember-orange: "#E88B3D"
  chrome-danger: "#E06C75"
  chrome-marked: "#98C379"
  hl-coral: "#E06C75"
  hl-moss: "#98C379"
  hl-amber: "#E5C07B"
  hl-azure: "#61AFEF"
  hl-orchid: "#C678DD"
  hl-cyan: "#56B6C2"
  hl-tangerine: "#E89B54"
  hl-rose: "#EC8CB0"
  hl-lime: "#B5CE6C"
  hl-mint: "#5FC9A6"
  hl-periwinkle: "#9AA7F0"
  hl-brass: "#D0B06A"
typography:
  display:
    fontFamily: "the terminal's own monospace font — loglens never specifies one"
    fontWeight: 700
    lineHeight: "1 cell"
  headline:
    fontFamily: "the terminal's own monospace font — loglens never specifies one"
    fontWeight: 700
    lineHeight: "1 cell"
  title:
    fontFamily: "the terminal's own monospace font — loglens never specifies one"
    fontWeight: 700
    lineHeight: "1 cell"
  body:
    fontFamily: "the terminal's own monospace font — loglens never specifies one"
    fontWeight: 400
    lineHeight: "1 cell"
  label:
    fontFamily: "the terminal's own monospace font — loglens never specifies one"
    fontWeight: 700
    lineHeight: "1 cell"
rounded:
  panel: "1 cell, arc glyphs (╭ ╮ ╰ ╯)"
  none: "0"
spacing:
  tight: "1 cell"
  glyph: "2 cells"
  gap: "3 cells"
  field: "4 cells"
components:
  panel:
    textColor: "{colors.slate-mute}"
    rounded: "{rounded.panel}"
    padding: "0"
  panel-active:
    textColor: "{colors.signal-blue}"
    typography: "{typography.headline}"
    rounded: "{rounded.panel}"
    padding: "0"
  log-line:
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    padding: "0"
  log-line-cursor:
    backgroundColor: "{colors.row-wash}"
    textColor: "{colors.paper-white}"
    typography: "{typography.label}"
  log-line-gutter:
    textColor: "{colors.gutter-steel}"
    typography: "{typography.body}"
    width: "4 cells minimum, widening to the digit count of the file's last line"
  highlight-span:
    backgroundColor: "{colors.hl-coral}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
  search-match:
    backgroundColor: "{colors.search-magnesium}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
  severity-badge-crit:
    backgroundColor: "{colors.crit-alarm-red}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    padding: "1 cell horizontal"
    width: "6 cells (4-cell left-aligned label plus one cell each side)"
  severity-badge-high:
    backgroundColor: "{colors.high-ember-orange}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    padding: "1 cell horizontal"
    width: "6 cells (4-cell left-aligned label plus one cell each side)"
  severity-badge-med:
    backgroundColor: "{colors.warn-amber}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    padding: "1 cell horizontal"
    width: "6 cells (4-cell left-aligned label plus one cell each side)"
  tab-active:
    backgroundColor: "{colors.signal-blue}"
    textColor: "{colors.ink-black}"
    typography: "{typography.label}"
    padding: "1 cell horizontal"
  tab-inactive:
    textColor: "{colors.slate-mute}"
    typography: "{typography.body}"
    padding: "1 cell horizontal"
  status-bar:
    backgroundColor: "{colors.status-trench}"
    textColor: "{colors.status-quartz}"
    typography: "{typography.body}"
    height: "1 cell"
    padding: "1 cell leading"
  status-bar-message:
    backgroundColor: "{colors.status-trench}"
    textColor: "{colors.signal-blue}"
    typography: "{typography.label}"
    height: "1 cell"
  keycap:
    textColor: "{colors.signal-blue}"
    typography: "{typography.label}"
  input-prompt:
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    rounded: "{rounded.panel}"
    height: "3 cells"
    width: "60% of the terminal width"
---

# Design System: loglens

## Overview

**Creative North Star: "The Radiologist's Lightbox"**

loglens is a dark, evenly-lit field that you hold a log up against so its anomalies glow on their own. The ground is deliberately underexposed — a muted one-dark graphite — not because dark terminals are fashionable, but because tint only carries meaning when nothing around it competes. An `INFO` line recedes into the ground. A `WARN` line warms. An `ERROR` line glows. That gradient is the primary reading instrument, and it works before the user has typed a single keyword.

Reading a lightbox is diagnosis, so a signal is never left to speak for itself. Every marked thing is paired with plain English: a severity finding carries a title, a category, and an explanation of what the condition *means*; an empty state names the key that gets you out of it; a footer spells out its own keycaps. The system is **legible under pressure** first — a tired reader at 2am must never have to decode a color — and **warm and explanatory** second, where warmth means the interface teaches rather than that it softens. There is no pastel here, no illustration, no reassurance. The warmth is entirely in the sentences.

Two anti-references are confirmed and binding. loglens is **not an enterprise SIEM dashboard**: no tiles, no donuts, no KPI panels, no chrome that frames data instead of showing it. And it is **not a neon hacker terminal**: no glow, no blink, no green-on-black, no saturation deployed as personality. Both failures share a root cause — spending attention on the interface that belongs to the evidence. The log is the subject; everything else is apparatus.

**Key Characteristics:**

- A dark, even ground (`#1B1F27`–`#2E3440`) whose job is to stay boring so tint reads
- Four-step level tint applied to raw log text before any user configuration
- A five-step severity scale in which exactly one value is permitted to leave the palette family
- Bold and reverse are the *only* text attributes in the system — no italic, no underline, no blink
- Every judgment is a marginal annotation (`●` `◆` `▸` `██`), never an edit to the log line
- Every colored background carries near-black `#14161B` text, at every size, without exception
- Rounded-arc panels (`╭ ╮ ╰ ╯`) as the single container form
- No shadows, no fake depth: three tonal tiers and a hard popup punch-out

## Colors

A muted one-dark graphite ground carrying two independent color languages — a semantic severity ramp that loglens assigns, and a 12-hue rotation that the user assigns — over near-black text on every filled surface.

### Primary

- **Signal Blue** (`#61AFEF`): the single accent, and the most overloaded token in the system. It marks focus (active panel borders and titles), interactivity (every keycap in every footer), the current selection (active file tab, selected browser row), live progress (the scan gauge), the scrollbar thumb, the input caret, bookmark glyphs, and the `Low` severity step. If something is *reachable or currently yours*, it is Signal Blue.

### Secondary

The severity ramp. This is loglens's own voice — the one place the product asserts a judgment — and it runs `Critical → Info`, always left to right, always with its text label attached.

- **Alarm Red** (`#FF5555`) — `CRIT`: the loudest value in the product and the only one that leaves the one-dark family. See The One Break Rule.
- **Ember Orange** (`#E88B3D`) — `HIGH`: the second rank; warm, unmistakably hotter than amber, still in-family.
- **Warn Amber** (`#E5C07B`) — `MED`: the floor of the shipped signature library. Nothing quieter than this currently appears in a findings list.
- **Signal Blue** (`#61AFEF`) — `LOW`: defined but **latent**, and currently rendered nowhere. The signature library ships nothing below `Medium`; the severity bar skips empty segments; and the panel title, filter tabs, and export header are all derived from the reportable set. Real infrastructure, not dead code — treat it as reserved.
- **Slate Mute** (`#7C8394`) — `INFO`: latent for the same reason.

### Tertiary

The highlight rotation: 12 hues cycled by index as the user adds keyword and regex rules, so each term gets its own identity. This language belongs to the *user*, not the product.

- **Coral** (`#E06C75`), **Moss** (`#98C379`), **Amber** (`#E5C07B`), **Azure** (`#61AFEF`), **Orchid** (`#C678DD`), **Cyan** (`#56B6C2`), **Tangerine** (`#E89B54`), **Rose** (`#EC8CB0`), **Lime** (`#B5CE6C`), **Mint** (`#5FC9A6`), **Periwinkle** (`#9AA7F0`), **Brass** (`#D0B06A`)

Order is load-bearing and it is a contract, not a preference. Four of these twelve values are also semantic elsewhere — coral is the `ERROR` tint, amber is the `WARN` tint and `MED`, azure is the accent plus the `INFO` tint and `LOW`, and tangerine sits one shade off `HIGH` — so a highlight wearing one of them reads as the product's judgment rather than the user's bookkeeping. The four compromised hues are therefore handed out **last**, ranked by how compromised they are, leaving eight clean slots first. Those eight are also ordered for distinguishability: minimum circular hue separation between neighbours is 107°, up from 51° when coral led the list. A test enforces the clean run (`first_rotation_slots_avoid_semantic_colors`), so the rule cannot quietly rot.

The two languages still never occupy the same pixels — a tint is foreground on the log's own ground, a highlight is near-black on a filled block — but that is now the second line of defense rather than the only one. Do not add a 13th hue, and do not reorder the first nine, without checking against all four level tints and all five severity steps.

### Neutral

- **Paper White** (`#CED3DE`): default log text and any line with no detected level. The brightest *unfilled* thing on screen.
- **Status Quartz** (`#ABB2BF`): status-bar text — a step below body, because the status line is reference, not content.
- **Slate Mute** (`#7C8394`): the workhorse recessive tone. Secondary text, explanations, footer prose, inactive panel titles, the `DEBUG`/`TRACE` tint, and the pan-cue chevron.
- **Gutter Steel** (`#5A6172`): line numbers and the `│` rule that separates them from the text. Sits deliberately below Slate Mute — the gutter must be countable without being read.
- **Panel Graphite** (`#454C5E`): inactive panel borders and the scrollbar track. The dimmest structural line in the system.
- **Row Wash** (`#2E3440`): the cursor row and the selected findings row. A background, never a foreground.
- **Status Trench** (`#1B1F27`): the status band, the darkest surface in the product.
- **Ink Black** (`#14161B`): the text color for every filled surface. Never a background.
- **Search Magnesium** (`#F5F5F5`): near-white search-match fill. The only near-white in the palette, and the one value permitted to outshine a highlight — because a search is a question the user asked one second ago.
- **Level tints**: `ERROR` **Error Coral** (`#E06C75`) · `WARN` **Warn Amber** (`#E5C07B`) · `INFO` **Signal Blue** (`#61AFEF`) · `DEBUG`/`TRACE` **Slate Mute** (`#7C8394`).
- **Logo gradient**: **Cobalt** (`#5B84EF`) to **Turquoise** (`#3EE0D8`), interpolated per row across the banner. The only gradient in the product and the only place a decorative color appears.
- **Browser chrome**: `danger` (`#E06C75`) for a failed directory read and `marked` (`#98C379`) for a marked file. These carry the same values as the `ERROR` tint and the moss highlight, but they are their own tokens on purpose — they used to be `palette[0]` and `palette[1]` lookups, which coupled the browser's colors to the highlight rotation's order. They are exempt from the rotation's collision rule because the browser is a punch-out overlay: it is never on screen beside a highlight.

### Named Rules

**The One Break Rule.** Exactly one color in loglens may leave the one-dark family, and it is Alarm Red `#FF5555` on `CRIT`. It outranks the in-family `ERROR` tint `#E06C75` by being *visibly out of place* — that dissonance is the mechanism, not an accident. A second out-of-family value would spend the same rank twice and cost this one its power. Adding one is a violation.

**The Dark-Text-On-Fill Rule.** Every filled surface — severity badge, highlight span, search match, active tab, selected row — pairs its color with Ink Black `#14161B`. No exceptions for "light enough" fills. This is what lets the 12-hue rotation accept any new color without a per-hue contrast decision.

**The Two Languages Rule.** Severity color is the product's judgment; highlight color is the user's bookkeeping. They must never be blended, cross-referenced, or unified into one scale. A finding never adopts a highlight hue, and a highlight never inherits a severity.

**The Label-Always Rule.** Color never carries meaning alone. Every severity renders its text label (`CRIT` `HIGH` `MED` `LOW` `INFO`) adjacent to its color, so a monochrome terminal, a colorblind reader, or a low-fidelity palette loses no information. Any future signal must pass the same test: turn the color off, and the screen must still be readable.

## Typography

**Display Font:** the terminal's own monospace font — loglens never specifies, requests, or ships one.
**Body Font:** the same font. There is exactly one family, and it is not ours.
**Label/Mono Font:** the same font.

**Character:** Typography here is a discipline of restraint rather than selection. With no families, no sizes, and no leading to compose, the entire hierarchy is built from four moves: **weight** (bold or not), **color** (five recessive steps), **case** (the severity labels and level tokens are the log's own uppercase, never ours), and **glyph** (a small vocabulary of box and geometric characters). The result reads as instrumentation because every row occupies exactly one cell of height and every column lands on a grid — a rhythm no proportional system can imitate.

### Hierarchy

- **Display** (bold, 6 rows tall, gradient-filled): the ANSI-Shadow banner on the welcome screen, at 60–61 cells wide, with a 34-cell fallback for narrow panes. The only typographic gesture in the product, and it appears exactly once, before any log is open.
- **Headline** (bold, accent or dim): panel titles, inlaid into the top border (` agent.log [FILTER] [/cert] `). Active panels title in Signal Blue; inactive in Slate Mute. Titles carry live state, which is why they earn bold.
- **Title** (bold when selected, `#CED3DE` otherwise): finding titles in the findings list and the detail header. Bold is the selection cue here, paired with a Row Wash background.
- **Body** (regular, `#CED3DE` or its level tint): the log line itself, and all list rows. Never bold — the log is quoted material, and the system does not editorialize inside it. Only the cursor row goes bold, and only to answer "where am I".
- **Label** (bold, near-black on fill, or accent on ground): severity badges, keycaps, tab labels, repeat counts, the `██` legend swatch. Labels are the smallest unit that carries state, so they are always bold.

### Named Rules

**The Two-Attribute Rule.** Bold and reverse are the only text attributes in this system. No italic, no underline, no strikethrough, and above all no blink. Reverse is reserved for one job (see below).

**The Dim-Is-A-Color Rule.** Recession is expressed with a dimmer *color* — Slate Mute, Gutter Steel, Panel Graphite — never with the terminal `DIM` attribute, which renders inconsistently or not at all across terminals and would silently drop the hierarchy. If something should recede, give it a color, not an attribute.

**The Reverse-For-Selected Rule.** `REVERSED` exists for one purpose: the active severity filter tab. Because those tabs are tinted with the severity palette itself, a terminal that renders those hues faintly would leave the selection ambiguous — reversing the cell makes "selected" structural rather than chromatic. Do not spend reverse anywhere else.

**The Log-Is-Quoted Rule.** Never restyle the log's own text to express your own emphasis. Level tint recolors it; highlights and search fill behind it; nothing bolds, cases, truncates, or rewrites it. Panning horizontally does not even change a line's tint, because the tint is a property of the whole line, not of the slice on screen.

## Layout

The unit is the character cell, and the grid is absolute: every row is exactly one cell tall, and every column is one cell wide. There is no fluid spacing, no optical centering, and no fractional rhythm — only integer counts.

**Vertical structure**, top to bottom: a 3-cell file-tab strip (present only when more than one file is open, so a single-file session gives the log those three rows back), the body at `Min(3)`, and a 1-cell status band pinned to the bottom. The status band is never bordered and never taller than one row.

**Horizontal structure**: the log pane takes `Min(20)` cells; the highlights legend, when shown, is a fixed 34-cell rail on the right. Fixed-versus-flexible is the point — the legend is a reference column whose rows must not reflow while the user reads them, so the log absorbs every terminal resize.

**The log row** composes left to right in fixed zones: a 2-cell annotation slot (`● ` severity dot, `◆ ` bookmark, or two blanks), then the right-aligned line number at a minimum of 4 cells — widening to the digit count of the file's last line, so the `│` rule stays in one column for the entire file — then ` │ `, then an optional `‹` pan cue, then the text. Annotation accrues leftward; the text column never moves.

**Spacing rhythm**: 1 cell separates adjacent spans; 2 cells form the glyph slot; a 3-cell-dot-3-cell separator (`   ·   `) divides metadata groups inside progress and status rows; 4 cells is the minimum gutter. Status metadata joins with ` · ` and appears only when non-default — no filter means no filter segment, not an empty one.

**Overlays** are centered rects, sized by intent rather than a shared modal scale: findings 84%×84% (the working surface — it earns the most room), browser 74%×76%, input 60%×3 cells. The progress overlay, the settings panel and the help sheet are all sized to their own content in cells instead — a live counter, a setting's explanation, or a keybinding row that truncates mid-word is worse than a narrower panel. The help sheet takes the width its widest row needs, reflows into two columns when both fit (~135 cells), and caps its height at 92% of the terminal, scrolling the remainder. The findings panel subdivides its interior into a 1-cell severity bar, a 1-cell filter-tab row, a `Min(3)` list, and a fixed 5-cell detail box — the detail box never grows, so the list is the only thing that responds to height.

**Responsive behavior** is width-driven and discrete. Below roughly 65 cells of pane width the display banner swaps to its 34-cell variant. The legend is a user toggle (`l`, persisted) rather than an automatic breakpoint — loglens does not decide for the user that their terminal is too small. Scrollbars appear only when content overflows, inset one cell from the panel's top and bottom so they never collide with the border arcs.

### Named Rules

**The Held-Row Rule.** A row must not move because state changed elsewhere. Findings scroll position is held in application state, not derived at render time, so the window stays still while the selection moves inside it. A directory-read error takes over the browser's footer row instead of being inserted into the list, because inserting a row would shift every entry and silently break click-to-row mapping. If new information needs a row, take an existing one.

**The Quiet-Default Rule.** Status segments, repeat counts, pan cues, and scrollbars exist only when they carry information. A repeat count is absent at `×1` and emphasized in the severity's own color at `×900`, because the difference between "this happened" and "this happened 900 times" is the whole finding.

## Elevation & Depth

A terminal has no shadows, so depth here is **strictly tonal, in three explicit tiers** — and the absence of shadow is a constraint to design within, never one to simulate.

1. **Ground** — the log field and its panels, on the terminal's own background.
2. **Wash** — Row Wash `#2E3440` on the cursor row and the selected findings row; Status Trench `#1B1F27` on the status band. These read as *nearer* because they are darker and denser than the field, not because they are lifted.
3. **Punch-out** — overlays clear the cells beneath them outright before drawing. A popup does not float above the viewer; it replaces that region of it. Nothing shows through, and nothing is dimmed behind it.

Focus is carried by border color rather than by elevation: an active panel borders and titles in Signal Blue, an inactive one in Panel Graphite. That is the only "raised" signal in the system.

### Named Rules

**The No-Fake-Depth Rule.** Never simulate elevation. No ASCII drop shadows, no offset duplicate borders, no half-block gradients under panels, no dimmed backdrop behind a modal. Three tiers, tonal only. If something needs to feel closer, darken beneath it or give it the accent border.

## Shapes

One container form, one corner language: a full box border in rounded-arc glyphs (`╭ ╮ ╰ ╯` with `─` and `│`), used by every panel — viewer, legend, tabs, findings, browser, help, input, progress. Uniformity is the decision. A second border style would read as a second kind of surface, and loglens has only one kind: a framed region with a titled top edge.

Titles are inlaid into the top border rather than placed below it, which buys back a row and makes the frame carry state instead of merely enclosing it. Centered titles are used exactly once, on the help sheet.

The geometric vocabulary is small and each glyph means one thing: `●` a scanned severity, `◆` a bookmark, `▸` the row being acted on (the active legend rule, the selected setting), `██` a highlight's color swatch, `│` the gutter rule, `‹` content hidden to the left, `›` an input prompt, `█` the input caret, `✓` a marked file, `×N` a repeat count, `▌` the leading edge of work in progress, `░` the part not yet read. Emoji appear in exactly one place — `📁`/`📄` in the file browser — and that is the ceiling, not a precedent.

### Named Rules

**The One-Frame Rule.** Rounded arcs on every panel, no other border type, ever. No double lines, no heavy lines, no borderless "card" surfaces, no dashed dividers.

**The One-Glyph-One-Meaning Rule.** Each glyph in the vocabulary carries exactly one meaning system-wide. Before introducing a new glyph, prove that no existing one covers it — and prove it survives a terminal that renders it as a blank or a double-width cell.

## Components

Components are **explanatory — every surface names its next move**. No panel, empty state, or footer leaves the user without a stated action, and the action is always a literal key rendered as a keycap. This is the mechanism by which the system is warm.

### Panels

- **Shape:** full rounded-arc border (1 cell, `╭ ╮ ╰ ╯`), title inlaid in the top edge.
- **Active:** Signal Blue border, bold Signal Blue title.
- **Inactive:** Panel Graphite border, bold Slate Mute title.
- **Distinctive behavior:** the title is a live status readout, not a static name. The log panel's title accumulates state as the user works — ` agent.log [FILTER] [/cert] ` — so the frame answers "what am I looking at, and what have I done to it".

### Log Line

The signature component. Fixed left-to-right zones: 2-cell annotation slot → right-aligned line number (min 4 cells, Gutter Steel, or Signal Blue when bookmarked) → ` │ ` → optional `‹` → text.

- **Text color:** the line's level tint, computed once per line from its highest-ranking level token (`ERROR`/`ERR`/`FATAL`/`CRITICAL` > `WARN` > `INFO` > `DEBUG`/`TRACE`), falling back to Paper White.
- **Highlight span:** the rule's rotation color as background, Ink Black bold text, square corners.
- **Search match:** Search Magnesium background, Ink Black bold — layered *over* highlight spans, always winning.
- **Cursor row:** Row Wash background plus bold, applied to the whole row including the gutter.

### Severity Badge

- **Style:** severity color as background, Ink Black bold label, left-aligned in a 4-cell field with one cell of padding each side (` CRIT ` / ` HIGH ` / ` MED  `). The fixed field is what keeps a mixed-severity list aligned in one column.
- **In the detail header:** the same badge, followed by the category in Signal Blue, then the bold title, then a dim span statement (`3 hits, lines 412–7781`) when the finding repeats.

### Findings List Row

- **Composition:** badge → title (bold when selected) → repeat count `×N` in the severity's own bold color, omitted at 1 → dim `file:line` location.
- **Selected:** Row Wash background plus bold title. Never a border, never an arrow.

### Severity Bar

A one-cell-tall stacked bar of `█` blocks, Critical to Info left to right, each segment proportional to its share and floored at one cell so a lone Critical is never rounded out of existence. This is the only quantitative graphic in the product, and it is exactly one row tall with no axis, no legend, and no frame — the boundary that separates it from the banned dashboard idiom. Measurement is allowed inline; a panel built around a measurement is not.

### Severity Filter Tabs

- **Style:** ` all 12 `, ` CRIT 3 `, ` HIGH 5 `, ` MED  4 ` — each label paired with its live count, tinted with its own severity color.
- **Active:** `REVERSED` + bold (see The Reverse-For-Selected Rule).
- **Empty:** a tab with zero findings drops to Slate Mute — still selectable, but not competing with tabs that hold something.
- **Trailing:** the `f/F or ←/→` keycap, so the control explains itself in place.

### File Tabs

- **Active:** Signal Blue background, Ink Black bold text, one cell of padding each side.
- **Inactive:** Slate Mute on ground.
- **Title:** ` Files (Tab/]) ` — the panel title carries the keybinding, so the strip teaches its own navigation.

### Status Bar

- **Style:** 1 cell, Status Trench background, Status Quartz text, no border, one leading space.
- **Default content:** ` L4/15 · 7 hl · 2 bm · 7 fd  ·  ? help` — segments joined by ` · `, each appearing only when non-default, and always ending in the help affordance.
- **Message state:** transient messages take the whole band in bold Signal Blue. Voice is lowercase, unpunctuated, and tells you the key to press: `no bookmarks — press m to mark a line`, `line 900 past end — jumped to L412`.

### Input Prompt

- **Style:** 60%-wide, 3-cell rounded panel, `›` prompt in Signal Blue, Paper White text, a `█` block caret in Signal Blue.
- **Title:** states both the task and both exits — ` Add keyword highlight — Enter to go, Esc to cancel `.

### Progress Overlay

- **Style:** a 5-row rounded panel sized to its own rows (never a share of the terminal), with a 44-cell content floor so the bar stays coarse enough to read a severity mix off. Row one is the work bar with a right-aligned percentage in a fixed 5-cell field, so the bar does not shift sideways as the number gains a digit; row two is a live detail row (`1247/9000 lines   ·   4 findings so far`, the count in accent); row three is a dim row naming the current file and `Esc to cancel`.
- **The work bar is the verdict assembling.** Its *length* is real progress and its *composition* is the severity mix found so far — the same Critical→Info order and one-cell floor as the findings panel's severity bar, scaled to the scanned length. A scan that has found nothing fills in Signal Blue, which is the honest reading of "running, clean so far"; the first Critical repaints the run in Alarm Red. By the time the panel opens, the reader has already watched its severity bar form.
- **The head marks the boundary.** `▌` in accent sits between what has been read and what has not, and `░` in Panel Graphite carries the remainder. At 100% both disappear rather than implying more to come.
- **Motion comes only from real work.** The head advances because lines were scanned, never on a timer. A rescan has no verdict to paint, so its bar stays a single accent — same component, one less dimension.
- **Distinctive behavior:** long work is chunked and always cancellable, and the overlay says so. Progress is never shown without an exit.

### Settings Panel

- **Style:** a rounded panel sized to its own rows, opened with `,` (the editor convention for preferences). Interior is a 1-cell pad, one row per setting, a pad, a single dim explanation row for the selected setting, a pad, and a keycapped footer (`j/k move   Enter toggle   Esc close`).
- **A row is `▸ Label      i   [ on]`.** The marker is the same `▸` the legend uses for the row being acted on, and the selected row wears the Row Wash — the same cursor treatment as the log and the findings list. `REVERSED` stays reserved for the severity filter tabs.
- **The value column belongs to the list, not to the panel.** `[ on]` / `[off]` is a fixed 5-cell field pinned to the widest *row*, so a long explanation underneath can widen the panel without stranding the values on the far side of it. On carries the accent; off recedes with a dimmer color, never an attribute.
- **The panel teaches its own shortcut.** A setting that also has a viewer key shows it in accent beside the value (`i`, `l`), so opening settings once is how a user stops needing to open it. A setting with no key shows nothing rather than inventing one.
- **Distinctive behavior:** every row dispatches to the same toggle its keybinding calls, so the panel is a second door onto one behaviour rather than a parallel implementation that can drift. Being the topmost overlay, it claims the whole click — a row toggles, anywhere else is absorbed rather than falling through to the log it covers.

### Empty States

Two cases, distinguished on purpose: a genuinely empty file says `This file has no lines.`, while a filter that excluded everything says `No lines match the current filter.` — never blaming the filter for an empty file, or the file for an aggressive filter. Both offer two keycapped exits.

### Welcome Screen

Vertically centered in the log pane: the gradient banner, the version, the line `highlight what matters in your logs`, then two rows of keycaps (`o` open · `a` add highlight · `S` scan / `?` help · `q` quit). The one place the product is allowed to be decorative — and it disappears permanently the moment a file is open.

## Do's and Don'ts

### Do:

- **Do** let the ground stay underexposed and even. Tint only carries meaning when nothing around it competes; the field's dullness is load-bearing.
- **Do** pair every color with a word. Severity labels (`CRIT`/`HIGH`/`MED`), level tokens, and counts must survive the color being turned off.
- **Do** put Ink Black `#14161B` on every filled surface — badges, highlights, search matches, active tabs, selected rows — without a per-color contrast exception.
- **Do** keep annotation in the margin. Dots, bookmarks, numbers, and cues accrue leftward of the `│`; the log's own text is quoted, never edited.
- **Do** hold the grid: one cell per row, the gutter sized to the file's last line number, the text column fixed for the whole file.
- **Do** end every surface with its next move as a literal keycap in Signal Blue with dim prose beside it.
- **Do** express recession with a dimmer color, and reserve `REVERSED` for the active severity filter tab.
- **Do** show a segment only when it carries information — no `×1`, no empty filter marker, no scrollbar on content that fits.
- **Do** make long work chunked, cancellable, and honest about its progress — and let the progress carry the finding, not just the percentage.
- **Do** tie motion to real work. The bar head moves because lines were read; nothing in this product animates on a timer.
- **Do** distinguish "nothing here" from "nothing matched" in every empty state.
- **Do** let a panel that collects existing commands dispatch to those same commands, and show the keys beside them. A second door onto one behaviour, never a second implementation of it.

### Don't:

- **Don't** add a second out-of-family color. Alarm Red `#FF5555` on `CRIT` is the one permitted break, and a second one costs it its rank.
- **Don't** build a dashboard. No tiles, donuts, gauges-as-decoration, KPI panels, or chart frames. Quantitative graphics stay one row tall and inline, like the severity bar.
- **Don't** reach for neon-terminal affect: no glow, no blink, no green-on-black, no saturation standing in for personality.
- **Don't** use italic, underline, strikethrough, blink, or the terminal `DIM` attribute. Bold and reverse are the whole vocabulary.
- **Don't** simulate depth — no ASCII shadows, offset borders, half-block gradients, or dimmed modal backdrops. Three tonal tiers and a hard punch-out.
- **Don't** introduce a second border style. Rounded arcs on every panel, always.
- **Don't** blend the two color languages: findings never adopt highlight hues, highlights never inherit severities.
- **Don't** let a row move because state changed elsewhere — take an existing row instead of inserting one, and never break click-to-row mapping.
- **Don't** restyle the log's own text for emphasis, or let horizontal panning change a line's tint.
- **Don't** add a 13th highlight hue, or reorder the first nine, without checking against all four level tints and all five severity steps — `first_rotation_slots_avoid_semantic_colors` will fail if you do.
- **Don't** borrow a rotation index for chrome. `danger` and `marked` exist because `palette[0]` and `palette[1]` were standing in for them, which silently coupled the browser's colors to the highlight order.
- **Don't** size a surface to a percentage of the terminal when its content has a natural width. Truncated help, or a truncated live counter, is worse than a narrower panel.
- **Don't** animate on a timer, spin a decorative glyph, or show motion that does not correspond to work actually completing. A bar that moves while nothing happens is a lie.
- **Don't** add emoji beyond the file browser's `📁`/`📄`, or a glyph whose meaning an existing one already carries.
- **Don't** let an overlay pass input through to the surface underneath it. A panel that covers the log owns every click inside its own rect, whether or not the click landed on something actionable — and it owns the keyboard for as long as it is open. Overlays are checked *before* the mode routing, never inside one mode's handler: help is reachable from the browser as well as the viewer, and while its keys lived in the viewer's handler alone, `q` on the help sheet quit the application instead of closing it.
- **Don't** compute a row's layout in two places. The width formula and the row builder must come from one function, or the longest label eventually collides with the column beside it.
- **Don't** specify a font, font size, or line height. The terminal owns those, and assuming otherwise breaks the grid.
