use std::collections::BTreeSet;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Clear, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs, Wrap,
};
use regex::Regex;

use crate::app::{
    App, FINDING_FILTERS, InputKind, LogFile, MatchSpan, Mode, SETTINGS, Setting, severity_tally,
};
use crate::rules::Rule;
use crate::signatures::Severity;
use crate::theme::{self, Theme};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    draw_viewer(frame, app, area);

    match app.mode {
        Mode::Input => draw_input(frame, app, area),
        Mode::Browser => draw_browser_popup(frame, app, area),
        Mode::Viewer => {}
    }
    if app.show_findings {
        draw_findings(frame, app, area);
    }
    if app.show_settings {
        draw_settings(frame, app, area);
    }
    if app.show_help {
        draw_help(frame, app, area);
    }
    if app.scanning() {
        draw_scan_progress(frame, app, area);
    } else if app.rescanning() {
        draw_rescan_progress(frame, app, area);
    }
}

/// Cells reserved at the right of the work-bar row for `" 100%"`. Fixed, so the
/// bar does not shift sideways as the number gains a digit.
const PCT_FIELD: u16 = 5;

/// Content-width floor for the progress overlay. Below this the bar is too
/// coarse to read a severity mix off, so the panel keeps the width even when its
/// text rows would fit in less.
const PROGRESS_MIN_CONTENT: u16 = 44;

/// The work bar: length is real progress, composition is the verdict so far.
///
/// `counts` is the severity mix found up to this point — the same stacked bar
/// the findings panel shows, scaled to the scanned length, so the report is
/// already half-read by the time it opens. `None` (or nothing found yet) fills
/// in accent, which is the honest reading of "running, clean so far". `▌` marks
/// the boundary between read and unread, `░` carries the remainder, and both
/// vanish at 100% rather than implying more to come.
fn work_bar(theme: &Theme, counts: Option<[usize; 5]>, frac: f64, width: u16) -> Line<'static> {
    let frac = frac.clamp(0.0, 1.0);
    let bar_width = width.saturating_sub(PCT_FIELD);
    let filled = ((frac * bar_width as f64).round() as u16).min(bar_width);

    let mut spans: Vec<Span<'static>> = Vec::new();
    let segments = counts
        .map(|c| severity_segments(c, filled))
        .unwrap_or_default();
    if segments.is_empty() {
        if filled > 0 {
            spans.push(Span::styled(
                "\u{2588}".repeat(filled as usize),
                Style::default().fg(theme.accent),
            ));
        }
    } else {
        for (sev, seg) in segments {
            spans.push(Span::styled(
                "\u{2588}".repeat(seg),
                Style::default().fg(sev.color()),
            ));
        }
    }

    let remaining = bar_width - filled;
    if remaining > 0 {
        spans.push(Span::styled(
            "\u{258C}",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            "\u{2591}".repeat((remaining - 1) as usize),
            Style::default().fg(theme.border),
        ));
    }

    let pct = (frac * 100.0).round() as u16;
    spans.push(Span::styled(
        format!("{pct:>4}%"),
        Style::default().fg(theme.text),
    ));
    Line::from(spans)
}

/// Everything the progress overlay differs on between a scan and a rescan.
struct WorkProgress<'a> {
    title: &'a str,
    frac: f64,
    /// Severity mix found so far, or `None` for work with no verdict to paint.
    counts: Option<[usize; 5]>,
    info: Line<'static>,
    file_name: String,
}

fn draw_work_progress(frame: &mut Frame, theme: &Theme, area: Rect, work: WorkProgress<'_>) {
    let WorkProgress {
        title,
        frac,
        counts,
        info,
        file_name,
    } = work;

    let sub = Line::from(vec![
        Span::styled(format!(" {file_name}"), dim(theme)),
        Span::styled("      Esc to cancel", dim(theme)),
    ]);

    // Sized to its own rows, not to a share of the terminal: a live counter that
    // truncates mid-number is worse than a narrower panel.
    let content = PROGRESS_MIN_CONTENT
        .max(info.width() as u16 + 1)
        .max(sub.width() as u16 + 1)
        .max(title.chars().count() as u16 + 2);
    let rect = centered_rect_cells(area, content.saturating_add(2), 5);
    let block = theme.panel(title, true);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(work_bar(theme, counts, frac, rows[0].width)),
        rows[0],
    );
    frame.render_widget(Paragraph::new(info), rows[1]);
    frame.render_widget(Paragraph::new(sub), rows[2]);
}

fn draw_scan_progress(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let frac = app.scan_fraction().unwrap_or(0.0);
    let (processed, total, found, file_name) =
        app.scan_detail().unwrap_or((0, 0, 0, String::new()));

    let info = Line::from(vec![
        Span::styled(
            format!(" {processed}/{total} lines"),
            Style::default().fg(t.text),
        ),
        Span::styled("   ·   ", dim(t)),
        Span::styled(
            format!("{found} findings so far"),
            Style::default().fg(t.accent),
        ),
    ]);
    draw_work_progress(
        frame,
        t,
        area,
        WorkProgress {
            title: " Scanning for known-bad signatures… ",
            frac,
            counts: app.scan_severity_counts(),
            info,
            file_name,
        },
    );
}

fn draw_rescan_progress(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let frac = app.rescan_fraction().unwrap_or(0.0);
    let (processed, total, file_name) = app.rescan_detail().unwrap_or((0, 0, String::new()));
    let n_rules = app.rules.len();

    let info = Line::from(vec![
        Span::styled(
            format!(" {processed}/{total} lines"),
            Style::default().fg(t.text),
        ),
        Span::styled("   ·   ", dim(t)),
        Span::styled(
            format!("{n_rules} highlight rule(s)"),
            Style::default().fg(t.accent),
        ),
    ]);
    draw_work_progress(
        frame,
        t,
        area,
        WorkProgress {
            title: " Updating highlights… ",
            frac,
            // A rescan has no verdict to paint — same component, one less dimension.
            counts: None,
            info,
            file_name,
        },
    );
}

/// Inlaid title of the settings panel.
const TITLE: &str = " Settings ";
/// Leading indent on a settings row, before the `▸` marker.
const SETTING_INDENT: usize = 2;
/// `[ on]` / `[off]` — a fixed field, so the values form a column.
const SETTING_VALUE_COL: usize = 5;
/// Cells between the key hint and the value.
const SETTING_GAP: usize = 3;

/// Cells a settings row needs before its value column would crowd its label.
///
/// The list width is the max of this over every row, and `setting_row` lays out
/// against that same number — deriving both from one place is what keeps the
/// longest label from colliding with the key column.
fn setting_row_width(setting: Setting) -> usize {
    let key = setting.key_hint().unwrap_or(" ").chars().count();
    SETTING_INDENT
        + 2
        + setting.label().chars().count()
        + SETTING_GAP
        + key
        + SETTING_GAP
        + SETTING_VALUE_COL
        + 1
}

/// One settings row: `▸ Label            i   [ on]`.
///
/// `column_width` is the width of the *list*, not of the panel: the value column
/// is pinned to the widest row rather than to the panel's right edge, so a long
/// explanation underneath can widen the panel without stranding the values out
/// on the far side of it.
fn setting_row(
    t: &Theme,
    setting: Setting,
    on: bool,
    selected: bool,
    column_width: u16,
) -> Line<'static> {
    let marker = if selected { "\u{25B8} " } else { "  " };
    let left = format!(
        "{:indent$}{marker}{}",
        "",
        setting.label(),
        indent = SETTING_INDENT
    );

    // The key that also does this, so the panel teaches its own shortcut.
    let key = setting.key_hint().unwrap_or(" ");
    let value = if on { "[ on]" } else { "[off]" };
    let right_width = key.chars().count() + SETTING_GAP + SETTING_VALUE_COL + 1;
    let filler = (column_width as usize).saturating_sub(left.chars().count() + right_width);

    Line::from(vec![
        Span::styled(left, Style::default().fg(t.text)),
        Span::raw(" ".repeat(filler)),
        Span::styled(key.to_string(), Style::default().fg(t.accent)),
        Span::raw(" ".repeat(SETTING_GAP)),
        Span::styled(
            value.to_string(),
            // On is the product doing something, so it carries the accent; off
            // recedes with a dimmer color rather than an attribute.
            if on {
                Style::default().fg(t.accent)
            } else {
                dim(t)
            },
        ),
    ])
}

fn draw_settings(frame: &mut Frame, app: &mut App, area: Rect) {
    let t = &app.theme;
    let sel = app.settings_sel.min(SETTINGS.len() - 1);
    let detail = SETTINGS[sel].detail();
    let footer = Line::from(vec![
        Span::styled("  j/k", Style::default().fg(t.accent)),
        Span::styled(" move   ", dim(t)),
        Span::styled("Enter", Style::default().fg(t.accent)),
        Span::styled(" toggle   ", dim(t)),
        Span::styled("Esc", Style::default().fg(t.accent)),
        Span::styled(" close", dim(t)),
    ]);

    // Sized to its own rows, like the progress overlay and the help sheet: a
    // setting whose explanation wraps mid-word is worse than a wider panel.
    let widest_row = SETTINGS
        .iter()
        .map(|s| setting_row_width(*s))
        .max()
        .unwrap_or(0);
    // +1 so the longest explanation never sits flush against the border.
    let widest_detail = SETTINGS
        .iter()
        .map(|s| SETTING_INDENT + s.detail().chars().count() + 1)
        .max()
        .unwrap_or(0);
    let content = widest_row
        .max(widest_detail)
        .max(footer.width())
        .max(TITLE.chars().count() + 2) as u16;

    let rows_tall = SETTINGS.len() as u16;
    // pad · rows · pad · detail · pad · footer
    let rect = centered_rect_cells(area, content.saturating_add(2), rows_tall + 7);
    let block = t.panel(TITLE, true);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(rows_tall),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    app.regions.settings_list = parts[1];

    for (i, setting) in SETTINGS.iter().enumerate() {
        let row = Rect {
            y: parts[1].y + i as u16,
            height: 1,
            ..parts[1]
        };
        let selected = i == sel;
        let line = setting_row(
            t,
            *setting,
            app.setting_value(*setting),
            selected,
            widest_row as u16,
        );
        let mut para = Paragraph::new(line);
        if selected {
            // Row wash marks the cursor row here exactly as it does in the log
            // and the findings list; REVERSED stays reserved for the filter tabs.
            para = para.style(Style::default().bg(t.cursor_bg));
        }
        frame.render_widget(para, row);
    }

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{:indent$}{detail}", "", indent = SETTING_INDENT),
            dim(t),
        ))),
        parts[3],
    );
    frame.render_widget(Paragraph::new(footer), parts[5]);
}

/// Split `width` cells across the severity mix in `counts`, Critical → Info,
/// left to right. Every present severity gets at least one cell so a lone
/// Critical among a thousand Mediums cannot round away to nothing.
///
/// Shared by the findings panel's severity bar and the progress overlay's work
/// bar: same proportions, same order, same one-cell floor — the second is the
/// first scaled to however much of the corpus has been read.
fn severity_segments(counts: [usize; 5], width: u16) -> Vec<(Severity, usize)> {
    let total: usize = counts.iter().sum();
    if total == 0 || width == 0 {
        return Vec::new();
    }
    let order = [
        (Severity::Critical, 4usize),
        (Severity::High, 3),
        (Severity::Medium, 2),
        (Severity::Low, 1),
        (Severity::Info, 0),
    ];
    let w = width as usize;
    let mut used = 0usize;
    let mut segments = Vec::new();
    for (sev, idx) in order {
        let c = counts[idx];
        if c == 0 {
            continue;
        }
        let mut seg = ((c as f64 / total as f64) * w as f64).round() as usize;
        seg = seg.max(1);
        if used + seg > w {
            seg = w.saturating_sub(used);
        }
        if seg == 0 {
            break;
        }
        segments.push((sev, seg));
        used += seg;
    }
    // Rounding can leave the run a cell or two short of `width`. Give the
    // shortfall to the last segment: in the work bar the run's *length* is the
    // progress reading, so it has to land exactly where the head is.
    if used < w
        && let Some(last) = segments.last_mut()
    {
        last.1 += w - used;
    }
    segments
}

/// A one-line stacked bar depicting the severity mix of the findings.
fn severity_bar(counts: [usize; 5], width: u16) -> Line<'static> {
    let spans = severity_segments(counts, width)
        .into_iter()
        .map(|(sev, seg)| Span::styled("\u{2588}".repeat(seg), Style::default().fg(sev.color())))
        .collect::<Vec<_>>();
    Line::from(spans)
}

/// The base viewer (always drawn; popups layer on top of it).
fn draw_viewer(frame: &mut Frame, app: &mut App, area: Rect) {
    let show_tabs = app.files.len() > 1;
    let mut constraints = Vec::new();
    if show_tabs {
        constraints.push(Constraint::Length(3));
    }
    constraints.push(Constraint::Min(3));
    constraints.push(Constraint::Length(1));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut idx = 0;
    app.regions.tabs = Rect::default();
    app.regions.tab_hits.clear();
    if show_tabs {
        app.regions.tabs = chunks[idx];
        draw_tabs(frame, app, chunks[idx]);
        idx += 1;
    }
    let body_area = chunks[idx];
    idx += 1;
    let status_area = chunks[idx];

    let body_constraints = if app.show_legend {
        vec![Constraint::Min(20), Constraint::Length(34)]
    } else {
        vec![Constraint::Min(20)]
    };
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(body_constraints)
        .split(body_area);

    let log_area = body_chunks[0];
    app.regions.log = log_area;
    app.viewport_height = log_area.height.saturating_sub(2) as usize;

    // Record the scrollbar track so the mouse handler can hit-test it.
    app.regions.scrollbar = Rect::default();
    if app.has_files() && log_area.height > 2 && app.file().view.len() > app.viewport_height.max(1)
    {
        app.regions.scrollbar = Rect {
            x: log_area.x + log_area.width.saturating_sub(1),
            y: log_area.y + 1,
            width: 1,
            height: log_area.height - 2,
        };
    }

    if app.has_files() {
        draw_log(frame, app, log_area);
    } else {
        draw_welcome(frame, &app.theme, log_area);
    }

    app.regions.legend = Rect::default();
    if app.show_legend {
        app.regions.legend = body_chunks[1];
        draw_legend(frame, app, body_chunks[1]);
    }

    draw_status(frame, app, status_area);
}

fn draw_tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    let titles: Vec<Line> = app
        .files
        .iter()
        .map(|f| Line::from(format!(" {} ", f.name)))
        .collect();
    let t = &app.theme;
    let tabs = Tabs::new(titles)
        .block(t.panel(" Files (Tab/]) ", false))
        .style(Style::default().fg(t.text_dim))
        .select(app.current)
        .highlight_style(
            Style::default()
                .fg(t.match_fg)
                .bg(t.accent)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);

    // Hit boxes for mouse tab switching: inner area of the bordered panel.
    app.regions.tab_hits.clear();
    let inner_x = area.x.saturating_add(1);
    let inner_y = area.y.saturating_add(1);
    let inner_w = area.width.saturating_sub(2);
    let inner_end = inner_x.saturating_add(inner_w);
    let mut x = inner_x;
    for f in &app.files {
        let width = f.name.chars().count() as u16 + 2; // spaces around name
        if x >= inner_end {
            break;
        }
        let hit_w = width.min(inner_end.saturating_sub(x));
        if hit_w > 0 {
            app.regions.tab_hits.push(Rect {
                x,
                y: inner_y,
                width: hit_w,
                height: 1,
            });
        }
        x = x.saturating_add(width).saturating_add(1); // +1 for divider
    }
}

// Big "ANSI Shadow" banner (needs a wide-ish pane).
const LOGO_BIG: &[&str] = &[
    r"██╗      ██████╗  ██████╗ ██╗     ███████╗███╗   ██╗███████╗",
    r"██║     ██╔═══██╗██╔════╝ ██║     ██╔════╝████╗  ██║██╔════╝",
    r"██║     ██║   ██║██║  ███╗██║     █████╗  ██╔██╗ ██║███████╗",
    r"██║     ██║   ██║██║   ██║██║     ██╔══╝  ██║╚██╗██║╚════██║",
    r"███████╗╚██████╔╝╚██████╔╝███████╗███████╗██║ ╚██╗██║███████║",
    r"╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝",
];

// Compact banner for narrow panes.
const LOGO_SMALL: &[&str] = &[
    r" _    ___   ___ _    ___ _  _ ___ ",
    r"| |  / _ \ / __| |  | __| \| / __|",
    r"| |_| (_) | (_ | |__| _|| .` \__ \",
    r"|____\___/ \___|____|___|_|\_|___/",
];

fn draw_welcome(frame: &mut Frame, theme: &Theme, area: Rect) {
    let key = |k: &'static str| {
        Span::styled(
            k,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    };

    // Pick the widest banner that fits inside the panel (minus borders/padding).
    let avail = area.width.saturating_sub(4);
    let logo: &[&str] = if (LOGO_BIG[4].chars().count() as u16) <= avail {
        LOGO_BIG
    } else {
        LOGO_SMALL
    };

    let mut lines: Vec<Line> = Vec::new();
    let last = logo.len().saturating_sub(1).max(1);
    for (i, l) in logo.iter().enumerate() {
        let frac = i as f64 / last as f64;
        let color = theme::lerp_color(theme.logo_top, theme.logo_bottom, frac);
        lines.push(
            Line::from(Span::styled(
                *l,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ))
            .centered(),
        );
    }
    // Current product version, shown under the logo.
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            concat!("Version ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(theme.text_dim),
        ))
        .centered(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "highlight what matters in your logs",
            Style::default().fg(theme.text_dim),
        ))
        .centered(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(vec![
            key("o"),
            Span::raw(" open logs    "),
            key("a"),
            Span::raw(" add highlight    "),
            key("S"),
            Span::raw(" scan"),
        ])
        .centered(),
    );
    lines.push(
        Line::from(vec![
            key("?"),
            Span::raw(" help    "),
            key("q"),
            Span::raw(" quit"),
        ])
        .centered(),
    );

    // Vertically center the block within the pane.
    let content_h = lines.len() as u16;
    let inner_h = area.height.saturating_sub(2);
    let pad_top = inner_h.saturating_sub(content_h) / 2;
    let mut padded: Vec<Line> = Vec::with_capacity((pad_top + content_h) as usize);
    for _ in 0..pad_top {
        padded.push(Line::from(""));
    }
    padded.extend(lines);

    let block = theme.panel(" loglens ", true);
    frame.render_widget(
        Paragraph::new(padded)
            .style(Style::default().fg(theme.text))
            .block(block),
        area,
    );
}

/// Byte offset after skipping `cols` Unicode scalars from the start of `text`.
/// Used for horizontal scroll so we always cut on a char boundary.
fn h_scroll_byte_offset(text: &str, cols: usize) -> usize {
    if cols == 0 {
        return 0;
    }
    text.char_indices()
        .nth(cols)
        .map(|(i, _)| i)
        .unwrap_or(text.len())
}

/// Shift match spans left by `byte_off`, dropping anything that ends before the cut.
fn shift_spans_left(spans: &[MatchSpan], byte_off: usize) -> Vec<MatchSpan> {
    if byte_off == 0 {
        return spans.to_vec();
    }
    spans
        .iter()
        .filter_map(|s| {
            if s.end <= byte_off {
                return None;
            }
            Some(MatchSpan {
                start: s.start.saturating_sub(byte_off),
                end: s.end - byte_off,
                rule: s.rule,
            })
        })
        .collect()
}

/// Split one line into styled spans, layering search matches over rule matches.
///
/// `text` is the slice actually painted (already cut by horizontal scroll);
/// `full_line` is the whole log line and is used only for level-tint detection,
/// so panning right does not change a line's ERROR/WARN color.
fn render_line_spans<'a>(
    text: &'a str,
    full_line: &str,
    rule_spans: &[MatchSpan],
    rules: &[Rule],
    search: Option<&Regex>,
    theme: &Theme,
) -> Vec<Span<'a>> {
    // The level tint is a property of the line, not of each segment: computing it
    // once here (instead of per span) keeps a long line with many matches from
    // rescanning the line hundreds of times per frame.
    let base_fg = theme::level_fg(full_line, theme);

    let len = text.len();
    if len == 0 {
        return vec![Span::raw("")];
    }

    // Cap ranges collected per painted line so a busy search over a long line
    // cannot allocate unbounded style cut-points during render.
    const MAX_SEARCH_RANGES: usize = 256;
    let search_ranges: Vec<(usize, usize)> = match search {
        Some(re) => re
            .find_iter(text)
            .filter(|m| m.start() != m.end())
            .take(MAX_SEARCH_RANGES)
            .map(|m| (m.start(), m.end()))
            .collect(),
        None => Vec::new(),
    };

    if rule_spans.is_empty() && search_ranges.is_empty() {
        return vec![Span::styled(text, Style::default().fg(base_fg))];
    }

    let mut points: BTreeSet<usize> = BTreeSet::new();
    points.insert(0);
    points.insert(len);
    for s in rule_spans {
        points.insert(s.start);
        points.insert(s.end);
    }
    for (s, e) in &search_ranges {
        points.insert(*s);
        points.insert(*e);
    }

    // Clamp/filter cut points to valid char boundaries within the line so a
    // corrupt span can never panic the renderer with a slicing error.
    let pts: Vec<usize> = points
        .into_iter()
        .filter(|&p| p <= len && text.is_char_boundary(p))
        .collect();
    let mut spans = Vec::with_capacity(pts.len());
    for w in pts.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b {
            continue;
        }
        if search_ranges.iter().any(|&(s, e)| s <= a && b <= e) {
            spans.push(Span::styled(
                &text[a..b],
                Style::default()
                    .fg(theme.match_fg)
                    .bg(theme.search_bg)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if let Some(m) = rule_spans.iter().find(|m| m.start <= a && b <= m.end) {
            let color = rules.get(m.rule).map(|r| r.color).unwrap_or(theme.accent);
            spans.push(Span::styled(
                &text[a..b],
                Style::default()
                    .fg(theme.match_fg)
                    .bg(color)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(&text[a..b], Style::default().fg(base_fg)));
        }
    }
    spans
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let file = app.file();
    let height = app.viewport_height.max(1);
    let search = app.search.as_ref().map(|s| &s.regex);
    let block = t.panel(&log_title(app, file), true);

    if file.view.is_empty() {
        // An empty view means "filtered everything out" only when a filter is on;
        // a genuinely empty file must not be blamed on the filter.
        let msg = if file.lines.is_empty() {
            vec![
                Line::from(""),
                Line::from("  This file has no lines."),
                Line::from(vec![
                    Span::raw("  Press  "),
                    Span::styled(
                        "o",
                        Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  to open another log, or  "),
                    Span::styled(
                        "w",
                        Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  to close this tab."),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from("  No lines match the current filter."),
                Line::from(vec![
                    Span::raw("  Press  "),
                    Span::styled(
                        "f",
                        Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  to exit filter, or  "),
                    Span::styled(
                        "/",
                        Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  to search."),
                ]),
            ]
        };
        frame.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(t.text_dim))
                .block(block),
            area,
        );
        return;
    }

    let gutter_width = file.lines.len().to_string().len().max(4);
    let end = (file.top + height).min(file.view.len());
    let h_scroll = file.h_scroll;

    let mut lines: Vec<Line> = Vec::with_capacity(end.saturating_sub(file.top));
    for vp in file.top..end {
        let line_idx = file.view[vp];
        let full = &file.lines[line_idx];
        let byte_off = h_scroll_byte_offset(full, h_scroll);
        let text = &full[byte_off..];
        let shifted = shift_spans_left(&file.matches[line_idx], byte_off);
        let is_cursor = vp == file.view_pos;

        let mut spans = Vec::new();
        let bookmarked = file.bookmarks.binary_search(&line_idx).is_ok();
        // Severity dot from the last scan; bookmark ◆ when unmarked by scan.
        match file.scan_severity.get(line_idx).copied().flatten() {
            Some(sev) => spans.push(Span::styled("\u{25CF} ", Style::default().fg(sev.color()))),
            None if bookmarked => {
                spans.push(Span::styled("\u{25C6} ", Style::default().fg(t.accent)));
            }
            None => spans.push(Span::raw("  ")),
        }
        let gutter_fg = if bookmarked { t.accent } else { t.gutter };
        spans.push(Span::styled(
            format!("{:>width$} \u{2502} ", line_idx + 1, width = gutter_width),
            Style::default().fg(gutter_fg),
        ));
        // Dim cue that more content exists to the left of the viewport.
        if h_scroll > 0 {
            spans.push(Span::styled("‹", Style::default().fg(t.text_dim)));
        }
        spans.extend(render_line_spans(
            text, full, &shifted, &app.rules, search, t,
        ));

        let mut line = Line::from(spans);
        if is_cursor {
            line = line.style(
                Style::default()
                    .bg(t.cursor_bg)
                    .add_modifier(Modifier::BOLD),
            );
        }
        lines.push(line);
    }

    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(t.text))
            .block(block),
        area,
    );

    // Scrollbar on the right border when content overflows.
    if file.view.len() > height && area.height > 2 {
        let mut sb_state = ScrollbarState::new(file.view.len()).position(file.top);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(t.accent))
            .track_style(Style::default().fg(t.border));
        let sb_area = Rect {
            x: area.x,
            y: area.y + 1,
            width: area.width,
            height: area.height.saturating_sub(2),
        };
        frame.render_stateful_widget(sb, sb_area, &mut sb_state);
    }
}

fn log_title(app: &App, file: &LogFile) -> String {
    let mut title = format!(" {} ", file.name);
    if app.filter_on {
        title.push_str("[FILTER] ");
    }
    if let Some(s) = &app.search {
        title.push_str(&format!("[/{}] ", s.raw));
    }
    title
}

fn draw_legend(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let mut items: Vec<ListItem> = Vec::new();
    if app.rules.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "  no highlights yet — press a",
            Style::default().fg(t.text_dim),
        ))));
    } else {
        for (i, rule) in app.rules.iter().enumerate() {
            // Prefer `.get` so a transient rules/counts mismatch (e.g. mid
            // chunked rescan) cannot panic the render path.
            let count = if app.has_files() {
                app.file().rule_counts.get(i).copied().unwrap_or(0)
            } else {
                0
            };
            let active = app.active_rule == Some(i);
            let marker = if active { "\u{25B8} " } else { "  " };
            let kind = if rule.is_regex { "re" } else { "kw" };
            let label_style = if active {
                Style::default().fg(t.text).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(t.text)
            };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(t.accent)),
                Span::styled("\u{2588}\u{2588} ", Style::default().fg(rule.color)),
                Span::styled(format!("{} ", rule.label), label_style),
                Span::styled(format!("{kind} {count}"), Style::default().fg(t.text_dim)),
            ])));
        }
    }

    let block = t.panel(" Highlights (click to jump) ", false);
    frame.render_widget(List::new(items).block(block), area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let base = Style::default().fg(t.status_fg).bg(t.status_bg);
    let line = if let Some(msg) = &app.status {
        Line::from(vec![Span::styled(
            format!(" {msg}"),
            base.fg(t.accent).add_modifier(Modifier::BOLD),
        )])
    } else if app.has_files() {
        let file = app.file();
        // Absolute (1-based) line of the cursor — stays meaningful in filter mode.
        let abs_line = file
            .view
            .get(file.view_pos)
            .copied()
            .map(|i| i + 1)
            .unwrap_or(0);
        let total_lines = file.lines.len();
        let shown = file.view.len();
        let hl = file.total_matches();
        // When filtered, surface how many lines remain so Lx/y isn't misleading.
        let filter = if app.filter_on {
            format!(" · {shown} shown")
        } else {
            String::new()
        };
        let trunc = if file.truncated { " · trunc" } else { "" };
        let ic = if app.ignore_case { " · ic" } else { "" };
        let search = match &app.search {
            Some(s) => {
                let raw: String = s.raw.chars().take(20).collect();
                let truncated = if s.raw.chars().count() > 20 {
                    format!("{raw}…")
                } else {
                    raw
                };
                format!(" · /{truncated}")
            }
            None => String::new(),
        };
        let bm = file.bookmarks.len();
        let bookmarks = if bm > 0 {
            format!(" · {bm} bm")
        } else {
            String::new()
        };
        let col = if file.h_scroll > 0 {
            format!(" · col {}", file.h_scroll + 1)
        } else {
            String::new()
        };
        let findings = if app.findings.is_empty() {
            String::new()
        } else {
            format!(" · {} fd", app.findings.len())
        };
        Line::from(vec![Span::styled(
            format!(
                " L{abs_line}/{total_lines} · {hl} hl{filter}{trunc}{ic}{search}{bookmarks}{col}{findings}  ·  ? help"
            ),
            base,
        )])
    } else {
        Line::from(vec![Span::styled(" o open  ·  ? help  ·  q quit", base)])
    };
    frame.render_widget(Paragraph::new(line).style(base), area);
}

fn draw_browser_popup(frame: &mut Frame, app: &mut App, area: Rect) {
    let t = &app.theme;
    let popup = centered_rect(74, 76, area);
    app.regions.browser = popup;

    let b = &app.browser;
    let title = format!(
        " Open logs — {}  ({} marked) ",
        b.cwd.display(),
        b.marked.len()
    );
    let block = t.panel(&title, true);
    let inner = block.inner(popup);

    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);
    let list_area = parts[0];
    let footer_area = parts[1];
    app.regions.browser_list = list_area;

    let list_height = list_area.height as usize;
    let top = if b.selected >= list_height {
        b.selected - list_height + 1
    } else {
        0
    };
    app.regions.browser_top = top;
    let end = (top + list_height).min(b.entries.len());

    let mut items: Vec<ListItem> = Vec::new();
    for i in top..end {
        let entry = &b.entries[i];
        let is_sel = i == b.selected;
        let marked = b.marked.contains(&entry.path);

        let mark = if marked { "\u{2713} " } else { "  " };
        let icon = if entry.is_dir {
            "\u{1F4C1} "
        } else {
            "\u{1F4C4} "
        };
        let name = if entry.is_dir {
            format!("{}/", entry.name)
        } else {
            entry.name.clone()
        };

        let mut style = Style::default().fg(t.text);
        if entry.is_dir {
            style = style.fg(t.accent);
        }
        if marked {
            style = style.fg(t.marked).add_modifier(Modifier::BOLD);
        }
        if is_sel {
            style = Style::default()
                .bg(t.accent)
                .fg(t.match_fg)
                .add_modifier(Modifier::BOLD);
        }

        items.push(ListItem::new(Line::from(Span::styled(
            format!("{mark}{icon}{name}"),
            style,
        ))));
    }

    frame.render_widget(List::new(items), list_area);

    // A directory read error takes over the footer row (rendering it inside
    // the list would shift entries and break mouse-click row mapping).
    let footer = if let Some(err) = &b.error {
        Line::from(Span::styled(err.clone(), Style::default().fg(t.danger)))
    } else {
        Line::from(vec![
            Span::styled("Enter", key(t)),
            Span::styled(" open/enter  ", dim(t)),
            Span::styled("Space", key(t)),
            Span::styled(" mark  ", dim(t)),
            Span::styled("o", key(t)),
            Span::styled(" open marked  ", dim(t)),
            Span::styled("O", key(t)),
            Span::styled(" open folder/zip  ", dim(t)),
            Span::styled("h", key(t)),
            Span::styled(" up  ", dim(t)),
            Span::styled("q", key(t)),
            Span::styled(" close", dim(t)),
        ])
    };
    frame.render_widget(Paragraph::new(footer), footer_area);
}

fn key(t: &Theme) -> Style {
    Style::default().fg(t.accent).add_modifier(Modifier::BOLD)
}
fn dim(t: &Theme) -> Style {
    Style::default().fg(t.text_dim)
}

/// Severity filter tabs with per-tab counts. The active tab is reversed rather
/// than merely coloured, so it reads as selected on terminals that render the
/// severity palette faintly.
fn findings_filter_tabs(app: &App, counts: [usize; 5]) -> Line<'static> {
    let t = &app.theme;
    let mut spans = vec![Span::styled(" filter ", Style::default().fg(t.text_dim))];
    for opt in FINDING_FILTERS {
        let (label, n, colour) = match opt {
            None => ("all", app.findings.len(), t.text),
            Some(sev) => (sev.label(), counts[sev as usize], sev.color()),
        };
        let active = app.findings_filter == opt;
        let mut style = Style::default().fg(colour);
        if active {
            style = style.add_modifier(Modifier::REVERSED | Modifier::BOLD);
        } else if n == 0 {
            // An empty tab is still selectable, but dim so it does not compete
            // with tabs that have something in them.
            style = Style::default().fg(t.text_dim);
        }
        spans.push(Span::styled(format!(" {label} {n} "), style));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled("f/F or ←/→", key(t)));
    Line::from(spans)
}

/// Title for the findings popup: the finding count (with the raw hit count when
/// grouping collapsed repeats) followed by one tally segment per reportable
/// severity. The tally itself comes from [`severity_tally`] so the header cannot
/// drift from the severities the filter tabs can select.
fn findings_title(total: usize, hits: usize, counts: [usize; 5]) -> String {
    let scale = if hits > total {
        format!("{total} ({hits} hits)")
    } else {
        format!("{total}")
    };
    format!(" Scan findings — {scale}   {} ", severity_tally(counts))
}

fn draw_findings(frame: &mut Frame, app: &mut App, area: Rect) {
    let popup = centered_rect(84, 84, area);
    app.regions.findings = popup;

    let c = app.severity_counts();
    let title = findings_title(app.findings.len(), app.occurrence_count(), c);
    let block = app.theme.panel(&title, true);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    // Severity bar, filter tabs, the list, then a detail box.
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .split(inner);
    let bar_area = parts[0];
    let tabs_area = parts[1];
    let list_area = parts[2];
    let detail_area = parts[3];
    app.regions.findings_list = list_area;

    frame.render_widget(Paragraph::new(severity_bar(c, bar_area.width)), bar_area);
    frame.render_widget(Paragraph::new(findings_filter_tabs(app, c)), tabs_area);

    // Scroll state lives on App so the window holds still while the selection
    // moves inside it; only the height is a render-time fact.
    let list_height = list_area.height as usize;
    app.findings_scroll_into_view(list_height);
    let visible = app.visible_findings();
    let top = app.findings_top.min(visible.len());
    app.regions.findings_top = top;
    let end = (top + list_height).min(visible.len());

    // Borrowed only after the &mut scroll update above.
    let t = &app.theme;
    let mut items: Vec<ListItem> = Vec::new();
    for &i in &visible[top..end] {
        let f = app.findings[i];
        let sig = &app.signatures[f.sig];
        let is_sel = i == app.findings_sel;
        // Defensive: findings are remapped when files close, but a panic mid-
        // render would corrupt the terminal, so degrade instead of indexing.
        let file_name = app
            .files
            .get(f.file)
            .map(|lf| lf.name.as_str())
            .unwrap_or("?");

        let badge = Span::styled(
            format!(" {:<4} ", sig.severity.label()),
            Style::default()
                .fg(t.match_fg)
                .bg(sig.severity.color())
                .add_modifier(Modifier::BOLD),
        );
        let title_style = if is_sel {
            Style::default().fg(t.text).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(t.text)
        };
        let loc = Span::styled(
            format!("  {}:{}", file_name, f.line + 1),
            Style::default().fg(t.text_dim),
        );
        // A repeat count is the difference between "this happened" and "this
        // happened 900 times", so it is emphasised rather than dimmed. Absent
        // for single hits to keep the common row quiet.
        let repeat = if f.count > 1 {
            Span::styled(
                format!("  ×{}", f.count),
                Style::default()
                    .fg(sig.severity.color())
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("")
        };
        let mut line = Line::from(vec![
            badge,
            Span::raw(" "),
            Span::styled(sig.title.to_string(), title_style),
            repeat,
            loc,
        ]);
        if is_sel {
            line = line.style(Style::default().bg(t.cursor_bg));
        }
        items.push(ListItem::new(line));
    }
    frame.render_widget(List::new(items), list_area);

    // Detail box: explanation + the matched line for the current selection. A
    // filter with no matches shows why the list is empty rather than nothing.
    let detail = if visible.is_empty() && !app.findings.is_empty() {
        vec![Line::from(Span::styled(
            format!(
                "no {} findings — press f to change the filter",
                app.findings_filter.map_or("", |s| s.label())
            ),
            Style::default().fg(app.theme.text_dim),
        ))]
    } else if let Some(f) = app.findings.get(app.findings_sel).copied() {
        let sig = &app.signatures[f.sig];
        let excerpt = app
            .files
            .get(f.file)
            .and_then(|lf| lf.lines.get(f.line))
            .map(|l| l.trim())
            .unwrap_or("");
        vec![
            Line::from(vec![
                Span::styled(
                    format!(" {} ", sig.severity.label()),
                    Style::default()
                        .fg(t.match_fg)
                        .bg(sig.severity.color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(sig.category, Style::default().fg(t.accent)),
                Span::styled(
                    format!("  {}", sig.title),
                    Style::default().fg(t.text).add_modifier(Modifier::BOLD),
                ),
                // Spell out the span a repeated condition covers: two hits 4000
                // lines apart mean something different from two adjacent ones.
                Span::styled(
                    if f.count > 1 {
                        format!("   {} hits, lines {}–{}", f.count, f.line + 1, f.last + 1)
                    } else {
                        String::new()
                    },
                    Style::default().fg(t.text_dim),
                ),
            ]),
            Line::from(Span::styled(
                sig.explain.to_string(),
                Style::default().fg(t.text_dim),
            )),
            Line::from(Span::styled(
                format!("→ {excerpt}"),
                Style::default().fg(t.text),
            )),
            Line::from(vec![
                Span::styled("j/k", key(t)),
                Span::styled(" move   ", dim(t)),
                Span::styled("f/F", key(t)),
                Span::styled(" filter   ", dim(t)),
                Span::styled("Enter/click", key(t)),
                Span::styled(" jump   ", dim(t)),
                Span::styled("e", key(t)),
                Span::styled(" export   ", dim(t)),
                Span::styled("q/Esc", key(t)),
                Span::styled(" close", dim(t)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "nothing notable found",
            Style::default().fg(t.text_dim),
        ))]
    };
    frame.render_widget(
        Paragraph::new(detail).wrap(Wrap { trim: true }),
        detail_area,
    );
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let prompt = match app.input_kind {
        InputKind::Keyword => "Add keyword highlight",
        InputKind::Regex => "Add regex highlight",
        InputKind::Search => "Search (case-insensitive)",
        InputKind::GoToLine => "Go to line number",
    };
    let rect = centered_rect_lines(area, 60, 3);
    let block = t.panel(&format!(" {prompt} — Enter to go, Esc to cancel "), true);
    let line = Line::from(vec![
        Span::styled("\u{203A} ", Style::default().fg(t.accent)),
        Span::styled(app.input_buffer.clone(), Style::default().fg(t.text)),
        Span::styled("\u{2588}", Style::default().fg(t.accent)),
    ]);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(line).block(block), rect);
}

fn centered_rect_lines(area: Rect, percent_x: u16, lines: u16) -> Rect {
    // Widen to u32 for the multiply: `width * percent` overflows u16 on very
    // wide terminals (e.g. 1100 cols * 60 > 65535).
    let width = (area.width as u32 * percent_x as u32 / 100) as u16;
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(lines) / 2;
    Rect {
        x,
        y,
        width,
        height: lines.min(area.height),
    }
}

/// Centre a rect of an explicit cell size, clamped to `area`. Used where the
/// content's own width decides the panel instead of a share of the terminal.
fn centered_rect_cells(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// One keybinding: the key(s), then what they do. An empty key is a
/// continuation of the row above it.
type HelpRow = (&'static str, &'static str);

struct HelpSection {
    title: &'static str,
    rows: &'static [HelpRow],
}

/// Cells reserved for the key column. The longest labels (`Shift-Tab / [`,
/// `Ctrl-d/Ctrl-u`) are 13 cells, so 16 keeps the description column clear.
const HELP_KEY_COL: usize = 16;
/// Leading indent on every keybinding row.
const HELP_INDENT: usize = 2;
/// Cells between the two columns in the wide layout.
const HELP_COL_GAP: u16 = 3;
/// Sections in the left column when the sheet is wide enough for two. `Viewer`
/// alone balances against everything else (21 rows against 22).
const HELP_SPLIT: usize = 1;

const HELP_SECTIONS: &[HelpSection] = &[
    HelpSection {
        title: "Viewer",
        rows: &[
            ("j/k, ↑/↓", "scroll one line   (or mouse wheel)"),
            ("← / →", "pan left / right (long lines)"),
            ("0", "reset horizontal scroll to column 1"),
            ("Ctrl-d/Ctrl-u", "scroll one page"),
            ("Space / PgDn", "page down"),
            ("PgUp", "page up"),
            ("g / G", "jump to top / bottom"),
            ("Home / End", "jump to top / bottom"),
            (":", "go to line number"),
            ("m", "toggle bookmark on current line"),
            ("M", "clear all bookmarks on this file"),
            ("' / \"", "next / previous bookmark (wraps)"),
            ("Enter", "jump to first match"),
            ("n / N", "next / previous match (wraps)"),
            ("Tab / ]", "next open file"),
            ("Shift-Tab / [", "previous open file"),
            ("click a tab", "switch open file"),
            ("click a line", "move the cursor there"),
            ("o / w", "open browser / close current file"),
            ("y", "copy the cursor line to the clipboard"),
            ("Y", "copy the current file path to the clipboard"),
        ],
    },
    HelpSection {
        title: "Scan & triage",
        rows: &[
            ("S", "scan for known-bad signatures, ranked"),
            ("s", "reopen last findings panel (no rescan)"),
            ("p / P", "next / previous finding (wraps; no panel)"),
            ("e", "export findings (never overwrites an export)"),
            ("(in panel)", "j/k move · f/F or ←/→ severity filter"),
            ("", "Enter jump · e export · , settings · ? help · q close"),
        ],
    },
    HelpSection {
        title: "Search & filter",
        rows: &[
            ("/", "search (Enter first · n/N walk)"),
            ("f", "filter: matching lines only (status if cursor hidden)"),
            ("c", "clear search and filter together"),
            ("Esc", "clear search → clear filter → quit"),
        ],
    },
    HelpSection {
        title: "Highlights",
        rows: &[
            ("a / r", "add keyword / regex highlight"),
            ("click legend", "jump through that highlight's matches"),
            ("x", "remove the last highlight"),
            ("i / l", "toggle case-insensitive / legend (both persisted)"),
        ],
    },
    HelpSection {
        title: "Settings",
        rows: &[
            (",", "open settings (all prefs, persisted)"),
            ("(in panel)", "j/k move · Enter toggle · Esc close"),
        ],
    },
    HelpSection {
        title: "File browser",
        rows: &[
            ("Enter / l", "enter directory / open file"),
            ("Space  o", "mark a file / open marked"),
            ("O", "open whole folder or .zip recursively"),
            ("h / .", "parent dir / toggle hidden"),
        ],
    },
];

/// Render one keybinding row: the key in body text, its description recessed.
///
/// The key column is padded by *character* count, not byte length — several
/// labels carry multi-byte arrows (`↑ ↓ ← →`), so byte padding would push their
/// descriptions out of column.
fn help_row(keys: &str, desc: &str, t: &Theme) -> Line<'static> {
    let pad = HELP_KEY_COL.saturating_sub(keys.chars().count());
    Line::from(vec![
        Span::styled(
            format!("{:indent$}{keys}", "", indent = HELP_INDENT),
            Style::default().fg(t.text),
        ),
        Span::raw(" ".repeat(pad)),
        Span::styled(desc.to_string(), Style::default().fg(t.text_dim)),
    ])
}

/// Widest rendered row across `sections`, in cells.
fn help_section_width(sections: &[HelpSection]) -> usize {
    sections
        .iter()
        .flat_map(|s| {
            std::iter::once(s.title.chars().count()).chain(s.rows.iter().map(|(k, d)| {
                HELP_INDENT + HELP_KEY_COL.max(k.chars().count()) + d.chars().count()
            }))
        })
        .max()
        .unwrap_or(0)
}

/// Lay out `sections` as titled blocks separated by a blank row.
fn help_lines(sections: &[HelpSection], t: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, section) in sections.iter().enumerate() {
        if i > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            section.title,
            Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
        )));
        for (keys, desc) in section.rows {
            lines.push(help_row(keys, desc, t));
        }
    }
    lines
}

fn draw_help(frame: &mut Frame, app: &mut App, area: Rect) {
    let t = &app.theme;

    // The sheet is sized to its own content rather than to a share of the
    // terminal: a keybinding reference that truncates its descriptions is worse
    // than one that scrolls. Two columns halve the row count but need both
    // columns' width, so they engage only where that fits.
    let (left, right) = HELP_SECTIONS.split_at(HELP_SPLIT);
    let left_w = help_section_width(left);
    let right_w = help_section_width(right);
    const BORDERS: u16 = 2;
    let two_col_w = (left_w + HELP_COL_GAP as usize + right_w) as u16 + BORDERS;
    let two_col = area.width >= two_col_w;

    let (body, want_w) = if two_col {
        (help_lines(left, t), two_col_w)
    } else {
        (
            help_lines(HELP_SECTIONS, t),
            help_section_width(HELP_SECTIONS) as u16 + BORDERS,
        )
    };
    let right_body = if two_col {
        help_lines(right, t)
    } else {
        Vec::new()
    };
    let rows = body.len().max(right_body.len());

    // Header (title + rule) and footer are pinned; only the columns scroll.
    const CHROME: u16 = BORDERS + 2 /* header */ + 1 /* footer */;
    let want_h = rows as u16 + CHROME;
    let popup = centered_rect_cells(
        area,
        want_w.min(area.width),
        want_h.min(area.height * 92 / 100),
    );

    let block = t
        .panel(" Help (?/q/Esc to close) ", true)
        .title_alignment(Alignment::Center);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);
    let (head_area, body_area, foot_area) = (parts[0], parts[1], parts[2]);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "loglens — keybindings",
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ]),
        head_area,
    );

    // Scroll state lives on App so a resize cannot strand the view past the end.
    let height = body_area.height as usize;
    app.help_clamp_scroll(rows, height);
    let offset = app.help_scroll as u16;
    let t = &app.theme;

    if two_col {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(left_w as u16),
                Constraint::Length(HELP_COL_GAP),
                Constraint::Min(0),
            ])
            .split(body_area);
        frame.render_widget(Paragraph::new(body).scroll((offset, 0)), cols[0]);
        frame.render_widget(Paragraph::new(right_body).scroll((offset, 0)), cols[2]);
    } else {
        frame.render_widget(Paragraph::new(body).scroll((offset, 0)), body_area);
    }

    // Same scrollbar the log pane uses, and only when it carries information.
    // It rides the popup's right border rather than the body area, so it never
    // paints over a description.
    if rows > height {
        let mut sb_state = ScrollbarState::new(rows).position(app.help_scroll);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(t.accent))
            .track_style(Style::default().fg(t.border));
        let sb_area = Rect {
            x: popup.x,
            y: body_area.y,
            width: popup.width,
            height: body_area.height,
        };
        frame.render_stateful_widget(sb, sb_area, &mut sb_state);
    }

    let footer = if rows > height {
        Line::from(vec![
            Span::styled("j/k", key(t)),
            Span::styled(" scroll   ", dim(t)),
            Span::styled("?/q/Esc", key(t)),
            Span::styled(" close help", dim(t)),
        ])
    } else {
        Line::from(vec![
            Span::styled("?/q/Esc", key(t)),
            Span::styled(" close help", dim(t)),
        ])
    };
    frame.render_widget(Paragraph::new(footer), foot_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules;
    use crate::theme::Theme;

    /// Render the help sheet into an off-screen terminal and return it row by
    /// row, so the assertions below check painted cells rather than intent.
    fn render_help_with(app: &mut App, width: u16, height: u16) -> Vec<String> {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        term.draw(|f| {
            let area = f.area();
            draw_help(f, app, area);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn render_help(width: u16, height: u16) -> Vec<String> {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.show_help = true;
        render_help_with(&mut app, width, height)
    }

    /// Display column of `needle`, counting characters rather than bytes so the
    /// arrow glyphs earlier in a row do not skew the answer.
    fn column_of(row: &str, needle: &str) -> usize {
        let byte = row
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?}"));
        row[..byte].chars().count()
    }

    /// The key column is padded by character count. Byte padding would push the
    /// descriptions of arrow rows (`↑ ↓ ← →` are 3 bytes each) out of column.
    #[test]
    fn help_key_column_aligns_across_multibyte_keys() {
        let rows = render_help(100, 60);
        let find = |needle: &str| {
            rows.iter()
                .find(|r| r.contains(needle))
                .unwrap_or_else(|| panic!("missing row {needle:?}"))
        };
        let arrows = column_of(find("j/k, ↑/↓"), "scroll one line");
        let ascii = column_of(find("Ctrl-d/Ctrl-u"), "scroll one page");
        let short = column_of(find("  0  "), "reset horizontal scroll");
        assert_eq!(arrows, ascii, "multi-byte keys must not shift the column");
        assert_eq!(ascii, short, "short keys must pad to the same column");
    }

    #[test]
    fn help_sheet_uses_two_columns_only_when_the_terminal_can_hold_them() {
        // 160 cells: the second column fits, so a left row and the first
        // right-hand section land on the same painted line.
        let wide = render_help(160, 50);
        assert!(
            wide.iter()
                .any(|r| r.contains("Viewer") && r.contains("Scan & triage")),
            "wide terminal should reflow into two columns"
        );
        // 100 cells: not enough width, so the sheet stays single-column.
        let narrow = render_help(100, 60);
        assert!(
            !narrow
                .iter()
                .any(|r| r.contains("Viewer") && r.contains("Scan & triage")),
            "narrow terminal must stay single-column"
        );
    }

    /// The reported defect: at 48 rows the sheet needs a 55-row terminal, so on
    /// anything shorter the tail used to be unreachable with no cue.
    #[test]
    fn help_sheet_tail_is_reachable_on_a_short_terminal() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.show_help = true;

        let first = render_help_with(&mut app, 80, 24);
        assert!(
            !first.iter().any(|r| r.contains("File browser")),
            "an 80x24 terminal cannot show the whole sheet at once"
        );
        let footer = first
            .iter()
            .find(|r| r.contains("close help"))
            .expect("footer");
        assert!(
            footer.contains("j/k"),
            "an overflowing sheet must advertise how to scroll: {footer:?}"
        );

        app.help_scroll_to_end();
        let scrolled = render_help_with(&mut app, 80, 24);
        assert!(
            scrolled.iter().any(|r| r.contains("File browser")),
            "the last section must be reachable by scrolling"
        );
    }

    #[test]
    fn help_sheet_hides_the_scroll_hint_when_everything_fits() {
        let rows = render_help(160, 50);
        let footer = rows
            .iter()
            .find(|r| r.contains("close help"))
            .expect("footer");
        assert!(
            !footer.contains("j/k"),
            "a sheet that fits should not advertise scrolling: {footer:?}"
        );
    }

    #[test]
    fn h_scroll_byte_offset_respects_unicode() {
        assert_eq!(h_scroll_byte_offset("abcdef", 0), 0);
        assert_eq!(h_scroll_byte_offset("abcdef", 3), 3);
        assert_eq!(h_scroll_byte_offset("abcdef", 99), 6);
        // Multi-byte scalar: skip one char → past "字".
        assert_eq!(h_scroll_byte_offset("字abc", 1), "字".len());
        assert_eq!(h_scroll_byte_offset("字abc", 2), "字".len() + 1);
    }

    #[test]
    fn shift_spans_left_drops_and_clips() {
        let spans = [
            MatchSpan {
                start: 0,
                end: 5,
                rule: 0,
            },
            MatchSpan {
                start: 8,
                end: 12,
                rule: 1,
            },
        ];
        let shifted = shift_spans_left(&spans, 8);
        assert_eq!(shifted.len(), 1);
        assert_eq!(shifted[0].start, 0);
        assert_eq!(shifted[0].end, 4);
        assert_eq!(shifted[0].rule, 1);
        // Partial overlap: start before cut, end after.
        let partial = shift_spans_left(
            &[MatchSpan {
                start: 2,
                end: 10,
                rule: 0,
            }],
            5,
        );
        assert_eq!(partial[0].start, 0);
        assert_eq!(partial[0].end, 5);
    }

    /// Regression guard: the header used to spell out all five severities, so it
    /// permanently read `… · 0 low · 0 info` even though `MIN_FINDING_SEVERITY`
    /// keeps anything below Medium out of the findings list.
    #[test]
    fn findings_title_omits_severities_the_list_cannot_hold() {
        // counts are indexed by `Severity as usize`: info, low, medium, high, crit.
        let title = findings_title(12, 12, [7, 9, 4, 5, 3]);
        assert_eq!(title, " Scan findings — 12   3 crit · 5 high · 4 med ");
        assert!(!title.contains("low"), "{title}");
        assert!(!title.contains("info"), "{title}");
    }

    #[test]
    fn findings_title_shows_hit_count_only_when_grouping_collapsed_repeats() {
        // More hits than findings: grouping collapsed repeats, so say both.
        assert!(findings_title(3, 900, [0, 0, 1, 1, 1]).contains("3 (900 hits)"));
        // One hit per finding: the parenthetical would be noise.
        assert!(!findings_title(3, 3, [0, 0, 1, 1, 1]).contains("hits"));
    }

    #[test]
    fn severity_bar_handles_zero_width_and_sparse_counts() {
        let empty = severity_bar([0; 5], 0);
        assert!(empty.spans.is_empty() || empty.width() == 0);

        let counts = [1, 0, 2, 0, 1]; // info, low, med, high, crit
        let bar = severity_bar(counts, 10);
        assert!(bar.width() <= 10);
        assert!(!bar.spans.is_empty());
    }

    /// The longest label used to run straight into the key column, because the
    /// width formula and the row builder computed the layout independently.
    #[test]
    fn settings_value_column_clears_the_longest_label() {
        let t = Theme::dark();
        let width = SETTINGS
            .iter()
            .map(|s| setting_row_width(*s))
            .max()
            .unwrap_or(0) as u16;

        for setting in SETTINGS {
            let line = setting_row(&t, setting, true, false, width);
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            assert!(
                text.contains(setting.label()),
                "row lost its label: {text:?}"
            );
            // Whatever the label's length, the value stays a distinct column.
            let label_end = text.find(setting.label()).unwrap() + setting.label().len();
            let tail = &text[label_end..];
            assert!(
                tail.starts_with("   "),
                "label runs into the next column: {text:?}"
            );
            assert!(text.ends_with("[ on]"), "{text:?}");
            assert!(line.width() <= width as usize, "{text:?}");
        }
    }

    #[test]
    fn settings_row_shows_state_and_marks_only_the_selection() {
        let t = Theme::dark();
        let width = 44;

        let on = setting_row(&t, Setting::ScanOnOpen, true, false, width);
        let off = setting_row(&t, Setting::ScanOnOpen, false, false, width);
        let on_text: String = on.spans.iter().map(|s| s.content.as_ref()).collect();
        let off_text: String = off.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(on_text.contains("[ on]"), "{on_text:?}");
        assert!(off_text.contains("[off]"), "{off_text:?}");

        // The selected row is the only one wearing the marker.
        let selected = setting_row(&t, Setting::IgnoreCase, false, true, width);
        let plain = setting_row(&t, Setting::IgnoreCase, false, false, width);
        let sel_text: String = selected.spans.iter().map(|s| s.content.as_ref()).collect();
        let plain_text: String = plain.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(sel_text.contains('\u{25B8}'), "{sel_text:?}");
        assert!(!plain_text.contains('\u{25B8}'), "{plain_text:?}");
        // Marker and blank both take two cells, so the labels stay in column.
        assert_eq!(selected.width(), plain.width());

        // A setting with a keybinding advertises it; one without shows nothing.
        assert!(sel_text.contains(" i   "), "{sel_text:?}");
        let no_key: String = setting_row(&t, Setting::ScanOnOpen, false, false, width)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(!no_key.contains('i'), "{no_key:?}");
    }

    /// The work bar reads its length as progress, so a rounding shortfall would
    /// put the run and the `▌` head in different places.
    #[test]
    fn severity_segments_span_the_full_width() {
        for counts in [[1, 0, 2, 0, 1], [0, 0, 0, 0, 1], [3, 3, 3, 3, 3]] {
            for width in [1u16, 7, 10, 44, 137] {
                let total: usize = severity_segments(counts, width).iter().map(|s| s.1).sum();
                assert_eq!(total, width as usize, "counts {counts:?} at width {width}");
            }
        }
        assert!(severity_segments([0; 5], 40).is_empty());
        assert!(severity_segments([1, 0, 0, 0, 0], 0).is_empty());
    }

    /// Cells of `s` in `line`, and the color of the first cell that isn't track.
    fn bar_parts(line: &Line<'static>) -> (usize, usize, usize, Option<ratatui::style::Color>) {
        let mut filled = 0;
        let mut head = 0;
        let mut track = 0;
        let mut lead = None;
        for span in &line.spans {
            for ch in span.content.chars() {
                match ch {
                    '\u{2588}' => {
                        if lead.is_none() {
                            lead = span.style.fg;
                        }
                        filled += 1;
                    }
                    '\u{258C}' => head += 1,
                    '\u{2591}' => track += 1,
                    _ => {}
                }
            }
        }
        (filled, head, track, lead)
    }

    #[test]
    fn work_bar_reserves_a_fixed_percentage_field_and_length_tracks_progress() {
        let t = Theme::dark();
        for width in [PROGRESS_MIN_CONTENT, 60, 100] {
            for (frac, pct) in [(0.0, "   0%"), (0.5, "  50%"), (1.0, " 100%")] {
                let line = work_bar(&t, None, frac, width);
                assert_eq!(line.width(), width as usize, "width {width} at {frac}");
                let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                assert!(text.ends_with(pct), "{text:?}");

                // Bar cells (filled + head + track) always fill what's left.
                let bar = (width - PCT_FIELD) as usize;
                let (filled, head, track, _) = bar_parts(&line);
                assert_eq!(filled + head + track, bar);
                assert_eq!(filled, (frac * bar as f64).round() as usize);
            }
        }
    }

    #[test]
    fn work_bar_paints_the_severity_mix_found_so_far() {
        let t = Theme::dark();
        // One Critical among Mediums still leads the bar — same order as the
        // findings panel, so the reader recognises the shape when it opens.
        let line = work_bar(&t, Some([0, 0, 6, 0, 1]), 0.5, 60);
        let (_, _, _, lead) = bar_parts(&line);
        assert_eq!(lead, Some(Severity::Critical.color()));

        // Nothing found yet reads as "running, clean so far", not as empty.
        let clean = work_bar(&t, Some([0; 5]), 0.5, 60);
        let (filled, _, _, lead) = bar_parts(&clean);
        assert_eq!(lead, Some(t.accent));
        assert!(filled > 0);

        // A rescan has no verdict, so it is the same single-accent bar.
        let (rescan_filled, _, _, rescan_lead) = bar_parts(&work_bar(&t, None, 0.5, 60));
        assert_eq!((rescan_filled, rescan_lead), (filled, Some(t.accent)));
    }

    #[test]
    fn work_bar_drops_the_head_and_track_at_completion() {
        let t = Theme::dark();
        let running = work_bar(&t, None, 0.7, 60);
        let (_, head, track, _) = bar_parts(&running);
        assert_eq!(head, 1, "one boundary cell while work remains");
        assert!(track > 0);

        // Nothing left to read: neither glyph implies more to come.
        let done = work_bar(&t, Some([0, 0, 1, 0, 0]), 1.0, 60);
        let (filled, head, track, _) = bar_parts(&done);
        assert_eq!((head, track), (0, 0));
        assert_eq!(filled, (60 - PCT_FIELD) as usize);
    }

    /// A terminal narrower than the panel's floor must not panic or wrap.
    #[test]
    fn work_bar_survives_widths_below_the_percentage_field() {
        let t = Theme::dark();
        for width in 0..=PCT_FIELD + 2 {
            let line = work_bar(&t, Some([0, 0, 1, 0, 1]), 0.5, width);
            assert!(line.width() <= (width as usize).max(PCT_FIELD as usize));
        }
    }

    #[test]
    fn centered_rect_lines_does_not_overflow_wide_terminals() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 2000,
            height: 60,
        };
        let rect = centered_rect_lines(area, 60, 3);
        assert_eq!(rect.height, 3);
        assert!(rect.width <= area.width);
        assert!(rect.x + rect.width <= area.x + area.width);
    }

    #[test]
    fn render_line_spans_search_overrides_rule_color() {
        let theme = Theme::dark();
        let rule = rules::compile_rule("ERROR", false, false, 0, &theme).unwrap();
        let spans = [MatchSpan {
            start: 0,
            end: 5,
            rule: 0,
        }];
        let search = Regex::new("ERR").unwrap();
        let out = render_line_spans(
            "ERROR happened",
            "ERROR happened",
            &spans,
            &[rule],
            Some(&search),
            &theme,
        );
        assert!(out.len() >= 2);
        // The search-styled prefix should use SEARCH_BG.
        assert_eq!(out[0].style.bg, Some(theme.search_bg));
    }

    #[test]
    fn render_line_spans_ignores_non_char_boundary_cuts() {
        let theme = Theme::dark();
        let rule = rules::compile_rule("字", false, false, 0, &theme).unwrap();
        // Corrupt span pointing mid-codepoint must not panic.
        let spans = [MatchSpan {
            start: 1,
            end: 2,
            rule: 0,
        }];
        let out = render_line_spans("字abc", "字abc", &spans, &[rule], None, &theme);
        assert!(!out.is_empty());
        let joined: String = out.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, "字abc");
    }

    #[test]
    fn render_line_spans_empty_line() {
        let out = render_line_spans("", "", &[], &[], None, &Theme::dark());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].content.as_ref(), "");
    }

    #[test]
    fn render_line_spans_applies_level_error_tint() {
        let theme = Theme::dark();
        let out = render_line_spans(
            "2026 ERROR failed",
            "2026 ERROR failed",
            &[],
            &[],
            None,
            &theme,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].style.fg, Some(theme.level_error));
    }

    #[test]
    fn render_line_spans_handles_replacement_chars_from_sanitized_ansi() {
        let theme = Theme::dark();
        // After sanitize_log_line, ESC sequences become U+FFFD — rendering must
        // stay panic-free and preserve surrounding text.
        let text = "ERROR \u{FFFD}[31mred\u{FFFD}[0m failed";
        let rule = rules::compile_rule("ERROR", false, false, 0, &theme).unwrap();
        let spans = [MatchSpan {
            start: 0,
            end: 5,
            rule: 0,
        }];
        let out = render_line_spans(text, text, &spans, &[rule], None, &theme);
        let joined: String = out.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, text);
        assert!(!joined.contains('\u{1b}'));
    }

    #[test]
    fn render_line_spans_keeps_level_tint_when_panned_past_the_level_token() {
        let theme = Theme::dark();
        let full = "2026-07-22 10:00:07 ERROR failed to connect to update server";
        // Horizontal scroll cuts the ERROR token out of the painted slice; the
        // line must keep its error tint instead of falling back to plain text.
        let painted = &full[40..];
        assert!(!painted.contains("ERROR"));
        let out = render_line_spans(painted, full, &[], &[], None, &theme);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].style.fg, Some(theme.level_error));
    }

    /// Regression guard: the level tint is a per-line property, so it must be
    /// computed once — not once per styled segment. Painting it per segment made
    /// a long line with many matches rescan the whole line hundreds of times per
    /// frame (~13 ms per line in release, i.e. a visibly frozen viewport).
    ///
    /// Compares a busy line against the same line rendered as a single span, so
    /// the bound is a ratio and does not depend on machine speed or build profile.
    #[test]
    fn render_line_spans_stays_fast_on_a_long_busy_line() {
        let theme = Theme::dark();
        let mut line = String::from("2026-07-22 10:00:00 ERROR ");
        while line.len() < 32 * 1024 {
            line.push_str("connection refused to host xyz; retrying now. ");
        }
        let search = Regex::new("(?i)retrying").unwrap();

        let time_it = |search: Option<&Regex>| {
            let start = std::time::Instant::now();
            for _ in 0..20 {
                let spans = render_line_spans(&line, &line, &[], &[], search, &theme);
                assert!(!spans.is_empty());
            }
            start.elapsed().max(std::time::Duration::from_nanos(1))
        };

        // One span, one level scan: the floor for this line.
        let plain = time_it(None);
        // MAX_SEARCH_RANGES segments: must add segmentation work, not 256 more
        // full-line scans.
        let busy = time_it(Some(&search));
        let ratio = busy.as_secs_f64() / plain.as_secs_f64();
        assert!(
            ratio < 20.0,
            "busy line cost {ratio:.1}× the single-span line ({busy:?} vs {plain:?}) \
             — level tint recomputed per span?"
        );
    }
}
