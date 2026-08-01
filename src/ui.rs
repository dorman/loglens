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
    App, FINDING_FILTERS, InputKind, LogFile, MatchSpan, Mode, PanelRow, SETTINGS, Setting,
    severity_tally,
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
                " ".repeat(filled as usize),
                Style::default().bg(theme.accent),
            ));
        }
    } else {
        for (sev, cells, count) in segments {
            spans.push(severity_segment_span(theme, sev, cells, count));
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
    let block = theme.panel_raised(title);
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
    let block = t.panel_raised(TITLE);
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
fn severity_segments(counts: [usize; 5], width: u16) -> Vec<(Severity, usize, usize)> {
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
        segments.push((sev, seg, c));
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

    // The worst thing found is never too small to say its own name. The
    // one-cell floor already keeps a lone Critical visible; this extends the
    // same principle from visible to *named*, buying the leading segment enough
    // room for its label out of the widest one below it.
    //
    // It costs a little proportional accuracy, deliberately: this bar is a
    // verdict, not a measurement, and a two-cell red sliver that cannot identify
    // itself is the one reading the system must not allow.
    if segments.len() > 1 {
        let need = segments[0].0.label().chars().count() + 2;
        if segments[0].1 < need {
            let deficit = need - segments[0].1;
            let donor = segments
                .iter()
                .enumerate()
                .skip(1)
                .max_by_key(|(_, seg)| seg.1)
                .map(|(i, _)| i);
            if let Some(d) = donor
                && segments[d].1 > deficit
            {
                segments[d].1 -= deficit;
                segments[0].1 += deficit;
            }
        }
    }
    segments
}

/// One segment of a severity bar, labelled with as much of `CRIT 3` as it can
/// hold, in Ink Black on the severity's own fill.
///
/// This is the badge treatment at bar scale, and it is deliberate: every other
/// colored thing in loglens is paired with a word — badges, tabs, highlights,
/// search matches, filter tabs — and the bars were the only components that
/// opted out. A bar whose sole channel is hue says nothing on a 256-color
/// terminal, to a colorblind reader, or in a screenshot pasted into a ticket.
///
/// Space is spent in the order the reader needs it: label and count, then label
/// alone, then bare fill when even that will not fit. A segment never shrinks
/// below the one-cell floor, so a lone Critical is always visible even when it
/// is too narrow to name itself.
fn severity_segment_span(t: &Theme, sev: Severity, cells: usize, count: usize) -> Span<'static> {
    let filled = Style::default()
        .fg(t.match_fg)
        .bg(sev.color())
        .add_modifier(Modifier::BOLD);
    let label = sev.label();
    let full = format!("{label} {count}");

    // ` CRIT 3 ` needs the text plus a cell of breathing room each side, the
    // same padding the severity badge uses.
    if cells >= full.chars().count() + 2 {
        let pad = cells - full.chars().count();
        let left = pad / 2;
        Span::styled(
            format!("{:l$}{full}{:r$}", "", "", l = left, r = pad - left),
            filled,
        )
    } else if cells >= label.chars().count() + 2 {
        let pad = cells - label.chars().count();
        let left = pad / 2;
        Span::styled(
            format!("{:l$}{label}{:r$}", "", "", l = left, r = pad - left),
            filled,
        )
    } else {
        // Too narrow to name: fill only, so the proportion still reads.
        Span::styled(" ".repeat(cells), Style::default().bg(sev.color()))
    }
}

/// A one-line stacked bar depicting the severity mix of the findings, each
/// segment stating what it is.
fn severity_bar(t: &Theme, counts: [usize; 5], width: u16) -> Line<'static> {
    let spans = severity_segments(counts, width)
        .into_iter()
        .map(|(sev, cells, count)| severity_segment_span(t, sev, cells, count))
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
        vec![
            Constraint::Min(20),
            Constraint::Length(legend_width(area.width)),
        ]
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

/// Fit `text` into `width` cells, marking the cut with `…` rather than letting
/// the terminal clip mid-word.
///
/// `keep_tail` decides which end survives. A path keeps its tail — the
/// directory you are actually in is the point, and `/private/tmp/claude-501/-Us…`
/// answers nothing — while prose keeps its head.
fn fit(text: &str, width: usize, keep_tail: bool) -> String {
    let n = text.chars().count();
    if n <= width {
        return text.to_string();
    }
    if width <= 1 {
        return "\u{2026}".chars().take(width).collect();
    }
    if keep_tail {
        let skip = n - (width - 1);
        std::iter::once('\u{2026}')
            .chain(text.chars().skip(skip))
            .collect()
    } else {
        text.chars()
            .take(width - 1)
            .chain(std::iter::once('\u{2026}'))
            .collect()
    }
}

/// Width of the highlight rail for a given terminal width.
///
/// Fixed at 34 cells, the rail took a third of a 100-column terminal and *half*
/// of a 60-column one — 32 of 60 cells to show a single placeholder sentence.
/// It now keeps its full width wherever there is room for it and yields to the
/// log below that, with a floor at the narrowest row that can still carry
/// `██ label kw N`.
fn legend_width(total: u16) -> u16 {
    const MAX: u16 = 34;
    const MIN: u16 = 16;
    // Widen for the multiply: `width * 2` overflows u16 on absurd terminals.
    let share = (total as u32 * 2 / 5) as u16;
    share.clamp(MIN, MAX)
}

/// One legend row. The label is the only elastic part: the count is the reason
/// the rail exists, so it is never the thing that gets clipped.
fn legend_row(t: &Theme, rule: &Rule, count: usize, active: bool, width: u16) -> Line<'static> {
    let marker = if active { "\u{25B8} " } else { "  " };
    let kind = if rule.is_regex { "re" } else { "kw" };
    let tail = format!("{kind} {count}");
    // marker(2) + swatch(3) + one space before the tail.
    let fixed = 2 + 3 + 1 + tail.chars().count();
    let room = (width as usize).saturating_sub(fixed);

    let label: String = if rule.label.chars().count() <= room {
        rule.label.clone()
    } else if room >= 2 {
        // Truncate the label, never the count, and say that it was truncated.
        let keep = room - 1;
        rule.label
            .chars()
            .take(keep)
            .chain(std::iter::once('\u{2026}'))
            .collect()
    } else {
        String::new()
    };

    let pad = room.saturating_sub(label.chars().count());
    let label_style = if active {
        Style::default().fg(t.text).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(t.text)
    };
    Line::from(vec![
        Span::styled(marker, Style::default().fg(t.accent)),
        Span::styled("\u{2588}\u{2588} ", Style::default().fg(rule.color)),
        Span::styled(label, label_style),
        Span::raw(" ".repeat(pad + 1)),
        Span::styled(tail, Style::default().fg(t.text_dim)),
    ])
}

fn draw_legend(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = app.theme.panel(" Highlights (click to jump) ", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let t = &app.theme;
    if app.rules.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  no highlights yet — press a",
                Style::default().fg(t.text_dim),
            ))),
            inner,
        );
        app.regions.legend_top = 0;
        return;
    }

    let height = inner.height as usize;
    let rows = app.rules.len();
    app.legend_scroll_into_view(height);
    app.legend_clamp_scroll(rows, height);
    let top = app.legend_top.min(rows.saturating_sub(1));
    app.regions.legend_top = top;
    let end = (top + height).min(rows);

    let t = &app.theme;
    let mut items: Vec<ListItem> = Vec::new();
    for i in top..end {
        // Prefer `.get` so a transient rules/counts mismatch (e.g. mid
        // chunked rescan) cannot panic the render path.
        let count = if app.has_files() {
            app.file().rule_counts.get(i).copied().unwrap_or(0)
        } else {
            0
        };
        items.push(ListItem::new(legend_row(
            t,
            &app.rules[i],
            count,
            app.active_rule == Some(i),
            inner.width,
        )));
    }
    frame.render_widget(List::new(items), inner);

    // Same scrollbar the log and help use, and only when it carries information.
    if rows > height {
        let mut state = ScrollbarState::new(rows).position(top);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(t.accent))
            .track_style(Style::default().fg(t.border));
        let track = Rect {
            x: area.x + area.width.saturating_sub(1),
            y: inner.y,
            width: 1,
            height: inner.height,
        };
        frame.render_stateful_widget(sb, track, &mut state);
    }
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
    // The panel's own width bounds the title; the path yields first and keeps
    // its tail, because the folder you are standing in is the whole point.
    let marked = format!("  ({} marked) ", b.marked.len());
    let room = (popup.width as usize).saturating_sub(" Open logs — ".len() + marked.len() + 4);
    let title = format!(
        " Open logs — {}{marked}",
        fit(&b.cwd.display().to_string(), room, true)
    );
    let block = t.panel_raised(&title);
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
    spans.push(Span::styled("f/F", key(t)));
    Line::from(spans)
}

/// Fixed height of the findings detail box.
const DETAIL_ROWS: u16 = 5;

/// A repeat count is the difference between "this happened" and "this happened
/// 900 times", so it is emphasised rather than dimmed. Absent for a single hit
/// to keep the common row quiet.
fn repeat_span(count: usize, color: ratatui::style::Color) -> Span<'static> {
    if count > 1 {
        Span::styled(
            format!("  \u{00D7}{count}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    }
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
    let c = app.severity_counts();
    let rows = app.panel_rows();

    // Size to content, like every other overlay in the product. The collapsed
    // default caps this at one row per reportable signature, so the panel is
    // short unless the reader opens a group — the detail box then sits directly
    // under the row it explains instead of 17 blank rows below it.
    // An empty tab has no finding to describe, so its detail box shrinks to the
    // one line that says why the list is empty.
    let detail_rows = if rows.is_empty() { 1 } else { DETAIL_ROWS };
    let chrome: u16 = 2 /* borders */ + 1 /* severity bar */ + 1 /* tabs */ + detail_rows;
    let want_rows = rows.len().max(1) as u16;
    let max_h = (area.height * 84 / 100).max(chrome + 1);
    let popup = centered_rect_cells(area, area.width * 84 / 100, (want_rows + chrome).min(max_h));
    app.regions.findings = popup;

    let title = findings_title(app.findings.len(), app.occurrence_count(), c);
    let block = app.theme.panel_raised(&title);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    // Severity bar, filter tabs, the list, then a detail box.
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(detail_rows),
        ])
        .split(inner);
    let bar_area = parts[0];
    let tabs_area = parts[1];
    let list_area = parts[2];
    let detail_area = parts[3];
    app.regions.findings_list = list_area;

    frame.render_widget(
        Paragraph::new(severity_bar(&app.theme, c, bar_area.width)),
        bar_area,
    );
    frame.render_widget(Paragraph::new(findings_filter_tabs(app, c)), tabs_area);

    // Scroll state lives on App so the window holds still while the selection
    // moves inside it; only the height is a render-time fact.
    let list_height = list_area.height as usize;
    app.findings_scroll_into_view(list_height);
    let top = app.findings_top.min(rows.len());
    app.regions.findings_top = top;
    let end = (top + list_height).min(rows.len());

    // Borrowed only after the &mut scroll update above.
    let t = &app.theme;
    let sel = app.findings_sel;
    let mut items: Vec<ListItem> = Vec::new();
    for row in &rows[top..end] {
        let mut line = match *row {
            PanelRow::Parent {
                sig,
                first,
                files,
                hits,
                expandable,
            } => {
                let s = &app.signatures[sig];
                let open = app.is_expanded(sig);
                // `▸`/`▾` is the disclosure state. The panel marks its cursor
                // with the Row Wash, never with a marker glyph, so the two
                // senses never share a surface. A one-file group shows neither:
                // it has nothing to open, and a marker would promise otherwise.
                let marker = Span::styled(
                    if !expandable {
                        "  "
                    } else if open {
                        "\u{25BE} "
                    } else {
                        "\u{25B8} "
                    },
                    Style::default().fg(t.text_dim),
                );
                let badge = Span::styled(
                    format!(" {:<4} ", s.severity.label()),
                    Style::default()
                        .fg(t.match_fg)
                        .bg(s.severity.color())
                        .add_modifier(Modifier::BOLD),
                );
                // Where the evidence is: one file names it outright, several
                // report the spread — the escalation-relevant fact on a bundle.
                let where_ = if files == 1 {
                    let name = app
                        .files
                        .get(app.findings[first].file)
                        .map(|lf| lf.name.as_str())
                        .unwrap_or("?");
                    format!("  {}:{}", name, app.findings[first].line + 1)
                } else {
                    format!("  {files} files")
                };
                Line::from(vec![
                    marker,
                    badge,
                    Span::raw(" "),
                    Span::styled(
                        s.title.to_string(),
                        Style::default().fg(t.text).add_modifier(Modifier::BOLD),
                    ),
                    repeat_span(hits, s.severity.color()),
                    Span::styled(where_, Style::default().fg(t.text_dim)),
                ])
            }
            PanelRow::Child(i) => {
                let f = app.findings[i];
                let s = &app.signatures[f.sig];
                // Defensive: findings are remapped when files close, but a panic
                // mid-render would corrupt the terminal, so degrade instead.
                let name = app
                    .files
                    .get(f.file)
                    .map(|lf| lf.name.as_str())
                    .unwrap_or("?");
                Line::from(vec![
                    Span::raw("      "),
                    Span::styled(
                        format!("{}:{}", name, f.line + 1),
                        Style::default().fg(t.text),
                    ),
                    repeat_span(f.count, s.severity.color()),
                ])
            }
        };
        if App::row_is(row, sel) {
            line = line.style(Style::default().bg(t.cursor_bg));
        }
        items.push(ListItem::new(line));
    }
    frame.render_widget(List::new(items), list_area);

    let visible = app.visible_findings();
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
    } else if let Some(f) = app.selected_finding() {
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
    let block = t.panel_raised(&format!(" {prompt} — Enter to go, Esc to cancel "));
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
/// alone is the closest balance available (22 rows against 29) — it is one row
/// longer than every other section put together, so moving any section left
/// makes the split worse, not better. The columns scroll to their own ends
/// rather than sharing one offset, so the imbalance costs nothing.
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
            (
                "(in panel)",
                "j/k move · f/F severity filter · h/l fold groups",
            ),
            ("", "Enter open or jump · e export · , settings · q close"),
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
        .panel_raised(" Help (?/q/Esc to close) ")
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
        // Each column stops at its own end. The scroll range is the taller
        // column's, so applying that offset to both scrolled the shorter one
        // past its content and left a ragged blank tail beside a column that
        // was still going.
        let col_offset = |len: usize| offset.min(len.saturating_sub(height) as u16);
        let (left_len, right_len) = (body.len(), right_body.len());
        frame.render_widget(
            Paragraph::new(body).scroll((col_offset(left_len), 0)),
            cols[0],
        );
        frame.render_widget(
            Paragraph::new(right_body).scroll((col_offset(right_len), 0)),
            cols[2],
        );
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

    /// The two columns are unequal (Viewer is 22 rows, the rest 29), and the
    /// scroll range belongs to the taller one. Sharing a single offset scrolled
    /// the shorter column past its own end, so reaching the last right-hand
    /// section blanked the bottom of the left one.
    #[test]
    fn help_columns_scroll_to_their_own_ends() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.show_help = true;

        // Wide enough for two columns, short enough to force scrolling.
        let wide = 150;
        let first = render_help_with(&mut app, wide, 30);
        assert!(
            first.iter().any(|r| r.contains("Scan & triage")),
            "expected the two-column layout at {wide} cells"
        );

        app.help_scroll_to_end();
        let end = render_help_with(&mut app, wide, 30);

        // The right column reached its last section...
        assert!(
            end.iter().any(|r| r.contains("File browser")),
            "the taller column did not reach its end"
        );
        // ...and the left column is still showing content, not blank tail. Its
        // last row is the deepest Viewer binding, which must still be painted.
        assert!(
            end.iter().any(|r| r.contains("copy the current file path")),
            "the shorter column scrolled past its own content"
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
        let t = Theme::dark();
        let empty = severity_bar(&t, [0; 5], 0);
        assert!(empty.spans.is_empty() || empty.width() == 0);

        let counts = [1, 0, 2, 0, 1]; // info, low, med, high, crit
        let bar = severity_bar(&t, counts, 10);
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

    /// Cells of bar fill, head and track in `line`, plus the color of the first
    /// filled cell. Fill is now a background — the badge treatment at bar scale
    /// — so this reads `.bg` rather than counting a glyph.
    fn bar_parts(line: &Line<'static>) -> (usize, usize, usize, Option<ratatui::style::Color>) {
        let mut filled = 0;
        let mut head = 0;
        let mut track = 0;
        let mut lead = None;
        for span in &line.spans {
            let n = span.content.chars().count();
            if span.content.contains('\u{258C}') {
                head += span.content.matches('\u{258C}').count();
                continue;
            }
            if span.content.contains('\u{2591}') {
                track += span.content.matches('\u{2591}').count();
                continue;
            }
            if let Some(bg) = span.style.bg {
                if lead.is_none() {
                    lead = Some(bg);
                }
                filled += n;
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
        // Deliberately no level token anywhere: `detect_level` returns on the
        // first one it finds, so a line carrying `ERROR` in its prefix exits
        // after a few bytes and could not detect a per-span rescan at all. The
        // worst case for the tint scan is the line that never matches.
        let mut line = String::from("2026-07-22 10:00:00 ");
        while line.len() < 32 * 1024 {
            line.push_str("connection refused to host xyz; retrying now. ");
        }
        assert_eq!(
            crate::theme::level_fg(&line, &theme),
            theme.text,
            "the fixture must have no level token, or it exits early"
        );
        let search = Regex::new("(?i)retrying").unwrap();

        let time_it = |search: Option<&Regex>| {
            let start = std::time::Instant::now();
            for _ in 0..20 {
                let spans = render_line_spans(&line, &line, &[], &[], search, &theme);
                assert!(!spans.is_empty());
            }
            start.elapsed().max(std::time::Duration::from_nanos(1))
        };

        // One span, one full-line level scan: the floor for this line.
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
    /// Depth here is tonal, not simulated: the panel must be darker than the
    /// field it punched out of, and the selected row darker still. If the fill
    /// is lost the panel draws on the same tone as the log behind it and the
    /// border color is left carrying the separation alone.
    #[test]
    fn findings_panel_stacks_the_three_tonal_tiers() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::style::Color;

        let mut app = App::new(&["samples/bundle".into()], Vec::new(), false).unwrap();
        app.enable_auto_scan();
        while app.scanning() {
            app.scan_step(4000);
        }
        app.show_findings = true;

        let mut term = Terminal::new(TestBackend::new(96, 28)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let buf = term.backend().buffer().clone();

        let t = Theme::dark();
        let count = |c: Color| {
            (0..buf.area.height)
                .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
                .filter(|&(x, y)| buf[(x, y)].bg == c)
                .count()
        };

        // Tier 1 (ground) survives outside the panel, tier 2 fills it, and tier
        // 3 marks the cursor row inside it.
        assert!(count(Color::Reset) > 0, "the log field must stay on ground");
        assert!(
            count(t.status_bg) > 200,
            "the panel interior must carry the trench fill"
        );
        assert!(
            count(t.cursor_bg) > 0,
            "the selected row must read above the panel"
        );

        // The three tiers must be genuinely distinct values.
        assert_ne!(t.status_bg, t.cursor_bg);
    }
    /// The rule the bars used to break: every colored thing in loglens is
    /// paired with a word. A bar whose only channel is hue says nothing on a
    /// 256-color terminal, to a colorblind reader, or in a pasted screenshot.
    #[test]
    fn severity_bar_states_what_each_band_is() {
        let t = Theme::dark();
        let text =
            |l: &Line<'static>| -> String { l.spans.iter().map(|s| s.content.as_ref()).collect() };

        // counts are indexed by `Severity as usize`: info, low, medium, high, crit.
        let bar = severity_bar(&t, [0, 0, 4, 5, 0], 82);
        let out = text(&bar);
        assert!(out.contains("HIGH 5"), "{out:?}");
        assert!(out.contains("MED 4"), "{out:?}");
        assert_eq!(bar.width(), 82, "the bar must still fill its width");

        // Every filled cell carries Ink Black on the severity's own fill — the
        // badge treatment, so the label survives at any size.
        for span in &bar.spans {
            if span.content.trim().is_empty() {
                continue;
            }
            assert_eq!(span.style.fg, Some(t.match_fg), "label must be Ink Black");
            assert!(
                span.style.bg.is_some(),
                "label must sit on the severity fill"
            );
        }
    }

    /// The worst finding is never too small to name itself: one Critical among
    /// forty Mediums used to render as an unlabelled two-cell sliver.
    #[test]
    fn the_leading_severity_always_earns_its_label() {
        let t = Theme::dark();
        let out: String = severity_bar(&t, [0, 0, 40, 6, 1], 82)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            out.contains("CRIT"),
            "a lone Critical must name itself: {out:?}"
        );
        assert!(
            out.contains("MED 40"),
            "the donor keeps its own label: {out:?}"
        );

        // Promotion never breaks the width invariant.
        for width in [20u16, 40, 82, 137] {
            let total: usize = severity_segments([0, 0, 40, 6, 1], width)
                .iter()
                .map(|s| s.1)
                .sum();
            assert_eq!(total, width as usize, "width {width}");
        }
    }

    /// Too narrow to name is still honest: the band keeps its fill so the
    /// proportion reads, rather than being dropped or truncated mid-word.
    #[test]
    fn a_band_too_narrow_to_label_keeps_its_fill() {
        let t = Theme::dark();
        let bar = severity_bar(&t, [0, 0, 1, 1, 1], 9);
        assert_eq!(bar.width(), 9);
        let out: String = bar.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            !out.contains("CRI"),
            "never truncate a label mid-word: {out:?}"
        );
        assert!(
            bar.spans.iter().all(|s| s.style.bg.is_some()),
            "every cell keeps a severity fill"
        );
    }
    /// A path answers "where am I", so its tail is the part worth keeping. The
    /// browser used to clip the other end, leaving the drive root on screen and
    /// the actual directory off it.
    #[test]
    fn fit_keeps_the_end_that_carries_the_meaning() {
        let path = "/private/tmp/claude-501/loglens/samples/mbam-android";
        let tail = fit(path, 24, true);
        assert_eq!(tail.chars().count(), 24);
        assert!(tail.starts_with('\u{2026}'), "{tail:?}");
        assert!(tail.ends_with("mbam-android"), "{tail:?}");

        let prose = fit("Scanning for known-bad signatures", 20, false);
        assert_eq!(prose.chars().count(), 20);
        assert!(prose.starts_with("Scanning"), "{prose:?}");
        assert!(prose.ends_with('\u{2026}'), "{prose:?}");

        // Fits already: untouched, no ellipsis.
        assert_eq!(fit("short", 20, false), "short");
        assert_eq!(fit("short", 20, true), "short");
        // Exactly the budget is not a truncation.
        assert_eq!(fit("12345", 5, false), "12345");
        // Degenerate widths must not panic or overflow.
        for w in 0..4 {
            assert!(fit(path, w, true).chars().count() <= w);
            assert!(fit(path, w, false).chars().count() <= w);
        }
        // Multibyte is counted in characters, not bytes.
        let uni = fit("日本語のディレクトリ名", 6, true);
        assert_eq!(uni.chars().count(), 6);
    }

    /// Fixed at 34 cells the rail took half of a 60-column terminal to show one
    /// placeholder sentence. It keeps its full width where there is room and
    /// yields to the log below that.
    #[test]
    fn legend_width_yields_to_the_log_on_narrow_terminals() {
        assert_eq!(legend_width(200), 34, "wide terminals keep the full rail");
        assert_eq!(legend_width(100), 34);
        assert!(
            legend_width(60) < 34,
            "60 cols must not spend 34 on the rail"
        );
        assert!(
            legend_width(60) as usize * 2 < 60,
            "the rail must never take half the terminal"
        );
        // Never so narrow it cannot carry `██ label kw N`.
        assert!(legend_width(20) >= 16);
        assert!(legend_width(1) >= 16);
        // Monotonic: a wider terminal never yields a narrower rail.
        let mut prev = 0;
        for w in (10u16..=300).step_by(7) {
            let cur = legend_width(w);
            assert!(cur >= prev, "width {w} narrowed the rail");
            prev = cur;
        }
    }

    /// The count is the reason the rail exists, so the label is the only elastic
    /// part. Truncating right-to-left used to drop the number instead.
    #[test]
    fn legend_row_truncates_the_label_never_the_count() {
        let t = Theme::dark();
        let rule =
            rules::compile_rule("certificate-validation-failure", false, false, 0, &t).unwrap();

        for width in [16u16, 20, 24, 34] {
            let line = legend_row(&t, &rule, 47, false, width);
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            assert!(
                text.contains("kw 47"),
                "the count must survive at width {width}: {text:?}"
            );
            assert!(
                line.width() <= width as usize,
                "row overflowed at width {width}: {text:?}"
            );
        }

        // Long label at a narrow width is marked as truncated, not silently cut.
        let narrow: String = legend_row(&t, &rule, 47, false, 24)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(narrow.contains('\u{2026}'), "{narrow:?}");

        // A short label is left intact.
        let short = rules::compile_rule("ERROR", false, false, 1, &t).unwrap();
        let wide: String = legend_row(&t, &short, 4, false, 34)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(wide.contains("ERROR"), "{wide:?}");
        assert!(!wide.contains('\u{2026}'), "{wide:?}");
    }
}
