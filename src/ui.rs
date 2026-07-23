use std::collections::BTreeSet;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Clear, Gauge, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs,
    Wrap,
};
use ratatui::Frame;
use regex::Regex;

use crate::app::{App, InputKind, LogFile, Mode};
use crate::rules::Rule;
use crate::signatures::Severity;
use crate::theme;

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
    if app.show_help {
        draw_help(frame, area);
    }
    if app.scanning() {
        draw_scan_progress(frame, app, area);
    }
}

fn draw_scan_progress(frame: &mut Frame, app: &App, area: Rect) {
    let frac = app.scan_fraction().unwrap_or(0.0);
    let (processed, total, found, file_name) = app.scan_detail().unwrap_or((0, 0, 0, String::new()));

    let rect = centered_rect_lines(area, 56, 6);
    let block = theme::panel(" Scanning for known-bad signatures… ", true);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
        .split(inner);

    let pct = (frac * 100.0).round() as u16;
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(theme::ACCENT).bg(theme::CURSOR_BG))
        .ratio(frac.clamp(0.0, 1.0))
        .label(format!("{pct}%"));
    frame.render_widget(gauge, rows[0]);

    let info = Line::from(vec![
        Span::styled(
            format!(" {processed}/{total} lines"),
            Style::default().fg(theme::TEXT),
        ),
        Span::styled("   ·   ", dim()),
        Span::styled(
            format!("{found} findings so far"),
            Style::default().fg(theme::ACCENT),
        ),
    ]);
    frame.render_widget(Paragraph::new(info), rows[1]);

    let sub = Line::from(vec![
        Span::styled(format!(" {file_name}"), dim()),
        Span::styled("      Esc to cancel", dim()),
    ]);
    frame.render_widget(Paragraph::new(sub), rows[2]);
}

/// A one-line stacked bar depicting the severity mix of the findings.
fn severity_bar(counts: [usize; 5], width: u16) -> Line<'static> {
    let total: usize = counts.iter().sum();
    if total == 0 || width == 0 {
        return Line::from("");
    }
    // Critical → Info, left to right.
    let order = [
        (Severity::Critical, 4usize),
        (Severity::High, 3),
        (Severity::Medium, 2),
        (Severity::Low, 1),
        (Severity::Info, 0),
    ];
    let w = width as usize;
    let mut used = 0usize;
    let mut spans = Vec::new();
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
        spans.push(Span::styled(
            "\u{2588}".repeat(seg),
            Style::default().fg(sev.color()),
        ));
        used += seg;
    }
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
    if app.has_files()
        && log_area.height > 2
        && app.file().view.len() > app.viewport_height.max(1)
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
        draw_welcome(frame, log_area);
    }

    app.regions.legend = Rect::default();
    if app.show_legend {
        app.regions.legend = body_chunks[1];
        draw_legend(frame, app, body_chunks[1]);
    }

    draw_status(frame, app, status_area);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = app
        .files
        .iter()
        .map(|f| Line::from(format!(" {} ", f.name)))
        .collect();
    let tabs = Tabs::new(titles)
        .block(theme::panel(" Files (Tab) ", false))
        .style(Style::default().fg(theme::TEXT_DIM))
        .select(app.current)
        .highlight_style(
            Style::default()
                .fg(theme::MATCH_FG)
                .bg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
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

fn draw_welcome(frame: &mut Frame, area: Rect) {
    let key = |k: &'static str| {
        Span::styled(
            k,
            Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD),
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
        let t = i as f64 / last as f64;
        let color = theme::lerp_color(theme::LOGO_TOP, theme::LOGO_BOTTOM, t);
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
            Style::default().fg(theme::TEXT_DIM),
        ))
        .centered(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(Span::styled(
            "highlight what matters in your logs",
            Style::default().fg(theme::TEXT_DIM),
        ))
        .centered(),
    );
    lines.push(Line::from(""));
    lines.push(
        Line::from(vec![key("o"), Span::raw(" open logs    "), key("a"), Span::raw(" add highlight    "), key("S"), Span::raw(" scan")])
            .centered(),
    );
    lines.push(
        Line::from(vec![key("?"), Span::raw(" help    "), key("q"), Span::raw(" quit")]).centered(),
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

    let block = theme::panel(" loglens ", true);
    frame.render_widget(
        Paragraph::new(padded)
            .style(Style::default().fg(theme::TEXT))
            .block(block),
        area,
    );
}

/// Split one line into styled spans, layering search matches over rule matches.
fn render_line_spans<'a>(
    text: &'a str,
    rule_spans: &[crate::app::MatchSpan],
    rules: &[Rule],
    search: Option<&Regex>,
) -> Vec<Span<'a>> {
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
        return vec![Span::raw(text)];
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
                    .fg(theme::MATCH_FG)
                    .bg(theme::SEARCH_BG)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if let Some(m) = rule_spans.iter().find(|m| m.start <= a && b <= m.end) {
            let color = rules.get(m.rule).map(|r| r.color).unwrap_or(theme::ACCENT);
            spans.push(Span::styled(
                &text[a..b],
                Style::default()
                    .fg(theme::MATCH_FG)
                    .bg(color)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::raw(&text[a..b]));
        }
    }
    spans
}

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let file = app.file();
    let height = app.viewport_height.max(1);
    let search = app.search.as_ref().map(|s| &s.regex);
    let block = theme::panel(&log_title(app, file), true);

    if file.view.is_empty() {
        let msg = vec![
            Line::from(""),
            Line::from("  No lines match the current filter."),
            Line::from(vec![
                Span::raw("  Press  "),
                Span::styled("f", Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
                Span::raw("  to exit filter, or  "),
                Span::styled("/", Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
                Span::raw("  to search."),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(msg).style(Style::default().fg(theme::TEXT_DIM)).block(block),
            area,
        );
        return;
    }

    let gutter_width = file.lines.len().to_string().len().max(4);
    let end = (file.top + height).min(file.view.len());

    let mut lines: Vec<Line> = Vec::with_capacity(end.saturating_sub(file.top));
    for vp in file.top..end {
        let line_idx = file.view[vp];
        let text = &file.lines[line_idx];
        let is_cursor = vp == file.view_pos;

        let mut spans = Vec::new();
        // Severity dot from the last scan (blank until scanned).
        match file.scan_severity.get(line_idx).copied().flatten() {
            Some(sev) => spans.push(Span::styled(
                "\u{25CF} ",
                Style::default().fg(sev.color()),
            )),
            None => spans.push(Span::raw("  ")),
        }
        spans.push(Span::styled(
            format!("{:>width$} \u{2502} ", line_idx + 1, width = gutter_width),
            Style::default().fg(theme::GUTTER),
        ));
        spans.extend(render_line_spans(text, &file.matches[line_idx], &app.rules, search));

        let mut line = Line::from(spans);
        if is_cursor {
            line = line.style(Style::default().bg(theme::CURSOR_BG).add_modifier(Modifier::BOLD));
        }
        lines.push(line);
    }

    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(theme::TEXT)).block(block),
        area,
    );

    // Scrollbar on the right border when content overflows.
    if file.view.len() > height && area.height > 2 {
        let mut sb_state = ScrollbarState::new(file.view.len()).position(file.top);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(theme::ACCENT))
            .track_style(Style::default().fg(theme::BORDER));
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
    let mut items: Vec<ListItem> = Vec::new();
    if app.rules.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "  no highlights yet — press a",
            Style::default().fg(theme::TEXT_DIM),
        ))));
    } else {
        for (i, rule) in app.rules.iter().enumerate() {
            let count = if app.has_files() {
                app.file().rule_counts[i]
            } else {
                0
            };
            let active = app.active_rule == Some(i);
            let marker = if active { "\u{25B8} " } else { "  " };
            let kind = if rule.is_regex { "re" } else { "kw" };
            let label_style = if active {
                Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT)
            };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(theme::ACCENT)),
                Span::styled("\u{2588}\u{2588} ", Style::default().fg(rule.color)),
                Span::styled(format!("{} ", rule.label), label_style),
                Span::styled(
                    format!("{kind} {count}"),
                    Style::default().fg(theme::TEXT_DIM),
                ),
            ])));
        }
    }

    let block = theme::panel(" Highlights (click to jump) ", false);
    frame.render_widget(List::new(items).block(block), area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let base = Style::default().fg(theme::STATUS_FG).bg(theme::STATUS_BG);
    let line = if let Some(msg) = &app.status {
        Line::from(vec![Span::styled(
            format!(" {msg}"),
            base.fg(theme::ACCENT).add_modifier(Modifier::BOLD),
        )])
    } else if app.has_files() {
        let file = app.file();
        Line::from(vec![Span::styled(
            format!(
                " {}/{} shown ({} total)  ·  {} hl  ·  S scan   / search   f filter   n/N next   o open   a add   ? help   q quit",
                (file.view_pos + 1).min(file.view.len().max(1)),
                file.view.len(),
                file.lines.len(),
                file.total_matches(),
            ),
            base,
        )])
    } else {
        Line::from(vec![Span::styled(
            " o open files   ·   a add highlight   ·   ? help   ·   q quit",
            base,
        )])
    };
    frame.render_widget(Paragraph::new(line).style(base), area);
}

fn draw_browser_popup(frame: &mut Frame, app: &mut App, area: Rect) {
    let popup = centered_rect(74, 76, area);
    app.regions.browser = popup;

    let b = &app.browser;
    let title = format!(" Open logs — {}  ({} marked) ", b.cwd.display(), b.marked.len());
    let block = theme::panel(&title, true);
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
        let icon = if entry.is_dir { "\u{1F4C1} " } else { "\u{1F4C4} " };
        let name = if entry.is_dir {
            format!("{}/", entry.name)
        } else {
            entry.name.clone()
        };

        let mut style = Style::default().fg(theme::TEXT);
        if entry.is_dir {
            style = style.fg(theme::ACCENT);
        }
        if marked {
            style = style.fg(theme::PALETTE[1]).add_modifier(Modifier::BOLD);
        }
        if is_sel {
            style = Style::default()
                .bg(theme::ACCENT)
                .fg(theme::MATCH_FG)
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
        Line::from(Span::styled(
            err.clone(),
            Style::default().fg(theme::PALETTE[0]),
        ))
    } else {
        Line::from(vec![
            Span::styled("Enter", key()),
            Span::styled(" open/enter  ", dim()),
            Span::styled("Space", key()),
            Span::styled(" mark  ", dim()),
            Span::styled("o", key()),
            Span::styled(" open marked  ", dim()),
            Span::styled("O", key()),
            Span::styled(" open folder/zip  ", dim()),
            Span::styled("h", key()),
            Span::styled(" up  ", dim()),
            Span::styled("q", key()),
            Span::styled(" close", dim()),
        ])
    };
    frame.render_widget(Paragraph::new(footer), footer_area);
}

fn key() -> Style {
    Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)
}
fn dim() -> Style {
    Style::default().fg(theme::TEXT_DIM)
}

fn draw_findings(frame: &mut Frame, app: &mut App, area: Rect) {
    let popup = centered_rect(84, 84, area);
    app.regions.findings = popup;

    let c = app.severity_counts();
    let title = format!(
        " Scan findings — {}   {} crit · {} high · {} med · {} low · {} info ",
        app.findings.len(),
        c[4],
        c[3],
        c[2],
        c[1],
        c[0],
    );
    let block = theme::panel(&title, true);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    // Severity distribution bar, then the list, then a detail box.
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .split(inner);
    let bar_area = parts[0];
    let list_area = parts[1];
    let detail_area = parts[2];
    app.regions.findings_list = list_area;

    frame.render_widget(Paragraph::new(severity_bar(c, bar_area.width)), bar_area);

    let list_height = list_area.height as usize;
    let top = if app.findings_sel >= list_height {
        app.findings_sel - list_height + 1
    } else {
        0
    };
    app.regions.findings_top = top;
    let end = (top + list_height).min(app.findings.len());

    let mut items: Vec<ListItem> = Vec::new();
    for i in top..end {
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
                .fg(theme::MATCH_FG)
                .bg(sig.severity.color())
                .add_modifier(Modifier::BOLD),
        );
        let title_style = if is_sel {
            Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT)
        };
        let loc = Span::styled(
            format!("  {}:{}", file_name, f.line + 1),
            Style::default().fg(theme::TEXT_DIM),
        );
        let mut line = Line::from(vec![
            badge,
            Span::raw(" "),
            Span::styled(sig.title.to_string(), title_style),
            loc,
        ]);
        if is_sel {
            line = line.style(Style::default().bg(theme::CURSOR_BG));
        }
        items.push(ListItem::new(line));
    }
    frame.render_widget(List::new(items), list_area);

    // Detail box: explanation + the matched line for the current selection.
    let detail = if let Some(f) = app.findings.get(app.findings_sel).copied() {
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
                    Style::default().fg(theme::MATCH_FG).bg(sig.severity.color()).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(sig.category, Style::default().fg(theme::ACCENT)),
                Span::styled(format!("  {}", sig.title), Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(Span::styled(sig.explain.to_string(), Style::default().fg(theme::TEXT_DIM))),
            Line::from(Span::styled(format!("→ {excerpt}"), Style::default().fg(theme::TEXT))),
            Line::from(vec![
                Span::styled("j/k", key()),
                Span::styled(" move   ", dim()),
                Span::styled("Enter/click", key()),
                Span::styled(" jump to line   ", dim()),
                Span::styled("q/Esc", key()),
                Span::styled(" close", dim()),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "nothing notable found",
            Style::default().fg(theme::TEXT_DIM),
        ))]
    };
    frame.render_widget(
        Paragraph::new(detail).wrap(Wrap { trim: true }),
        detail_area,
    );
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = match app.input_kind {
        InputKind::Keyword => "Add keyword highlight",
        InputKind::Regex => "Add regex highlight",
        InputKind::Search => "Search (case-insensitive)",
    };
    let rect = centered_rect_lines(area, 60, 3);
    let block = theme::panel(&format!(" {prompt} — Enter to go, Esc to cancel "), true);
    let line = Line::from(vec![
        Span::styled("\u{203A} ", Style::default().fg(theme::ACCENT)),
        Span::styled(app.input_buffer.clone(), Style::default().fg(theme::TEXT)),
        Span::styled("\u{2588}", Style::default().fg(theme::ACCENT)),
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

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(66, 92, area);
    let head = |s: &'static str| Line::from(Span::styled(s, Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)));
    let text = vec![
        Line::from(Span::styled(
            "loglens — keybindings",
            Style::default().fg(theme::TEXT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        head("Viewer"),
        Line::from("  j/k, ↑/↓        scroll one line   (or mouse wheel)"),
        Line::from("  Ctrl-d/Ctrl-u   scroll one page"),
        Line::from("  g / G           jump to top / bottom"),
        Line::from("  n / N           next / previous match"),
        Line::from("  Tab / Shift-Tab switch between open files"),
        Line::from("  click a line    move the cursor there"),
        Line::from("  o / w           open browser / close current file"),
        Line::from(""),
        head("Scan & triage"),
        Line::from("  S               scan for known-bad signatures, ranked"),
        Line::from("  (in panel)      j/k move · Enter/click jump · q close"),
        Line::from(""),
        head("Search & filter"),
        Line::from("  /               search (n/N walk results, Esc clears)"),
        Line::from("  f               filter: show only matching lines"),
        Line::from(""),
        head("Highlights"),
        Line::from("  a / r           add keyword / regex highlight"),
        Line::from("  click legend    jump through that highlight's matches"),
        Line::from("  x               remove the last highlight"),
        Line::from("  i / l           toggle case-insensitive / legend"),
        Line::from(""),
        head("File browser"),
        Line::from("  Enter / l       enter directory / open file"),
        Line::from("  Space  o        mark a file / open marked"),
        Line::from("  O               open whole folder or .zip recursively"),
        Line::from("  h / .           parent dir / toggle hidden"),
        Line::from(""),
        Line::from(Span::styled("  ? close help    q quit", Style::default().fg(theme::TEXT_DIM))),
    ];
    let block = theme::panel(" Help (? to close) ", true).title_alignment(Alignment::Center);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(theme::TEXT)).block(block),
        popup,
    );
}
