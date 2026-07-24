use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::DefaultTerminal;
use ratatui::layout::Rect;

use crate::app::{App, InputKind, Mode};
use crate::ui;

/// Lines scanned per rendered frame while a scan is running.
const SCAN_CHUNK: usize = 4000;

pub fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;

        // While scanning, advance a chunk per frame and drain the whole input
        // queue (only Esc/q act, everything else is discarded) so the progress
        // bar animates, cancel stays responsive, and buffered keystrokes don't
        // burst-execute as commands the moment the scan finishes.
        if app.scanning() {
            app.scan_step(SCAN_CHUNK);
            let mut timeout = Duration::from_millis(8);
            while event::poll(timeout)? {
                timeout = Duration::ZERO;
                if let Event::Key(key) = event::read()?
                    && key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                {
                    app.cancel_scan();
                }
            }
            continue;
        }

        match event::read()? {
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match app.mode {
                    Mode::Input => handle_input(app, key.code),
                    Mode::Browser => handle_browser(app, key.code),
                    Mode::Viewer => handle_viewer(app, key.code, key.modifiers),
                }
            }
            Event::Mouse(m) => handle_mouse(app, m),
            // Bracketed paste: only meaningful while typing in the input prompt.
            // Everywhere else it is deliberately ignored — without this, pasted
            // text would be replayed as keystrokes ('q' quits, 'S' scans, …).
            Event::Paste(text) if app.mode == Mode::Input => {
                app.push_input_chars(text.chars());
            }
            _ => {}
        }
    }
    Ok(())
}

fn hit(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

fn handle_mouse(app: &mut App, m: MouseEvent) {
    let (col, row) = (m.column, m.row);
    let r = app.regions;

    match m.kind {
        MouseEventKind::ScrollDown => {
            if app.show_findings {
                app.findings_move(3);
            } else if app.mode == Mode::Browser {
                app.browser.move_selection(3);
            } else {
                app.scroll(3);
            }
        }
        MouseEventKind::ScrollUp => {
            if app.show_findings {
                app.findings_move(-3);
            } else if app.mode == Mode::Browser {
                app.browser.move_selection(-3);
            } else {
                app.scroll(-3);
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            app.status = None;
            if app.show_findings {
                // Click a finding row to jump straight to it. Hit-test against
                // the exact list rect (the popup also contains a severity bar
                // and detail box, which must not map to findings).
                if hit(r.findings_list, col, row) {
                    let idx = r.findings_top + (row - r.findings_list.y) as usize;
                    if idx < app.findings.len() {
                        app.findings_sel = idx;
                        app.findings_jump();
                    }
                }
                return;
            }
            if app.mode == Mode::Browser {
                // Click a row in the browser popup to select it (exact list
                // rect: excludes the popup borders and footer row).
                if hit(r.browser_list, col, row) {
                    let idx = r.browser_top + (row - r.browser_list.y) as usize;
                    if idx < app.browser.entries.len() {
                        app.browser.selected = idx;
                    }
                }
                return;
            }
            if app.mode != Mode::Viewer {
                return;
            }
            // Click the scrollbar track -> jump to that position (and start a drag).
            if r.scrollbar.height > 0 && hit(r.scrollbar, col, row) {
                app.scrollbar_drag = true;
                app.scroll_to_fraction(track_fraction(r.scrollbar, row));
                return;
            }
            // Click a highlight in the legend -> jump through its matches.
            let legend_inner = inner(r.legend);
            if app.show_legend && hit(legend_inner, col, row) {
                let idx = (row - legend_inner.y) as usize;
                app.click_rule(idx);
                return;
            }
            // Click a line in the log -> move the cursor there.
            let log_inner = inner(r.log);
            if hit(log_inner, col, row) {
                app.select_view_row((row - log_inner.y) as usize);
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if app.scrollbar_drag {
                app.scroll_to_fraction(track_fraction(r.scrollbar, row));
            }
        }
        MouseEventKind::Up(MouseButton::Left) => {
            app.scrollbar_drag = false;
        }
        _ => {}
    }
}

/// Where `row` falls along a scrollbar track, as a fraction 0.0..=1.0.
fn track_fraction(track: Rect, row: u16) -> f64 {
    if track.height <= 1 {
        return 0.0;
    }
    let clamped = row.clamp(track.y, track.y + track.height - 1);
    (clamped - track.y) as f64 / (track.height - 1) as f64
}

/// The content rect inside a bordered block.
fn inner(rect: Rect) -> Rect {
    if rect.width < 2 || rect.height < 2 {
        return rect;
    }
    Rect {
        x: rect.x + 1,
        y: rect.y + 1,
        width: rect.width - 2,
        height: rect.height - 2,
    }
}

fn handle_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => app.confirm_input(),
        KeyCode::Esc => app.cancel_input(),
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Char(c) => app.push_input_chars(std::iter::once(c)),
        _ => {}
    }
}

fn handle_browser(app: &mut App, code: KeyCode) {
    app.status = None;
    match code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.has_files() {
                app.close_browser();
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => app.browser.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => app.browser.move_selection(-1),
        KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
            // Enter a directory, or open the selected/marked file(s).
            if !app.browser.enter_dir() {
                app.open_selected_files();
            }
        }
        KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => app.browser.go_parent(),
        KeyCode::Char(' ') => app.browser.toggle_mark(),
        KeyCode::Char('o') => app.open_selected_files(),
        KeyCode::Char('O') => app.open_selected_dir(),
        KeyCode::Char('.') => app.browser.toggle_hidden(),
        KeyCode::Char('?') => app.toggle_help(),
        _ => {}
    }
}

fn handle_viewer(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    if app.show_help {
        if matches!(code, KeyCode::Char('?') | KeyCode::Esc) {
            app.toggle_help();
        }
        return;
    }
    if app.show_findings {
        match code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('S') => app.close_findings(),
            KeyCode::Char('j') | KeyCode::Down => app.findings_move(1),
            KeyCode::Char('k') | KeyCode::Up => app.findings_move(-1),
            KeyCode::Enter => app.findings_jump(),
            _ => {}
        }
        return;
    }
    app.status = None;

    match code {
        KeyCode::Char('q') => app.should_quit = true,
        // Esc backs out of an active search first, then quits.
        KeyCode::Esc => {
            if app.search.is_some() {
                app.clear_search();
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => app.move_cursor(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_cursor(-1),
        KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => app.page_down(),
        KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => app.page_up(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::Char('g') | KeyCode::Home => app.go_top(),
        KeyCode::Char('G') | KeyCode::End => app.go_bottom(),
        KeyCode::Char('n') => app.next_match(),
        KeyCode::Char('N') => app.prev_match(),
        KeyCode::Tab => app.next_file(),
        KeyCode::BackTab => app.prev_file(),
        // Scan for known-bad signatures.
        KeyCode::Char('S') => app.begin_scan(),
        // Search & filter (require an open file — otherwise search_hits would
        // panic on the empty welcome screen).
        KeyCode::Char('/') => {
            if app.has_files() {
                app.begin_input(InputKind::Search);
            } else {
                app.status = Some("open a file before searching".into());
            }
        }
        KeyCode::Char('f') => {
            if app.has_files() {
                app.toggle_filter();
            } else {
                app.status = Some("open a file before filtering".into());
            }
        }
        // Import / manage files.
        KeyCode::Char('o') => app.open_browser(),
        KeyCode::Char('w') => app.close_current_file(),
        // Manage highlights.
        KeyCode::Char('a') => app.begin_input(InputKind::Keyword),
        KeyCode::Char('r') => app.begin_input(InputKind::Regex),
        KeyCode::Char('x') => app.remove_last_rule(),
        KeyCode::Char('i') => app.toggle_ignore_case(),
        KeyCode::Char('l') => app.toggle_legend(),
        KeyCode::Char('?') => app.toggle_help(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn app_with_sample() -> App {
        App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap()
    }

    #[test]
    fn track_fraction_clamps_and_handles_short_track() {
        let tall = Rect {
            x: 0,
            y: 10,
            width: 1,
            height: 11,
        };
        assert!((track_fraction(tall, 10) - 0.0).abs() < f64::EPSILON);
        assert!((track_fraction(tall, 20) - 1.0).abs() < f64::EPSILON);
        assert!((track_fraction(tall, 0) - 0.0).abs() < f64::EPSILON);
        assert!((track_fraction(tall, 100) - 1.0).abs() < f64::EPSILON);

        let short = Rect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(track_fraction(short, 0), 0.0);
    }

    #[test]
    fn viewer_slash_and_filter_require_open_file() {
        let mut empty = App::new(&[], Vec::new(), false).unwrap();
        handle_viewer(&mut empty, KeyCode::Char('/'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before searching")
        );
        handle_viewer(&mut empty, KeyCode::Char('f'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before filtering")
        );
    }

    #[test]
    fn viewer_begins_search_and_scan() {
        let mut app = app_with_sample();
        handle_viewer(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        assert_eq!(app.mode, Mode::Input);
        assert_eq!(app.input_kind, InputKind::Search);

        app.mode = Mode::Viewer;
        handle_viewer(&mut app, KeyCode::Char('S'), KeyModifiers::NONE);
        assert!(app.scanning());
    }

    #[test]
    fn input_chars_enter_and_esc() {
        let mut app = app_with_sample();
        app.begin_input(InputKind::Keyword);
        handle_input(&mut app, KeyCode::Char('E'));
        handle_input(&mut app, KeyCode::Char('R'));
        assert_eq!(app.input_buffer, "ER");
        handle_input(&mut app, KeyCode::Backspace);
        assert_eq!(app.input_buffer, "E");
        handle_input(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Viewer);
        assert!(app.input_buffer.is_empty());

        app.begin_input(InputKind::Keyword);
        handle_input(&mut app, KeyCode::Char('X'));
        handle_input(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Viewer);
        assert_eq!(app.rules.len(), 1);
        assert_eq!(app.rules[0].label, "X");
    }

    #[test]
    fn esc_clears_search_before_quit() {
        let mut app = app_with_sample();
        app.begin_input(InputKind::Search);
        app.push_input_chars("error".chars());
        app.confirm_input();
        assert!(app.search.is_some());
        handle_viewer(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.search.is_none());
        assert!(!app.should_quit);
        handle_viewer(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.should_quit);
    }
}
