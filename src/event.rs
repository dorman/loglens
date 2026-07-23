use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use ratatui::DefaultTerminal;

use crate::app::{App, InputKind, Mode};
use crate::ui;

/// Lines scanned per rendered frame while a scan is running.
const SCAN_CHUNK: usize = 4000;

pub fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;

        // While scanning, advance a chunk per frame and poll (non-blocking, with
        // a small timeout for frame pacing) so the progress bar animates and the
        // user can cancel with Esc/q.
        if app.scanning() {
            app.scan_step(SCAN_CHUNK);
            if event::poll(Duration::from_millis(8))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press
                        && matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                    {
                        app.cancel_scan();
                    }
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
                // Click a finding row to jump straight to it.
                let inner = inner(r.findings);
                if hit(inner, col, row) {
                    let idx = r.findings_top + (row - inner.y) as usize;
                    if idx < app.findings.len() {
                        app.findings_sel = idx;
                        app.findings_jump();
                    }
                }
                return;
            }
            if app.mode == Mode::Browser {
                // Click a row in the browser popup to select it.
                let inner = inner(r.browser);
                if hit(inner, col, row) {
                    let idx = r.browser_top + (row - inner.y) as usize;
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
        KeyCode::Char(c) => app.input_buffer.push(c),
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
        // Search & filter.
        KeyCode::Char('/') => app.begin_input(InputKind::Search),
        KeyCode::Char('f') => app.toggle_filter(),
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
