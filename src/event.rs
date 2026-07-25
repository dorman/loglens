use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::DefaultTerminal;
use ratatui::layout::Rect;

use crate::app::{App, InputKind, Mode};
use crate::ui;

/// Lines scanned per rendered frame while a scan is running.
const SCAN_CHUNK: usize = 4000;
/// Lines of highlight-matching per frame while rules are being rescanned.
/// Slightly smaller than [`SCAN_CHUNK`] because each line may run many regexes.
const RESCAN_CHUNK: usize = 2000;

/// Key kinds that should drive the UI. Accept both Press and Repeat:
/// some terminals and automated input inject Repeat (or only one of the
/// two), and ignoring Repeat made held keys / burst typing look broken.
fn key_is_actionable(kind: KeyEventKind) -> bool {
    matches!(kind, KeyEventKind::Press | KeyEventKind::Repeat)
}

fn dispatch_key(app: &mut App, key: KeyEvent) {
    match app.mode {
        Mode::Input => handle_input(app, key.code),
        Mode::Browser => handle_browser(app, key.code),
        Mode::Viewer => handle_viewer(app, key.code, key.modifiers),
    }
}

pub fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;

        // While a signature scan or highlight rescan is running, advance a
        // chunk per frame and drain the input queue (only Esc/q act) so the
        // progress bar animates, cancel stays responsive, and buffered keys
        // don't burst-execute as commands the moment the work finishes.
        if app.busy() {
            if app.scanning() {
                app.scan_step(SCAN_CHUNK);
            } else if app.rescanning() {
                app.rescan_step(RESCAN_CHUNK);
            }
            let mut timeout = Duration::from_millis(8);
            while event::poll(timeout)? {
                timeout = Duration::ZERO;
                if let Event::Key(key) = event::read()?
                    && key_is_actionable(key.kind)
                    && matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                {
                    if app.scanning() {
                        app.cancel_scan();
                    } else {
                        app.cancel_rescan();
                    }
                }
            }
            continue;
        }

        match event::read()? {
            Event::Key(key) => {
                if !key_is_actionable(key.kind) {
                    continue;
                }
                dispatch_key(app, key);
                // While the input prompt is open, drain any already-queued
                // keystrokes/pastes before the next redraw. Fast typists and
                // automation often deliver a burst between frames; handling
                // them together keeps characters from appearing "lost".
                if app.mode == Mode::Input {
                    while event::poll(Duration::ZERO)? {
                        match event::read()? {
                            Event::Key(k) if key_is_actionable(k.kind) => dispatch_key(app, k),
                            Event::Paste(text) => app.push_input_chars(text.chars()),
                            _ => {}
                        }
                        if app.mode != Mode::Input {
                            break;
                        }
                    }
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
    let r = app.regions.clone();

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
            // Click a file tab -> switch to that file.
            for (i, tab) in r.tab_hits.iter().enumerate() {
                if hit(*tab, col, row) {
                    app.select_file(i);
                    return;
                }
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
        // Footer advertises q; treat it like ?/Esc so it closes the overlay
        // instead of being swallowed with no effect.
        if matches!(code, KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Esc) {
            app.toggle_help();
        }
        return;
    }
    if app.show_findings {
        match code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('S') | KeyCode::Char('s') => {
                app.close_findings()
            }
            KeyCode::Char('j') | KeyCode::Down => app.findings_move(1),
            KeyCode::Char('k') | KeyCode::Up => app.findings_move(-1),
            KeyCode::Enter => app.findings_jump(),
            KeyCode::Char('e') => app.export_findings(),
            _ => {}
        }
        return;
    }
    app.status = None;

    match code {
        KeyCode::Char('q') => app.should_quit = true,
        // Esc backs out of search, then filter, then quits — same “peel one
        // layer” pattern as every other Esc binding in the TUI.
        KeyCode::Esc => {
            if app.search.is_some() {
                app.clear_search();
            } else if app.filter_on {
                app.clear_filter();
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => app.move_cursor(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_cursor(-1),
        KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) => app.page_down(),
        KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => app.page_up(),
        // Space mirrors less/more page-down; Shift-Space is not distinguished in
        // most terminals, so page-up stays on Ctrl-u / PgUp.
        KeyCode::Char(' ') | KeyCode::PageDown => app.page_down(),
        KeyCode::PageUp => app.page_up(),
        KeyCode::Char('g') | KeyCode::Home => app.go_top(),
        KeyCode::Char('G') | KeyCode::End => app.go_bottom(),
        KeyCode::Char('m') => app.toggle_bookmark(),
        KeyCode::Char('M') => app.clear_bookmarks(),
        KeyCode::Char('\'') => app.next_bookmark(),
        KeyCode::Char('"') => app.prev_bookmark(),
        KeyCode::Char('n') => app.next_match(),
        KeyCode::Char('N') => app.prev_match(),
        KeyCode::Tab | KeyCode::Char(']') => app.next_file(),
        KeyCode::BackTab | KeyCode::Char('[') => app.prev_file(),
        // Scan for known-bad signatures. Lowercase `s` reopens the last panel.
        KeyCode::Char('S') => app.begin_scan(),
        KeyCode::Char('s') => app.toggle_findings(),
        KeyCode::Char('e') => app.export_findings(),
        // Go to absolute line number (1-based), like less/vim.
        KeyCode::Char(':') => {
            if app.has_files() {
                app.begin_input(InputKind::GoToLine);
            } else {
                app.status = Some("open a file before jumping to a line".into());
            }
        }
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
        // One-shot clear of search + filter (Esc still peels one layer at a time).
        KeyCode::Char('c') => app.clear_search_and_filter(),
        // Import / manage files.
        KeyCode::Char('o') => app.open_browser(),
        KeyCode::Char('w') => app.close_current_file(),
        // Copy the cursor line to the system clipboard (OSC-52).
        KeyCode::Char('y') => app.yank_current_line(),
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
        handle_viewer(&mut empty, KeyCode::Char(':'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before jumping to a line")
        );
    }

    #[test]
    fn viewer_colon_begins_go_to_line() {
        let mut app = app_with_sample();
        handle_viewer(&mut app, KeyCode::Char(':'), KeyModifiers::NONE);
        assert_eq!(app.mode, Mode::Input);
        assert_eq!(app.input_kind, InputKind::GoToLine);
    }

    #[test]
    fn viewer_y_without_files_prompts_to_open() {
        // Avoid yanking with a real file here — OSC-52 would write escape
        // codes to the test runner's stdout.
        let mut empty = App::new(&[], Vec::new(), false).unwrap();
        handle_viewer(&mut empty, KeyCode::Char('y'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before copying")
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
    fn viewer_space_pages_down_like_less() {
        let mut app = app_with_sample();
        app.viewport_height = 5;
        let start = app.file().view_pos;
        handle_viewer(&mut app, KeyCode::Char(' '), KeyModifiers::NONE);
        assert_eq!(app.file().view_pos, start + 5);
        handle_viewer(&mut app, KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(app.file().view_pos, start + 10);
    }

    #[test]
    fn findings_keys_toggle_and_export() {
        let mut app = app_with_sample();
        handle_viewer(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no findings — press S to scan")
        );
        handle_viewer(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no findings to export")
        );

        app.begin_scan();
        for _ in 0..10_000 {
            if app.scan_step(10_000) {
                break;
            }
        }
        assert!(!app.findings.is_empty());
        assert!(app.show_findings);
        handle_viewer(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
        assert!(!app.show_findings);
        handle_viewer(&mut app, KeyCode::Char('s'), KeyModifiers::NONE);
        assert!(app.show_findings);

        let path = std::env::temp_dir().join(format!(
            "loglens-findings-event-{}-{}.md",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        app.export_findings_to(&path).unwrap();
        assert!(path.exists());
        std::fs::remove_file(&path).ok();

        // `e` from the findings panel also exports (status reflects success).
        handle_viewer(&mut app, KeyCode::Char('e'), KeyModifiers::NONE);
        assert!(
            app.status.as_deref().unwrap_or("").contains("exported")
                || app
                    .status
                    .as_deref()
                    .unwrap_or("")
                    .contains("export failed"),
            "unexpected status: {:?}",
            app.status
        );
        // Clean up default cwd export if the keybinding wrote it.
        let _ = std::fs::remove_file("loglens-findings.md");
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
    fn burst_typing_into_input_prompt() {
        // Simulates the automation / fast-typist case: many chars arrive
        // back-to-back after opening the prompt.
        let mut app = app_with_sample();
        handle_viewer(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(app.mode, Mode::Input);
        for c in "ERROR".chars() {
            handle_input(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.input_buffer, "ERROR");
        handle_input(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Viewer);
        assert_eq!(app.rules.len(), 1);
        assert_eq!(app.rules[0].label, "ERROR");
        assert!(key_is_actionable(KeyEventKind::Press));
        assert!(key_is_actionable(KeyEventKind::Repeat));
        assert!(!key_is_actionable(KeyEventKind::Release));
    }

    #[test]
    fn bracket_keys_switch_files_like_tab() {
        let mut app = App::new(
            &["samples/sample.log".into(), "samples/network.log".into()],
            Vec::new(),
            false,
        )
        .unwrap();
        assert_eq!(app.files.len(), 2);
        assert_eq!(app.current, 0);
        handle_viewer(&mut app, KeyCode::Char(']'), KeyModifiers::NONE);
        assert_eq!(app.current, 1);
        handle_viewer(&mut app, KeyCode::Char(']'), KeyModifiers::NONE);
        assert_eq!(app.current, 0);
        handle_viewer(&mut app, KeyCode::Char('['), KeyModifiers::NONE);
        assert_eq!(app.current, 1);
        handle_viewer(&mut app, KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.current, 0);
        handle_viewer(&mut app, KeyCode::BackTab, KeyModifiers::NONE);
        assert_eq!(app.current, 1);
    }

    #[test]
    fn mouse_click_selects_tab() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        let mut app = App::new(
            &["samples/sample.log".into(), "samples/network.log".into()],
            Vec::new(),
            false,
        )
        .unwrap();
        app.regions.tab_hits = vec![
            Rect {
                x: 2,
                y: 1,
                width: 12,
                height: 1,
            },
            Rect {
                x: 15,
                y: 1,
                width: 14,
                height: 1,
            },
        ];
        assert_eq!(app.current, 0);
        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 16,
                row: 1,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.current, 1);
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

    #[test]
    fn esc_clears_filter_before_quit() {
        let mut app = app_with_sample();
        app.begin_input(InputKind::Search);
        app.push_input_chars("error".chars());
        app.confirm_input();
        handle_viewer(&mut app, KeyCode::Char('f'), KeyModifiers::NONE);
        assert!(app.filter_on);
        // First Esc clears search; filter stays on.
        handle_viewer(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.search.is_none());
        assert!(app.filter_on);
        assert!(!app.should_quit);
        // Second Esc clears filter.
        handle_viewer(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!app.filter_on);
        assert!(!app.should_quit);
        assert_eq!(app.status.as_deref(), Some("filter cleared"));
        // Third Esc finally quits.
        handle_viewer(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.should_quit);
    }

    #[test]
    fn c_clears_search_and_filter_together() {
        let mut app = app_with_sample();
        app.begin_input(InputKind::Search);
        app.push_input_chars("error".chars());
        app.confirm_input();
        handle_viewer(&mut app, KeyCode::Char('f'), KeyModifiers::NONE);
        assert!(app.search.is_some());
        assert!(app.filter_on);
        handle_viewer(&mut app, KeyCode::Char('c'), KeyModifiers::NONE);
        assert!(app.search.is_none());
        assert!(!app.filter_on);
        assert!(!app.should_quit);
        assert_eq!(app.status.as_deref(), Some("search and filter cleared"));
        // Idle press reports nothing to clear (does not quit).
        handle_viewer(&mut app, KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(app.status.as_deref(), Some("nothing to clear"));
        assert!(!app.should_quit);
    }

    #[test]
    fn help_q_closes_overlay_without_quitting() {
        let mut app = app_with_sample();
        handle_viewer(&mut app, KeyCode::Char('?'), KeyModifiers::NONE);
        assert!(app.show_help);
        handle_viewer(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(!app.show_help);
        assert!(!app.should_quit);
    }

    #[test]
    fn bookmark_keys_toggle_and_jump() {
        let mut app = app_with_sample();
        assert!(app.file().lines.len() >= 3);
        app.file_mut().view_pos = 0;
        handle_viewer(&mut app, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(app.file().bookmarks, vec![0]);
        app.move_cursor(2);
        handle_viewer(&mut app, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(app.file().bookmarks, vec![0, 2]);
        handle_viewer(&mut app, KeyCode::Char('\''), KeyModifiers::NONE);
        assert_eq!(app.file().view_pos, 0);
        handle_viewer(&mut app, KeyCode::Char('\''), KeyModifiers::NONE);
        assert_eq!(app.file().view_pos, 2);
        handle_viewer(&mut app, KeyCode::Char('"'), KeyModifiers::NONE);
        assert_eq!(app.file().view_pos, 0);
        handle_viewer(&mut app, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(app.file().bookmarks, vec![2]);
    }

    #[test]
    fn clear_bookmarks_key_empties_marks() {
        let mut app = app_with_sample();
        app.file_mut().view_pos = 0;
        handle_viewer(&mut app, KeyCode::Char('m'), KeyModifiers::NONE);
        app.move_cursor(1);
        handle_viewer(&mut app, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(app.file().bookmarks.len(), 2);
        handle_viewer(&mut app, KeyCode::Char('M'), KeyModifiers::NONE);
        assert!(app.file().bookmarks.is_empty());
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("cleared 2 bookmarks")
        );
        // Second press reports that there is nothing left.
        handle_viewer(&mut app, KeyCode::Char('M'), KeyModifiers::NONE);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no bookmarks to clear")
        );
    }

    #[test]
    fn bookmark_requires_open_file() {
        let mut empty = App::new(&[], Vec::new(), false).unwrap();
        handle_viewer(&mut empty, KeyCode::Char('m'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before bookmarking")
        );
        handle_viewer(&mut empty, KeyCode::Char('\''), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before jumping bookmarks")
        );
        handle_viewer(&mut empty, KeyCode::Char('M'), KeyModifiers::NONE);
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before clearing bookmarks")
        );
    }
}
