use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::layout::Rect;
use regex::Regex;

use crate::browser::Browser;
use crate::ingest;
use crate::rules::{self, Rule};
use crate::signatures::{self, Severity, Signature};

/// A single scan hit: signature `sig` matched line `line` of file `file`.
#[derive(Clone, Copy)]
pub struct Finding {
    pub file: usize,
    pub line: usize,
    pub sig: usize,
}

/// In-progress scan state, advanced a chunk at a time so the UI can show a
/// live progress bar and stay responsive (cancellable).
pub struct ScanState {
    pub file: usize,
    pub line: usize,
    pub processed: usize,
    pub total: usize,
    pub findings: Vec<Finding>,
}

/// Screen rectangles recorded during rendering so the mouse handler can
/// hit-test clicks against what is actually on screen.
#[derive(Default, Clone, Copy)]
pub struct Regions {
    pub tabs: Rect,
    pub log: Rect,
    pub legend: Rect,
    /// The scrollbar track column (empty when the file fits on screen).
    pub scrollbar: Rect,
    pub browser: Rect,
    /// First visible entry index in the browser list (for click mapping).
    pub browser_top: usize,
    pub findings: Rect,
    /// First visible finding index (for click mapping).
    pub findings_top: usize,
}

pub struct MatchSpan {
    pub start: usize,
    pub end: usize,
    pub rule: usize,
}

pub struct LogFile {
    pub name: String,
    pub lines: Vec<String>,
    /// Match spans per line, indexed the same as `lines`.
    pub matches: Vec<Vec<MatchSpan>>,
    /// Line indices (into `lines`) that contain at least one highlight match.
    pub match_lines: Vec<usize>,
    /// Total match count per rule, indexed the same as `App::rules`.
    pub rule_counts: Vec<usize>,

    /// The line indices currently displayed, in order. In normal mode this is
    /// every line; in filter mode it is only the matching subset.
    pub view: Vec<usize>,
    /// Cursor position as an index *into `view`*.
    pub view_pos: usize,
    /// Index into `view` of the first visible row.
    pub top: usize,
    /// Highest-severity scan finding per line (None until a scan runs).
    pub scan_severity: Vec<Option<Severity>>,
}

impl LogFile {
    fn load(path: &Path, name: String, rules: &[Rule]) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

        let line_count = lines.len();
        let mut file = LogFile {
            name,
            lines,
            matches: Vec::new(),
            match_lines: Vec::new(),
            rule_counts: Vec::new(),
            view: Vec::new(),
            view_pos: 0,
            top: 0,
            scan_severity: vec![None; line_count],
        };
        file.rescan(rules);
        file.view = (0..file.lines.len()).collect();
        Ok(file)
    }

    /// Recompute all highlight match spans against the current rule set.
    pub fn rescan(&mut self, rules: &[Rule]) {
        let mut matches: Vec<Vec<MatchSpan>> = Vec::with_capacity(self.lines.len());
        let mut match_lines = Vec::new();
        let mut rule_counts = vec![0usize; rules.len()];

        for (i, line) in self.lines.iter().enumerate() {
            let mut spans = Vec::new();
            for (rule_idx, rule) in rules.iter().enumerate() {
                for m in rule.regex.find_iter(line) {
                    spans.push(MatchSpan {
                        start: m.start(),
                        end: m.end(),
                        rule: rule_idx,
                    });
                    rule_counts[rule_idx] += 1;
                }
            }
            if !spans.is_empty() {
                spans.sort_by_key(|s| s.start);
                match_lines.push(i);
            }
            matches.push(spans);
        }

        self.matches = matches;
        self.match_lines = match_lines;
        self.rule_counts = rule_counts;
    }

    /// Rebuild `view` for the current filter/search state, keeping the cursor on
    /// (or just past) the line it was on before.
    pub fn rebuild_view(&mut self, filter_on: bool, search: Option<&Regex>) {
        let anchor = self.view.get(self.view_pos).copied().unwrap_or(0);

        self.view = if !filter_on {
            (0..self.lines.len()).collect()
        } else if let Some(re) = search {
            self.lines
                .iter()
                .enumerate()
                .filter(|(_, l)| re.is_match(l))
                .map(|(i, _)| i)
                .collect()
        } else {
            self.match_lines.clone()
        };

        self.view_pos = self
            .view
            .iter()
            .position(|&l| l >= anchor)
            .unwrap_or_else(|| self.view.len().saturating_sub(1));
        if self.view.is_empty() {
            self.view_pos = 0;
        }
        self.top = 0;
    }

    pub fn total_matches(&self) -> usize {
        self.rule_counts.iter().sum()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Viewer,
    Browser,
    Input,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum InputKind {
    Keyword,
    Regex,
    Search,
}

pub struct Search {
    pub raw: String,
    pub regex: Regex,
}

pub struct App {
    pub rules: Vec<Rule>,
    pub files: Vec<LogFile>,
    pub current: usize,
    pub mode: Mode,
    pub browser: Browser,
    pub ignore_case: bool,

    pub filter_on: bool,
    pub search: Option<Search>,
    /// Rule the user last clicked in the legend, marked and stepped through.
    pub active_rule: Option<usize>,

    /// Built-in detection library and the results of the last scan.
    pub signatures: Vec<Signature>,
    pub findings: Vec<Finding>,
    pub findings_sel: usize,
    pub show_findings: bool,
    /// Present while a scan is running.
    pub scan: Option<ScanState>,

    pub input_kind: InputKind,
    pub input_buffer: String,

    pub show_legend: bool,
    pub show_help: bool,
    pub viewport_height: usize,
    pub regions: Regions,
    /// True while the user is dragging the scrollbar thumb.
    pub scrollbar_drag: bool,
    pub status: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(inputs: &[String], rules: Vec<Rule>, ignore_case: bool) -> Result<Self> {
        let start_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let mut app = App {
            rules,
            files: Vec::new(),
            current: 0,
            mode: Mode::Viewer,
            browser: Browser::new(start_dir),
            ignore_case,
            filter_on: false,
            search: None,
            active_rule: None,
            signatures: signatures::builtin(),
            findings: Vec::new(),
            findings_sel: 0,
            show_findings: false,
            scan: None,
            input_kind: InputKind::Keyword,
            input_buffer: String::new(),
            show_legend: true,
            show_help: false,
            viewport_height: 20,
            regions: Regions::default(),
            scrollbar_drag: false,
            status: None,
            should_quit: false,
        };

        let paths: Vec<PathBuf> = inputs.iter().map(PathBuf::from).collect();
        if !paths.is_empty() {
            app.open_resolved(&paths);
        }

        // With no files, land on the branded welcome screen (press `o` to open
        // the browser); otherwise go straight to the viewer.
        app.mode = Mode::Viewer;
        app.status = None;
        Ok(app)
    }

    // --- Opening files ---------------------------------------------------

    /// Resolve each input (file / folder / zip) and open the resulting logs.
    pub fn open_resolved(&mut self, inputs: &[PathBuf]) {
        let mut targets = Vec::new();
        let mut errors = Vec::new();
        for p in inputs {
            match ingest::resolve(p) {
                Ok(mut t) => targets.append(&mut t),
                Err(e) => errors.push(format!("{e}")),
            }
        }

        let mut opened = 0;
        for t in &targets {
            match LogFile::load(&t.path, t.name.clone(), &self.rules) {
                Ok(mut f) => {
                    f.rebuild_view(self.filter_on, self.search.as_ref().map(|s| &s.regex));
                    self.files.push(f);
                    opened += 1;
                }
                Err(e) => errors.push(format!("{e}")),
            }
        }

        if opened > 0 {
            self.current = self.files.len() - opened;
            self.mode = Mode::Viewer;
        }
        self.status = Some(match (opened, errors.len()) {
            (0, 0) => "no log files found".to_string(),
            (n, 0) => format!("opened {n} file(s)"),
            (n, e) => format!("opened {n}, {e} failed/skipped"),
        });
    }

    /// Open the marked files (or the selected file) from the browser.
    pub fn open_selected_files(&mut self) {
        let paths = self.browser.files_to_open();
        if paths.is_empty() {
            self.status = Some("nothing selected (Space to mark, O to open a folder)".into());
            return;
        }
        self.browser.marked.clear();
        self.open_resolved(&paths);
    }

    /// Open every log under the highlighted directory (or the current directory
    /// if a file is selected) recursively.
    pub fn open_selected_dir(&mut self) {
        let dir = self.browser.selected_dir();
        self.open_resolved(&[dir]);
    }

    pub fn has_files(&self) -> bool {
        !self.files.is_empty()
    }

    pub fn file(&self) -> &LogFile {
        &self.files[self.current]
    }

    pub fn file_mut(&mut self) -> &mut LogFile {
        &mut self.files[self.current]
    }

    // --- Rule management -------------------------------------------------

    pub fn begin_input(&mut self, kind: InputKind) {
        self.input_kind = kind;
        self.input_buffer.clear();
        self.mode = Mode::Input;
    }

    fn leave_input(&mut self) {
        self.input_buffer.clear();
        self.mode = if self.has_files() {
            Mode::Viewer
        } else {
            Mode::Browser
        };
    }

    pub fn cancel_input(&mut self) {
        self.leave_input();
    }

    pub fn confirm_input(&mut self) {
        let text = self.input_buffer.trim().to_string();
        let kind = self.input_kind;
        self.leave_input();

        match kind {
            InputKind::Search => self.set_search(&text),
            InputKind::Keyword | InputKind::Regex => {
                if text.is_empty() {
                    return;
                }
                let is_regex = kind == InputKind::Regex;
                match rules::compile_rule(&text, is_regex, self.ignore_case, self.rules.len()) {
                    Ok(rule) => {
                        self.rules.push(rule);
                        self.rescan_all();
                        self.status = Some(format!("added highlight: {text}"));
                    }
                    Err(e) => self.status = Some(format!("{e}")),
                }
            }
        }
    }

    pub fn remove_last_rule(&mut self) {
        if let Some(rule) = self.rules.pop() {
            if self.active_rule == Some(self.rules.len()) {
                self.active_rule = None;
            }
            self.rescan_all();
            self.status = Some(format!("removed highlight: {}", rule.label));
        }
    }

    pub fn toggle_ignore_case(&mut self) {
        self.ignore_case = !self.ignore_case;
        let mut rebuilt = Vec::with_capacity(self.rules.len());
        for (i, r) in self.rules.iter().enumerate() {
            if let Ok(rule) = rules::compile_rule(&r.label, r.is_regex, self.ignore_case, i) {
                rebuilt.push(rule);
            }
        }
        self.rules = rebuilt;
        self.rescan_all();
        self.status = Some(format!(
            "case-insensitive: {}",
            if self.ignore_case { "on" } else { "off" }
        ));
    }

    // --- Search & filter -------------------------------------------------

    fn set_search(&mut self, text: &str) {
        if text.is_empty() {
            self.search = None;
            self.rebuild_views();
            self.status = Some("search cleared".into());
            return;
        }
        // Search is always case-insensitive literal-substring matching.
        match Regex::new(&format!("(?i){}", regex::escape(text))) {
            Ok(regex) => {
                self.search = Some(Search {
                    raw: text.to_string(),
                    regex,
                });
                self.rebuild_views();
                self.jump_to_first_match();
                let hits = self.search_hits();
                self.status = Some(format!("search '{text}': {hits} match(es)"));
            }
            Err(e) => self.status = Some(format!("{e}")),
        }
    }

    pub fn clear_search(&mut self) {
        if self.search.is_some() {
            self.search = None;
            self.rebuild_views();
            self.status = Some("search cleared".into());
        }
    }

    pub fn toggle_filter(&mut self) {
        self.filter_on = !self.filter_on;
        self.rebuild_views();
        self.ensure_cursor_visible();
        self.status = Some(format!(
            "filter: {}",
            if self.filter_on { "on" } else { "off" }
        ));
    }

    fn search_hits(&self) -> usize {
        match &self.search {
            Some(s) => self
                .file()
                .lines
                .iter()
                .map(|l| s.regex.find_iter(l).count())
                .sum(),
            None => 0,
        }
    }

    /// Is `line_idx` part of the active match set (search results if searching,
    /// otherwise highlight matches)? Used by next/prev-match navigation.
    fn is_active_match(&self, line_idx: usize) -> bool {
        if let Some(s) = &self.search {
            s.regex.is_match(&self.file().lines[line_idx])
        } else {
            !self.file().matches[line_idx].is_empty()
        }
    }

    fn jump_to_first_match(&mut self) {
        if !self.has_files() {
            return;
        }
        let positions: Vec<usize> = self.file().view.clone();
        for (pos, &line) in positions.iter().enumerate() {
            if self.is_active_match(line) {
                self.file_mut().view_pos = pos;
                break;
            }
        }
        self.ensure_cursor_visible();
    }

    fn rescan_all(&mut self) {
        let rules = &self.rules;
        for f in &mut self.files {
            f.rescan(rules);
        }
        self.rebuild_views();
    }

    fn rebuild_views(&mut self) {
        let filter_on = self.filter_on;
        let search = self.search.as_ref().map(|s| &s.regex);
        for f in &mut self.files {
            f.rebuild_view(filter_on, search);
        }
        self.clamp_scroll();
    }

    // --- Viewer navigation ----------------------------------------------

    fn clamp_scroll(&mut self) {
        if !self.has_files() {
            return;
        }
        let height = self.viewport_height.max(1);
        let f = self.file_mut();
        let vlen = f.view.len();
        if f.view_pos >= vlen {
            f.view_pos = vlen.saturating_sub(1);
        }
        let max_top = vlen.saturating_sub(height);
        if f.top > max_top {
            f.top = max_top;
        }
    }

    fn ensure_cursor_visible(&mut self) {
        if !self.has_files() {
            return;
        }
        let height = self.viewport_height.max(1);
        let f = self.file_mut();
        if f.view_pos < f.top {
            f.top = f.view_pos;
        } else if f.view_pos >= f.top + height {
            f.top = f.view_pos - height + 1;
        }
    }

    pub fn move_cursor(&mut self, delta: isize) {
        if !self.has_files() {
            return;
        }
        let f = self.file_mut();
        let len = f.view.len();
        if len == 0 {
            return;
        }
        let new_pos = (f.view_pos as isize + delta).clamp(0, len as isize - 1);
        f.view_pos = new_pos as usize;
        self.ensure_cursor_visible();
        self.clamp_scroll();
    }

    pub fn page_down(&mut self) {
        self.move_cursor(self.viewport_height.max(1) as isize);
    }

    pub fn page_up(&mut self) {
        self.move_cursor(-(self.viewport_height.max(1) as isize));
    }

    pub fn go_top(&mut self) {
        if !self.has_files() {
            return;
        }
        let f = self.file_mut();
        f.view_pos = 0;
        f.top = 0;
    }

    pub fn go_bottom(&mut self) {
        if !self.has_files() {
            return;
        }
        let f = self.file_mut();
        f.view_pos = f.view.len().saturating_sub(1);
        self.ensure_cursor_visible();
        self.clamp_scroll();
    }

    pub fn next_match(&mut self) {
        if !self.has_files() {
            return;
        }
        let start = self.file().view_pos;
        let view = self.file().view.clone();
        for pos in (start + 1)..view.len() {
            if self.is_active_match(view[pos]) {
                self.file_mut().view_pos = pos;
                self.ensure_cursor_visible();
                self.clamp_scroll();
                return;
            }
        }
    }

    pub fn prev_match(&mut self) {
        if !self.has_files() {
            return;
        }
        let start = self.file().view_pos;
        let view = self.file().view.clone();
        for pos in (0..start).rev() {
            if self.is_active_match(view[pos]) {
                self.file_mut().view_pos = pos;
                self.ensure_cursor_visible();
                self.clamp_scroll();
                return;
            }
        }
    }

    /// Scroll the viewport by `delta` lines (mouse wheel / scrollbar), dragging
    /// the cursor along only as far as needed to keep it on screen.
    pub fn scroll(&mut self, delta: isize) {
        if !self.has_files() {
            return;
        }
        let height = self.viewport_height.max(1);
        let f = self.file_mut();
        let vlen = f.view.len();
        let max_top = vlen.saturating_sub(height) as isize;
        f.top = (f.top as isize + delta).clamp(0, max_top) as usize;
        if f.view_pos < f.top {
            f.view_pos = f.top;
        } else if f.view_pos >= f.top + height {
            f.view_pos = (f.top + height - 1).min(vlen.saturating_sub(1));
        }
    }

    /// Jump the viewport so `frac` (0.0..=1.0) of the scrollable range is above
    /// the top row. Used for clicking / dragging the scrollbar.
    pub fn scroll_to_fraction(&mut self, frac: f64) {
        if !self.has_files() {
            return;
        }
        let height = self.viewport_height.max(1);
        let f = self.file_mut();
        let vlen = f.view.len();
        let max_top = vlen.saturating_sub(height);
        let top = (frac.clamp(0.0, 1.0) * max_top as f64).round() as usize;
        f.top = top.min(max_top);
        if f.view_pos < f.top {
            f.view_pos = f.top;
        } else if f.view_pos >= f.top + height {
            f.view_pos = (f.top + height - 1).min(vlen.saturating_sub(1));
        }
    }

    /// Move the cursor to a visible row (clicked line), counted from the top of
    /// the viewport.
    pub fn select_view_row(&mut self, row_from_top: usize) {
        if !self.has_files() {
            return;
        }
        let pos = self.file().top + row_from_top;
        if pos < self.file().view.len() {
            self.file_mut().view_pos = pos;
        }
    }

    /// Clicking a legend entry marks that rule and jumps to its next occurrence
    /// (wrapping around), so repeated clicks step through every match.
    pub fn click_rule(&mut self, rule: usize) {
        if rule >= self.rules.len() || !self.has_files() {
            return;
        }
        self.active_rule = Some(rule);
        let view = self.file().view.clone();
        let n = view.len();
        if n == 0 {
            return;
        }
        let start = self.file().view_pos;
        for step in 1..=n {
            let pos = (start + step) % n;
            if self.file().matches[view[pos]].iter().any(|m| m.rule == rule) {
                self.file_mut().view_pos = pos;
                self.ensure_cursor_visible();
                self.clamp_scroll();
                self.status = Some(format!("jumped to '{}'", self.rules[rule].label));
                return;
            }
        }
        self.status = Some(format!(
            "no '{}' matches in this file",
            self.rules[rule].label
        ));
    }

    // --- Scan (built-in detections) -------------------------------------

    /// Start a scan. The work is then advanced by [`scan_step`] so the UI can
    /// render a progress bar. Resets any prior findings/markers.
    pub fn begin_scan(&mut self) {
        if !self.has_files() {
            self.status = Some("open a file before scanning".into());
            return;
        }
        self.show_findings = false;
        self.findings.clear();
        let mut total = 0;
        for f in &mut self.files {
            f.scan_severity = vec![None; f.lines.len()];
            total += f.lines.len();
        }
        self.scan = Some(ScanState {
            file: 0,
            line: 0,
            processed: 0,
            total,
            findings: Vec::new(),
        });
        self.status = Some("scanning…".into());
        // An empty corpus finishes immediately.
        if total == 0 {
            self.scan_step(1);
        }
    }

    /// Process up to `budget` lines of the running scan. Returns true when the
    /// scan has finished (and the findings panel has been populated).
    pub fn scan_step(&mut self, budget: usize) -> bool {
        let Some(mut st) = self.scan.take() else {
            return true;
        };
        let mut done = 0;
        while done < budget {
            if st.file >= self.files.len() {
                self.finalize_scan(st);
                return true;
            }
            let flen = self.files[st.file].lines.len();
            if st.line >= flen {
                st.file += 1;
                st.line = 0;
                continue;
            }
            let line = &self.files[st.file].lines[st.line];
            let mut best: Option<Severity> = None;
            for (si, sig) in self.signatures.iter().enumerate() {
                if sig.regex.is_match(line) {
                    st.findings.push(Finding {
                        file: st.file,
                        line: st.line,
                        sig: si,
                    });
                    best = Some(best.map_or(sig.severity, |b| b.max(sig.severity)));
                }
            }
            self.files[st.file].scan_severity[st.line] = best;
            st.line += 1;
            st.processed += 1;
            done += 1;
        }
        self.scan = Some(st);
        false
    }

    fn finalize_scan(&mut self, mut st: ScanState) {
        st.findings.sort_by(|a, b| {
            self.signatures[b.sig]
                .severity
                .cmp(&self.signatures[a.sig].severity)
                .then(a.file.cmp(&b.file))
                .then(a.line.cmp(&b.line))
        });
        let total = st.findings.len();
        self.findings = st.findings;
        self.findings_sel = 0;
        self.show_findings = total > 0;
        self.scan = None;

        let c = self.severity_counts();
        self.status = Some(if total == 0 {
            "scan complete — nothing notable found".into()
        } else {
            format!(
                "scan: {total} findings  ({} crit, {} high, {} med, {} low, {} info)",
                c[4], c[3], c[2], c[1], c[0]
            )
        });
    }

    pub fn cancel_scan(&mut self) {
        if self.scan.take().is_some() {
            self.status = Some("scan cancelled".into());
        }
    }

    pub fn scanning(&self) -> bool {
        self.scan.is_some()
    }

    /// Fraction complete (0.0..=1.0) of the running scan, if any.
    pub fn scan_fraction(&self) -> Option<f64> {
        self.scan.as_ref().map(|s| {
            if s.total == 0 {
                1.0
            } else {
                s.processed as f64 / s.total as f64
            }
        })
    }

    /// (lines processed, total lines, findings so far, current file name).
    pub fn scan_detail(&self) -> Option<(usize, usize, usize, String)> {
        self.scan.as_ref().map(|s| {
            let name = self
                .files
                .get(s.file)
                .map(|f| f.name.clone())
                .unwrap_or_default();
            (s.processed, s.total, s.findings.len(), name)
        })
    }

    /// Counts indexed by `Severity as usize` (Info=0 .. Critical=4).
    pub fn severity_counts(&self) -> [usize; 5] {
        let mut c = [0usize; 5];
        for f in &self.findings {
            c[self.signatures[f.sig].severity as usize] += 1;
        }
        c
    }

    pub fn findings_move(&mut self, delta: isize) {
        if self.findings.is_empty() {
            return;
        }
        let n = self.findings.len() as isize;
        self.findings_sel = (self.findings_sel as isize + delta).clamp(0, n - 1) as usize;
    }

    /// Jump to the selected finding and close the panel.
    pub fn findings_jump(&mut self) {
        if let Some(f) = self.findings.get(self.findings_sel).copied() {
            self.show_findings = false;
            self.jump_to_line(f.file, f.line);
        }
    }

    /// Focus a specific file+line, defeating the filter if it would hide it.
    pub fn jump_to_line(&mut self, file: usize, line: usize) {
        if file >= self.files.len() {
            return;
        }
        self.current = file;
        if !self.file().view.iter().any(|&l| l == line) {
            self.filter_on = false;
            self.rebuild_views();
        }
        if let Some(pos) = self.file().view.iter().position(|&l| l == line) {
            self.file_mut().view_pos = pos;
        }
        self.ensure_cursor_visible();
        self.clamp_scroll();
    }

    pub fn close_findings(&mut self) {
        self.show_findings = false;
    }

    pub fn next_file(&mut self) {
        if self.files.len() > 1 {
            self.current = (self.current + 1) % self.files.len();
        }
    }

    pub fn prev_file(&mut self) {
        if self.files.len() > 1 {
            self.current = (self.current + self.files.len() - 1) % self.files.len();
        }
    }

    pub fn close_current_file(&mut self) {
        if self.files.is_empty() {
            return;
        }
        self.files.remove(self.current);
        if self.current >= self.files.len() {
            self.current = self.files.len().saturating_sub(1);
        }
        if self.files.is_empty() {
            self.mode = Mode::Browser;
        }
    }

    pub fn open_browser(&mut self) {
        self.browser.refresh();
        self.mode = Mode::Browser;
    }

    pub fn close_browser(&mut self) {
        if self.has_files() {
            self.mode = Mode::Viewer;
        }
    }

    pub fn toggle_legend(&mut self) {
        self.show_legend = !self.show_legend;
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }
}
