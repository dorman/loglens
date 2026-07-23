use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::layout::Rect;
use regex::Regex;

use crate::browser::Browser;
use crate::ingest::{self, MAX_LOG_BYTES};
use crate::rules::{self, Rule, MAX_RULES};
use crate::signatures::{self, Severity, Signature};

/// Hard caps that keep hostile or pathological inputs from exhausting memory.
const MAX_MATCHES_PER_LINE: usize = 256;
const MAX_MATCHES_PER_FILE: usize = 100_000;
const MAX_FINDINGS: usize = 10_000;
const MAX_OPEN_FILES: usize = 500;
/// A 50 MB file of 1-byte lines would otherwise allocate tens of millions of
/// `String`s; cap line count so RAM stays bounded inside the byte budget.
const MAX_LINES_PER_FILE: usize = 250_000;
/// Truncate individual lines beyond this many bytes (at a char boundary).
const MAX_LINE_BYTES: usize = 32 * 1024;
/// Soft budget across all open tabs — further opens are skipped once hit.
const MAX_TOTAL_LINES: usize = 1_000_000;
/// Max characters accepted in the keyword / regex / search prompt (incl. paste).
pub const MAX_INPUT_LEN: usize = 4_096;

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
    /// Exact rect of the browser's entry list (excludes borders/footer), so
    /// mouse clicks map 1:1 onto entries.
    pub browser_list: Rect,
    /// First visible entry index in the browser list (for click mapping).
    pub browser_top: usize,
    pub findings: Rect,
    /// Exact rect of the findings list (excludes the severity bar and detail
    /// box), so mouse clicks map 1:1 onto findings.
    pub findings_list: Rect,
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
    /// True if the file was truncated (too many lines and/or overlong lines).
    pub truncated: bool,
}

impl LogFile {
    fn load(path: &Path, name: String, rules: &[Rule]) -> Result<Self> {
        // Cap the read so a direct open (CLI/browser) cannot bypass the folder
        // collection size limit and OOM the process. `take(limit+1)` also closes
        // the race where a file grows between a metadata check and the read.
        let file = File::open(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_LOG_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
            anyhow::bail!(
                "'{}' is larger than {} MB; open a smaller file or split it",
                path.display(),
                MAX_LOG_BYTES / (1024 * 1024)
            );
        }
        // Read bytes and convert lossily: real-world diagnostic logs routinely
        // contain stray non-UTF-8 bytes, which must not make the file unopenable.
        let content = String::from_utf8_lossy(&bytes);
        let (lines, truncated) = split_log_lines(&content);

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
            truncated,
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
        let mut total_matches = 0usize;

        'lines: for (i, line) in self.lines.iter().enumerate() {
            let mut spans = Vec::new();
            for (rule_idx, rule) in rules.iter().enumerate() {
                for m in rule.regex.find_iter(line) {
                    // Skip zero-width matches; they add no visual value and can
                    // explode span counts for patterns like `a*`.
                    if m.start() == m.end() {
                        continue;
                    }
                    spans.push(MatchSpan {
                        start: m.start(),
                        end: m.end(),
                        rule: rule_idx,
                    });
                    rule_counts[rule_idx] += 1;
                    total_matches += 1;
                    if spans.len() >= MAX_MATCHES_PER_LINE || total_matches >= MAX_MATCHES_PER_FILE
                    {
                        break;
                    }
                }
                if spans.len() >= MAX_MATCHES_PER_LINE || total_matches >= MAX_MATCHES_PER_FILE {
                    break;
                }
            }
            if !spans.is_empty() {
                spans.sort_by_key(|s| s.start);
                match_lines.push(i);
            }
            matches.push(spans);
            if total_matches >= MAX_MATCHES_PER_FILE {
                // Fill remaining lines with empty match lists so indices stay aligned.
                for _ in (i + 1)..self.lines.len() {
                    matches.push(Vec::new());
                }
                break 'lines;
            }
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

/// Split log text into owned lines, truncating overlong lines and stopping at
/// [`MAX_LINES_PER_FILE`]. Returns `(lines, truncated)`.
fn split_log_lines(content: &str) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut truncated = false;
    for line in content.lines() {
        if lines.len() >= MAX_LINES_PER_FILE {
            truncated = true;
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            truncated = true;
            let mut end = MAX_LINE_BYTES;
            while end > 0 && !line.is_char_boundary(end) {
                end -= 1;
            }
            lines.push(format!("{}…", &line[..end]));
        } else {
            lines.push(line.to_string());
        }
    }
    // A trailing empty line after a final newline is usually noise; `str::lines`
    // already drops it. Nothing else to do.
    (lines, truncated)
}

/// Compile a case-insensitive literal search pattern with the same size/nest
/// budgets as user highlight rules.
pub fn compile_search(text: &str) -> Result<Regex> {
    rules::compile_regex(&format!("(?i){}", regex::escape(text)))
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
    /// Temp directories created while extracting zip bundles; removed on Drop.
    temp_dirs: Vec<PathBuf>,
}

impl Drop for App {
    fn drop(&mut self) {
        for dir in self.temp_dirs.drain(..) {
            let _ = fs::remove_dir_all(dir);
        }
    }
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
            temp_dirs: Vec::new(),
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

    /// Append characters to the input prompt, respecting [`MAX_INPUT_LEN`].
    pub fn push_input_chars(&mut self, chars: impl IntoIterator<Item = char>) {
        for c in chars {
            if self.input_buffer.chars().count() >= MAX_INPUT_LEN {
                self.status = Some(format!("input limited to {MAX_INPUT_LEN} characters"));
                break;
            }
            if !c.is_control() {
                self.input_buffer.push(c);
            }
        }
    }

    // --- Opening files ---------------------------------------------------

    /// Resolve each input (file / folder / zip) and open the resulting logs.
    pub fn open_resolved(&mut self, inputs: &[PathBuf]) {
        let mut targets = Vec::new();
        let mut errors = Vec::new();
        for p in inputs {
            match ingest::resolve(p) {
                Ok(outcome) => {
                    if let Some(dir) = outcome.temp_dir {
                        self.temp_dirs.push(dir);
                    }
                    targets.extend(outcome.targets);
                }
                Err(e) => errors.push(format!("{e}")),
            }
        }

        let mut opened = 0;
        let mut skipped_cap = 0;
        let mut truncated = 0;
        let mut total_lines: usize = self.files.iter().map(|f| f.lines.len()).sum();
        for t in &targets {
            if self.files.len() >= MAX_OPEN_FILES || total_lines >= MAX_TOTAL_LINES {
                skipped_cap += 1;
                continue;
            }
            match LogFile::load(&t.path, t.name.clone(), &self.rules) {
                Ok(mut f) => {
                    if total_lines + f.lines.len() > MAX_TOTAL_LINES {
                        skipped_cap += 1;
                        continue;
                    }
                    if f.truncated {
                        truncated += 1;
                    }
                    total_lines += f.lines.len();
                    f.rebuild_view(self.filter_on, self.search.as_ref().map(|s| &s.regex));
                    self.files.push(f);
                    opened += 1;
                }
                Err(e) => errors.push(format!("{e}")),
            }
        }
        if skipped_cap > 0 {
            errors.push(format!(
                "open cap reached ({MAX_OPEN_FILES} files / {MAX_TOTAL_LINES} lines); skipped {skipped_cap}"
            ));
        }

        if opened > 0 {
            self.current = self.files.len() - opened;
            self.mode = Mode::Viewer;
        }
        self.status = Some(match (opened, errors.len(), truncated) {
            (0, 0, _) => "no log files found".to_string(),
            (n, 0, 0) => format!("opened {n} file(s)"),
            (n, 0, t) => format!("opened {n} file(s) ({t} truncated to line/length caps)"),
            (n, e, 0) => format!("opened {n}, {e} failed/skipped"),
            (n, e, t) => format!("opened {n}, {e} failed/skipped ({t} truncated)"),
        });
    }

    /// Open the marked files (or the selected file) from the browser.
    pub fn open_selected_files(&mut self) {
        let paths = self.browser.files_to_open();
        if paths.is_empty() {
            self.status = Some("nothing selected (Space to mark, O to open a folder/zip)".into());
            return;
        }
        self.browser.marked.clear();
        self.open_resolved(&paths);
    }

    /// Open every log under the highlighted directory or zip (or the current
    /// directory if a non-zip file is selected) recursively.
    pub fn open_selected_dir(&mut self) {
        let path = match self.browser.selected_entry() {
            Some(e) if e.is_dir || ingest::is_zip(&e.path) => e.path.clone(),
            _ => self.browser.cwd.clone(),
        };
        self.open_resolved(&[path]);
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
        // Stay on the welcome viewer when nothing is open; jumping to the
        // browser after a cancelled prompt was surprising from the splash screen.
        self.mode = Mode::Viewer;
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
                if self.rules.len() >= MAX_RULES {
                    self.status = Some(format!("highlight limit reached ({MAX_RULES})"));
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
        if !self.has_files() {
            self.status = Some("open a file before searching".into());
            return;
        }
        if text.is_empty() {
            self.search = None;
            self.rebuild_views();
            self.status = Some("search cleared".into());
            return;
        }
        // Search is always case-insensitive literal-substring matching.
        match compile_search(text) {
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
        if !self.has_files() {
            return 0;
        }
        match &self.search {
            // Bound work per line so a pathological literal over a huge line
            // cannot walk unbounded match counts during status reporting.
            Some(s) => self
                .file()
                .lines
                .iter()
                .map(|l| s.regex.find_iter(l).take(MAX_MATCHES_PER_LINE).count())
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
        let hit = view
            .iter()
            .enumerate()
            .skip(start + 1)
            .find(|&(_, &line)| self.is_active_match(line))
            .map(|(pos, _)| pos);
        if let Some(pos) = hit {
            self.file_mut().view_pos = pos;
            self.ensure_cursor_visible();
            self.clamp_scroll();
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
                    // Still record severity on the line even after the findings
                    // list is capped, so gutter markers remain useful.
                    best = Some(best.map_or(sig.severity, |b| b.max(sig.severity)));
                    if st.findings.len() < MAX_FINDINGS {
                        st.findings.push(Finding {
                            file: st.file,
                            line: st.line,
                            sig: si,
                        });
                    }
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
        let capped = total >= MAX_FINDINGS;
        self.status = Some(if total == 0 {
            "scan complete — nothing notable found".into()
        } else if capped {
            format!(
                "scan: {total}+ findings (capped)  ({} crit, {} high, {} med, {} low, {} info)",
                c[4], c[3], c[2], c[1], c[0]
            )
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
        if !self.file().view.contains(&line) {
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
        let removed = self.current;
        self.files.remove(removed);

        // Findings reference files by index: drop the closed file's findings
        // and shift the rest down so they keep pointing at the right files.
        self.scan = None;
        self.findings.retain(|f| f.file != removed);
        for f in &mut self.findings {
            if f.file > removed {
                f.file -= 1;
            }
        }
        if self.findings.is_empty() {
            self.show_findings = false;
        }
        self.findings_sel = self
            .findings_sel
            .min(self.findings.len().saturating_sub(1));

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_name(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("loglens-{prefix}-{nonce}"))
    }

    #[test]
    fn search_without_files_does_not_panic() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        assert!(!app.has_files());
        app.begin_input(InputKind::Search);
        app.push_input_chars("error".chars());
        app.confirm_input();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before searching")
        );
    }

    #[test]
    fn rejects_oversized_direct_file() {
        let path = tmp_name("huge");
        {
            let mut f = File::create(&path).unwrap();
            // Write just over the cap using a repeating buffer.
            let chunk = vec![b'a'; 1024 * 1024];
            let mut written = 0u64;
            while written <= MAX_LOG_BYTES {
                f.write_all(&chunk).unwrap();
                written += chunk.len() as u64;
            }
        }
        match LogFile::load(&path, "huge.log".into(), &[]) {
            Ok(_) => panic!("expected oversized file to be rejected"),
            Err(e) => assert!(format!("{e}").contains("larger than")),
        }
        fs::remove_file(&path).ok();
    }

    #[test]
    fn loads_sample_log() {
        let path = Path::new("samples/sample.log");
        if !path.exists() {
            return;
        }
        let file = LogFile::load(path, "sample.log".into(), &[]).unwrap();
        assert!(!file.lines.is_empty());
        assert_eq!(file.matches.len(), file.lines.len());
    }

    #[test]
    fn zero_width_regex_does_not_explode_matches() {
        let path = tmp_name("zw");
        fs::write(&path, "aaaa\nbbbb\n").unwrap();
        let rule = rules::compile_rule("a*", true, false, 0).unwrap();
        let file = LogFile::load(&path, "zw.log".into(), &[rule]).unwrap();
        let total: usize = file.matches.iter().map(|m| m.len()).sum();
        assert!(total <= MAX_MATCHES_PER_FILE);
        for spans in &file.matches {
            assert!(spans.len() <= MAX_MATCHES_PER_LINE);
            assert!(spans.iter().all(|s| s.start < s.end));
        }
        fs::remove_file(&path).ok();
    }

    #[test]
    fn input_buffer_respects_max_len() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.begin_input(InputKind::Keyword);
        app.push_input_chars(std::iter::repeat_n('x', MAX_INPUT_LEN + 50));
        assert_eq!(app.input_buffer.chars().count(), MAX_INPUT_LEN);
    }

    #[test]
    fn split_lines_caps_count_and_length() {
        // More lines than the cap.
        let many = "x\n".repeat(MAX_LINES_PER_FILE + 10);
        let (lines, truncated) = split_log_lines(&many);
        assert_eq!(lines.len(), MAX_LINES_PER_FILE);
        assert!(truncated);

        // A single overlong line is truncated at a char boundary.
        let long = "字".repeat((MAX_LINE_BYTES / 3) + 20);
        let (lines, truncated) = split_log_lines(&long);
        assert_eq!(lines.len(), 1);
        assert!(truncated);
        assert!(lines[0].ends_with('…'));
        assert!(lines[0].len() <= MAX_LINE_BYTES + '…'.len_utf8());
    }

    #[test]
    fn loads_truncated_many_short_lines() {
        let path = tmp_name("manylines");
        let mut f = File::create(&path).unwrap();
        for _ in 0..(MAX_LINES_PER_FILE + 5) {
            f.write_all(b"x\n").unwrap();
        }
        drop(f);
        let file = LogFile::load(&path, "many.log".into(), &[]).unwrap();
        assert_eq!(file.lines.len(), MAX_LINES_PER_FILE);
        assert!(file.truncated);
        fs::remove_file(&path).ok();
    }
}
