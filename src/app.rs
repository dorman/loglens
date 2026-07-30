use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::layout::Rect;
use regex::Regex;

use crate::browser::Browser;
use crate::ingest::{self, MAX_LOG_BYTES};
use crate::rules::{self, MAX_RULES, Rule};
use crate::signatures::{Library, Severity};
use crate::theme::Theme;

/// Hard caps that keep hostile or pathological inputs from exhausting memory.
const MAX_MATCHES_PER_LINE: usize = 256;
const MAX_MATCHES_PER_FILE: usize = 100_000;
const MAX_FINDINGS: usize = 10_000;
/// Findings below this severity are recorded on the gutter only (if matched)
/// and never enter the triage panel — keeps Low/Info noise from burning the cap.
const MIN_FINDING_SEVERITY: Severity = Severity::Medium;
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
/// Soft cap on bookmarks per open file (toggle fails past this).
const MAX_BOOKMARKS: usize = 64;
/// Findings export: base name, and how many numbered variants `e` will try
/// before giving up rather than overwriting an existing export.
const EXPORT_STEM: &str = "loglens-findings";
const EXPORT_DEFAULT_NAME: &str = "loglens-findings.md";
const MAX_EXPORT_FILES: usize = 99;

/// Severity filter tabs for the findings panel, in the order they are drawn and
/// cycled. `None` shows everything. Only Medium and above appear because
/// [`MIN_FINDING_SEVERITY`] keeps anything quieter out of the findings list.
pub(crate) const FINDING_FILTERS: [Option<Severity>; 4] = [
    None,
    Some(Severity::Critical),
    Some(Severity::High),
    Some(Severity::Medium),
];

/// Render a per-severity tally as `3 crit · 5 high · 4 med`, indexed by
/// `Severity as usize`.
///
/// Segments are derived from [`FINDING_FILTERS`] instead of being spelled out, so
/// a tally can never advertise a severity the findings list is unable to hold:
/// [`MIN_FINDING_SEVERITY`] keeps anything quieter out, which used to leave a
/// permanent `0 low · 0 info` in both the findings panel title and the export
/// header. Widening the filters widens every tally with them.
pub(crate) fn severity_tally(counts: [usize; 5]) -> String {
    FINDING_FILTERS
        .iter()
        .copied()
        .flatten()
        .map(|sev| {
            format!(
                "{} {}",
                counts[sev as usize],
                sev.label().to_ascii_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Every hit of signature `sig` within file `file`, collapsed into one entry.
///
/// A noisy log repeats the same condition on hundreds of lines. One finding per
/// line buried the few interesting hits under them and burned through
/// [`MAX_FINDINGS`], so occurrences of a signature within a file are counted
/// instead of listed. `line` is the first hit — the jump target — and `last` the
/// final one, so the panel can show the span a condition covers.
#[derive(Clone, Copy)]
pub struct Finding {
    pub file: usize,
    pub line: usize,
    pub sig: usize,
    pub last: usize,
    pub count: usize,
}

/// In-progress scan state, advanced a chunk at a time so the UI can show a
/// live progress bar and stay responsive (cancellable).
pub struct ScanState {
    pub file: usize,
    pub line: usize,
    pub processed: usize,
    pub total: usize,
    pub findings: Vec<Finding>,
    /// For the file under the cursor, where each signature's finding already
    /// sits in `findings`. Files are scanned in order, so this is cleared when
    /// the cursor advances — grouping needs no hashing, just one slot per
    /// signature.
    seen: Vec<Option<usize>>,
}

/// Fresh highlight-match data for one file, built off to the side during a
/// chunked rescan so cancel can drop the work without leaving half-updated tabs.
struct FileMatchData {
    matches: Vec<Vec<MatchSpan>>,
    match_lines: Vec<usize>,
    rule_counts: Vec<usize>,
    total_matches: usize,
}

impl FileMatchData {
    fn new(rule_count: usize, line_capacity: usize) -> Self {
        Self {
            matches: Vec::with_capacity(line_capacity),
            match_lines: Vec::new(),
            rule_counts: vec![0; rule_count],
            total_matches: 0,
        }
    }
}

/// In-progress highlight rescan, advanced a chunk at a time like [`ScanState`]
/// so adding/removing rules over a large corpus cannot freeze the TUI.
pub struct RescanState {
    pub file: usize,
    pub line: usize,
    pub processed: usize,
    pub total: usize,
    /// Completed files awaiting commit; `None` means "not finished yet".
    pending: Vec<Option<FileMatchData>>,
    /// Match data for the file currently being rescanned.
    current: Option<FileMatchData>,
    /// Status to show once the rescan commits (e.g. "added highlight: ERROR").
    done_status: Option<String>,
}

/// Screen rectangles recorded during rendering so the mouse handler can
/// hit-test clicks against what is actually on screen.
#[derive(Default, Clone)]
pub struct Regions {
    pub tabs: Rect,
    /// Exact hit boxes for each open-file tab (in screen coords), parallel to
    /// `App::files`. Used for mouse tab switching.
    pub tab_hits: Vec<Rect>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchSpan {
    pub start: usize,
    pub end: usize,
    pub rule: usize,
}

pub struct LogFile {
    pub name: String,
    /// Filesystem path used to open this tab (canonical when available).
    /// Kept for yank-path (`Y`) and future reopen/reload features.
    pub path: PathBuf,
    pub lines: Vec<String>,
    /// Match spans per line, indexed the same as `lines`.
    pub matches: Vec<Vec<MatchSpan>>,
    /// Line indices (into `lines`) that contain at least one highlight match.
    pub match_lines: Vec<usize>,
    /// Total match count per rule, indexed the same as `App::rules`.
    pub rule_counts: Vec<usize>,

    /// The line indices currently displayed, in order. In normal mode this is
    /// every line; in filter mode it is only the matching subset.
    ///
    /// Always strictly ascending, which lets lookups use `binary_search`.
    pub view: Vec<usize>,
    /// Cached `view` positions of the active match set (search hits when a search
    /// is on, else highlight hits), built lazily by
    /// [`App::ensure_match_positions`] so `n`/`N` do not re-scan the whole file
    /// on every keypress. `None` means "not computed yet"; both writers of `view`
    /// and of the match data clear it.
    match_positions: Option<Vec<usize>>,
    /// Cursor position as an index *into `view`*.
    pub view_pos: usize,
    /// Index into `view` of the first visible row.
    pub top: usize,
    /// Horizontal scroll offset in Unicode scalar values (columns of text).
    /// Long lines are clipped by the terminal; Left/Right pan the visible slice.
    pub h_scroll: usize,
    /// Highest-severity scan finding per line (None until a scan runs).
    pub scan_severity: Vec<Option<Severity>>,
    /// Bookmarked absolute line indices (sorted, unique). Toggle with `m`.
    pub bookmarks: Vec<usize>,
    /// True if the file was truncated (too many lines and/or overlong lines).
    pub truncated: bool,
}

impl LogFile {
    fn load(path: &Path, name: String, rules: &[Rule]) -> Result<Self> {
        // Cap the read so a direct open (CLI/browser) cannot bypass the folder
        // collection size limit and OOM the process. `take(limit+1)` also closes
        // the race where a file grows between a metadata check and the read.
        let file =
            File::open(path).with_context(|| format!("failed to read '{}'", path.display()))?;
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
        // Prefer a canonical absolute path for yank/reload; fall back to the
        // open path (e.g. if the file vanishes between open and canonicalize).
        let stored_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let mut file = LogFile {
            name,
            path: stored_path,
            lines,
            matches: Vec::new(),
            match_lines: Vec::new(),
            rule_counts: Vec::new(),
            view: Vec::new(),
            match_positions: None,
            view_pos: 0,
            top: 0,
            h_scroll: 0,
            scan_severity: vec![None; line_count],
            bookmarks: Vec::new(),
            truncated,
        };
        file.rescan(rules);
        file.view = (0..file.lines.len()).collect();
        Ok(file)
    }

    /// Recompute all highlight match spans against the current rule set.
    /// Used for initial file load; interactive rule changes go through the
    /// chunked [`App::begin_rescan`] path so the UI stays responsive.
    pub fn rescan(&mut self, rules: &[Rule]) {
        self.match_positions = None;
        let mut data = FileMatchData::new(rules.len(), self.lines.len());
        for (i, line) in self.lines.iter().enumerate() {
            if data.total_matches >= MAX_MATCHES_PER_FILE {
                // Fill remaining lines with empty match lists so indices stay aligned.
                for _ in i..self.lines.len() {
                    data.matches.push(Vec::new());
                }
                break;
            }
            let spans = match_line(line, rules, &mut data);
            if !spans.is_empty() {
                data.match_lines.push(i);
            }
            data.matches.push(spans);
        }
        self.matches = data.matches;
        self.match_lines = data.match_lines;
        self.rule_counts = data.rule_counts;
    }

    /// Rebuild `view` for the current filter/search state, keeping the cursor on
    /// (or just past) the line it was on before.
    pub fn rebuild_view(&mut self, filter_on: bool, search: Option<&Regex>) {
        // Positions are indices into `view`, and the active match set depends on
        // the search that built it — both change here.
        self.match_positions = None;
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

/// Replace C0/C1 control characters (except TAB) so hostile log content cannot
/// inject ANSI / OSC sequences into the TUI and corrupt the host terminal.
fn sanitize_log_line(line: &str) -> String {
    line.chars()
        .map(|c| {
            if c == '\t' || !c.is_control() {
                c
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// Match one log line against every highlight rule, respecting per-line /
/// per-file match caps. Updates `data`'s running counts.
fn match_line(line: &str, rules: &[Rule], data: &mut FileMatchData) -> Vec<MatchSpan> {
    let mut spans = Vec::new();
    if data.total_matches >= MAX_MATCHES_PER_FILE {
        return spans;
    }
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
            data.rule_counts[rule_idx] += 1;
            data.total_matches += 1;
            if spans.len() >= MAX_MATCHES_PER_LINE || data.total_matches >= MAX_MATCHES_PER_FILE {
                break;
            }
        }
        if spans.len() >= MAX_MATCHES_PER_LINE || data.total_matches >= MAX_MATCHES_PER_FILE {
            break;
        }
    }
    if !spans.is_empty() {
        spans.sort_by_key(|s| s.start);
    }
    spans
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
        let cleaned = sanitize_log_line(line);
        if cleaned.len() > MAX_LINE_BYTES {
            truncated = true;
            let mut end = MAX_LINE_BYTES;
            while end > 0 && !cleaned.is_char_boundary(end) {
                end -= 1;
            }
            lines.push(format!("{}…", &cleaned[..end]));
        } else {
            lines.push(cleaned);
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Viewer,
    Browser,
    Input,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InputKind {
    Keyword,
    Regex,
    Search,
    /// Jump to a 1-based absolute line number in the current file.
    GoToLine,
}

pub struct Search {
    pub raw: String,
    pub regex: Regex,
}

pub struct App {
    /// Scan on open, without waiting for `S`. Off until `enable_auto_scan` turns
    /// it on, so constructing an App never kicks off background work by surprise.
    auto_scan: bool,
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
    pub signatures: Library,
    pub findings: Vec<Finding>,
    /// Index into `findings`, not into the filtered view. Keeping it absolute
    /// means jump/step/detail all stay correct while a filter is active.
    pub findings_sel: usize,
    /// Severity shown in the panel; `None` shows every finding.
    pub findings_filter: Option<Severity>,
    /// First visible row of the filtered list. Real scroll state rather than a
    /// value derived from the selection, so the window stays put as the
    /// selection moves inside it.
    pub findings_top: usize,
    pub show_findings: bool,
    /// Present while a scan is running.
    pub scan: Option<ScanState>,
    /// Present while highlight rules are being rescanned across open files.
    pub rescan: Option<RescanState>,

    pub input_kind: InputKind,
    pub input_buffer: String,

    pub show_legend: bool,
    pub show_help: bool,
    /// First visible row of the help sheet, plus the row counts the last frame
    /// measured. Held here rather than derived at render time so the view holds
    /// still while the sheet reflows.
    pub help_scroll: usize,
    help_rows: usize,
    help_height: usize,
    pub viewport_height: usize,
    pub regions: Regions,
    /// True while the user is dragging the scrollbar thumb.
    pub scrollbar_drag: bool,
    pub status: Option<String>,
    pub should_quit: bool,
    /// When set, the next `open_browser` flashes where we restored from prefs.
    browser_cwd_hint: Option<PathBuf>,
    /// Active UI palette (dark theme).
    pub theme: Theme,
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
            signatures: Library::builtin(),
            findings: Vec::new(),
            findings_sel: 0,
            findings_filter: None,
            findings_top: 0,
            show_findings: false,
            scan: None,
            rescan: None,
            input_kind: InputKind::Keyword,
            input_buffer: String::new(),
            auto_scan: false,
            show_legend: true,
            show_help: false,
            help_scroll: 0,
            help_rows: 0,
            help_height: 0,
            viewport_height: 20,
            regions: Regions::default(),
            scrollbar_drag: false,
            status: None,
            should_quit: false,
            browser_cwd_hint: None,
            theme: Theme::dark(),
            temp_dirs: Vec::new(),
        };

        let paths: Vec<PathBuf> = inputs.iter().map(PathBuf::from).collect();
        let had_inputs = !paths.is_empty();
        if had_inputs {
            app.open_resolved(&paths);
        }

        // With no files, land on the branded welcome screen (press `o` to open
        // the browser); otherwise go straight to the viewer.
        app.mode = Mode::Viewer;
        // Keep open feedback when the user passed paths (success *or* failure).
        // Only clear status for a bare welcome launch so the banner stays clean.
        if !had_inputs {
            app.status = None;
        }
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
        // Findings are global, so adding files rescans the corpus and keeps the
        // report whole rather than reporting on a subset.
        if self.auto_scan && opened > 0 {
            self.scan_after_open();
        }
    }

    /// Scan on open from here on, and scan whatever is already loaded.
    ///
    /// Separate from [`App::new`] so building an App is side-effect free — tests
    /// and any non-interactive caller opt in explicitly.
    pub fn enable_auto_scan(&mut self) {
        self.auto_scan = true;
        if self.has_files() {
            self.scan_after_open();
        }
    }

    /// Start a scan without discarding the open feedback that preceded it: the
    /// reader still needs to know what was opened, and what failed.
    fn scan_after_open(&mut self) {
        let opened = self.status.take();
        self.begin_scan();
        if let Some(msg) = opened {
            self.status = Some(format!("{msg} · scanning…"));
        }
    }

    /// Open the marked files (or the selected file) from the browser.
    pub fn open_selected_files(&mut self) {
        let paths = self.browser.files_to_open();
        if paths.is_empty() {
            self.status = Some("nothing selected (Space to mark, O to open a folder/zip)".into());
            return;
        }
        self.remember_browser_cwd();
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
        self.remember_browser_cwd();
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
            InputKind::GoToLine => self.go_to_line_number(&text),
            InputKind::Keyword | InputKind::Regex => {
                if text.is_empty() {
                    return;
                }
                if self.rules.len() >= MAX_RULES {
                    self.status = Some(format!("highlight limit reached ({MAX_RULES})"));
                    return;
                }
                let is_regex = kind == InputKind::Regex;
                match rules::compile_rule(
                    &text,
                    is_regex,
                    self.ignore_case,
                    self.rules.len(),
                    &self.theme,
                ) {
                    Ok(rule) => {
                        self.rules.push(rule);
                        self.begin_rescan(Some(format!("added highlight: {text}")));
                    }
                    Err(e) => self.status = Some(format!("{e}")),
                }
            }
        }
    }

    /// Jump to a 1-based line number typed in the `:` prompt.
    ///
    /// Empty input is a no-op. Values past the end of the file clamp to the
    /// last line (vim-style). Out-of-range zeros and non-numeric text report
    /// a status message instead of moving. Empty files report that there is
    /// nothing to jump to (rather than pretending line 1 exists).
    fn go_to_line_number(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if !self.has_files() {
            self.status = Some("open a file before jumping to a line".into());
            return;
        }
        let Ok(n) = text.parse::<usize>() else {
            self.status = Some(format!("invalid line number: {text}"));
            return;
        };
        if n == 0 {
            self.status = Some("line numbers start at 1".into());
            return;
        }
        let last = self.file().lines.len();
        if last == 0 {
            self.status = Some("file has no lines".into());
            return;
        }
        let line = n.min(last) - 1; // convert to 0-based
        let file = self.current;
        self.jump_to_line(file, line);
        let landed = self
            .file()
            .view
            .get(self.file().view_pos)
            .copied()
            .unwrap_or(line)
            + 1;
        if n > last {
            self.status = Some(format!("line {n} past end — jumped to L{landed}"));
        } else {
            self.status = Some(format!("jumped to L{landed}"));
        }
    }

    pub fn remove_last_rule(&mut self) {
        if let Some(rule) = self.rules.pop() {
            if self.active_rule == Some(self.rules.len()) {
                self.active_rule = None;
            }
            self.begin_rescan(Some(format!("removed highlight: {}", rule.label)));
        }
    }

    pub fn toggle_ignore_case(&mut self) {
        self.ignore_case = !self.ignore_case;
        let mut rebuilt = Vec::with_capacity(self.rules.len());
        let mut dropped = 0usize;
        for r in &self.rules {
            match rules::compile_rule(
                &r.label,
                r.is_regex,
                self.ignore_case,
                rebuilt.len(),
                &self.theme,
            ) {
                Ok(rule) => rebuilt.push(rule),
                Err(_) => dropped += 1,
            }
        }
        if dropped > 0 {
            // Indices into the old rule list are no longer valid.
            self.active_rule = None;
        } else if let Some(ar) = self.active_rule
            && ar >= rebuilt.len()
        {
            self.active_rule = None;
        }
        self.rules = rebuilt;
        let case = if self.ignore_case { "on" } else { "off" };
        let persist = self.persist_prefs();
        let status = if dropped > 0 {
            format!(
                "case-insensitive: {case}{persist} ({dropped} rule(s) dropped — failed to recompile)"
            )
        } else {
            format!("case-insensitive: {case}{persist}")
        };
        self.begin_rescan(Some(status));
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

    /// Turn filter mode off (used by Esc: search → filter → quit).
    pub fn clear_filter(&mut self) {
        if self.filter_on {
            self.filter_on = false;
            self.rebuild_views();
            self.ensure_cursor_visible();
            self.status = Some("filter cleared".into());
        }
    }

    /// Clear search and filter together (`c`). One rebuild; status names what went away.
    pub fn clear_search_and_filter(&mut self) {
        let had_search = self.search.is_some();
        let had_filter = self.filter_on;
        if !had_search && !had_filter {
            self.status = Some("nothing to clear".into());
            return;
        }
        self.search = None;
        self.filter_on = false;
        self.rebuild_views();
        self.ensure_cursor_visible();
        self.status = Some(match (had_search, had_filter) {
            (true, true) => "search and filter cleared".into(),
            (true, false) => "search cleared".into(),
            (false, true) => "filter cleared".into(),
            (false, false) => unreachable!(),
        });
    }

    pub fn toggle_filter(&mut self) {
        // Remember the absolute line under the cursor so we can tell the user
        // when turning filter on drops that line out of the view.
        let prior_line = if self.has_files() {
            self.file().view.get(self.file().view_pos).copied()
        } else {
            None
        };

        self.filter_on = !self.filter_on;
        self.rebuild_views();
        self.ensure_cursor_visible();

        self.status = Some(if !self.filter_on {
            "filter: off".into()
        } else if !self.has_files() {
            "filter: on".into()
        } else if self.file().view.is_empty() {
            match prior_line {
                Some(line) => format!("filter: on · no matches (was on L{})", line + 1),
                None => "filter: on · no matches".into(),
            }
        } else if let Some(line) = prior_line {
            if self.file().view.contains(&line) {
                "filter: on".into()
            } else {
                let now = self
                    .file()
                    .view
                    .get(self.file().view_pos)
                    .map(|l| l + 1)
                    .unwrap_or(1);
                format!("filter: on · L{} hidden — now L{now}", line + 1)
            }
        } else {
            "filter: on".into()
        });
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

    /// Start a chunked highlight rescan. New match data is built off to the
    /// side and committed only on completion, so Esc can cancel cleanly.
    pub fn begin_rescan(&mut self, done_status: Option<String>) {
        // Don't interleave with a signature scan — cancel it first.
        self.cancel_scan();
        self.rescan = None;

        if self.files.is_empty() {
            self.status = done_status;
            return;
        }

        // Rules are already mutated (add/remove/case) before the chunked pass
        // commits. Align per-file metadata now so the legend cannot index past
        // `rule_counts` on the next draw, and so Esc-cancel cannot leave
        // highlight spans pointing at removed rule indices.
        self.align_rule_metadata();

        let total: usize = self.files.iter().map(|f| f.lines.len()).sum();
        self.rescan = Some(RescanState {
            file: 0,
            line: 0,
            processed: 0,
            total,
            pending: (0..self.files.len()).map(|_| None).collect(),
            current: None,
            done_status,
        });
        self.status = Some("updating highlights…".into());
        if total == 0 {
            let _ = self.rescan_step(1);
        }
    }

    /// Keep `rule_counts` / orphan match spans consistent with `self.rules`.
    ///
    /// Called when rules change before a chunked rescan commits (or when a
    /// rescan is cancelled) so UI paths that index `rule_counts[i]` for each
    /// rule cannot panic, and removed rules do not leave ghost highlights.
    fn align_rule_metadata(&mut self) {
        let n = self.rules.len();
        let mut stripped_any = false;
        for f in &mut self.files {
            let mut stripped = false;
            for spans in &mut f.matches {
                let before = spans.len();
                spans.retain(|m| m.rule < n);
                if spans.len() != before {
                    stripped = true;
                }
            }
            if stripped {
                stripped_any = true;
                f.match_positions = None;
                f.match_lines = f
                    .matches
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| (!s.is_empty()).then_some(i))
                    .collect();
                f.rule_counts = vec![0; n];
                for spans in &f.matches {
                    for m in spans {
                        f.rule_counts[m.rule] += 1;
                    }
                }
            } else if f.rule_counts.len() != n {
                f.rule_counts.resize(n, 0);
            }
        }
        if stripped_any {
            // Filter views keyed on `match_lines` must drop lines that only
            // matched a just-removed rule.
            self.rebuild_views();
        }
    }

    /// Process up to `budget` lines of the running highlight rescan.
    /// Returns true when finished (matches committed, views rebuilt).
    pub fn rescan_step(&mut self, budget: usize) -> bool {
        let Some(mut st) = self.rescan.take() else {
            return true;
        };
        let mut done = 0;
        while done < budget {
            if st.file >= self.files.len() {
                self.finalize_rescan(st);
                return true;
            }
            let flen = self.files[st.file].lines.len();
            if st.current.is_none() {
                st.current = Some(FileMatchData::new(self.rules.len(), flen));
                st.line = 0;
            }
            let capped = st
                .current
                .as_ref()
                .is_some_and(|c| c.total_matches >= MAX_MATCHES_PER_FILE);
            if st.line >= flen || capped {
                // Pad remaining lines if we hit the per-file match cap early.
                if let Some(cur) = st.current.as_mut() {
                    while cur.matches.len() < flen {
                        cur.matches.push(Vec::new());
                    }
                }
                let remaining = flen.saturating_sub(st.line);
                st.processed += remaining;
                st.pending[st.file] = st.current.take();
                st.file += 1;
                st.line = 0;
                continue;
            }

            let spans = match_line(
                &self.files[st.file].lines[st.line],
                &self.rules,
                st.current.as_mut().expect("current file data"),
            );
            if !spans.is_empty() {
                st.current
                    .as_mut()
                    .expect("current file data")
                    .match_lines
                    .push(st.line);
            }
            st.current
                .as_mut()
                .expect("current file data")
                .matches
                .push(spans);
            st.line += 1;
            st.processed += 1;
            done += 1;
        }
        self.rescan = Some(st);
        false
    }

    fn finalize_rescan(&mut self, st: RescanState) {
        // Commit every finished file. Any gap (shouldn't happen) falls back to
        // a synchronous rescan so tabs never keep stale rule indices.
        for (i, slot) in st.pending.into_iter().enumerate() {
            if i >= self.files.len() {
                break;
            }
            if let Some(data) = slot {
                let f = &mut self.files[i];
                f.matches = data.matches;
                f.match_lines = data.match_lines;
                f.rule_counts = data.rule_counts;
                f.match_positions = None;
            } else {
                let rules = &self.rules;
                self.files[i].rescan(rules);
            }
        }
        // If we were mid-file when somehow finalized, discard — pending covers
        // completed files only; `current` is dropped with `st`.
        self.rebuild_views();
        self.rescan = None;
        self.status = st.done_status.or_else(|| Some("highlights updated".into()));
    }

    pub fn cancel_rescan(&mut self) {
        if self.rescan.take().is_some() {
            // Pending work is dropped; previously committed highlights stay.
            // Re-align in case `begin_rescan` was skipped or rules changed again.
            self.align_rule_metadata();
            self.status = Some("highlight update cancelled".into());
        }
    }

    pub fn rescanning(&self) -> bool {
        self.rescan.is_some()
    }

    /// True while a signature scan or highlight rescan is running.
    pub fn busy(&self) -> bool {
        self.scanning() || self.rescanning()
    }

    /// Fraction complete (0.0..=1.0) of the running highlight rescan, if any.
    pub fn rescan_fraction(&self) -> Option<f64> {
        self.rescan.as_ref().map(|s| {
            if s.total == 0 {
                1.0
            } else {
                s.processed as f64 / s.total as f64
            }
        })
    }

    /// (lines processed, total lines, current file name).
    pub fn rescan_detail(&self) -> Option<(usize, usize, String)> {
        self.rescan.as_ref().map(|s| {
            let name = self
                .files
                .get(s.file)
                .map(|f| f.name.clone())
                .unwrap_or_default();
            (s.processed, s.total, name)
        })
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

    /// Pan the log pane horizontally by `delta` columns (Unicode scalars).
    /// Positive = right (reveal more of long lines); negative = left toward col 0.
    pub fn scroll_horiz(&mut self, delta: isize) {
        if !self.has_files() {
            return;
        }
        let f = self.file_mut();
        let next = (f.h_scroll as isize + delta).max(0) as usize;
        // Soft cap so a held key cannot push the offset into absurd territory.
        const MAX_H_SCROLL: usize = 10_000;
        f.h_scroll = next.min(MAX_H_SCROLL);
    }

    /// Jump horizontal scroll back to column 0.
    pub fn reset_h_scroll(&mut self) {
        if !self.has_files() {
            return;
        }
        self.file_mut().h_scroll = 0;
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

    /// Toggle a bookmark on the cursor's absolute line.
    pub fn toggle_bookmark(&mut self) {
        if !self.has_files() {
            self.status = Some("open a file before bookmarking".into());
            return;
        }
        let f = self.file_mut();
        let Some(&line) = f.view.get(f.view_pos) else {
            // File open but filter emptied the view (or cursor off-end).
            self.status = Some("nothing to bookmark".into());
            return;
        };
        match f.bookmarks.binary_search(&line) {
            Ok(idx) => {
                f.bookmarks.remove(idx);
                let left = f.bookmarks.len();
                self.status = Some(if left == 0 {
                    format!("cleared bookmark on line {}", line + 1)
                } else {
                    format!("cleared bookmark on line {} ({left} left)", line + 1)
                });
            }
            Err(idx) => {
                if f.bookmarks.len() >= MAX_BOOKMARKS {
                    self.status = Some(format!("bookmark limit reached ({MAX_BOOKMARKS})"));
                    return;
                }
                f.bookmarks.insert(idx, line);
                let n = f.bookmarks.len();
                self.status = Some(format!("bookmarked line {} ({n})", line + 1));
            }
        }
    }

    /// Clear every bookmark on the current file.
    pub fn clear_bookmarks(&mut self) {
        if !self.has_files() {
            self.status = Some("open a file before clearing bookmarks".into());
            return;
        }
        let f = self.file_mut();
        let n = f.bookmarks.len();
        if n == 0 {
            self.status = Some("no bookmarks to clear".into());
            return;
        }
        f.bookmarks.clear();
        self.status = Some(if n == 1 {
            "cleared 1 bookmark".into()
        } else {
            format!("cleared {n} bookmarks")
        });
    }

    /// Jump to the next bookmarked line (wraps). Clears filter if needed.
    pub fn next_bookmark(&mut self) {
        self.jump_bookmark(1);
    }

    /// Jump to the previous bookmarked line (wraps). Clears filter if needed.
    pub fn prev_bookmark(&mut self) {
        self.jump_bookmark(-1);
    }

    fn jump_bookmark(&mut self, dir: isize) {
        if !self.has_files() {
            self.status = Some("open a file before jumping bookmarks".into());
            return;
        }
        if self.file().bookmarks.is_empty() {
            self.status = Some("no bookmarks — press m to mark a line".into());
            return;
        }
        let file_idx = self.current;
        let marks = self.file().bookmarks.clone();
        let cur_line = self
            .file()
            .view
            .get(self.file().view_pos)
            .copied()
            .unwrap_or(0);
        let n = marks.len() as isize;
        let next = if dir > 0 {
            marks.iter().position(|&l| l > cur_line).unwrap_or(0)
        } else {
            marks
                .iter()
                .rposition(|&l| l < cur_line)
                .unwrap_or((n - 1) as usize)
        };
        let line = marks[next];
        self.jump_to_line(file_idx, line);
        self.status = Some(format!(
            "bookmark {}/{} · line {}",
            next + 1,
            marks.len(),
            line + 1
        ));
    }

    /// Jump to the first active match (search hits if searching, else highlight
    /// hits). Bound to Enter in the viewer — handy after scrolling away from
    /// the top hit. Reports `match 1/n · line L` like [`Self::next_match`].
    pub fn first_match(&mut self) {
        self.jump_match_to(0);
    }

    /// Jump to the next active match (search hits if searching, else highlight
    /// hits). Wraps and reports `match i/n · line L` like bookmark jumps.
    pub fn next_match(&mut self) {
        self.jump_match(1);
    }

    /// Jump to the previous active match (wraps; see [`Self::next_match`]).
    pub fn prev_match(&mut self) {
        self.jump_match(-1);
    }

    fn jump_match(&mut self, dir: isize) {
        if !self.has_files() {
            self.status = Some("open a file before jumping matches".into());
            return;
        }
        if !self.ensure_match_positions() {
            return;
        }
        // Read the cached hit list, pick the target, then drop the borrow before
        // mutating — no copy of the (potentially 250k-entry) list per keypress.
        let (idx, pos, total) = {
            let file = self.file();
            let hits = file
                .match_positions
                .as_ref()
                .expect("ensure_match_positions populated the cache");
            let cur = file.view_pos;
            // `hits` is ascending, so the neighbour is a binary search: walking it
            // linearly would get slower the deeper into the file the cursor is.
            let idx = if dir > 0 {
                // First hit after the cursor, wrapping to the first.
                let after = hits.partition_point(|&p| p <= cur);
                if after == hits.len() { 0 } else { after }
            } else {
                // Last hit before the cursor, wrapping to the last.
                match hits.partition_point(|&p| p < cur) {
                    0 => hits.len() - 1,
                    k => k - 1,
                }
            };
            (idx, hits[idx], hits.len())
        };
        self.apply_match_jump(idx, pos, total);
    }

    /// Jump to an absolute hit index (`0` = first). Empty / no-file cases share
    /// status messaging with [`Self::jump_match`].
    fn jump_match_to(&mut self, idx: usize) {
        if !self.has_files() {
            self.status = Some("open a file before jumping matches".into());
            return;
        }
        if !self.ensure_match_positions() {
            return;
        }
        let (idx, pos, total) = {
            let hits = self
                .file()
                .match_positions
                .as_ref()
                .expect("ensure_match_positions populated the cache");
            let idx = idx.min(hits.len() - 1);
            (idx, hits[idx], hits.len())
        };
        self.apply_match_jump(idx, pos, total);
    }

    /// Populate `LogFile::match_positions` for the current file if it is missing.
    ///
    /// Returns false (after setting an empty-state status) when there are no
    /// active matches. Computing this walks every line — and runs the search
    /// regex on each — so the result is cached until the view or match data
    /// changes, otherwise every `n`/`N` press would rescan the file.
    fn ensure_match_positions(&mut self) -> bool {
        if self.file().match_positions.is_none() {
            let hits: Vec<usize> = self
                .file()
                .view
                .iter()
                .enumerate()
                .filter(|&(_, &line)| self.is_active_match(line))
                .map(|(pos, _)| pos)
                .collect();
            self.file_mut().match_positions = Some(hits);
        }
        let empty = self
            .file()
            .match_positions
            .as_ref()
            .is_none_or(|h| h.is_empty());
        if empty {
            self.status = Some(if self.search.is_some() {
                "no search matches".into()
            } else {
                "no highlight matches — press a to add, or / to search".into()
            });
            return false;
        }
        true
    }

    /// Move the cursor to hit `idx` (0-based) at view position `pos`, of `total`.
    fn apply_match_jump(&mut self, idx: usize, pos: usize, total: usize) {
        let line = self.file().view.get(pos).copied().unwrap_or(pos);
        self.file_mut().view_pos = pos;
        self.ensure_cursor_visible();
        self.clamp_scroll();
        self.status = Some(format!("match {}/{total} · line {}", idx + 1, line + 1));
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
            if self.file().matches[view[pos]]
                .iter()
                .any(|m| m.rule == rule)
            {
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
        // Don't interleave with a highlight rescan.
        self.cancel_rescan();
        self.show_findings = false;
        self.findings.clear();
        // A filter left over from the previous scan would make a fresh result
        // look empty, so each scan starts showing everything.
        self.findings_filter = None;
        self.findings_top = 0;
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
            seen: vec![None; self.signatures.signature_count()],
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
                // Groups are per (file, signature), so the next file starts with
                // no signature seen.
                st.seen.iter_mut().for_each(|s| *s = None);
                continue;
            }
            let line = &self.files[st.file].lines[st.line];
            let mut best: Option<Severity> = None;
            // One `RegexSet` pass yields every matching signature index, in
            // ascending order — same result as testing each regex in turn.
            for si in self.signatures.matches(line) {
                let sig = &self.signatures[si];
                // Still record severity on the line even after the findings
                // list is capped, so gutter markers remain useful.
                best = Some(best.map_or(sig.severity, |b| b.max(sig.severity)));
                if sig.severity < MIN_FINDING_SEVERITY {
                    continue;
                }
                match st.seen[si] {
                    // Already a group for this signature in this file: count the
                    // repeat and extend the span, adding no row.
                    Some(idx) => {
                        let f = &mut st.findings[idx];
                        f.count += 1;
                        f.last = st.line;
                    }
                    None if st.findings.len() < MAX_FINDINGS => {
                        st.seen[si] = Some(st.findings.len());
                        st.findings.push(Finding {
                            file: st.file,
                            line: st.line,
                            sig: si,
                            last: st.line,
                            count: 1,
                        });
                    }
                    None => {}
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
        let hits = self.occurrence_count();
        // Distinct findings and raw hits diverge whenever a condition repeats,
        // so report both: "3 findings" alone hides that one of them fired 900
        // times, which is usually the most interesting thing on screen.
        let scale = if hits > total {
            format!("{total} findings ({hits} hits)")
        } else {
            format!("{total} findings")
        };
        // The tally lists only reportable severities; spelling all five out left a
        // permanent "0 low, 0 info" here the way it used to in the panel title.
        let tally = severity_tally(c);
        self.status = Some(if total == 0 {
            // No panel opens on a clean scan, so the status line is the whole
            // report: say what was covered, not just that nothing turned up.
            let lines: usize = self.files.iter().map(|f| f.lines.len()).sum();
            let files = self.files.len();
            if files == 1 {
                format!("scan complete — nothing notable in {lines} lines")
            } else {
                format!("scan complete — nothing notable in {lines} lines across {files} files")
            }
        } else if capped {
            format!("scan: {scale} (capped) · {tally}")
        } else {
            format!("scan: {scale} · {tally}")
        });
    }

    pub fn cancel_scan(&mut self) {
        if self.scan.take().is_some() {
            // Drop partial gutter markers so a cancelled scan doesn't leave the
            // file looking half-triaged.
            for f in &mut self.files {
                f.scan_severity = vec![None; f.lines.len()];
            }
            self.findings.clear();
            self.findings_sel = 0;
            self.show_findings = false;
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

    /// Severity mix of the *in-flight* scan, indexed like [`Self::severity_counts`].
    /// The progress bar paints this, so the reader watches the verdict assemble
    /// before the panel opens; `self.findings` is still the previous scan's (or
    /// empty) until `finalize_scan` commits, so it cannot serve here.
    pub fn scan_severity_counts(&self) -> Option<[usize; 5]> {
        self.scan.as_ref().map(|s| {
            let mut c = [0usize; 5];
            for f in &s.findings {
                c[self.signatures[f.sig].severity as usize] += 1;
            }
            c
        })
    }

    /// Counts indexed by `Severity as usize` (Info=0 .. Critical=4).
    /// Distinct findings per severity — one per (file, signature) group, not one
    /// per matching line. See [`Self::occurrence_count`] for raw hits.
    pub fn severity_counts(&self) -> [usize; 5] {
        let mut c = [0usize; 5];
        for f in &self.findings {
            c[self.signatures[f.sig].severity as usize] += 1;
        }
        c
    }

    /// Total matching lines across every finding. Equals the number of findings
    /// only when nothing repeated.
    pub fn occurrence_count(&self) -> usize {
        self.findings.iter().map(|f| f.count).sum()
    }

    /// Indices into `findings` passing the active filter, in list order.
    ///
    /// Recomputed per call rather than cached: findings are one row per (file,
    /// signature) since grouping landed, so the list is short and a stale cache
    /// would be a correctness risk for no measurable gain.
    pub fn visible_findings(&self) -> Vec<usize> {
        match self.findings_filter {
            None => (0..self.findings.len()).collect(),
            Some(sev) => (0..self.findings.len())
                .filter(|&i| self.signatures[self.findings[i].sig].severity == sev)
                .collect(),
        }
    }

    /// Where the selection sits within the filtered list, if it is visible.
    fn findings_pos(&self, vis: &[usize]) -> Option<usize> {
        vis.iter().position(|&i| i == self.findings_sel)
    }

    /// Step the selection through the filtered list, clamped at both ends.
    pub fn findings_move(&mut self, delta: isize) {
        let vis = self.visible_findings();
        if vis.is_empty() {
            return;
        }
        // A selection hidden by the filter counts as being before the first row,
        // so `j` enters the list from the top rather than doing nothing.
        let pos = self.findings_pos(&vis).unwrap_or(0) as isize;
        let next = (pos + delta).clamp(0, vis.len() as isize - 1) as usize;
        self.findings_sel = vis[next];
    }

    /// Cycle the severity filter. `delta` is in tab positions, wrapping.
    pub fn cycle_findings_filter(&mut self, delta: isize) {
        let n = FINDING_FILTERS.len() as isize;
        let cur = FINDING_FILTERS
            .iter()
            .position(|f| *f == self.findings_filter)
            .unwrap_or(0) as isize;
        self.findings_filter = FINDING_FILTERS[(((cur + delta) % n + n) % n) as usize];

        // The previous selection may no longer be shown; land on the first row
        // of the new tab so the detail box always matches something visible.
        let vis = self.visible_findings();
        if self.findings_pos(&vis).is_none() {
            self.findings_sel = vis.first().copied().unwrap_or(0);
        }
        self.findings_top = 0;
        self.status = Some(match self.findings_filter {
            None => format!("findings: all ({})", self.findings.len()),
            Some(sev) => format!("findings: {} only ({})", sev.label(), vis.len()),
        });
    }

    /// Scroll the filtered list the minimum needed to show the selection in a
    /// window of `height` rows. The renderer owns the height, so it calls this.
    pub fn findings_scroll_into_view(&mut self, height: usize) {
        let vis = self.visible_findings();
        if vis.is_empty() || height == 0 {
            self.findings_top = 0;
            return;
        }
        let pos = self.findings_pos(&vis).unwrap_or(0);
        if pos < self.findings_top {
            self.findings_top = pos;
        } else if pos >= self.findings_top + height {
            self.findings_top = pos - height + 1;
        }
        // Never scroll so far that blank rows show below a list that could fill
        // the window (reachable after switching to a tab with fewer rows).
        self.findings_top = self.findings_top.min(vis.len().saturating_sub(height));
    }

    /// Jump to the next scan finding in severity-ranked order (wraps).
    /// Stays in the viewer — no need to open the findings panel.
    pub fn next_finding(&mut self) {
        self.step_finding(1);
    }

    /// Jump to the previous scan finding (wraps; see [`Self::next_finding`]).
    pub fn prev_finding(&mut self) {
        self.step_finding(-1);
    }

    /// Walk findings by list index. If the cursor is already on the selected
    /// finding, advance/retreat with wrap; otherwise jump to the selection
    /// first (so the first `p` after a scan lands on finding 1/n).
    fn step_finding(&mut self, dir: isize) {
        if self.findings.is_empty() {
            self.status = Some("no findings — press S to scan".into());
            return;
        }
        // The active filter defines what the user is triaging, so p/P walk the
        // same rows the panel shows rather than the whole list.
        let vis = self.visible_findings();
        let Some(&first) = vis.first() else {
            self.status = Some(format!(
                "no {} findings — press f to change the filter",
                self.findings_filter.map_or("", |s| s.label())
            ));
            return;
        };
        let n = vis.len();
        let pos = self.findings_pos(&vis);
        let selected = self.findings[self.findings_sel];
        let on_selected = self.current == selected.file
            && self.file().view.get(self.file().view_pos).copied() == Some(selected.line);
        self.findings_sel = match pos {
            // Selection is hidden by the filter: enter the visible list rather
            // than stepping from a row that is not on screen.
            None => first,
            Some(p) if on_selected => {
                vis[if dir > 0 {
                    (p + 1) % n
                } else {
                    (p + n - 1) % n
                }]
            }
            Some(p) => vis[p],
        };
        let f = self.findings[self.findings_sel];
        self.show_findings = false;
        self.jump_to_line(f.file, f.line);
        let sig = &self.signatures[f.sig];
        let name = self
            .files
            .get(f.file)
            .map(|file| file.name.as_str())
            .unwrap_or("?");
        self.status = Some(format!(
            "finding {}/{} · {} · {} · {}:{}",
            self.findings_sel + 1,
            n,
            sig.severity.label(),
            sig.title,
            name,
            f.line + 1
        ));
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
        // `view` is strictly ascending, so both lookups are binary searches
        // rather than scans of a possibly 250k-entry list.
        if self.file().view.binary_search(&line).is_err() {
            self.filter_on = false;
            self.rebuild_views();
        }
        if let Ok(pos) = self.file().view.binary_search(&line) {
            self.file_mut().view_pos = pos;
        }
        self.ensure_cursor_visible();
        self.clamp_scroll();
    }

    pub fn close_findings(&mut self) {
        self.show_findings = false;
    }

    /// Reopen (or close) the findings panel without rescanning.
    /// `S` always starts a fresh scan; use this after closing the panel.
    pub fn toggle_findings(&mut self) {
        if self.findings.is_empty() {
            self.status = Some("no findings — press S to scan".into());
            return;
        }
        self.show_findings = !self.show_findings;
        if self.show_findings {
            self.status = Some(format!(
                "findings ({}) — e export · Enter jump · q close",
                self.findings.len()
            ));
        }
    }

    /// Write the current findings list to `loglens-findings.md` in the cwd,
    /// or `loglens-findings-2.md`, `-3.md`, … when earlier exports are still there.
    ///
    /// `e` is one keypress next to `Enter`/`q` in the findings panel, so a
    /// mis-press must never destroy a previous export. Callers that *want* to
    /// overwrite a specific file use [`Self::export_findings_to`] directly.
    pub fn export_findings(&mut self) {
        if self.findings.is_empty() {
            self.status = Some("no findings to export — press S to scan".into());
            return;
        }
        // Empty base = the process cwd: `Path::new("").join("x.md")` is "x.md".
        let Some(path) = Self::next_export_path_in(Path::new("")) else {
            self.status = Some(format!(
                "export failed: {EXPORT_STEM}*.md already exists (tried {MAX_EXPORT_FILES})"
            ));
            return;
        };
        let renamed = path.file_name() != Some(std::ffi::OsStr::new(EXPORT_DEFAULT_NAME));
        match self.export_findings_to(&path) {
            Ok(n) => {
                // Report where the file actually landed: the export goes to the
                // process cwd, which is rarely the directory the logs came from.
                let shown = path.canonicalize().unwrap_or_else(|_| path.clone());
                self.status = Some(if renamed {
                    format!(
                        "exported {n} findings → {} (kept the earlier export)",
                        shown.display()
                    )
                } else {
                    format!("exported {n} findings → {}", shown.display())
                });
            }
            Err(e) => {
                self.status = Some(format!("export failed: {e}"));
            }
        }
    }

    /// First free export filename under `dir`, or `None` if they are all taken.
    /// Takes the directory as a parameter so it is testable without changing the
    /// process-wide cwd.
    fn next_export_path_in(dir: &Path) -> Option<PathBuf> {
        let first = dir.join(EXPORT_DEFAULT_NAME);
        if !first.exists() {
            return Some(first);
        }
        (2..=MAX_EXPORT_FILES)
            .map(|n| dir.join(format!("{EXPORT_STEM}-{n}.md")))
            .find(|p| !p.exists())
    }

    /// Format findings as a short markdown triage summary and write to `path`.
    pub fn export_findings_to(&self, path: &Path) -> Result<usize> {
        let text = self.format_findings_markdown();
        fs::write(path, text).with_context(|| format!("failed to write '{}'", path.display()))?;
        Ok(self.findings.len())
    }

    fn format_findings_markdown(&self) -> String {
        let c = self.severity_counts();
        let mut out = String::new();
        out.push_str("# loglens scan findings\n\n");
        let hits = self.occurrence_count();
        out.push_str(&format!(
            "{} findings · {hits} matching lines · {}\n\n",
            self.findings.len(),
            severity_tally(c),
        ));
        for (i, f) in self.findings.iter().enumerate() {
            let sig = &self.signatures[f.sig];
            let file_name = self
                .files
                .get(f.file)
                .map(|lf| lf.name.as_str())
                .unwrap_or("?");
            let excerpt = self
                .files
                .get(f.file)
                .and_then(|lf| lf.lines.get(f.line))
                .map(|l| {
                    let trimmed = l.trim();
                    let truncated: String = trimmed.chars().take(240).collect();
                    if trimmed.chars().count() > 240 {
                        format!("{truncated}…")
                    } else {
                        truncated
                    }
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "## {}. {} — {}\n",
                i + 1,
                sig.severity.label(),
                sig.title
            ));
            out.push_str(&format!("- **location:** `{file_name}:{}`\n", f.line + 1));
            out.push_str(&format!("- **category:** {}\n", sig.category));
            if f.count > 1 {
                out.push_str(&format!(
                    "- **occurrences:** {} (lines {}–{})\n",
                    f.count,
                    f.line + 1,
                    f.last + 1
                ));
            }
            out.push_str(&format!("- **why:** {}\n", sig.explain));
            if !excerpt.is_empty() {
                out.push_str(&format!("- **line:** `{excerpt}`\n"));
            }
            out.push('\n');
        }
        out
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

    /// Jump to an open file by tab index (mouse click on the tab bar).
    pub fn select_file(&mut self, index: usize) {
        if index < self.files.len() {
            self.current = index;
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
        self.findings_sel = self.findings_sel.min(self.findings.len().saturating_sub(1));

        if self.current >= self.files.len() {
            self.current = self.files.len().saturating_sub(1);
        }
        if self.files.is_empty() {
            // Match cold-start: land on the branded welcome viewer (press `o`
            // for the browser), not a surprise file-browser popup.
            self.mode = Mode::Viewer;
            self.filter_on = false;
            self.search = None;
            self.active_rule = None;
            self.show_findings = false;
            self.status = Some("all files closed — press o to open".into());
        }
    }

    pub fn open_browser(&mut self) {
        if let Some(dir) = self.browser_cwd_hint.take() {
            self.status = Some(format!("browser restored: {}", dir.display()));
        }
        self.browser.refresh();
        self.mode = Mode::Browser;
    }

    pub fn close_browser(&mut self) {
        self.remember_browser_cwd();
        if self.has_files() {
            self.mode = Mode::Viewer;
        }
    }

    /// Re-open the file browser at a previously saved directory when it still
    /// exists; otherwise leave the current (usually process cwd) location.
    pub fn restore_browser_cwd(&mut self, saved: Option<PathBuf>) {
        let Some(dir) = saved else {
            return;
        };
        if dir.is_dir() {
            self.browser = Browser::new(dir.clone());
            self.browser_cwd_hint = Some(dir);
        }
    }

    /// Persist the browser's current working directory for the next launch.
    pub fn remember_browser_cwd(&self) {
        let _ = crate::config::save(&crate::config::Config {
            ignore_case: self.ignore_case,
            show_legend: self.show_legend,
            browser_cwd: Some(self.browser.cwd.clone()),
        });
    }

    pub fn toggle_legend(&mut self) {
        self.show_legend = !self.show_legend;
        let state = if self.show_legend { "shown" } else { "hidden" };
        let persist = self.persist_prefs();
        self.status = Some(format!("legend: {state}{persist}"));
    }

    /// Write current prefs to disk. Returns a short status suffix.
    fn persist_prefs(&self) -> String {
        match crate::config::save(&crate::config::Config {
            ignore_case: self.ignore_case,
            show_legend: self.show_legend,
            browser_cwd: Some(self.browser.cwd.clone()),
        }) {
            Ok(()) => " · saved".to_string(),
            Err(_) => " · could not save pref".to_string(),
        }
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
        // Reopening starts at the top: the sheet is a reference, not a place the
        // user left off.
        self.help_scroll = 0;
    }

    /// Keep the help scroll inside the current sheet. Both arguments are
    /// render-time facts (the sheet reflows between one and two columns), so the
    /// clamp runs on every frame as well as on every keypress.
    pub fn help_clamp_scroll(&mut self, rows: usize, height: usize) {
        self.help_rows = rows;
        self.help_height = height;
        self.help_scroll = self.help_scroll.min(self.help_max_scroll());
    }

    fn help_max_scroll(&self) -> usize {
        self.help_rows.saturating_sub(self.help_height)
    }

    /// Scroll the help sheet by `delta` rows, clamped at both ends. Help is a
    /// reference sheet, so it does not wrap the way findings and matches do.
    pub fn help_scroll_by(&mut self, delta: isize) {
        let max = self.help_max_scroll();
        let next = self.help_scroll as isize + delta;
        self.help_scroll = next.clamp(0, max as isize) as usize;
    }

    /// One screenful, keeping a row of overlap so the reader keeps their place.
    pub fn help_scroll_page(&mut self, dir: isize) {
        let page = self.help_height.saturating_sub(1).max(1) as isize;
        self.help_scroll_by(dir * page);
    }

    pub fn help_scroll_to_end(&mut self) {
        self.help_scroll = self.help_max_scroll();
    }

    /// Absolute 1-based line number and text under the cursor, if any.
    pub fn cursor_line(&self) -> Option<(usize, &str)> {
        if !self.has_files() {
            return None;
        }
        let file = self.file();
        let &line_idx = file.view.get(file.view_pos)?;
        Some((line_idx + 1, file.lines.get(line_idx)?.as_str()))
    }

    /// Copy the cursor line to the system clipboard (OSC-52) and set status.
    pub fn yank_current_line(&mut self) {
        if !self.has_files() {
            self.status = Some("open a file before copying".into());
            return;
        }
        let Some((line_no, text)) = self.cursor_line() else {
            // File open but filter emptied the view (or cursor off-end).
            self.status = Some("nothing to copy".into());
            return;
        };
        let text = text.to_owned();
        match crate::clipboard::copy_text(&text) {
            Ok(outcome) => {
                self.status = Some(if outcome.truncated {
                    format!("copied line {line_no} (truncated)")
                } else {
                    format!("copied line {line_no}")
                });
            }
            Err(_) => {
                self.status = Some("copy failed (terminal may block clipboard)".into());
            }
        }
    }

    /// Copy the current tab's filesystem path to the clipboard (OSC-52).
    pub fn yank_current_path(&mut self) {
        if !self.has_files() {
            self.status = Some("open a file before copying".into());
            return;
        }
        let path = self.file().path.display().to_string();
        if path.is_empty() {
            self.status = Some("nothing to copy".into());
            return;
        }
        match crate::clipboard::copy_text(&path) {
            Ok(outcome) => {
                self.status = Some(if outcome.truncated {
                    "copied path (truncated)".into()
                } else {
                    "copied path".into()
                });
            }
            Err(_) => {
                self.status = Some("copy failed (terminal may block clipboard)".into());
            }
        }
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
    fn help_scroll_stays_inside_the_sheet() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.help_clamp_scroll(44, 20); // 44 rows of content in a 20-row body

        app.help_scroll_by(1000);
        assert_eq!(app.help_scroll, 24, "cannot scroll past the last row");
        app.help_scroll_by(-1000);
        assert_eq!(app.help_scroll, 0, "cannot scroll above the first row");

        app.help_scroll_page(1);
        assert_eq!(app.help_scroll, 19, "a page keeps one row of overlap");
        app.help_scroll_to_end();
        assert_eq!(app.help_scroll, 24);

        // Reflowing to two columns shortens the sheet; the view must come back
        // into range instead of being stranded past the end.
        app.help_clamp_scroll(25, 25);
        assert_eq!(app.help_scroll, 0);
    }

    #[test]
    fn reopening_help_returns_to_the_top() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.toggle_help();
        app.help_clamp_scroll(44, 20);
        app.help_scroll_to_end();
        assert_ne!(app.help_scroll, 0);
        app.toggle_help(); // close
        app.toggle_help(); // reopen
        assert_eq!(
            app.help_scroll, 0,
            "help is a reference, not a resumed view"
        );
    }

    /// The whole flow the way `main` runs it: open a bundle, arm the scan, let the
    /// event loop advance it, and land on a report without a keystroke.
    #[test]
    fn opening_a_bundle_scans_it_and_opens_the_report() {
        let mut app = app_with_paths(&["samples/bundle"]);
        app.enable_auto_scan();
        assert!(app.scanning(), "no keystroke should be needed to start");
        assert!(
            !app.show_findings,
            "the report waits until the scan finishes"
        );

        let mut frames = 0;
        while !app.scan_step(4000) {
            frames += 1;
            assert!(frames < 10_000, "scan did not finish");
        }

        assert!(
            !app.findings.is_empty(),
            "the sample bundle has known findings"
        );
        assert!(app.show_findings, "a scan with findings opens the report");
        let status = app.status.clone().unwrap_or_default();
        assert!(status.starts_with("scan: "), "{status}");
        assert_eq!(
            app.severity_counts().iter().sum::<usize>(),
            app.findings.len()
        );
    }

    #[test]
    fn constructing_an_app_does_not_start_a_scan() {
        // App::new stays side-effect free; only `enable_auto_scan` arms it.
        let app = app_with_paths(&["samples/sample.log"]);
        assert!(!app.scanning());
        assert!(app.findings.is_empty());
    }

    #[test]
    fn enabling_auto_scan_scans_the_already_open_files() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.enable_auto_scan();
        assert!(
            app.scanning(),
            "the scan should be armed, not deferred to `S`"
        );
        // Open feedback survives: the reader still needs to know what loaded.
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("opened"), "{status}");
        assert!(status.contains("scanning…"), "{status}");
    }

    #[test]
    fn enabling_auto_scan_with_no_files_scans_nothing() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.enable_auto_scan();
        assert!(!app.scanning());
        // The welcome screen should stay clean rather than reporting on nothing.
        assert!(app.status.is_none(), "{:?}", app.status);
    }

    #[test]
    fn opening_more_files_rescans_once_auto_scan_is_on() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.enable_auto_scan();
        assert!(!app.scanning());
        app.open_resolved(&[PathBuf::from("samples/sample.log")]);
        assert!(
            app.scanning(),
            "findings are global, so adding a file must rescan the corpus"
        );
    }

    #[test]
    fn auto_scan_stays_off_when_it_was_never_enabled() {
        // The `--no-scan` path: main simply never calls `enable_auto_scan`.
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.open_resolved(&[PathBuf::from("samples/sample.log")]);
        assert!(app.has_files());
        assert!(!app.scanning());
    }

    #[test]
    fn a_clean_scan_reports_what_it_covered() {
        let path = tmp_name("clean.log");
        fs::write(&path, "started up\nall good here\nstill fine\n").unwrap();
        let mut app = app_with_paths(&[&path.to_string_lossy()]);
        run_scan_to_completion(&mut app);
        fs::remove_file(&path).ok();

        assert!(app.findings.is_empty());
        assert!(!app.show_findings, "a clean scan should not open a panel");
        let status = app.status.clone().unwrap_or_default();
        assert!(status.contains("nothing notable"), "{status}");
        assert!(
            status.contains("3 lines"),
            "an all-clear should say what it covered: {status}"
        );
    }

    #[test]
    fn a_scan_report_lists_only_reportable_severities() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        let status = app.status.clone().unwrap_or_default();
        assert!(status.starts_with("scan: "), "{status}");
        assert!(status.contains(" crit"), "{status}");
        // The third instance of the always-zero counts used to live here.
        assert!(!status.contains("low"), "{status}");
        assert!(!status.contains("info"), "{status}");
    }

    #[test]
    fn severity_tally_covers_exactly_the_selectable_filters() {
        // counts are indexed by `Severity as usize`: info, low, medium, high, crit.
        assert_eq!(severity_tally([7, 9, 4, 5, 3]), "3 crit · 5 high · 4 med");
        // Zeroes are still listed — a reportable severity with no hits is
        // information; a severity that cannot be reported at all is not.
        assert_eq!(severity_tally([0; 5]), "0 crit · 0 high · 0 med");
        // The tally and the filter tabs must stay derived from one source, so a
        // future MIN_FINDING_SEVERITY change updates both at once.
        assert_eq!(
            severity_tally([1; 5]).split(" · ").count(),
            FINDING_FILTERS.iter().flatten().count()
        );
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
        assert!(
            path.exists(),
            "samples/sample.log must exist (run tests from the crate root)"
        );
        let file = LogFile::load(path, "sample.log".into(), &[]).unwrap();
        assert!(!file.lines.is_empty());
        assert_eq!(file.matches.len(), file.lines.len());
    }

    fn app_with_paths(paths: &[&str]) -> App {
        let inputs: Vec<String> = paths.iter().map(|p| (*p).to_string()).collect();
        App::new(&inputs, Vec::new(), false).expect("app should construct")
    }

    fn run_scan_to_completion(app: &mut App) {
        app.begin_scan();
        // Bound iterations so a stuck scan fails the test instead of hanging CI.
        for _ in 0..10_000 {
            if app.scan_step(10_000) {
                return;
            }
        }
        panic!("scan did not finish");
    }

    fn run_rescan_to_completion(app: &mut App) {
        // Bound iterations so a stuck rescan fails the test instead of hanging CI.
        for _ in 0..100_000 {
            if !app.rescanning() || app.rescan_step(10_000) {
                return;
            }
        }
        panic!("rescan did not finish");
    }

    #[test]
    fn open_bundle_skips_binaries_and_uses_relative_names() {
        let app = app_with_paths(&["samples/bundle"]);
        assert!(app.has_files());
        let names: Vec<_> = app.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("agent.log")));
        assert!(names.iter().any(|n| n.contains("install.log")));
        assert!(names.iter().any(|n| n.contains("network.log")));
        assert!(
            names.iter().all(|n| !n.contains("thumbnail.bin")),
            "binary files must be skipped: {names:?}"
        );
        // Relative tab names distinguish files from nested folders.
        assert!(names.iter().any(|n| n.contains('/') || n.contains('\\')));
    }

    #[test]
    fn open_zip_loads_logs_and_registers_temp_dir() {
        let app = app_with_paths(&["samples/bundle.zip"]);
        assert!(app.has_files());
        assert!(
            !app.temp_dirs.is_empty(),
            "zip extract should retain a temp dir for cleanup"
        );
        assert!(app.temp_dirs.iter().all(|d| d.exists()));
        let names: Vec<_> = app.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("agent.log")));
        assert!(names.iter().all(|n| !n.contains("thumbnail.bin")));
    }

    #[test]
    fn resolve_missing_path_sets_status_without_panic() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.open_resolved(&[PathBuf::from("/nonexistent/loglens-missing-file.log")]);
        assert!(!app.has_files());
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains("failed") || status.contains("no log"),
            "unexpected status: {status}"
        );
    }

    #[test]
    fn startup_preserves_open_error_status() {
        // Regression: App::new used to wipe status after the initial open, so a
        // bad CLI path launched a silent welcome screen with no feedback.
        let app = App::new(
            &["/nonexistent/loglens-missing-file.log".into()],
            Vec::new(),
            false,
        )
        .unwrap();
        assert!(!app.has_files());
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains("failed") || status.contains("no log"),
            "startup must surface open errors: {status}"
        );
    }

    #[test]
    fn startup_preserves_successful_open_status() {
        let app = app_with_paths(&["samples/network.log"]);
        assert!(app.has_files());
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains("opened"),
            "startup should keep open confirmation: {status}"
        );
    }

    #[test]
    fn welcome_launch_has_no_status() {
        let app = App::new(&[], Vec::new(), false).unwrap();
        assert!(!app.has_files());
        assert_eq!(app.status, None);
    }

    #[test]
    fn sanitizes_ansi_and_control_characters_in_log_lines() {
        let path = tmp_name("ansi");
        // ESC[31m, OSC hyperlink fragments, backspace, bare CR, BEL.
        let hostile = "ERROR \x1b[31mred\x1b[0m\x07 secret\x08\rWARN done\n";
        fs::write(&path, hostile).unwrap();
        let file = LogFile::load(&path, "ansi.log".into(), &[]).unwrap();
        assert_eq!(file.lines.len(), 1);
        let line = &file.lines[0];
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{07}') && !line.contains('\r'),
            "control chars must be sanitized: {line:?}"
        );
        assert!(
            line.contains('�'),
            "controls should become replacement char"
        );
        assert!(line.contains("ERROR") && line.contains("WARN"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn tabs_are_preserved_in_log_lines() {
        let path = tmp_name("tabs");
        fs::write(&path, "col1\tcol2\tcol3\n").unwrap();
        let file = LogFile::load(&path, "tabs.log".into(), &[]).unwrap();
        assert_eq!(file.lines[0], "col1\tcol2\tcol3");
        fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_file_direct_open_succeeds_with_zero_lines() {
        let path = tmp_name("empty");
        fs::write(&path, b"").unwrap();
        let file = LogFile::load(&path, "empty.log".into(), &[]).unwrap();
        assert!(file.lines.is_empty());
        assert!(file.view.is_empty());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn symlink_to_bundle_opens_like_directory() {
        let link = tmp_name("link-bundle");
        let _ = fs::remove_file(&link);
        #[cfg(unix)]
        {
            let target = Path::new("samples/bundle")
                .canonicalize()
                .expect("samples/bundle must exist");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let app = App::new(&[link.to_string_lossy().into()], Vec::new(), false).unwrap();
            assert!(app.has_files(), "symlinked bundle directory should resolve");
            assert!(app.files.iter().any(|f| f.name.contains("agent.log")));
            fs::remove_file(&link).ok();
        }
        #[cfg(not(unix))]
        {
            let _ = link;
        }
    }

    #[test]
    fn findings_filter_narrows_visible_rows_and_cycles() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        assert!(app.findings.len() >= 2);
        assert!(
            app.findings_filter.is_none(),
            "a fresh scan starts unfiltered"
        );
        assert_eq!(app.visible_findings().len(), app.findings.len());

        for _ in 0..FINDING_FILTERS.len() {
            app.cycle_findings_filter(1);
            let vis = app.visible_findings();
            match app.findings_filter {
                None => assert_eq!(vis.len(), app.findings.len()),
                Some(sev) => {
                    assert!(
                        vis.iter()
                            .all(|&i| app.signatures[app.findings[i].sig].severity == sev),
                        "every visible row must match the active tab"
                    );
                    // The selection always addresses something on screen.
                    if !vis.is_empty() {
                        assert!(vis.contains(&app.findings_sel));
                    }
                }
            }
        }
        assert_eq!(app.findings_filter, None, "cycling wraps back to all");

        // Cycling backwards lands on the last tab.
        app.cycle_findings_filter(-1);
        assert_eq!(app.findings_filter, *FINDING_FILTERS.last().unwrap());
    }

    /// The window must move the minimum needed to reveal the selection. The old
    /// derived-`top` behaviour pinned the selection to the bottom row instead,
    /// so the list lurched on every step past the first page.
    #[test]
    fn findings_scroll_moves_the_minimum_to_reveal_the_selection() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        // Synthesise a long list so scrolling is exercised without opening
        // hundreds of files; grouping keeps real corpora short.
        let sig = app.findings[0].sig;
        app.findings = (0..50)
            .map(|i| Finding {
                file: 0,
                line: i,
                sig,
                last: i,
                count: 1,
            })
            .collect();
        app.findings_sel = 0;
        app.findings_top = 0;

        app.findings_scroll_into_view(10);
        assert_eq!(app.findings_top, 0, "selection already visible: no scroll");

        app.findings_sel = 10;
        app.findings_scroll_into_view(10);
        assert_eq!(
            app.findings_top, 1,
            "one row past the bottom scrolls by one"
        );

        app.findings_sel = 30;
        app.findings_scroll_into_view(10);
        assert_eq!(app.findings_top, 21);

        app.findings_sel = 20;
        app.findings_scroll_into_view(10);
        assert_eq!(
            app.findings_top, 20,
            "scrolling back up also moves minimally"
        );

        app.findings_sel = 49;
        app.findings_scroll_into_view(10);
        assert_eq!(
            app.findings_top, 40,
            "last row must not leave blank rows below"
        );
    }

    #[test]
    fn new_scan_clears_a_stale_findings_filter() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        app.findings_filter = Some(Severity::Critical);
        app.findings_top = 7;

        run_scan_to_completion(&mut app);
        assert!(
            app.findings_filter.is_none(),
            "a filter left over from the previous scan would make a fresh \
             result look empty"
        );
        assert_eq!(app.findings_top, 0);
    }

    /// A repeated condition must cost one row and a count, not one row per line.
    #[test]
    fn scan_collapses_repeated_hits_into_one_counted_finding() {
        let dir = tmp_name("scan-group");
        fs::create_dir_all(&dir).unwrap();
        let mut body = String::new();
        for _ in 0..50 {
            body.push_str("2026-07-29 ERROR disabled real-time protection on host\n");
        }
        body.push_str("2026-07-29 WARN powershell.exe -enc SQBFAFgA\n");
        let path = dir.join("noisy.log");
        fs::write(&path, body).unwrap();

        let mut app = app_with_paths(&[&path.to_string_lossy()]);
        run_scan_to_completion(&mut app);
        assert!(!app.findings.is_empty());

        // The invariant, stated without depending on how many signatures the
        // built-in library happens to fire on these lines.
        let mut pairs: Vec<(usize, usize)> = app.findings.iter().map(|f| (f.file, f.sig)).collect();
        let rows = pairs.len();
        pairs.sort_unstable();
        pairs.dedup();
        assert_eq!(pairs.len(), rows, "one row per (file, signature) at most");

        assert!(
            rows < 50,
            "50 identical lines must not produce 50 rows, got {rows}"
        );
        let repeated = app
            .findings
            .iter()
            .max_by_key(|f| f.count)
            .expect("a finding");
        assert_eq!(repeated.count, 50, "every repeat must be counted");
        assert_eq!(repeated.line, 0, "line is the first hit — the jump target");
        assert_eq!(repeated.last, 49, "last is the final hit");
        assert!(
            app.occurrence_count() >= 51,
            "hits must total every matching line, got {}",
            app.occurrence_count()
        );

        fs::remove_dir_all(&dir).ok();
    }

    /// Grouping is per file, so a per-file count is never silently merged across
    /// the corpus.
    #[test]
    fn scan_groups_per_file_not_across_files() {
        let dir = tmp_name("scan-group-files");
        fs::create_dir_all(&dir).unwrap();
        let line = "2026-07-29 ERROR disabled real-time protection\n";
        fs::write(dir.join("a.log"), line.repeat(3)).unwrap();
        fs::write(dir.join("b.log"), line.repeat(7)).unwrap();

        let mut app = app_with_paths(&[&dir.to_string_lossy()]);
        assert_eq!(app.files.len(), 2);
        run_scan_to_completion(&mut app);

        let mut counts: Vec<usize> = app.findings.iter().map(|f| f.count).collect();
        counts.sort_unstable();
        assert_eq!(counts, vec![3, 7], "each file keeps its own count");
        assert_eq!(app.occurrence_count(), 10);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_ranks_findings_by_severity_then_location() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        assert!(!app.findings.is_empty());
        assert!(app.show_findings);
        for w in app.findings.windows(2) {
            let (a, b) = (w[0], w[1]);
            let sa = app.signatures[a.sig].severity;
            let sb = app.signatures[b.sig].severity;
            assert!(sa >= sb, "findings must be sorted high→low severity");
            if sa == sb {
                assert!(
                    (a.file, a.line) <= (b.file, b.line),
                    "equal severity must keep file/line order"
                );
            }
        }
        // Sample contains known High/Critical-class signals.
        let counts = app.severity_counts();
        assert!(
            counts[Severity::High as usize] + counts[Severity::Critical as usize] > 0,
            "sample.log should yield high/critical findings"
        );
    }

    #[test]
    fn scan_without_files_sets_status() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.begin_scan();
        assert!(!app.scanning());
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before scanning")
        );
    }

    #[test]
    fn cancel_scan_clears_running_state() {
        let mut app = app_with_paths(&["samples/big.log"]);
        app.begin_scan();
        assert!(app.scanning());
        // Advance a little so gutter markers may be partial, then cancel.
        app.scan_step(5);
        assert!(
            app.files
                .iter()
                .any(|f| f.scan_severity.iter().any(|s| s.is_some())),
            "expected partial gutter markers before cancel"
        );
        app.cancel_scan();
        assert!(!app.scanning());
        assert_eq!(app.status.as_deref(), Some("scan cancelled"));
        assert!(
            app.files
                .iter()
                .all(|f| f.scan_severity.iter().all(|s| s.is_none())),
            "cancel must clear partial gutter markers"
        );
        assert!(app.findings.is_empty());
        assert!(!app.show_findings);
    }

    #[test]
    fn scan_findings_exclude_low_info_noise() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        run_scan_to_completion(&mut app);
        assert!(!app.findings.is_empty());
        assert!(
            app.findings
                .iter()
                .all(|f| app.signatures[f.sig].severity >= Severity::Medium),
            "findings panel must not include Low/Info catch-alls"
        );
        let counts = app.severity_counts();
        assert_eq!(counts[Severity::Info as usize], 0);
        assert_eq!(counts[Severity::Low as usize], 0);
    }

    #[test]
    fn next_prev_finding_walks_ranked_list_with_wrap() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.next_finding();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no findings — press S to scan")
        );

        run_scan_to_completion(&mut app);
        let n = app.findings.len();
        assert!(n >= 2, "sample.log should yield multiple findings");
        app.close_findings();

        // First press lands on the selected finding (index 0 after scan).
        let first = app.findings[0];
        app.next_finding();
        assert!(!app.show_findings);
        assert_eq!(app.findings_sel, 0);
        assert_eq!(app.current, first.file);
        assert_eq!(app.file().view[app.file().view_pos], first.line);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .starts_with("finding 1/"),
            "status should report position: {:?}",
            app.status
        );

        // Second press advances; from the last finding, wrap back to first.
        app.next_finding();
        assert_eq!(app.findings_sel, 1);
        app.findings_sel = n - 1;
        app.findings_jump();
        app.next_finding();
        assert_eq!(app.findings_sel, 0);
        assert_eq!(app.file().view[app.file().view_pos], app.findings[0].line);

        // prev from first wraps to last.
        app.prev_finding();
        assert_eq!(app.findings_sel, n - 1);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains(&format!("finding {n}/{n}")),
            "status should show last finding: {:?}",
            app.status
        );
    }

    #[test]
    fn toggle_findings_reopens_without_rescan() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.toggle_findings();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no findings — press S to scan")
        );

        run_scan_to_completion(&mut app);
        let n = app.findings.len();
        assert!(n > 0);
        assert!(app.show_findings);
        app.close_findings();
        assert!(!app.show_findings);
        app.toggle_findings();
        assert!(app.show_findings);
        assert_eq!(app.findings.len(), n, "toggle must not clear findings");
        app.toggle_findings();
        assert!(!app.show_findings);
        assert_eq!(app.findings.len(), n);
    }

    #[test]
    fn export_findings_writes_markdown_summary() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.export_findings();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no findings to export")
        );

        run_scan_to_completion(&mut app);
        let path = env::temp_dir().join(format!(
            "loglens-findings-test-{}-{}.md",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let n = app
            .export_findings_to(&path)
            .expect("export should succeed");
        assert_eq!(n, app.findings.len());
        let text = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).ok();
        assert!(text.contains("# loglens scan findings"));
        assert!(text.contains("sample.log"));
        assert!(
            text.contains("CRIT") || text.contains("HIGH") || text.contains("MED"),
            "export should include severity labels"
        );
        assert!(text.contains("**why:**"));
        assert!(text.contains("**location:**"));
    }

    /// `e` must never clobber an earlier export: it steps to the next free
    /// numbered name instead, and reports failure rather than overwriting once
    /// they are exhausted.
    #[test]
    fn export_picks_a_fresh_name_instead_of_overwriting() {
        let dir = tmp_name("export-collide");
        fs::create_dir_all(&dir).unwrap();

        // Nothing there yet → the plain default name.
        let first = App::next_export_path_in(&dir).expect("first export path");
        assert_eq!(first, dir.join("loglens-findings.md"));
        fs::write(&first, b"earlier export\n").unwrap();

        // Default taken → numbered, and the earlier file is untouched.
        let second = App::next_export_path_in(&dir).expect("second export path");
        assert_eq!(second, dir.join("loglens-findings-2.md"));
        fs::write(&second, b"second\n").unwrap();
        assert_eq!(fs::read_to_string(&first).unwrap(), "earlier export\n");

        let third = App::next_export_path_in(&dir).expect("third export path");
        assert_eq!(third, dir.join("loglens-findings-3.md"));

        // All names taken → None, so the caller reports an error and writes nothing.
        for n in 3..=MAX_EXPORT_FILES {
            fs::write(dir.join(format!("loglens-findings-{n}.md")), b"x").unwrap();
        }
        assert!(App::next_export_path_in(&dir).is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn findings_jump_disables_filter_when_line_hidden() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        // Filter to a rare term so most scan hits are hidden.
        app.begin_input(InputKind::Search);
        app.push_input_chars("Quarantine".chars());
        app.confirm_input();
        app.filter_on = true;
        app.rebuild_views();
        assert_eq!(app.file().view.len(), 1);

        run_scan_to_completion(&mut app);
        // Pick a finding that is not the Quarantine line.
        let target = app
            .findings
            .iter()
            .copied()
            .find(|f| !app.files[f.file].lines[f.line].contains("Quarantine"))
            .expect("need a non-quarantine finding");
        app.findings_sel = app
            .findings
            .iter()
            .position(|f| f.file == target.file && f.line == target.line)
            .unwrap();
        app.findings_jump();
        assert!(!app.filter_on, "jump must defeat a hiding filter");
        assert_eq!(app.file().view[app.file().view_pos], target.line);
        assert!(!app.show_findings);
    }

    #[test]
    fn close_current_file_remaps_finding_file_indices() {
        let mut app = app_with_paths(&["samples/sample.log", "samples/network.log"]);
        assert_eq!(app.files.len(), 2);
        run_scan_to_completion(&mut app);
        assert!(app.findings.iter().any(|f| f.file == 1));
        app.current = 0;
        app.close_current_file();
        assert_eq!(app.files.len(), 1);
        assert!(
            app.findings.iter().all(|f| f.file == 0),
            "remaining findings must point at the surviving file"
        );
        assert!(app.files[0].name.contains("network.log"));
    }

    #[test]
    fn close_last_file_returns_to_welcome_viewer() {
        let mut app = app_with_paths(&["samples/network.log"]);
        app.close_current_file();
        assert!(!app.has_files());
        assert_eq!(app.mode, Mode::Viewer);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("press o to open")
        );
    }

    #[test]
    fn keyword_and_search_filter_navigation() {
        let rule = rules::compile_rule("ERROR", false, true, 0, &Theme::dark()).unwrap();
        let mut app = App::new(&["samples/sample.log".into()], vec![rule], true).unwrap();
        assert!(app.file().rule_counts[0] > 0);

        app.begin_input(InputKind::Search);
        app.push_input_chars("ERROR".chars());
        app.confirm_input();
        let hit_lines = app
            .file()
            .lines
            .iter()
            .filter(|l| app.search.as_ref().unwrap().regex.is_match(l))
            .count();
        assert!(
            hit_lines >= 3,
            "expected several ERROR lines, got {hit_lines}"
        );
        // Occurrences can exceed line count when a line matches more than once
        // (e.g. "ERROR ... error").
        assert!(app.search_hits() >= hit_lines);

        app.toggle_filter();
        assert!(app.filter_on);
        assert_eq!(app.file().view.len(), hit_lines);
        assert!(
            app.file()
                .view
                .iter()
                .all(|&i| app.file().lines[i].to_lowercase().contains("error"))
        );

        let start = app.file().view_pos;
        app.next_match();
        assert!(app.file().view_pos > start || hit_lines <= 1);
        assert!(
            app.status.as_deref().unwrap_or("").starts_with("match "),
            "next_match should report position: {:?}",
            app.status
        );
        app.prev_match();
        assert_eq!(app.file().view_pos, start);
    }

    #[test]
    fn first_match_jumps_to_top_hit() {
        let rule = rules::compile_rule("ERROR", false, true, 0, &Theme::dark()).unwrap();
        let mut app = App::new(&["samples/sample.log".into()], vec![rule], true).unwrap();
        assert!(app.file().rule_counts[0] > 0);

        app.go_bottom();
        let away = app.file().view_pos;
        app.first_match();
        let first = app.file().view_pos;
        assert!(
            first < away,
            "first_match should leave the bottom: {first} vs {away}"
        );
        assert!(
            app.status.as_deref().unwrap_or("").starts_with("match 1/"),
            "first_match should report match 1/n: {:?}",
            app.status
        );

        // Idempotent: already on first hit still reports match 1/n.
        app.first_match();
        assert_eq!(app.file().view_pos, first);
        assert!(
            app.status.as_deref().unwrap_or("").starts_with("match 1/"),
            "{:?}",
            app.status
        );

        let mut bare = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        bare.first_match();
        assert!(
            bare.status
                .as_deref()
                .unwrap_or("")
                .contains("no highlight matches"),
            "{:?}",
            bare.status
        );

        let mut empty = App::new(&[], Vec::new(), false).unwrap();
        empty.first_match();
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before jumping matches")
        );
    }

    #[test]
    fn match_nav_wraps_and_reports_empty() {
        let rule = rules::compile_rule("ERROR", false, true, 0, &Theme::dark()).unwrap();
        let mut app = App::new(&["samples/sample.log".into()], vec![rule], true).unwrap();
        assert!(app.file().rule_counts[0] > 0);

        // From the bottom, next_match wraps to the first hit.
        app.go_bottom();
        app.next_match();
        let first = app.file().view_pos;
        assert!(
            app.status.as_deref().unwrap_or("").starts_with("match 1/"),
            "wrap-to-first should report match 1/n: {:?}",
            app.status
        );

        // From the first hit, prev_match wraps to the last.
        app.prev_match();
        let last = app.file().view_pos;
        let status = app.status.as_deref().unwrap_or("").to_string();
        assert!(
            status.starts_with("match ") && status.contains('/'),
            "prev wrap should report match i/n: {status:?}"
        );
        assert!(last >= first, "last match should be at or after first");

        // From the last hit, next_match wraps back to the first.
        app.next_match();
        assert_eq!(app.file().view_pos, first);
        assert!(
            app.status.as_deref().unwrap_or("").starts_with("match 1/"),
            "{:?}",
            app.status
        );

        // No highlights and no search → clear status guidance.
        let mut bare = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        bare.next_match();
        assert!(
            bare.status
                .as_deref()
                .unwrap_or("")
                .contains("no highlight matches"),
            "{:?}",
            bare.status
        );

        let mut empty = App::new(&[], Vec::new(), false).unwrap();
        empty.next_match();
        assert!(
            empty
                .status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before jumping matches")
        );
    }

    /// The active-match list is cached, so every path that changes the view or
    /// the match data must invalidate it. A stale cache would report the previous
    /// hit count — or index past the end of a shorter view.
    #[test]
    fn match_nav_cache_follows_search_filter_and_rule_changes() {
        fn hit_total(app: &App) -> usize {
            // Status is "match i/n · line L".
            let s = app.status.as_deref().unwrap_or("");
            s.split_once('/')
                .and_then(|(_, rest)| rest.split_once(' '))
                .and_then(|(n, _)| n.parse().ok())
                .unwrap_or_else(|| panic!("expected 'match i/n · line L', got {s:?}"))
        }

        let mut app = app_with_paths(&["samples/sample.log"]);

        // "ERROR" is on 4 lines of the sample; "WARN" on 3.
        let search = |app: &mut App, text: &str| {
            app.begin_input(InputKind::Search);
            app.push_input_chars(text.chars());
            app.confirm_input();
        };

        search(&mut app, "ERROR");
        app.go_top();
        app.next_match();
        assert_eq!(hit_total(&app), 4, "{:?}", app.status);

        // Switching the search must not reuse the previous hit list.
        search(&mut app, "WARN");
        app.go_top();
        app.next_match();
        assert_eq!(hit_total(&app), 3, "{:?}", app.status);

        // Filtering shrinks the view, so cached positions would be out of range.
        app.toggle_filter();
        assert!(app.filter_on);
        app.go_top();
        app.next_match();
        assert_eq!(hit_total(&app), 3, "{:?}", app.status);
        assert!(app.file().view_pos < app.file().view.len());
        app.toggle_filter();

        // With the search cleared, hits come from highlight rules instead.
        app.clear_search();
        app.begin_input(InputKind::Keyword);
        app.push_input_chars("Retrying".chars());
        app.confirm_input();
        run_rescan_to_completion(&mut app);
        app.go_top();
        app.next_match();
        assert_eq!(hit_total(&app), 2, "{:?}", app.status);

        // Removing the rule leaves no highlights at all.
        app.remove_last_rule();
        run_rescan_to_completion(&mut app);
        app.next_match();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no highlight matches"),
            "{:?}",
            app.status
        );
    }

    /// `n`/`N` must not re-scan the file on every press: the first jump builds the
    /// hit list, later ones reuse it. Compares the cost of one cold jump against
    /// many warm ones, so the bound is a ratio, not a wall-clock budget.
    #[test]
    fn match_nav_reuses_cached_positions() {
        let mut app = app_with_paths(&["samples/big.log"]);
        app.begin_input(InputKind::Search);
        app.push_input_chars("connection".chars());
        app.confirm_input();
        assert!(app.file().match_positions.is_none(), "cache starts empty");

        let cold = std::time::Instant::now();
        app.next_match();
        let cold = cold.elapsed().max(std::time::Duration::from_nanos(1));
        assert!(
            app.file().match_positions.is_some(),
            "first jump should populate the cache"
        );

        let warm = std::time::Instant::now();
        for _ in 0..50 {
            app.next_match();
        }
        let warm = warm.elapsed() / 50;

        assert!(
            warm < cold,
            "cached jump ({warm:?}) should beat the cold one ({cold:?})"
        );
    }

    #[test]
    fn confirm_input_rejects_invalid_regex_and_respects_rule_cap() {
        let mut app = app_with_paths(&["samples/network.log"]);
        app.begin_input(InputKind::Regex);
        app.push_input_chars("(".chars());
        app.confirm_input();
        assert!(app.rules.is_empty());
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("invalid regex")
                || app.status.as_deref().unwrap_or("").contains("failed")
        );

        for i in 0..MAX_RULES {
            let rule =
                rules::compile_rule(&format!("k{i}"), false, false, i, &Theme::dark()).unwrap();
            app.rules.push(rule);
        }
        app.begin_input(InputKind::Keyword);
        app.push_input_chars("overflow".chars());
        app.confirm_input();
        assert_eq!(app.rules.len(), MAX_RULES);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("highlight limit")
        );
    }

    #[test]
    fn remove_last_rule_clears_active_and_rescans() {
        let rule = rules::compile_rule("WARN", false, true, 0, &Theme::dark()).unwrap();
        let mut app = App::new(&["samples/sample.log".into()], vec![rule], true).unwrap();
        app.active_rule = Some(0);
        assert!(app.file().total_matches() > 0);
        app.remove_last_rule();
        run_rescan_to_completion(&mut app);
        assert!(app.rules.is_empty());
        assert_eq!(app.active_rule, None);
        assert_eq!(app.file().total_matches(), 0);
    }

    #[test]
    fn chunked_rescan_commits_matches_and_stays_cancellable() {
        let dir = tmp_name("rescan-chunk");
        fs::create_dir_all(&dir).unwrap();
        // Large enough that a single keystroke cannot finish the rescan.
        let mut body = String::new();
        for i in 0..12_000 {
            if i % 50 == 0 {
                body.push_str("ERROR boom\n");
            } else {
                body.push_str("INFO ok\n");
            }
        }
        let path = dir.join("big.log");
        fs::write(&path, body).unwrap();

        let mut app = App::new(&[path.to_string_lossy().into()], Vec::new(), false).unwrap();
        assert_eq!(app.file().lines.len(), 12_000);
        assert_eq!(app.file().total_matches(), 0);

        app.begin_input(InputKind::Keyword);
        app.push_input_chars("ERROR".chars());
        app.confirm_input();
        assert!(app.rescanning(), "large corpus must start a chunked rescan");
        assert_eq!(
            app.file().total_matches(),
            0,
            "old highlights must remain until commit"
        );

        // One small step should not finish.
        assert!(!app.rescan_step(500));
        assert!(app.rescanning());
        assert_eq!(app.file().total_matches(), 0);

        // Cancel drops pending work and keeps prior (empty) matches.
        app.cancel_rescan();
        assert!(!app.rescanning());
        assert_eq!(app.file().total_matches(), 0);
        assert!(app.status.as_deref().unwrap_or("").contains("cancelled"));

        // Restart and finish — matches commit and filter views rebuild.
        // Rule from the cancelled attempt is still present; rescan it in place.
        assert_eq!(app.rules.len(), 1);
        app.begin_rescan(Some("added highlight: ERROR".into()));
        run_rescan_to_completion(&mut app);
        assert!(!app.rescanning());
        assert!(app.file().total_matches() > 0);
        assert_eq!(app.file().rule_counts[0], app.file().total_matches());
        assert_eq!(app.file().total_matches(), 240); // every 50th of 12_000 lines
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("added highlight")
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn begin_scan_cancels_in_flight_rescan() {
        let dir = tmp_name("rescan-vs-scan");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.log");
        fs::write(&path, "ERROR a\n".repeat(8_000)).unwrap();
        let mut app = App::new(&[path.to_string_lossy().into()], Vec::new(), false).unwrap();
        app.begin_input(InputKind::Keyword);
        app.push_input_chars("ERROR".chars());
        app.confirm_input();
        assert!(app.rescanning());
        app.begin_scan();
        assert!(!app.rescanning());
        assert!(app.scanning());
        app.cancel_scan();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adding_rule_pads_rule_counts_before_rescan_commits() {
        // Regression: chunked rescan mutates `rules` before committing match
        // data. The legend indexes `rule_counts[i]` for each rule on every
        // frame — including the first frame after `a`/`r` confirm — so counts
        // must be length-aligned immediately in `begin_rescan`.
        let mut app = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        assert!(app.file().rule_counts.is_empty());
        app.begin_input(InputKind::Keyword);
        app.push_input_chars("ERROR".chars());
        app.confirm_input();
        assert_eq!(app.rules.len(), 1);
        assert_eq!(
            app.file().rule_counts.len(),
            app.rules.len(),
            "legend would panic if rule_counts lagged rules after add"
        );
        // Cancel must keep the alignment (rule stays; counts stay sized).
        if app.rescanning() {
            app.cancel_rescan();
        }
        assert_eq!(app.rules.len(), 1);
        assert_eq!(app.file().rule_counts.len(), 1);
    }

    #[test]
    fn cancel_rescan_after_remove_strips_orphan_spans() {
        let rule = rules::compile_rule("ERROR", false, true, 0, &Theme::dark()).unwrap();
        let dir = tmp_name("rescan-remove");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        fs::write(&path, "ERROR a\nINFO b\n".repeat(4_000)).unwrap();
        let mut app = App::new(&[path.to_string_lossy().into()], vec![rule], true).unwrap();
        assert!(app.file().total_matches() > 0);
        app.filter_on = true;
        app.rebuild_views();
        let filtered = app.file().view.len();
        assert!(filtered > 0);

        app.remove_last_rule();
        assert!(app.rules.is_empty());
        assert!(app.rescanning());
        // Orphan spans for the removed rule must not survive into cancel.
        assert!(
            app.file()
                .matches
                .iter()
                .all(|spans| spans.iter().all(|m| m.rule < app.rules.len())),
            "begin_rescan must strip spans for removed rules"
        );
        assert_eq!(app.file().rule_counts.len(), 0);
        app.cancel_rescan();
        assert!(app.rules.is_empty());
        assert_eq!(app.file().total_matches(), 0);
        assert!(
            app.file().view.is_empty() || !app.filter_on,
            "filter view must not keep lines that only matched the removed rule"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn soak_chunked_rescan_over_near_cap_corpus() {
        let dir = tmp_name("rescan-soak");
        fs::create_dir_all(&dir).unwrap();
        // Several medium files — enough lines that hitching would be obvious,
        // but still cheap enough for CI. Exercise many rules + chunked steps.
        for n in 0..8 {
            let mut body = String::new();
            for i in 0..8_000 {
                body.push_str(if i % 40 == 0 { "ERROR x\n" } else { "INFO y\n" });
            }
            fs::write(dir.join(format!("{n}.log")), body).unwrap();
        }
        let mut app = App::new(&[dir.to_string_lossy().into()], Vec::new(), false).unwrap();
        assert!(app.files.len() >= 8);

        let mut rules = Vec::new();
        for i in 0..16 {
            rules.push(
                rules::compile_rule(&format!("ERR{i}"), false, true, i, &Theme::dark()).unwrap(),
            );
        }
        rules.push(rules::compile_rule("ERROR", false, true, 16, &Theme::dark()).unwrap());
        app.rules = rules;
        app.begin_rescan(Some("soak rescan done".into()));
        assert!(app.rescanning());

        let mut steps = 0usize;
        for _ in 0..100_000 {
            steps += 1;
            if app.rescan_step(1_500) {
                break;
            }
            assert!(app.busy());
        }
        assert!(!app.rescanning(), "soak rescan should finish");
        assert!(steps > 1, "expected multiple chunks, got {steps}");
        let total: usize = app.files.iter().map(|f| f.total_matches()).sum();
        assert!(total > 0, "ERROR rule should match");
        assert_eq!(app.status.as_deref(), Some("soak rescan done"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lossy_utf8_load_replaces_invalid_bytes() {
        let path = tmp_name("latin1");
        // "ERROR café" with Latin-1 é (0xE9) — invalid UTF-8.
        fs::write(&path, b"ERROR caf\xe9\n").unwrap();
        let file = LogFile::load(&path, "latin1.log".into(), &[]).unwrap();
        assert_eq!(file.lines.len(), 1);
        assert!(file.lines[0].contains("ERROR"));
        assert!(file.lines[0].contains('�') || file.lines[0].contains('é'));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn highlight_only_filter_uses_match_lines() {
        let rule = rules::compile_rule("WARN", false, true, 0, &Theme::dark()).unwrap();
        let mut app = App::new(&["samples/sample.log".into()], vec![rule], true).unwrap();
        let expected = app.file().match_lines.clone();
        app.filter_on = true;
        app.rebuild_views();
        assert_eq!(app.file().view, expected);
        assert!(!expected.is_empty());
    }

    #[test]
    fn zero_width_regex_does_not_explode_matches() {
        let path = tmp_name("zw");
        fs::write(&path, "aaaa\nbbbb\n").unwrap();
        let rule = rules::compile_rule("a*", true, false, 0, &Theme::dark()).unwrap();
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

    #[test]
    fn soak_large_bundle_open_and_scan() {
        let dir = tmp_name("soak-bundle");
        fs::create_dir_all(dir.join("svc")).unwrap();
        // Hundreds of small logs with a mix of clean + notable lines.
        for i in 0..350 {
            let body = if i % 17 == 0 {
                format!("INFO start\nERROR Certificate validation failed for host-{i}\nINFO done\n")
            } else if i % 23 == 0 {
                format!("WARN noise\nconnection refused to peer-{i}\nINFO ok\n")
            } else {
                format!("INFO heartbeat {i}\nDEBUG tick\n")
            };
            fs::write(dir.join("svc").join(format!("{i:04}.log")), body).unwrap();
        }
        // Binary decoy that must be skipped.
        fs::write(dir.join("svc").join("blob.bin"), [0u8, 1, 2, 3]).unwrap();

        let mut app = App::new(&[dir.to_string_lossy().into()], Vec::new(), false).unwrap();
        assert!(
            app.files.len() >= 300,
            "expected a large open set, got {}",
            app.files.len()
        );
        assert!(app.files.len() <= MAX_OPEN_FILES);
        assert!(app.files.iter().all(|f| !f.name.contains("blob.bin")));

        run_scan_to_completion(&mut app);
        assert!(!app.findings.is_empty());
        assert!(
            app.findings
                .iter()
                .all(|f| app.signatures[f.sig].severity >= Severity::Medium)
        );
        // Cap must hold even on a large corpus.
        assert!(app.findings.len() <= MAX_FINDINGS);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn soak_dense_rules_over_big_log_stays_bounded() {
        let mut rules = Vec::new();
        // Mix of literal keywords and sparse regexes near the rule cap.
        for i in 0..32 {
            rules.push(
                rules::compile_rule(&format!("ERR{i}"), false, true, i, &Theme::dark()).unwrap(),
            );
        }
        for i in 0..16 {
            rules.push(
                rules::compile_rule(
                    &format!("warn{{0,{i}}}"),
                    true,
                    true,
                    32 + i,
                    &Theme::dark(),
                )
                .unwrap(),
            );
        }
        let path = Path::new("samples/big.log");
        assert!(path.exists(), "samples/big.log must exist");
        let file = LogFile::load(path, "big.log".into(), &rules).unwrap();
        let total: usize = file.matches.iter().map(|m| m.len()).sum();
        assert!(total <= MAX_MATCHES_PER_FILE);
        assert_eq!(file.matches.len(), file.lines.len());
        for spans in &file.matches {
            assert!(spans.len() <= MAX_MATCHES_PER_LINE);
        }
    }

    #[test]
    fn mixed_valid_and_missing_cli_paths_keeps_status() {
        let app = App::new(
            &[
                "samples/network.log".into(),
                "/nonexistent/loglens-missing.log".into(),
            ],
            Vec::new(),
            false,
        )
        .unwrap();
        assert!(app.has_files());
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains("failed") || status.contains("skipped"),
            "partial open must report failures: {status}"
        );
    }

    #[test]
    fn soak_hostile_zip_opens_safely() {
        let dir = tmp_name("soak-zip");
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("bundle.zip");
        {
            let file = File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            for i in 0..80 {
                zip.start_file(format!("n{i}/agent.log"), opts).unwrap();
                zip.write_all(format!("ERROR Certificate validation failed node-{i}\n").as_bytes())
                    .unwrap();
            }
            zip.start_file("../escape.log", opts).unwrap();
            zip.write_all(b"nope\n").unwrap();
            zip.start_file("noise.bin", opts).unwrap();
            zip.write_all(&[0u8; 64]).unwrap();
            zip.finish().unwrap();
        }

        let mut app = App::new(&[zip_path.to_string_lossy().into()], Vec::new(), false).unwrap();
        assert!(app.has_files());
        assert!(app.files.len() >= 50);
        assert!(app.files.iter().all(|f| !f.name.contains("..")));
        assert!(app.files.iter().all(|f| !f.name.contains("noise.bin")));
        run_scan_to_completion(&mut app);
        assert!(
            app.findings
                .iter()
                .any(|f| app.signatures[f.sig].title.contains("Certificate"))
        );
        // Dropping the app must clean temp extract dirs.
        let temps: Vec<_> = app.temp_dirs.clone();
        drop(app);
        for t in temps {
            assert!(!t.exists(), "temp extract dir should be removed on Drop");
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cursor_line_tracks_view_position() {
        let mut app = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        let (line_no, text) = app.cursor_line().expect("sample has lines");
        assert_eq!(line_no, 1);
        assert!(!text.is_empty());
        app.move_cursor(2);
        let (line_no, _) = app.cursor_line().expect("still on a line");
        assert_eq!(line_no, 3);
    }

    #[test]
    fn yank_without_files_sets_status() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.yank_current_line();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before copying")
        );
    }

    #[test]
    fn yank_empty_view_says_nothing_to_copy() {
        let mut app = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        app.set_search("this-will-not-match-zzzz");
        app.filter_on = true;
        app.rebuild_views();
        assert!(app.file().view.is_empty());
        app.yank_current_line();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("nothing to copy")
        );
    }

    #[test]
    fn go_to_line_jumps_clamps_and_rejects_bad_input() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        let last = app.file().lines.len();
        assert!(last >= 3);

        app.begin_input(InputKind::GoToLine);
        app.push_input_chars("3".chars());
        app.confirm_input();
        assert_eq!(app.file().view[app.file().view_pos], 2);
        assert!(app.status.as_deref().unwrap_or("").contains("jumped to L3"));

        app.begin_input(InputKind::GoToLine);
        app.push_input_chars(format!("{}", last + 50).chars());
        app.confirm_input();
        assert_eq!(app.file().view[app.file().view_pos], last - 1);
        assert!(app.status.as_deref().unwrap_or("").contains("past end"));

        app.begin_input(InputKind::GoToLine);
        app.push_input_chars("0".chars());
        app.confirm_input();
        assert!(app.status.as_deref().unwrap_or("").contains("start at 1"));

        app.begin_input(InputKind::GoToLine);
        app.push_input_chars("abc".chars());
        app.confirm_input();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("invalid line number")
        );
    }

    #[test]
    fn go_to_line_rejects_empty_file_without_false_success() {
        // Regression: lines.len().max(1) treated empty files as 1-line, so
        // confirming `:1` reported "jumped to L1" even though no content exists.
        let path = tmp_name("empty-goto");
        fs::write(&path, b"").unwrap();
        let mut app = app_with_paths(&[path.to_str().expect("utf8 temp path")]);
        assert!(app.file().lines.is_empty());
        assert!(app.file().view.is_empty());
        let view_pos_before = app.file().view_pos;

        app.begin_input(InputKind::GoToLine);
        app.push_input_chars("1".chars());
        app.confirm_input();

        assert!(
            app.status.as_deref().unwrap_or("").contains("no lines"),
            "empty file must not report a successful jump: {:?}",
            app.status
        );
        assert!(
            !app.status.as_deref().unwrap_or("").contains("jumped to"),
            "must not claim a jump landed: {:?}",
            app.status
        );
        assert_eq!(app.file().view_pos, view_pos_before);
        assert!(app.file().view.is_empty());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn go_to_line_disables_filter_when_target_hidden() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.begin_input(InputKind::Search);
        app.push_input_chars("ERROR".chars());
        app.confirm_input();
        app.toggle_filter();
        assert!(app.filter_on);
        assert!(app.file().view.len() < app.file().lines.len());

        // Line 1 is typically an INFO/header line not matching ERROR.
        app.begin_input(InputKind::GoToLine);
        app.push_input_chars("1".chars());
        app.confirm_input();
        assert!(!app.filter_on);
        assert_eq!(app.file().view[app.file().view_pos], 0);
    }

    #[test]
    fn toggle_bookmark_empty_view_sets_status() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.set_search("this-will-not-match-zzzz");
        app.filter_on = true;
        app.rebuild_views();
        assert!(app.file().view.is_empty());
        app.toggle_bookmark();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("nothing to bookmark")
        );
        assert!(app.file().bookmarks.is_empty());
    }

    #[test]
    fn toggle_bookmark_and_jump_wraps() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        assert!(app.file().lines.len() >= 4);
        app.file_mut().view_pos = 1;
        app.toggle_bookmark();
        app.file_mut().view_pos = 3;
        app.toggle_bookmark();
        assert_eq!(app.file().bookmarks, vec![1, 3]);

        // From line 3, next wraps to the first mark (line 1).
        app.next_bookmark();
        assert_eq!(app.file().view[app.file().view_pos], 1);
        app.next_bookmark();
        assert_eq!(app.file().view[app.file().view_pos], 3);

        // Prev wraps the other way.
        app.prev_bookmark();
        assert_eq!(app.file().view[app.file().view_pos], 1);
        app.prev_bookmark();
        assert_eq!(app.file().view[app.file().view_pos], 3);

        // Toggle clears.
        app.toggle_bookmark();
        assert_eq!(app.file().bookmarks, vec![1]);
    }

    #[test]
    fn clear_bookmarks_removes_all_marks() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.file_mut().view_pos = 0;
        app.toggle_bookmark();
        app.file_mut().view_pos = 2;
        app.toggle_bookmark();
        assert_eq!(app.file().bookmarks.len(), 2);
        app.clear_bookmarks();
        assert!(app.file().bookmarks.is_empty());
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("cleared 2 bookmarks")
        );
        app.clear_bookmarks();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("no bookmarks to clear")
        );
    }

    #[test]
    fn clear_search_and_filter_names_what_was_cleared() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.clear_search_and_filter();
        assert_eq!(app.status.as_deref(), Some("nothing to clear"));

        app.set_search("error");
        app.clear_search_and_filter();
        assert!(app.search.is_none());
        assert_eq!(app.status.as_deref(), Some("search cleared"));

        app.filter_on = true;
        app.rebuild_views();
        app.clear_search_and_filter();
        assert!(!app.filter_on);
        assert_eq!(app.status.as_deref(), Some("filter cleared"));

        app.set_search("error");
        app.filter_on = true;
        app.rebuild_views();
        app.clear_search_and_filter();
        assert!(app.search.is_none());
        assert!(!app.filter_on);
        assert_eq!(app.status.as_deref(), Some("search and filter cleared"));
    }

    #[test]
    fn next_bookmark_defeats_filter_when_hidden() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        app.file_mut().view_pos = 0;
        app.toggle_bookmark();
        let marked = app.file().bookmarks[0];
        // Filter to a pattern that excludes the bookmarked line.
        app.set_search("this-will-not-match-zzzz");
        app.filter_on = true;
        app.rebuild_views();
        assert!(!app.file().view.contains(&marked));
        app.next_bookmark();
        assert!(!app.filter_on);
        assert_eq!(app.file().view[app.file().view_pos], marked);
    }

    #[test]
    fn toggle_ignore_case_persists_preference() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_name("ic-pref");
        fs::create_dir_all(&dir).unwrap();
        // SAFETY: single-threaded under ENV_LOCK; restored before unlock.
        unsafe {
            std::env::set_var("LOGLENS_CONFIG_DIR", &dir);
        }
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        assert!(!app.ignore_case);
        app.toggle_ignore_case();
        assert!(app.ignore_case);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("case-insensitive: on")
        );
        let loaded = crate::config::load();
        assert!(loaded.ignore_case);
        assert!(loaded.show_legend); // default preserved across ignore_case save
        app.toggle_ignore_case();
        assert!(!app.ignore_case);
        assert!(!crate::config::load().ignore_case);
        unsafe {
            std::env::remove_var("LOGLENS_CONFIG_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn toggle_legend_persists_preference() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_name("legend-pref");
        fs::create_dir_all(&dir).unwrap();
        // SAFETY: single-threaded under ENV_LOCK; restored before unlock.
        unsafe {
            std::env::set_var("LOGLENS_CONFIG_DIR", &dir);
        }
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        assert!(app.show_legend);
        app.toggle_legend();
        assert!(!app.show_legend);
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("legend: hidden")
        );
        let loaded = crate::config::load();
        assert!(!loaded.show_legend);
        assert!(!loaded.ignore_case); // default preserved across legend save
        app.toggle_legend();
        assert!(app.show_legend);
        assert!(crate::config::load().show_legend);
        unsafe {
            std::env::remove_var("LOGLENS_CONFIG_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn browser_cwd_persists_and_restores() {
        let _guard = crate::config::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cfg_dir = tmp_name("browser-cwd-pref");
        let browse = tmp_name("browser-cwd-target");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::create_dir_all(&browse).unwrap();
        // SAFETY: single-threaded under ENV_LOCK; restored before unlock.
        unsafe {
            std::env::set_var("LOGLENS_CONFIG_DIR", &cfg_dir);
        }

        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.browser = Browser::new(browse.clone());
        app.remember_browser_cwd();

        let loaded = crate::config::load();
        assert_eq!(loaded.browser_cwd.as_deref(), Some(browse.as_path()));

        // Fresh app starts at process cwd; restore should jump back.
        let mut app2 = App::new(&[], Vec::new(), false).unwrap();
        assert_ne!(app2.browser.cwd, browse);
        app2.restore_browser_cwd(loaded.browser_cwd);
        assert_eq!(app2.browser.cwd, browse);

        // First open_browser after restore surfaces where we landed.
        app2.open_browser();
        assert!(
            app2.status
                .as_deref()
                .unwrap_or("")
                .contains("browser restored:")
        );
        assert!(app2.browser_cwd_hint.is_none());
        app2.status = None;
        app2.open_browser();
        assert!(app2.status.is_none());

        // Missing/invalid path is ignored.
        app2.restore_browser_cwd(Some(cfg_dir.join("does-not-exist")));
        assert_eq!(app2.browser.cwd, browse);
        assert!(app2.browser_cwd_hint.is_none());

        // Pref toggles must keep browser_cwd.
        app2.toggle_legend();
        let again = crate::config::load();
        assert_eq!(again.browser_cwd.as_deref(), Some(browse.as_path()));
        assert!(!again.show_legend);

        unsafe {
            std::env::remove_var("LOGLENS_CONFIG_DIR");
        }
        let _ = fs::remove_dir_all(&cfg_dir);
        let _ = fs::remove_dir_all(&browse);
    }

    #[test]
    fn scroll_horiz_pans_and_clamps_at_zero() {
        let mut app = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        assert_eq!(app.file().h_scroll, 0);
        app.scroll_horiz(-8);
        assert_eq!(app.file().h_scroll, 0);
        app.scroll_horiz(8);
        assert_eq!(app.file().h_scroll, 8);
        app.scroll_horiz(4);
        assert_eq!(app.file().h_scroll, 12);
        app.reset_h_scroll();
        assert_eq!(app.file().h_scroll, 0);
    }

    #[test]
    fn scroll_horiz_without_files_is_noop() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.scroll_horiz(8);
        app.reset_h_scroll();
        // No panic, no files to inspect.
        assert!(!app.has_files());
    }

    #[test]
    fn loaded_file_stores_path_for_yank() {
        let app = App::new(&["samples/sample.log".into()], Vec::new(), false).unwrap();
        let path = &app.file().path;
        assert!(
            path.ends_with("sample.log"),
            "expected path ending in sample.log, got {}",
            path.display()
        );
        assert!(
            path.is_absolute(),
            "stored path should be absolute when possible"
        );
    }

    #[test]
    fn yank_path_without_files_sets_status() {
        let mut app = App::new(&[], Vec::new(), false).unwrap();
        app.yank_current_path();
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("open a file before copying")
        );
    }

    #[test]
    fn toggle_filter_reports_when_cursor_line_is_hidden() {
        let mut app = app_with_paths(&["samples/sample.log"]);
        // set_search jumps to the first match — place the cursor on a non-match
        // afterwards so turning filter on actually hides that line.
        app.set_search("ERROR");
        let non_error = app
            .file()
            .lines
            .iter()
            .position(|l| !l.to_lowercase().contains("error"))
            .expect("sample.log should have a non-ERROR line");
        app.file_mut().view_pos = non_error;
        app.toggle_filter();
        assert!(app.filter_on);
        assert!(
            !app.file().view.contains(&non_error),
            "filtered view should exclude the prior cursor line"
        );
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains("hidden") && status.contains(&format!("L{}", non_error + 1)),
            "status should flash that the cursor line was hidden: {status:?}"
        );
        assert!(
            status.contains("now L"),
            "status should name the new cursor line: {status:?}"
        );

        // Cursor already on a matching line → plain "filter: on".
        app.toggle_filter(); // off
        assert_eq!(app.status.as_deref(), Some("filter: off"));
        let error_line = app
            .file()
            .lines
            .iter()
            .position(|l| l.contains("ERROR"))
            .expect("sample.log should have an ERROR line");
        app.file_mut().view_pos = error_line;
        app.toggle_filter(); // on again
        assert_eq!(app.status.as_deref(), Some("filter: on"));

        // Empty match set names the vacated line.
        app.toggle_filter(); // off
        app.set_search("this-will-not-match-zzzz");
        // set_search leaves the view unfiltered; park on absolute line 0.
        app.file_mut().view_pos = 0;
        app.toggle_filter();
        assert!(app.file().view.is_empty());
        assert_eq!(
            app.status.as_deref(),
            Some("filter: on · no matches (was on L1)")
        );
    }
}
