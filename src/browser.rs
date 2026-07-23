use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
}

/// A minimal filesystem browser used to import log files from inside the TUI.
pub struct Browser {
    pub cwd: PathBuf,
    pub entries: Vec<Entry>,
    pub selected: usize,
    pub top: usize,
    /// Files the user has marked (Space) to open together.
    pub marked: HashSet<PathBuf>,
    pub show_hidden: bool,
    pub error: Option<String>,
}

impl Browser {
    pub fn new(start: PathBuf) -> Self {
        let mut b = Browser {
            cwd: start,
            entries: Vec::new(),
            selected: 0,
            top: 0,
            marked: HashSet::new(),
            show_hidden: false,
            error: None,
        };
        b.refresh();
        b
    }

    pub fn refresh(&mut self) {
        let mut entries = Vec::new();
        if let Some(parent) = self.cwd.parent() {
            entries.push(Entry {
                name: "..".to_string(),
                path: parent.to_path_buf(),
                is_dir: true,
            });
        }

        match fs::read_dir(&self.cwd) {
            Ok(rd) => {
                let mut items: Vec<Entry> = rd
                    .filter_map(|e| e.ok())
                    .map(|e| {
                        let path = e.path();
                        let is_dir = path.is_dir();
                        let name = e.file_name().to_string_lossy().to_string();
                        Entry { name, path, is_dir }
                    })
                    .filter(|e| self.show_hidden || !e.name.starts_with('.'))
                    .collect();
                // Directories first, then case-insensitive alphabetical.
                items.sort_by(|a, b| {
                    b.is_dir
                        .cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                entries.extend(items);
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("cannot read {}: {e}", self.cwd.display()));
            }
        }

        self.entries = entries;
        if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
        self.top = 0;
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.entries.get(self.selected)
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let len = self.entries.len() as isize;
        self.selected = (self.selected as isize + delta).clamp(0, len - 1) as usize;
    }

    /// Enter the selected directory. Returns true if a directory was entered.
    pub fn enter_dir(&mut self) -> bool {
        if let Some(entry) = self.selected_entry()
            && entry.is_dir {
                self.cwd = entry.path.clone();
                self.selected = 0;
                self.refresh();
                return true;
            }
        false
    }

    pub fn go_parent(&mut self) {
        if let Some(parent) = self.cwd.parent() {
            self.cwd = parent.to_path_buf();
            self.selected = 0;
            self.refresh();
        }
    }

    /// Toggle the mark on the selected file. Directories cannot be marked.
    pub fn toggle_mark(&mut self) {
        let target = match self.selected_entry() {
            Some(entry) if !entry.is_dir => entry.path.clone(),
            _ => return,
        };
        if !self.marked.remove(&target) {
            self.marked.insert(target);
        }
    }

    pub fn toggle_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        self.refresh();
    }

    /// The directory to open recursively: the highlighted entry if it is a
    /// directory, otherwise the current directory.
    pub fn selected_dir(&self) -> PathBuf {
        match self.selected_entry() {
            Some(e) if e.is_dir => e.path.clone(),
            _ => self.cwd.clone(),
        }
    }

    /// The set of files to open: all marked files, or the selected file if none
    /// are marked. Directories are never returned.
    pub fn files_to_open(&self) -> Vec<PathBuf> {
        if !self.marked.is_empty() {
            let mut v: Vec<PathBuf> = self.marked.iter().cloned().collect();
            v.sort();
            return v;
        }
        match self.selected_entry() {
            Some(e) if !e.is_dir => vec![e.path.clone()],
            _ => Vec::new(),
        }
    }
}
