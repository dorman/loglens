//! Tiny on-disk preferences for loglens.
//!
//! Stored as a simple `key=value` file under the platform config directory
//! (`$XDG_CONFIG_HOME/loglens` / `~/.config/loglens`, or `%APPDATA%\loglens`
//! on Windows). Override with `LOGLENS_CONFIG_DIR` for tests / special setups.
//!
//! No TOML/JSON crate — keep the surface small until more settings appear.

use std::env;
use std::fs;
use std::path::PathBuf;

/// User preferences that survive across sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// When true, keyword/regex highlights match case-insensitively.
    pub ignore_case: bool,
    /// When true, the highlight legend panel is visible.
    pub show_legend: bool,
    /// Last directory opened in the in-TUI file browser (`o`).
    /// Restored on the next launch when the path still exists.
    pub browser_cwd: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ignore_case: false,
            // Match the App bootstrap default so a missing key keeps the legend.
            show_legend: true,
            browser_cwd: None,
        }
    }
}

/// Resolve the directory that holds `config`. Honours `LOGLENS_CONFIG_DIR`
/// first so unit tests can use a temp folder without touching the real home.
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = env::var("LOGLENS_CONFIG_DIR")
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir));
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Some(PathBuf::from(xdg).join("loglens"));
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = env::var("APPDATA")
            && !appdata.is_empty()
        {
            return Some(PathBuf::from(appdata).join("loglens"));
        }
    }
    env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("loglens"))
}

fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config"))
}

/// Load preferences. Missing file / unreadable path → [`Config::default`].
pub fn load() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Config::default();
    };
    parse(&text)
}

/// Persist preferences. Best-effort: failures are silent at the call site
/// (status text reports success/failure when the user toggles).
pub fn save(cfg: &Config) -> std::io::Result<()> {
    let dir = config_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no config directory (set HOME or LOGLENS_CONFIG_DIR)",
        )
    })?;
    fs::create_dir_all(&dir)?;
    let path = dir.join("config");
    let mut body = format!(
        "# loglens preferences — updated when you press `i` / `l` / browse with `o`\n\
         ignore_case={}\n\
         show_legend={}\n",
        if cfg.ignore_case { "true" } else { "false" },
        if cfg.show_legend { "true" } else { "false" }
    );
    if let Some(cwd) = &cfg.browser_cwd {
        // Path may contain '=' — only the first '=' is the separator on load.
        body.push_str(&format!("browser_cwd={}\n", cwd.display()));
    }
    fs::write(path, body)
}

fn parse(text: &str) -> Config {
    let mut cfg = Config::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "ignore_case" => cfg.ignore_case = parse_bool(value),
            "show_legend" => cfg.show_legend = parse_bool(value),
            "browser_cwd" => {
                cfg.browser_cwd = if value.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(value))
                };
            }
            _ => {}
        }
    }
    cfg
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize env mutations across config tests in this process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_ignore_case_variants() {
        assert!(parse("ignore_case=true\n").ignore_case);
        assert!(parse("ignore_case=YES\n").ignore_case);
        assert!(parse("ignore_case=1\n").ignore_case);
        assert!(parse("# comment\nignore_case = on\n").ignore_case);
        assert!(!parse("ignore_case=false\n").ignore_case);
        assert!(!parse("ignore_case=no\n").ignore_case);
        assert!(!parse("").ignore_case);
        assert!(!parse("# only comments\n").ignore_case);
    }

    #[test]
    fn parse_show_legend_defaults_true_when_absent() {
        assert!(parse("").show_legend);
        assert!(parse("ignore_case=true\n").show_legend);
        assert!(!parse("show_legend=false\n").show_legend);
        assert!(!parse("show_legend=0\n").show_legend);
        assert!(parse("show_legend=yes\n").show_legend);
    }

    #[test]
    fn parse_browser_cwd() {
        assert_eq!(parse("").browser_cwd, None);
        assert_eq!(
            parse("browser_cwd=/var/log\n").browser_cwd,
            Some(PathBuf::from("/var/log"))
        );
        // Value may contain '=' (split_once keeps the remainder).
        assert_eq!(
            parse("browser_cwd=/tmp/a=b\n").browser_cwd,
            Some(PathBuf::from("/tmp/a=b"))
        );
        assert_eq!(parse("browser_cwd=\n").browser_cwd, None);
    }

    #[test]
    fn load_save_roundtrip_via_env_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "loglens-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // SAFETY: single-threaded under ENV_LOCK; restored before unlock.
        unsafe {
            env::set_var("LOGLENS_CONFIG_DIR", &dir);
        }

        assert_eq!(load(), Config::default());

        let on = Config {
            ignore_case: true,
            show_legend: false,
            browser_cwd: Some(PathBuf::from("/var/log")),
        };
        save(&on).unwrap();
        assert_eq!(load(), on);

        let off = Config {
            ignore_case: false,
            show_legend: true,
            browser_cwd: None,
        };
        save(&off).unwrap();
        assert_eq!(load(), off);

        let text = fs::read_to_string(dir.join("config")).unwrap();
        assert!(text.contains("ignore_case=false"));
        assert!(text.contains("show_legend=true"));
        assert!(!text.contains("browser_cwd="));
        assert!(text.contains('#'));

        unsafe {
            env::remove_var("LOGLENS_CONFIG_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
