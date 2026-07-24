use clap::{Parser, ValueEnum};

use crate::theme::ThemeId;

/// loglens - highlight the things that matter in your logs.
///
/// Run with no arguments for the welcome screen (press `o` to browse for
/// logs), or pass files, folders, or .zip bundles directly. Keywords and
/// regexes can also be added live from inside the TUI.
#[derive(Parser, Debug)]
#[command(name = "loglens", version, about, long_about = None)]
pub struct Cli {
    /// Files, folders, or .zip archives to open (folders/zips recurse).
    pub files: Vec<String>,

    /// Literal keyword to highlight. Repeatable, or comma-separated within one flag.
    /// e.g. -k ERROR -k "timeout,rollback"
    #[arg(short = 'k', long = "keyword", value_delimiter = ',')]
    pub keywords: Vec<String>,

    /// Regex pattern to highlight. Repeatable.
    #[arg(short = 'r', long = "regex")]
    pub regexes: Vec<String>,

    /// Match case-insensitively (applies to both keywords and regexes).
    #[arg(short = 'i', long = "ignore-case")]
    pub ignore_case: bool,

    /// Color theme (also cycleable with `t` in the viewer).
    #[arg(short = 't', long = "theme", value_enum, default_value_t = ThemeCli::Dark)]
    pub theme: ThemeCli,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum ThemeCli {
    #[default]
    Dark,
    Light,
    #[value(name = "hc", alias = "high-contrast")]
    HighContrast,
}

impl From<ThemeCli> for ThemeId {
    fn from(value: ThemeCli) -> Self {
        match value {
            ThemeCli::Dark => ThemeId::Dark,
            ThemeCli::Light => ThemeId::Light,
            ThemeCli::HighContrast => ThemeId::HighContrast,
        }
    }
}
