use clap::Parser;

/// loglens - highlight the things that matter in your logs.
///
/// Run with no arguments to open the built-in file browser, or pass log files
/// directly. Keywords and regexes can also be added live from inside the TUI.
#[derive(Parser, Debug)]
#[command(name = "loglens", version, about, long_about = None)]
pub struct Cli {
    /// Log file(s) to open. Omit to start in the file browser.
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
}
