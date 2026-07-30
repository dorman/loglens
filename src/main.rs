mod app;
mod browser;
mod cli;
mod clipboard;
mod config;
mod event;
mod ingest;
mod rules;
mod signatures;
mod theme;
mod ui;

use std::io::{self, IsTerminal};

use anyhow::{Result, bail};
use clap::Parser;
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
use crossterm::execute;

use app::App;
use cli::Cli;

/// Turn off the extra terminal modes this app enables on top of ratatui's
/// raw-mode/alt-screen (which ratatui's own panic hook restores).
fn disable_extra_modes() {
    let _ = execute!(io::stdout(), DisableMouseCapture, DisableBracketedPaste);
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let theme = theme::Theme::dark();
    // `-i` always enables for this session; otherwise honour the saved pref
    // written when the user presses `i` in the TUI. `l` persists show_legend;
    // browsing with `o` persists the last browser directory.
    let prefs = config::load();
    let ignore_case = cli.ignore_case || prefs.ignore_case;
    let rules = rules::build_rules(&cli, &theme, ignore_case)?;
    let mut app = App::new(&cli.files, rules, ignore_case)?;
    app.show_legend = prefs.show_legend;
    app.restore_browser_cwd(prefs.browser_cwd);
    // Scanning is the point of the tool, so it starts on its own: this scans the
    // files just opened from the command line and arms every later open too.
    if !cli.no_scan {
        app.enable_auto_scan();
    }

    // ratatui::init() panics when stdout is not a TTY; fail with a clear message
    // instead so CI / pipes / non-interactive shells get a usable exit status.
    if !io::stdout().is_terminal() {
        bail!(
            "loglens needs an interactive terminal (TTY).\n\
             Open a real terminal, or try: loglens --help / loglens --version"
        );
    }

    let mut terminal = ratatui::init();
    let _ = execute!(io::stdout(), EnableMouseCapture, EnableBracketedPaste);

    // ratatui::init installed a panic hook that restores the base terminal
    // state; chain ours in front so a panic also disables mouse capture and
    // bracketed paste instead of leaving the shell spewing escape codes.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        disable_extra_modes();
        prev_hook(info);
    }));

    let result = event::run(&mut terminal, &mut app);

    disable_extra_modes();
    ratatui::restore();

    result
}
