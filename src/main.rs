mod app;
mod browser;
mod cli;
mod event;
mod ingest;
mod rules;
mod signatures;
mod theme;
mod ui;

use std::io;

use anyhow::Result;
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
    let rules = rules::build_rules(&cli)?;
    let mut app = App::new(&cli.files, rules, cli.ignore_case)?;

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
