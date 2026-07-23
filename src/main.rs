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
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;

use app::App;
use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rules = rules::build_rules(&cli)?;
    let mut app = App::new(&cli.files, rules, cli.ignore_case)?;

    let mut terminal = ratatui::init();
    let _ = execute!(io::stdout(), EnableMouseCapture);
    let result = event::run(&mut terminal, &mut app);
    let _ = execute!(io::stdout(), DisableMouseCapture);
    ratatui::restore();

    result
}
