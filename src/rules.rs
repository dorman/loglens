use anyhow::{Context, Result};
use ratatui::style::Color;
use regex::Regex;

use crate::cli::Cli;
use crate::theme;

pub fn color_for(index: usize) -> Color {
    theme::rule_color(index)
}

#[derive(Clone)]
pub struct Rule {
    /// The raw text the user entered (keyword or regex source). Kept so the
    /// rule can be recompiled when case-sensitivity is toggled at runtime.
    pub label: String,
    pub color: Color,
    pub regex: Regex,
    /// True if this rule came from a regex pattern rather than a plain keyword,
    /// shown in the legend so users can tell them apart.
    pub is_regex: bool,
}

/// Compile a single keyword or regex into a colored [`Rule`].
pub fn compile_rule(
    label: &str,
    is_regex: bool,
    ignore_case: bool,
    color_index: usize,
) -> Result<Rule> {
    let base = if is_regex {
        label.to_string()
    } else {
        regex::escape(label)
    };
    let pattern = if ignore_case {
        format!("(?i){base}")
    } else {
        base
    };
    let regex = Regex::new(&pattern).with_context(|| {
        if is_regex {
            format!("invalid regex '{label}'")
        } else {
            format!("failed to compile keyword '{label}'")
        }
    })?;
    Ok(Rule {
        label: label.to_string(),
        color: color_for(color_index),
        regex,
        is_regex,
    })
}

pub fn build_rules(cli: &Cli) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for kw in &cli.keywords {
        let kw = kw.trim();
        if kw.is_empty() {
            continue;
        }
        rules.push(compile_rule(kw, false, cli.ignore_case, rules.len())?);
    }

    for pat in &cli.regexes {
        rules.push(compile_rule(pat, true, cli.ignore_case, rules.len())?);
    }

    Ok(rules)
}
