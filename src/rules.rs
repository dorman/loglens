use anyhow::{bail, Context, Result};
use ratatui::style::Color;
use regex::{Regex, RegexBuilder};

use crate::cli::Cli;
use crate::theme;

/// Max highlight rules a session may hold (CLI + live adds).
pub const MAX_RULES: usize = 64;
/// Reject user regex source longer than this (keywords are escaped, so length
/// is less dangerous there, but the prompt is already capped separately).
pub const MAX_REGEX_PATTERN_LEN: usize = 512;
/// Approximate compiled-program size budget for each regex.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB
/// Cap nesting depth so pathological patterns fail at compile time.
const REGEX_NEST_LIMIT: u32 = 32;

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

/// Compile a regex with explicit size/nest budgets so hostile patterns fail
/// fast at compile time instead of burning CPU later.
pub fn compile_regex(pattern: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .context("failed to compile regex (size/nest limit?)")
}

/// Compile a single keyword or regex into a colored [`Rule`].
pub fn compile_rule(
    label: &str,
    is_regex: bool,
    ignore_case: bool,
    color_index: usize,
) -> Result<Rule> {
    if is_regex && label.len() > MAX_REGEX_PATTERN_LEN {
        bail!("regex too long (max {MAX_REGEX_PATTERN_LEN} bytes)");
    }
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
    let regex = compile_regex(&pattern).with_context(|| {
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
        if rules.len() >= MAX_RULES {
            bail!("too many highlight rules (max {MAX_RULES})");
        }
        rules.push(compile_rule(kw, false, cli.ignore_case, rules.len())?);
    }

    for pat in &cli.regexes {
        if rules.len() >= MAX_RULES {
            bail!("too many highlight rules (max {MAX_RULES})");
        }
        rules.push(compile_rule(pat, true, cli.ignore_case, rules.len())?);
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overlong_regex() {
        let pat = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        assert!(compile_rule(&pat, true, false, 0).is_err());
    }

    #[test]
    fn rejects_deeply_nested_regex() {
        // Nesting beyond REGEX_NEST_LIMIT should fail at compile time.
        let pat = format!("{}x{}", "(".repeat(40), ")".repeat(40));
        assert!(compile_rule(&pat, true, false, 0).is_err());
    }

    #[test]
    fn compiles_simple_keyword() {
        let rule = compile_rule("ERROR", false, true, 0).unwrap();
        assert!(rule.regex.is_match("an ERROR occurred"));
        assert!(!rule.is_regex);
    }
}
