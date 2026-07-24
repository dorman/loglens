use anyhow::{Context, Result, bail};
use ratatui::style::Color;
use regex::{Regex, RegexBuilder};

use crate::cli::Cli;
use crate::theme::Theme;

/// Max highlight rules a session may hold (CLI + live adds).
pub const MAX_RULES: usize = 64;
/// Reject user regex source longer than this (keywords are escaped, so length
/// is less dangerous there, but the prompt is already capped separately).
pub const MAX_REGEX_PATTERN_LEN: usize = 512;
/// Approximate compiled-program size budget for each regex.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB
/// Cap nesting depth so pathological patterns fail at compile time.
const REGEX_NEST_LIMIT: u32 = 32;

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
    theme: &Theme,
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
        color: theme.rule_color(color_index),
        regex,
        is_regex,
    })
}

pub fn build_rules(cli: &Cli, theme: &Theme) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for kw in &cli.keywords {
        let kw = kw.trim();
        if kw.is_empty() {
            continue;
        }
        if rules.len() >= MAX_RULES {
            bail!("too many highlight rules (max {MAX_RULES})");
        }
        rules.push(compile_rule(
            kw,
            false,
            cli.ignore_case,
            rules.len(),
            theme,
        )?);
    }

    for pat in &cli.regexes {
        if rules.len() >= MAX_RULES {
            bail!("too many highlight rules (max {MAX_RULES})");
        }
        rules.push(compile_rule(
            pat,
            true,
            cli.ignore_case,
            rules.len(),
            theme,
        )?);
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn dark() -> Theme {
        Theme::dark()
    }

    #[test]
    fn rejects_overlong_regex() {
        let pat = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        assert!(compile_rule(&pat, true, false, 0, &dark()).is_err());
    }

    #[test]
    fn rejects_deeply_nested_regex() {
        let pat = format!("{}x{}", "(".repeat(40), ")".repeat(40));
        assert!(compile_rule(&pat, true, false, 0, &dark()).is_err());
    }

    #[test]
    fn compiles_simple_keyword() {
        let rule = compile_rule("ERROR", false, true, 0, &dark()).unwrap();
        assert!(rule.regex.is_match("an ERROR occurred"));
        assert!(!rule.is_regex);
    }

    #[test]
    fn keyword_is_literal_not_regex_metachar() {
        let rule = compile_rule("file.txt", false, false, 0, &dark()).unwrap();
        assert!(rule.regex.is_match("see file.txt here"));
        assert!(
            !rule.regex.is_match("see fileXtxt here"),
            "keyword metacharacters must be escaped"
        );
    }

    #[test]
    fn ignore_case_applies_to_keyword_and_regex() {
        let kw = compile_rule("error", false, true, 0, &dark()).unwrap();
        assert!(kw.regex.is_match("ERROR"));
        let re = compile_rule(r"time\s*out", true, true, 1, &dark()).unwrap();
        assert!(re.regex.is_match("TIME OUT"));
    }

    #[test]
    fn cli_keywords_comma_split_and_trim_empties() {
        let cli = Cli::try_parse_from([
            "loglens",
            "-k",
            "ERROR",
            "-k",
            "timeout,rollback",
            "-k",
            " , ",
            "-i",
        ])
        .unwrap();
        let rules = build_rules(&cli, &dark()).unwrap();
        let labels: Vec<_> = rules.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["ERROR", "timeout", "rollback"]);
        assert!(cli.ignore_case);
    }

    #[test]
    fn cli_invalid_regex_fails_build_rules() {
        let cli = Cli::try_parse_from(["loglens", "-r", "("]).unwrap();
        match build_rules(&cli, &dark()) {
            Ok(_) => panic!("invalid regex should fail"),
            Err(e) => {
                let err = e.to_string();
                assert!(err.contains("invalid regex") || err.contains("failed to compile"));
            }
        }
    }

    #[test]
    fn build_rules_respects_max_rules() {
        let mut args = vec!["loglens".to_string()];
        for i in 0..(MAX_RULES + 1) {
            args.push("-k".into());
            args.push(format!("kw{i}"));
        }
        let cli = Cli::try_parse_from(&args).unwrap();
        assert!(build_rules(&cli, &dark()).is_err());
    }
}
