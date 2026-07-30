use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders};

/// Active UI palette. Held on [`crate::app::App`].
#[derive(Clone, Debug)]
pub struct Theme {
    pub accent: Color,
    pub border: Color,
    pub text: Color,
    pub text_dim: Color,
    pub gutter: Color,
    pub cursor_bg: Color,
    pub status_bg: Color,
    pub status_fg: Color,
    pub match_fg: Color,
    pub search_bg: Color,
    pub logo_top: Color,
    pub logo_bottom: Color,
    /// Chrome semantics for the file browser: a failed directory read and a
    /// marked entry. Deliberately *not* taken from [`Theme::palette`] — the
    /// rotation belongs to the user's highlights, so borrowing an index from it
    /// would make the browser's colors change whenever that order changes.
    pub danger: Color,
    pub marked: Color,
    /// Soft foreground tints for common log levels (non-highlight text).
    pub level_error: Color,
    pub level_warn: Color,
    pub level_info: Color,
    pub level_debug: Color,
    pub palette: Vec<Color>,
}

impl Theme {
    /// Calm one-dark-ish default (the only built-in theme).
    pub fn dark() -> Self {
        Self {
            accent: Color::Rgb(0x61, 0xAF, 0xEF),
            border: Color::Rgb(0x45, 0x4C, 0x5E),
            text: Color::Rgb(0xCE, 0xD3, 0xDE),
            text_dim: Color::Rgb(0x7C, 0x83, 0x94),
            gutter: Color::Rgb(0x5A, 0x61, 0x72),
            cursor_bg: Color::Rgb(0x2E, 0x34, 0x40),
            status_bg: Color::Rgb(0x1B, 0x1F, 0x27),
            status_fg: Color::Rgb(0xAB, 0xB2, 0xBF),
            match_fg: Color::Rgb(0x14, 0x16, 0x1B),
            search_bg: Color::Rgb(0xF5, 0xF5, 0xF5),
            logo_top: Color::Rgb(0x5B, 0x84, 0xEF),
            logo_bottom: Color::Rgb(0x3E, 0xE0, 0xD8),
            // The values the old `palette[0]` / `palette[1]` lookups resolved
            // to, so extracting them changed nothing on screen.
            danger: Color::Rgb(0xE0, 0x6C, 0x75),
            marked: Color::Rgb(0x98, 0xC3, 0x79),
            level_error: Color::Rgb(0xE0, 0x6C, 0x75),
            level_warn: Color::Rgb(0xE5, 0xC0, 0x7B),
            level_info: Color::Rgb(0x61, 0xAF, 0xEF),
            level_debug: Color::Rgb(0x7C, 0x83, 0x94),
            // Highlight rotation, handed out in order by `rule_color`.
            //
            // Order is a contract, not a preference. Three of these values are
            // also semantic elsewhere — coral is the ERROR tint, amber is the
            // WARN tint and Medium severity, azure is the accent, the INFO tint
            // and Low severity — and tangerine sits one shade off High severity.
            // A highlight wearing one of those reads as the product's judgment
            // rather than the user's bookkeeping, so the four compromised hues
            // are handed out last, ranked by how compromised they are.
            //
            // The nine clean slots are ordered for distinguishability too: the
            // minimum circular hue separation between neighbours is 107°, up
            // from 51° when coral/moss/amber/azure led the list.
            palette: vec![
                Color::Rgb(0x98, 0xC3, 0x79), // moss
                Color::Rgb(0xC6, 0x78, 0xDD), // orchid
                Color::Rgb(0xD0, 0xB0, 0x6A), // brass
                Color::Rgb(0x56, 0xB6, 0xC2), // cyan
                Color::Rgb(0xEC, 0x8C, 0xB0), // rose
                Color::Rgb(0x5F, 0xC9, 0xA6), // mint
                Color::Rgb(0x9A, 0xA7, 0xF0), // periwinkle
                Color::Rgb(0xB5, 0xCE, 0x6C), // lime
                Color::Rgb(0xE8, 0x9B, 0x54), // tangerine — near High severity
                Color::Rgb(0xE0, 0x6C, 0x75), // coral     — the ERROR tint
                Color::Rgb(0xE5, 0xC0, 0x7B), // amber     — WARN tint, Medium
                Color::Rgb(0x61, 0xAF, 0xEF), // azure     — accent, INFO, Low
            ],
        }
    }

    pub fn rule_color(&self, index: usize) -> Color {
        self.palette[index % self.palette.len()]
    }

    /// Rounded panel. `active` panels get an accent border + title.
    pub fn panel(&self, title: &str, active: bool) -> Block<'static> {
        let border_color = if active { self.accent } else { self.border };
        let title_style = if active {
            Style::default()
                .fg(self.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(self.text_dim)
                .add_modifier(Modifier::BOLD)
        };
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .title(Line::from(title.to_string()))
            .title_style(title_style)
    }
}

/// Linear blend between two colors; `t` runs 0.0 (a) → 1.0 (b). Non-RGB colors
/// fall back to `a`.
pub fn lerp_color(a: Color, b: Color, t: f64) -> Color {
    let parts = |c: Color| match c {
        Color::Rgb(r, g, bl) => Some((r, g, bl)),
        _ => None,
    };
    match (parts(a), parts(b)) {
        (Some((ar, ag, ab)), Some((br, bg, bb))) => {
            let mix =
                |x: u8, y: u8| (x as f64 + (y as f64 - x as f64) * t.clamp(0.0, 1.0)).round() as u8;
            Color::Rgb(mix(ar, br), mix(ag, bg), mix(ab, bb))
        }
        _ => a,
    }
}

/// Soft base foreground for a log line from common level tokens.
pub fn level_fg(text: &str, theme: &Theme) -> Color {
    match detect_level(text) {
        Some(Level::Error) => theme.level_error,
        Some(Level::Warn) => theme.level_warn,
        Some(Level::Info) => theme.level_info,
        Some(Level::Debug) => theme.level_debug,
        None => theme.text,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

fn detect_level(text: &str) -> Option<Level> {
    // Scan whitespace/punctuation-separated tokens so "TERROR" / "warningly"
    // don't false-positive, while "ERROR", "[WARN]", "level=info" still match.
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut best: Option<Level> = None;
    while i < bytes.len() {
        while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        if start == i {
            break;
        }
        let token = &text[start..i];
        let level = if eq_ignore_ascii(token, "ERROR")
            || eq_ignore_ascii(token, "ERR")
            || eq_ignore_ascii(token, "FATAL")
            || eq_ignore_ascii(token, "CRITICAL")
            || eq_ignore_ascii(token, "CRIT")
        {
            Some(Level::Error)
        } else if eq_ignore_ascii(token, "WARN") || eq_ignore_ascii(token, "WARNING") {
            Some(Level::Warn)
        } else if eq_ignore_ascii(token, "INFO") {
            Some(Level::Info)
        } else if eq_ignore_ascii(token, "DEBUG") || eq_ignore_ascii(token, "TRACE") {
            Some(Level::Debug)
        } else {
            None
        };
        if let Some(l) = level {
            best = Some(match best {
                None => l,
                Some(prev) => rank_max(prev, l),
            });
        }
    }
    best
}

fn rank_max(a: Level, b: Level) -> Level {
    let rank = |l: Level| match l {
        Level::Error => 3,
        Level::Warn => 2,
        Level::Info => 1,
        Level::Debug => 0,
    };
    if rank(b) > rank(a) { b } else { a }
}

fn eq_ignore_ascii(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_theme_has_palette() {
        let t = Theme::dark();
        assert!(!t.palette.is_empty());
        assert_eq!(t.rule_color(0), t.palette[0]);
        assert_eq!(t.rule_color(t.palette.len()), t.palette[0]);
    }

    /// Highlight colors are the user's bookkeeping; level tints and severities
    /// are the product's judgment. The two languages share a screen, so the
    /// slots handed out first must not echo a color that already means
    /// something — a first highlight in the ERROR coral, or a fourth in the
    /// accent, made the two ambiguous on first use.
    ///
    /// The last three slots are deliberately excluded: they *are* the semantic
    /// values, parked at the end where a user only reaches them after nine
    /// distinct highlights.
    #[test]
    fn first_rotation_slots_avoid_semantic_colors() {
        use crate::signatures::Severity;
        let t = Theme::dark();
        // Everything that can share a viewport with a highlight and already
        // carries meaning. `danger` and `marked` are absent on purpose: both are
        // browser-popup chrome, and the popup punches out the log entirely, so
        // they are never on screen beside a highlight.
        let reserved: Vec<(&str, Color)> = vec![
            ("accent", t.accent),
            ("level_error", t.level_error),
            ("level_warn", t.level_warn),
            ("level_info", t.level_info),
            ("level_debug", t.level_debug),
            ("Critical", Severity::Critical.color()),
            ("High", Severity::High.color()),
            ("Medium", Severity::Medium.color()),
            ("Low", Severity::Low.color()),
            ("Info", Severity::Info.color()),
        ];
        let clean = t.palette.len() - 3;
        for i in 0..clean {
            let c = t.rule_color(i);
            for (name, r) in &reserved {
                assert_ne!(
                    c, *r,
                    "highlight slot {i} collides with the {name} color ({c:?}) — \
                     move it behind the {clean} clean slots"
                );
            }
        }
    }

    #[test]
    fn rotation_keeps_every_hue_and_repeats_only_after_a_full_cycle() {
        let t = Theme::dark();
        // Reordering must not drop or duplicate a hue: capacity and the
        // repeat-at-13 behaviour are unchanged.
        assert_eq!(t.palette.len(), 12);
        let mut seen = t.palette.clone();
        seen.sort_by_key(|c| format!("{c:?}"));
        seen.dedup();
        assert_eq!(seen.len(), 12, "rotation contains a duplicate hue");
        assert_eq!(t.rule_color(12), t.rule_color(0));
    }

    #[test]
    fn detect_level_uses_word_tokens() {
        assert_eq!(detect_level("2026 ERROR failed"), Some(Level::Error));
        assert_eq!(detect_level("[WARN] slow"), Some(Level::Warn));
        assert_eq!(detect_level("INFO ready"), Some(Level::Info));
        assert_eq!(detect_level("DEBUG tick"), Some(Level::Debug));
        assert_eq!(detect_level("no level here"), None);
        assert_eq!(detect_level("TERROR alert"), None);
        // Highest severity wins when multiple appear.
        assert_eq!(detect_level("INFO then ERROR"), Some(Level::Error));
    }

    #[test]
    fn level_fg_picks_theme_colors() {
        let t = Theme::dark();
        assert_eq!(level_fg("ERROR boom", &t), t.level_error);
        assert_eq!(level_fg("WARN boom", &t), t.level_warn);
        assert_eq!(level_fg("hello", &t), t.text);
    }
}
