use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders};

/// Built-in look. Cycle with `t` in the viewer or pass `--theme`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ThemeId {
    #[default]
    Dark,
    Light,
    HighContrast,
}

impl ThemeId {
    pub fn label(self) -> &'static str {
        match self {
            ThemeId::Dark => "dark",
            ThemeId::Light => "light",
            ThemeId::HighContrast => "hc",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ThemeId::Dark => ThemeId::Light,
            ThemeId::Light => ThemeId::HighContrast,
            ThemeId::HighContrast => ThemeId::Dark,
        }
    }

    /// Parse a theme name from CLI / config text (`dark`, `light`, `hc`, …).
    #[allow(dead_code)] // exercised in unit tests; binary uses clap ValueEnum
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "dark" | "default" => Some(ThemeId::Dark),
            "light" => Some(ThemeId::Light),
            "hc" | "high-contrast" | "highcontrast" | "contrast" => Some(ThemeId::HighContrast),
            _ => None,
        }
    }
}

/// Active UI palette. Held on [`crate::app::App`] so themes can switch live.
#[derive(Clone, Debug)]
pub struct Theme {
    pub id: ThemeId,
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
    /// Soft foreground tints for common log levels (non-highlight text).
    pub level_error: Color,
    pub level_warn: Color,
    pub level_info: Color,
    pub level_debug: Color,
    pub palette: Vec<Color>,
}

impl Theme {
    pub fn from_id(id: ThemeId) -> Self {
        match id {
            ThemeId::Dark => Self::dark(),
            ThemeId::Light => Self::light(),
            ThemeId::HighContrast => Self::high_contrast(),
        }
    }

    /// Calm one-dark-ish default.
    pub fn dark() -> Self {
        Self {
            id: ThemeId::Dark,
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
            level_error: Color::Rgb(0xE0, 0x6C, 0x75),
            level_warn: Color::Rgb(0xE5, 0xC0, 0x7B),
            level_info: Color::Rgb(0x61, 0xAF, 0xEF),
            level_debug: Color::Rgb(0x7C, 0x83, 0x94),
            palette: vec![
                Color::Rgb(0xE0, 0x6C, 0x75),
                Color::Rgb(0x98, 0xC3, 0x79),
                Color::Rgb(0xE5, 0xC0, 0x7B),
                Color::Rgb(0x61, 0xAF, 0xEF),
                Color::Rgb(0xC6, 0x78, 0xDD),
                Color::Rgb(0x56, 0xB6, 0xC2),
                Color::Rgb(0xE8, 0x9B, 0x54),
                Color::Rgb(0xEC, 0x8C, 0xB0),
                Color::Rgb(0xB5, 0xCE, 0x6C),
                Color::Rgb(0x5F, 0xC9, 0xA6),
                Color::Rgb(0x9A, 0xA7, 0xF0),
                Color::Rgb(0xD0, 0xB0, 0x6A),
            ],
        }
    }

    /// Light paper theme for bright terminals.
    pub fn light() -> Self {
        Self {
            id: ThemeId::Light,
            accent: Color::Rgb(0x03, 0x66, 0xA8),
            border: Color::Rgb(0xC5, 0xCB, 0xD3),
            text: Color::Rgb(0x24, 0x29, 0x2E),
            text_dim: Color::Rgb(0x6B, 0x73, 0x80),
            gutter: Color::Rgb(0x8B, 0x93, 0xA0),
            cursor_bg: Color::Rgb(0xE8, 0xEE, 0xF5),
            status_bg: Color::Rgb(0xE4, 0xE9, 0xF0),
            status_fg: Color::Rgb(0x3A, 0x42, 0x4E),
            match_fg: Color::Rgb(0x14, 0x16, 0x1B),
            search_bg: Color::Rgb(0xFF, 0xD6, 0x6B),
            logo_top: Color::Rgb(0x03, 0x66, 0xA8),
            logo_bottom: Color::Rgb(0x0B, 0x9B, 0x8A),
            level_error: Color::Rgb(0xC0, 0x2D, 0x39),
            level_warn: Color::Rgb(0xA0, 0x6A, 0x00),
            level_info: Color::Rgb(0x03, 0x66, 0xA8),
            level_debug: Color::Rgb(0x6B, 0x73, 0x80),
            palette: vec![
                Color::Rgb(0xC0, 0x2D, 0x39),
                Color::Rgb(0x2E, 0x7D, 0x32),
                Color::Rgb(0xB5, 0x86, 0x00),
                Color::Rgb(0x03, 0x66, 0xA8),
                Color::Rgb(0x7B, 0x1F, 0xA2),
                Color::Rgb(0x00, 0x89, 0x8A),
                Color::Rgb(0xC4, 0x5C, 0x14),
                Color::Rgb(0xC2, 0x18, 0x5B),
                Color::Rgb(0x55, 0x8B, 0x2F),
                Color::Rgb(0x00, 0x79, 0x6B),
                Color::Rgb(0x39, 0x49, 0xAB),
                Color::Rgb(0x8D, 0x6E, 0x00),
            ],
        }
    }

    /// Maximum separation for low-vision / hard-to-read terminals.
    pub fn high_contrast() -> Self {
        Self {
            id: ThemeId::HighContrast,
            accent: Color::Rgb(0xFF, 0xCC, 0x00),
            border: Color::Rgb(0xAA, 0xAA, 0xAA),
            text: Color::Rgb(0xFF, 0xFF, 0xFF),
            text_dim: Color::Rgb(0xCC, 0xCC, 0xCC),
            gutter: Color::Rgb(0xBB, 0xBB, 0xBB),
            cursor_bg: Color::Rgb(0x33, 0x33, 0x33),
            status_bg: Color::Rgb(0x00, 0x00, 0x00),
            status_fg: Color::Rgb(0xFF, 0xFF, 0xFF),
            match_fg: Color::Rgb(0x00, 0x00, 0x00),
            search_bg: Color::Rgb(0xFF, 0xFF, 0x00),
            logo_top: Color::Rgb(0xFF, 0xCC, 0x00),
            logo_bottom: Color::Rgb(0x00, 0xFF, 0xCC),
            level_error: Color::Rgb(0xFF, 0x55, 0x55),
            level_warn: Color::Rgb(0xFF, 0xCC, 0x00),
            level_info: Color::Rgb(0x66, 0xCC, 0xFF),
            level_debug: Color::Rgb(0xAA, 0xAA, 0xAA),
            palette: vec![
                Color::Rgb(0xFF, 0x55, 0x55),
                Color::Rgb(0x55, 0xFF, 0x55),
                Color::Rgb(0xFF, 0xCC, 0x00),
                Color::Rgb(0x66, 0xCC, 0xFF),
                Color::Rgb(0xFF, 0x66, 0xFF),
                Color::Rgb(0x00, 0xFF, 0xCC),
                Color::Rgb(0xFF, 0x99, 0x33),
                Color::Rgb(0xFF, 0x88, 0xCC),
                Color::Rgb(0xAA, 0xFF, 0x33),
                Color::Rgb(0x33, 0xFF, 0xAA),
                Color::Rgb(0x99, 0x99, 0xFF),
                Color::Rgb(0xFF, 0xDD, 0x66),
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
    fn theme_id_parses_and_cycles() {
        assert_eq!(ThemeId::parse("dark"), Some(ThemeId::Dark));
        assert_eq!(ThemeId::parse("LIGHT"), Some(ThemeId::Light));
        assert_eq!(ThemeId::parse("hc"), Some(ThemeId::HighContrast));
        assert_eq!(ThemeId::parse("nope"), None);
        assert_eq!(ThemeId::Dark.next(), ThemeId::Light);
        assert_eq!(ThemeId::HighContrast.next(), ThemeId::Dark);
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
