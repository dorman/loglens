use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders};

// Core UI palette (a calm dark "one-dark"-ish scheme).
pub const ACCENT: Color = Color::Rgb(0x61, 0xAF, 0xEF); // blue
pub const BORDER: Color = Color::Rgb(0x45, 0x4C, 0x5E); // muted slate
pub const TEXT: Color = Color::Rgb(0xCE, 0xD3, 0xDE);
pub const TEXT_DIM: Color = Color::Rgb(0x7C, 0x83, 0x94);
pub const GUTTER: Color = Color::Rgb(0x5A, 0x61, 0x72);
pub const CURSOR_BG: Color = Color::Rgb(0x2E, 0x34, 0x40);

pub const STATUS_BG: Color = Color::Rgb(0x1B, 0x1F, 0x27);
pub const STATUS_FG: Color = Color::Rgb(0xAB, 0xB2, 0xBF);

// Text drawn on top of a colored highlight background — near-black for contrast.
pub const MATCH_FG: Color = Color::Rgb(0x14, 0x16, 0x1B);
// Live search matches: bright, distinct from every rule color.
pub const SEARCH_BG: Color = Color::Rgb(0xF5, 0xF5, 0xF5);

/// Highlight-rule palette. Light-to-mid saturation so black text stays legible
/// on the colored background, and visually distinct from each other.
pub const PALETTE: &[Color] = &[
    Color::Rgb(0xE0, 0x6C, 0x75), // red
    Color::Rgb(0x98, 0xC3, 0x79), // green
    Color::Rgb(0xE5, 0xC0, 0x7B), // yellow
    Color::Rgb(0x61, 0xAF, 0xEF), // blue
    Color::Rgb(0xC6, 0x78, 0xDD), // magenta
    Color::Rgb(0x56, 0xB6, 0xC2), // cyan
    Color::Rgb(0xE8, 0x9B, 0x54), // orange
    Color::Rgb(0xEC, 0x8C, 0xB0), // pink
    Color::Rgb(0xB5, 0xCE, 0x6C), // lime
    Color::Rgb(0x5F, 0xC9, 0xA6), // teal
    Color::Rgb(0x9A, 0xA7, 0xF0), // periwinkle
    Color::Rgb(0xD0, 0xB0, 0x6A), // gold
];

pub fn rule_color(index: usize) -> Color {
    PALETTE[index % PALETTE.len()]
}

// Gradient endpoints for the welcome logo (top → bottom).
pub const LOGO_TOP: Color = Color::Rgb(0x5B, 0x84, 0xEF); // blue
pub const LOGO_BOTTOM: Color = Color::Rgb(0x3E, 0xE0, 0xD8); // cyan

/// Linear blend between two colors; `t` runs 0.0 (a) → 1.0 (b). Non-RGB colors
/// fall back to `a`.
pub fn lerp_color(a: Color, b: Color, t: f64) -> Color {
    let parts = |c: Color| match c {
        Color::Rgb(r, g, bl) => Some((r, g, bl)),
        _ => None,
    };
    match (parts(a), parts(b)) {
        (Some((ar, ag, ab)), Some((br, bg, bb))) => {
            let mix = |x: u8, y: u8| {
                (x as f64 + (y as f64 - x as f64) * t.clamp(0.0, 1.0)).round() as u8
            };
            Color::Rgb(mix(ar, br), mix(ag, bg), mix(ab, bb))
        }
        _ => a,
    }
}

/// A rounded panel. `active` panels get an accent border + title. Returns an
/// owned (`'static`) block so callers can pass temporary title strings.
pub fn panel(title: &str, active: bool) -> Block<'static> {
    let border_color = if active { ACCENT } else { BORDER };
    let title_style = if active {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT_DIM).add_modifier(Modifier::BOLD)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .title(Line::from(title.to_string()))
        .title_style(title_style)
}
