//! Terminal clipboard helpers via OSC-52.
//!
//! Most modern terminals (iTerm2, Kitty, WezTerm, Windows Terminal, Ghostty,
//! recent VTE) honor OSC-52 and place the payload on the system clipboard.
//! tmux users typically need `set -g set-clipboard on` (or `external`).
//!
//! OSC-52 is written as raw ANSI bytes to stdout. Do **not** implement
//! `crossterm::Command` for this — on Windows that trait requires
//! `execute_winapi`, which we do not need for a pure escape sequence.

use std::io::{self, Write};

/// Soft cap so a hostile / huge line cannot flood the terminal's OSC buffer.
/// Base64 expands ~4/3, so 12 KiB of text stays near a common 16 KiB limit.
const MAX_CLIPBOARD_BYTES: usize = 12 * 1024;

/// Copy `text` to the system clipboard by writing an OSC-52 sequence to stdout.
pub fn copy_text(text: &str) -> io::Result<CopyOutcome> {
    let (payload, truncated) = truncate_for_clipboard(text);
    let seq = osc52_sequence(payload);
    let mut out = io::stdout();
    out.write_all(seq.as_bytes())?;
    out.flush()?;
    Ok(CopyOutcome { truncated })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOutcome {
    pub truncated: bool,
}

/// Build the BEL-terminated OSC-52 "copy to clipboard" (`Ps = c`) sequence.
fn osc52_sequence(text: &str) -> String {
    // BEL-terminated form is widely supported; ST (`ESC \`) is an alt.
    format!("\x1b]52;c;{}\x07", encode_base64(text.as_bytes()))
}

fn truncate_for_clipboard(text: &str) -> (&str, bool) {
    if text.len() <= MAX_CLIPBOARD_BYTES {
        return (text, false);
    }
    let mut end = MAX_CLIPBOARD_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

fn encode_base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_empty_and_padding() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let s = "a".repeat(MAX_CLIPBOARD_BYTES) + "🚀extra";
        let (cut, truncated) = truncate_for_clipboard(&s);
        assert!(truncated);
        assert!(cut.len() <= MAX_CLIPBOARD_BYTES);
        assert!(cut.is_char_boundary(cut.len()));
    }

    #[test]
    fn osc52_sequence_contains_encoded_payload() {
        let buf = osc52_sequence("hi");
        assert!(buf.starts_with("\x1b]52;c;"));
        assert!(buf.ends_with('\x07'));
        assert!(buf.contains(&encode_base64(b"hi")));
    }
}
