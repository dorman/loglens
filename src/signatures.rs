use ratatui::style::Color;
use regex::Regex;

use crate::rules;

/// Severity of a scan finding, ordered low → high so `max`/sort work directly.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Severity::Critical => Color::Rgb(0xFF, 0x55, 0x55),
            Severity::High => Color::Rgb(0xE8, 0x8B, 0x3D),
            Severity::Medium => Color::Rgb(0xE5, 0xC0, 0x7B),
            Severity::Low => Color::Rgb(0x61, 0xAF, 0xEF),
            Severity::Info => Color::Rgb(0x7C, 0x83, 0x94),
        }
    }
}

/// A compiled detection signature: what to match plus why it matters.
pub struct Signature {
    pub severity: Severity,
    pub category: &'static str,
    pub title: &'static str,
    pub explain: &'static str,
    pub regex: Regex,
}

/// The built-in detection library. Curated for general logs plus the kinds of
/// signals that show up in endpoint/anti-virus diagnostic bundles. All patterns
/// are case-insensitive.
pub fn builtin() -> Vec<Signature> {
    use Severity::*;
    // (severity, category, title, explanation, pattern)
    const DEFS: &[(Severity, &str, &str, &str, &str)] = &[
        (
            Critical,
            "tamper",
            "Security protection disabled/tampered",
            "Real-time protection or the AV service was disabled or tampered with — investigate whether this was user, policy, or malware driven.",
            r"(?i)\b(tamper|disabl(e|ed|ing)|turn(ed)? off|bypass(ed)?)\b.{0,20}\b(real[- ]?time|protection|defender|antivirus|self[- ]?protection|security)\b",
        ),
        (
            High,
            "suspicious",
            "Encoded PowerShell command",
            "PowerShell invoked with an encoded/hidden command — a very common malware and living-off-the-land technique.",
            r"(?i)powershell(\.exe)?\b.{0,60}(-enc(odedcommand)?|-e\b|frombase64string|-nop|-w\s*hidden)",
        ),
        (
            High,
            "suspicious",
            "Process injection / hollowing",
            "Log mentions injection into another process — often used to run code under a trusted process like explorer.exe.",
            r"(?i)\b(inject(ion|ed|ing)?|hollow(ing)?|reflective load)\b.{0,30}\b(process|explorer|memory|thread|dll)\b",
        ),
        (
            Medium,
            "suspicious",
            "Living-off-the-land binary",
            "A commonly-abused system binary was executed — legitimate at times, but frequently used by attackers to blend in.",
            r"(?i)\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|wmic|schtasks)\.exe\b",
        ),
        (
            High,
            "integrity",
            "Clock / time rollback detected",
            "System clock manipulation — can indicate license tampering or an attempt to evade time-based checks.",
            r"(?i)\b(clock|system time|time)\b.{0,20}\b(roll ?back|tamper|manipulat|set back)\b|rollback detected on system clock",
        ),
        (
            High,
            "integrity",
            "Certificate validation failure",
            "A TLS/code-signing certificate failed to validate — the update/comms channel may be misconfigured or intercepted.",
            r"(?i)cert(ificate)?\b.{0,20}(valid\w*\s+fail|invalid|untrusted|revoked|expired|verification failed)",
        ),
        (
            High,
            "integrity",
            "Signature/definition database corrupt",
            "The AV signature/definition database is corrupt or failed to load — protection may be degraded until repaired.",
            r"(?i)\b(signature|definition|virus def\w*)\b.{0,20}\b(corrupt|invalid|failed|missing|damaged)\b",
        ),
        (
            Critical,
            "crash",
            "Fatal error / crash",
            "A fatal error, crash, or unhandled exception occurred — the component likely stopped functioning.",
            r"(?i)\b(fatal|unhandled exception|access violation|segfault|segmentation fault|kernel panic|stack ?trace|core dumped|crash(ed)?)\b",
        ),
        (
            High,
            "resource",
            "Resource exhaustion",
            "The system ran out of a critical resource (memory/disk/handles) — a frequent root cause of cascading failures.",
            r"(?i)(out of memory|oom\b|disk full|no space left|insufficient (memory|disk)|handle leak|i/o error)",
        ),
        (
            Medium,
            "network",
            "Connection refused / reset",
            "A network connection was refused or reset — check connectivity to update/telemetry endpoints.",
            r"(?i)connection\s+(refused|reset|timed? ?out|aborted)",
        ),
        (
            Medium,
            "update",
            "Update failure",
            "A product/signature update failed — the client may be running with stale protection.",
            r"(?i)\b(update|upgrade)\b.{0,30}\b(fail(ed|ure)?|error|timeout|refused|could not)\b",
        ),
        (
            Medium,
            "install",
            "Installer rollback",
            "An installation rolled back (e.g. MSI error 1603) — the install/repair did not complete successfully.",
            r"(?i)(rollback|rolling back)\b|error\s*1603|msi.{0,20}(fail|abort)",
        ),
        (
            Medium,
            "access",
            "Access denied / unauthorized",
            "A permission or authorization check failed — may block the product from operating correctly.",
            r"(?i)(access denied|permission denied|unauthorized|0x80070005|e_accessdenied)",
        ),
        (
            Low,
            "error",
            "Generic error",
            "A line logged at ERROR level — worth a look but not inherently suspicious.",
            r"(?i)\b(error|failed|failure)\b",
        ),
        (
            Info,
            "warning",
            "Warning",
            "A line logged at WARN level — informational context.",
            r"(?i)\bwarn(ing)?\b",
        ),
    ];

    DEFS.iter()
        .map(|(sev, cat, title, explain, pat)| {
            let regex = rules::compile_regex(pat).unwrap_or_else(|e| {
                panic!("invalid built-in signature '{title}': {e}");
            });
            Signature {
                severity: *sev,
                category: cat,
                title,
                explain,
                regex,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_signatures_compile() {
        let sigs = builtin();
        assert!(!sigs.is_empty());
        // Every definition must compile — builtin() panics otherwise.
        assert!(sigs.iter().any(|s| s.severity == Severity::Critical));
    }
}
