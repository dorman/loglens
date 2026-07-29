use ratatui::style::Color;
use regex::RegexSet;

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

/// What a detection means: severity plus the plain-English explanation shown in
/// the findings panel. The pattern itself lives in the [`Library`]'s `RegexSet`.
pub struct Signature {
    pub severity: Severity,
    pub category: &'static str,
    pub title: &'static str,
    pub explain: &'static str,
}

/// The built-in detection library: signature metadata plus a single [`RegexSet`]
/// holding every pattern.
///
/// The set is the only compiled form of the patterns, so it cannot drift out of
/// step with the metadata, and [`Library::matches`] tests a line against all
/// signatures in one pass instead of running each regex separately.
pub struct Library {
    signatures: Vec<Signature>,
    set: RegexSet,
}

impl Library {
    /// Build the built-in library. Panics on a malformed built-in pattern —
    /// that is a bug in this file, not something a user can trigger.
    pub fn builtin() -> Self {
        let (signatures, patterns) = builtin_defs();
        let set = rules::compile_regex_set(&patterns)
            .unwrap_or_else(|e| panic!("invalid built-in signature set: {e}"));
        debug_assert_eq!(signatures.len(), set.len());
        Self { signatures, set }
    }

    /// Indices of every signature matching `line`, ascending.
    pub fn matches<'a>(&'a self, line: &str) -> impl Iterator<Item = usize> + 'a {
        self.set.matches(line).into_iter()
    }

    /// How many signatures the library holds. Callers size per-signature
    /// bookkeeping with this, so it must stay in step with the match indices
    /// [`Self::matches`] yields.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

/// Lets existing `signatures[finding.sig]` call sites keep working.
impl std::ops::Index<usize> for Library {
    type Output = Signature;

    fn index(&self, i: usize) -> &Signature {
        &self.signatures[i]
    }
}

/// The built-in detection library. Curated for general logs plus the kinds of
/// signals that show up in endpoint/anti-virus diagnostic bundles. All patterns
/// are case-insensitive.
///
/// Returns metadata and patterns as parallel lists, in the order the `RegexSet`
/// will report match indices.
fn builtin_defs() -> (Vec<Signature>, Vec<&'static str>) {
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
        // Deliberately omit catch-all "error" / "warn" signatures: they flood
        // real logs, burn the findings cap, and bury Medium+ triage signals.
        // Use keyword highlights (`a` / `-k ERROR,WARN`) for that volume instead.
    ];

    let signatures = DEFS
        .iter()
        .map(|(sev, cat, title, explain, _)| Signature {
            severity: *sev,
            category: cat,
            title,
            explain,
        })
        .collect();
    let patterns = DEFS.iter().map(|(_, _, _, _, pat)| *pat).collect();
    (signatures, patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature metadata, as defined in this file.
    fn defs() -> Vec<Signature> {
        builtin_defs().0
    }

    fn titles_matching(line: &str) -> Vec<&'static str> {
        let lib = Library::builtin();
        lib.matches(line).map(|i| lib[i].title).collect()
    }

    #[test]
    fn all_builtin_signatures_compile() {
        let defs = defs();
        assert!(!defs.is_empty());
        // Every pattern must compile — Library::builtin panics otherwise.
        let _ = Library::builtin();
        assert!(defs.iter().any(|s| s.severity == Severity::Critical));
    }

    /// One representative line per built-in signature, plus lines that must not
    /// match anything. `None` means "no findings at all".
    const EXPECTED: &[(&str, Option<&str>)] = &[
        // NB: this pattern wants the verb before the noun. The reversed phrasing
        // ("Real-time protection was disabled") does *not* match today — a real
        // coverage gap in the signature, left alone here because widening it
        // changes what gets flagged in customer logs.
        (
            "ERROR Disabled real-time protection via registry edit",
            Some("Security protection disabled/tampered"),
        ),
        (
            "WARN  Suspicious process detected: powershell.exe -enc <base64>",
            Some("Encoded PowerShell command"),
        ),
        (
            "ALERT Blocked process injection attempt targeting explorer.exe",
            Some("Process injection / hollowing"),
        ),
        (
            "DEBUG rundll32.exe launched with unusual arguments",
            Some("Living-off-the-land binary"),
        ),
        (
            "ERROR License validation failed: rollback detected on system clock",
            Some("Clock / time rollback detected"),
        ),
        (
            "ERROR Certificate validation failed for update.example.com",
            Some("Certificate validation failure"),
        ),
        (
            "ERROR Signature database corrupt, failed to load definitions",
            Some("Signature/definition database corrupt"),
        ),
        (
            "FATAL unhandled exception in scan engine (core dumped)",
            Some("Fatal error / crash"),
        ),
        (
            "ERROR out of memory while building index",
            Some("Resource exhaustion"),
        ),
        (
            "WARN  connection refused to telemetry.example.com",
            Some("Connection refused / reset"),
        ),
        (
            "ERROR update failed: could not reach the update server",
            Some("Update failure"),
        ),
        (
            "ERROR Installer rolling back changes (error 1603)",
            Some("Installer rollback"),
        ),
        (
            "ERROR access denied opening quarantine store (0x80070005)",
            Some("Access denied / unauthorized"),
        ),
        // Clean lines: a generic ERROR is highlight material, not a finding.
        (
            "2026-07-22 10:00:01 INFO  Starting AV agent service v14.2.1",
            None,
        ),
        (
            "2026-07-22 10:00:07 ERROR something went sideways in module X",
            None,
        ),
        ("plain text with no interesting tokens at all", None),
        ("", None),
    ];

    /// Guards the index→metadata pairing. The `RegexSet` reports only indices, so
    /// a change that let patterns drift out of step with the metadata beside them
    /// would keep matching lines while attaching the *wrong* explanation to them.
    /// Checking a known line resolves to its own title is what catches that; the
    /// coverage assertion stops a new signature from being added untested.
    #[test]
    fn every_signature_reports_its_own_title() {
        let lib = Library::builtin();
        for (line, expected) in EXPECTED {
            let titles: Vec<&str> = lib.matches(line).map(|i| lib[i].title).collect();
            match expected {
                // Other signatures may also match — overlap is by design — but the
                // one describing this line must be among them.
                Some(want) => assert!(
                    titles.contains(want),
                    "expected {want:?} for {line:?}, got {titles:?}"
                ),
                None => assert!(
                    titles.is_empty(),
                    "expected no findings for {line:?}, got {titles:?}"
                ),
            }
        }

        // Every built-in signature needs a line in the table above.
        for sig in defs() {
            assert!(
                EXPECTED.iter().any(|(_, want)| *want == Some(sig.title)),
                "signature {:?} has no line in EXPECTED — add one",
                sig.title
            );
        }
    }

    #[test]
    fn severity_ordering_critical_gt_info() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn matches_encoded_powershell_sample_line() {
        let line = "WARN  Suspicious process detected: powershell.exe -enc <base64>";
        let titles = titles_matching(line);
        assert!(
            titles.iter().any(|t| t.contains("PowerShell")),
            "expected encoded PowerShell signature, got {titles:?}"
        );
    }

    #[test]
    fn matches_certificate_validation_failure() {
        let line = "ERROR Certificate validation failed for update.example.com";
        let titles = titles_matching(line);
        assert!(
            titles.iter().any(|t| t.contains("Certificate")),
            "expected cert failure signature, got {titles:?}"
        );
    }

    #[test]
    fn matches_clock_rollback_phrase() {
        let line = "ERROR License validation failed: rollback detected on system clock";
        let titles = titles_matching(line);
        assert!(
            titles
                .iter()
                .any(|t| t.contains("Clock") || t.contains("rollback")),
            "expected clock rollback signature, got {titles:?}"
        );
    }

    #[test]
    fn matches_connection_refused() {
        let line = "connection refused while contacting update.example.com:443";
        let titles = titles_matching(line);
        assert!(
            titles.iter().any(|t| t.contains("Connection")),
            "expected connection signature, got {titles:?}"
        );
    }

    #[test]
    fn matches_installer_rollback() {
        let line = "Error 1603: Fatal error during installation — rolling back";
        let titles = titles_matching(line);
        assert!(
            titles
                .iter()
                .any(|t| t.contains("Installer") || t.contains("rollback")),
            "expected installer rollback signature, got {titles:?}"
        );
    }

    #[test]
    fn clean_info_line_is_not_an_error_finding() {
        let line = "2026-07-22 10:00:01 INFO  Starting AV agent service v14.2.1";
        let titles = titles_matching(line);
        assert!(
            titles.is_empty(),
            "clean INFO startup line should not match: {titles:?}"
        );
    }

    #[test]
    fn catch_all_error_and_warn_are_not_scan_signatures() {
        // Broad ERROR/WARN lines must not produce findings on their own —
        // those belong in keyword highlights, not the triage panel.
        let error_line = "2026-07-22 10:00:07 ERROR something went sideways in module X";
        let warn_line = "2026-07-22 10:00:05 WARN  Real-time protection module took 3200ms";
        assert!(
            titles_matching(error_line).is_empty(),
            "generic ERROR must not be a scan signature: {:?}",
            titles_matching(error_line)
        );
        assert!(
            titles_matching(warn_line).is_empty(),
            "generic WARN must not be a scan signature: {:?}",
            titles_matching(warn_line)
        );
        assert!(
            !defs()
                .iter()
                .any(|s| s.title == "Generic error" || s.title == "Warning")
        );
    }

    #[test]
    fn builtin_signatures_are_medium_or_higher() {
        assert!(
            defs().iter().all(|s| s.severity >= Severity::Medium),
            "scan signatures should stay at Medium+ to avoid findings flood"
        );
    }
}
