use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Skip files larger than this when auto-collecting logs from a folder/bundle,
/// and reject direct opens above this size so a single hostile file cannot OOM
/// the process.
pub const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Extraction caps guarding against zip bombs: a small archive must not be
/// allowed to expand into unbounded disk usage.
const MAX_EXTRACT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACT_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACT_ENTRIES: usize = 10_000;
/// Cap the *compressed archive* size before `ZipArchive::new` parses the
/// central directory — otherwise a zip with a huge CDR can OOM during open,
/// before per-entry extraction caps apply.
const MAX_ZIP_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Directory recursion depth cap (defensive; sane bundles are shallow).
const MAX_DIR_DEPTH: usize = 32;

/// Cap how many log files a single resolve (folder/zip) may return.
pub const MAX_FILES_PER_RESOLVE: usize = 2_000;

/// One resolved log file ready to open: a real path on disk plus the display
/// name shown in the tab bar (relative path when it came from a folder/bundle).
pub struct LoadTarget {
    pub path: PathBuf,
    pub name: String,
}

/// Outcome of resolving a user path. Zip extracts produce a temp directory that
/// the caller must keep for the session and remove on exit.
pub struct ResolveOutcome {
    pub targets: Vec<LoadTarget>,
    pub temp_dir: Option<PathBuf>,
}

/// Resolve a user-supplied path into concrete log files.
///
/// - a plain file  -> that file
/// - a `.zip`      -> every text log extracted from the archive
/// - a directory   -> every text log found recursively inside it
pub fn resolve(input: &Path) -> Result<ResolveOutcome> {
    if input.is_dir() {
        return Ok(ResolveOutcome {
            targets: collect_from_dir(input, input),
            temp_dir: None,
        });
    }
    if is_zip(input) {
        return extract_zip(input);
    }
    if input.is_file() {
        let name = file_name(input);
        return Ok(ResolveOutcome {
            targets: vec![LoadTarget {
                path: input.to_path_buf(),
                name,
            }],
            temp_dir: None,
        });
    }
    anyhow::bail!("no such file or directory: {}", input.display());
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

pub fn is_zip(path: &Path) -> bool {
    path.extension()
        .map(|e| e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

/// Recursively gather likely-text log files under `dir`. `base` is used to build
/// a short relative display name so files in a bundle stay distinguishable.
fn collect_from_dir(dir: &Path, base: &Path) -> Vec<LoadTarget> {
    let mut out = Vec::new();
    collect_inner(dir, base, 0, &mut out);
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

fn collect_inner(dir: &Path, base: &Path, depth: usize, out: &mut Vec<LoadTarget>) {
    if depth > MAX_DIR_DEPTH || out.len() >= MAX_FILES_PER_RESOLVE {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        if out.len() >= MAX_FILES_PER_RESOLVE {
            return;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        // Never follow symlinks during auto-collection: a cyclic link would
        // recurse forever, and links can point outside the bundle entirely.
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_inner(&path, base, depth + 1, out);
        } else if ft.is_file() && looks_like_text(&path) {
            let display = path
                .strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| file_name(&path));
            out.push(LoadTarget {
                path,
                name: display,
            });
        }
    }
}

/// Heuristic: reject files that are too big or that contain a NUL byte in their
/// first chunk (a reliable signal the file is binary, not a text log).
fn looks_like_text(path: &Path) -> bool {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if meta.len() == 0 || meta.len() > MAX_LOG_BYTES {
        return false;
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 8192];
    match file.read(&mut buf) {
        Ok(n) => !buf[..n].contains(&0),
        Err(_) => false,
    }
}

/// True if `candidate` is strictly inside `root` (zip-slip defense in depth).
/// Rejects `..` components even when `strip_prefix` succeeds on a non-normalized path.
fn path_within(root: &Path, candidate: &Path) -> bool {
    use std::path::Component;
    let Ok(rel) = candidate.strip_prefix(root) else {
        return false;
    };
    if rel.as_os_str().is_empty() {
        return false;
    }
    for c in rel.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

/// Extract text logs from a zip archive into a unique temp directory, then
/// collect them. The temp directory is returned so the app can delete it on exit.
///
/// Hardened against hostile archives: `mangled_name` + containment check defeat
/// zip-slip path traversal, and per-file / total-size / entry-count caps defeat
/// zip bombs.
fn extract_zip(path: &Path) -> Result<ResolveOutcome> {
    let meta = fs::metadata(path)
        .with_context(|| format!("failed to open archive '{}'", path.display()))?;
    if meta.len() > MAX_ZIP_ARCHIVE_BYTES {
        anyhow::bail!(
            "'{}' is larger than {} MB; refuse to open as zip",
            path.display(),
            MAX_ZIP_ARCHIVE_BYTES / (1024 * 1024)
        );
    }
    let file =
        File::open(path).with_context(|| format!("failed to open archive '{}'", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("'{}' is not a valid zip archive", path.display()))?;

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "bundle".to_string());
    // Sanitize stem so it cannot inject path separators into the temp dir name.
    let stem: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("loglens-{stem}-{nonce}"));
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create temp dir '{}'", root.display()))?;

    let mut total_written: u64 = 0;
    let entry_count = archive.len().min(MAX_EXTRACT_ENTRIES);
    for i in 0..entry_count {
        let mut zf = archive.by_index(i)?;
        if zf.is_dir() {
            continue;
        }
        // Skip entries that even *claim* to be oversized; the limited reader
        // below still guards against lying headers.
        if zf.size() > MAX_EXTRACT_FILE_BYTES {
            continue;
        }
        if total_written >= MAX_EXTRACT_TOTAL_BYTES {
            break;
        }
        // `mangled_name` strips absolute/`..` components, guarding against
        // zip-slip path traversal. Containment check is defense in depth.
        let out_path = root.join(zf.mangled_name());
        if !path_within(&root, &out_path) {
            continue;
        }
        if let Some(parent) = out_path.parent() {
            if !path_within(&root, parent) && parent != root {
                continue;
            }
            fs::create_dir_all(parent).ok();
        }
        let mut out_file = match File::create(&out_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // Copy through a hard limit; a decompressed stream that exceeds the cap
        // (zip bomb) is truncated and the partial file discarded.
        let budget = MAX_EXTRACT_FILE_BYTES.min(MAX_EXTRACT_TOTAL_BYTES - total_written);
        let mut limited = (&mut zf).take(budget + 1);
        match io::copy(&mut limited, &mut out_file) {
            Ok(written) if written > budget => {
                drop(out_file);
                fs::remove_file(&out_path).ok();
            }
            Ok(written) => total_written += written,
            Err(_) => {
                drop(out_file);
                fs::remove_file(&out_path).ok();
            }
        }
    }

    Ok(ResolveOutcome {
        targets: collect_from_dir(&root, &root),
        temp_dir: Some(root),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn path_within_accepts_children_only() {
        let root = Path::new("/tmp/loglens-root");
        assert!(path_within(root, Path::new("/tmp/loglens-root/a.log")));
        assert!(path_within(root, Path::new("/tmp/loglens-root/sub/a.log")));
        assert!(!path_within(root, Path::new("/tmp/loglens-root")));
        assert!(!path_within(root, Path::new("/tmp/other/a.log")));
        assert!(!path_within(root, Path::new("/etc/passwd")));
        // `..` after a successful strip_prefix must still be rejected.
        assert!(!path_within(
            root,
            Path::new("/tmp/loglens-root/foo/../../other")
        ));
        assert!(!path_within(root, Path::new("/tmp/loglens-root/../other")));
    }

    #[test]
    fn is_zip_detects_extension() {
        assert!(is_zip(Path::new("bundle.ZIP")));
        assert!(is_zip(Path::new("a.zip")));
        assert!(!is_zip(Path::new("a.log")));
    }

    #[test]
    fn extract_zip_rejects_path_traversal_and_returns_temp() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-zip-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("evil.zip");

        {
            let file = File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            // Traversal-style name; mangled_name + containment must keep it inside root.
            zip.start_file("../escape.log", opts).unwrap();
            zip.write_all(b"should not escape\n").unwrap();
            zip.start_file("safe.log", opts).unwrap();
            zip.write_all(b"hello from zip\n").unwrap();
            zip.finish().unwrap();
        }

        let outcome = extract_zip(&zip_path).unwrap();
        let names: Vec<_> = outcome.targets.iter().map(|t| t.name.as_str()).collect();
        assert!(names.iter().any(|n| n.ends_with("safe.log")));
        assert!(names.iter().all(|n| !n.contains("..")));
        let temp = outcome
            .temp_dir
            .expect("zip extract should return temp dir");
        assert!(temp.exists());
        // Nothing should have been written outside the temp root.
        assert!(!dir.join("escape.log").exists());
        fs::remove_dir_all(&temp).ok();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn looks_like_text_rejects_nul_empty_and_oversize() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-text-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();

        let empty = dir.join("empty.log");
        fs::write(&empty, b"").unwrap();
        assert!(!looks_like_text(&empty));

        let binary = dir.join("bin.log");
        fs::write(&binary, b"hello\0world\n").unwrap();
        assert!(!looks_like_text(&binary));

        let ok = dir.join("ok.log");
        fs::write(&ok, b"hello\n").unwrap();
        assert!(looks_like_text(&ok));

        // Sparse file: set length above the cap without writing 50MB of data.
        let huge = dir.join("huge.log");
        {
            let f = File::create(&huge).unwrap();
            f.set_len(MAX_LOG_BYTES + 1).unwrap();
        }
        assert!(!looks_like_text(&huge));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn collect_skips_symlinks_hidden_and_binaries() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-collect-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("ok.log");
        fs::write(&log, b"hello\n").unwrap();
        fs::write(dir.join(".hidden.log"), b"secret\n").unwrap();
        fs::write(dir.join("blob.bin"), b"a\0b\n").unwrap();

        #[cfg(unix)]
        {
            let link = dir.join("link.log");
            std::os::unix::fs::symlink(&log, &link).unwrap();
        }

        let targets = collect_from_dir(&dir, &dir);
        let names: Vec<_> = targets.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["ok.log"]);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn collect_respects_max_files_per_resolve() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        for i in 0..(MAX_FILES_PER_RESOLVE + 25) {
            fs::write(dir.join(format!("{i:04}.log")), b"x\n").unwrap();
        }
        let targets = collect_from_dir(&dir, &dir);
        assert_eq!(targets.len(), MAX_FILES_PER_RESOLVE);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_missing_path_errors() {
        match resolve(Path::new("/nonexistent/loglens-nope.log")) {
            Ok(_) => panic!("missing path should error"),
            Err(e) => assert!(format!("{e}").contains("no such file")),
        }
    }

    #[test]
    fn resolve_plain_file_and_directory() {
        let file = resolve(Path::new("samples/sample.log")).unwrap();
        assert_eq!(file.targets.len(), 1);
        assert!(file.temp_dir.is_none());

        let dir = resolve(Path::new("samples/bundle")).unwrap();
        assert!(dir.targets.len() >= 3);
        assert!(dir.temp_dir.is_none());
        assert!(dir.targets.iter().all(|t| !t.name.contains("thumbnail")));
    }

    #[test]
    fn extract_zip_rejects_oversize_archive_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-zipsize-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("huge.zip");
        {
            let f = File::create(&zip_path).unwrap();
            f.set_len(MAX_ZIP_ARCHIVE_BYTES + 1).unwrap();
        }
        match extract_zip(&zip_path) {
            Ok(_) => panic!("oversize archive should be rejected"),
            Err(e) => assert!(e.to_string().contains("larger than")),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn soak_extract_zip_caps_entry_count_and_discards_bomb() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-zipsoak-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let zip_path = dir.join("hostile.zip");

        {
            let file = File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            // Many small text logs — well under the entry cap, all collectible.
            for i in 0..120 {
                zip.start_file(format!("logs/{i:03}.log"), opts).unwrap();
                zip.write_all(format!("line {i} connection refused\n").as_bytes())
                    .unwrap();
            }

            // Path traversal + absolute-style name should stay contained.
            zip.start_file("../../escape.log", opts).unwrap();
            zip.write_all(b"should not escape\n").unwrap();

            // Binary decoy — looks_like_text rejects NUL bytes so it never
            // becomes a tab even though it lives inside the archive.
            zip.start_file("logs/payload.bin", opts).unwrap();
            zip.write_all(&[0u8; 4096]).unwrap();

            zip.finish().unwrap();
        }

        let outcome = extract_zip(&zip_path).unwrap();
        assert!(
            outcome.targets.len() >= 100,
            "expected many collected logs, got {}",
            outcome.targets.len()
        );
        assert!(
            outcome.targets.len() <= MAX_FILES_PER_RESOLVE,
            "resolve must honor file cap"
        );
        assert!(outcome.targets.iter().all(|t| !t.name.contains("..")));
        assert!(
            outcome
                .targets
                .iter()
                .all(|t| !t.name.ends_with("payload.bin"))
        );
        assert!(!dir.join("escape.log").exists());
        let temp = outcome.temp_dir.expect("temp dir");
        fs::remove_dir_all(&temp).ok();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn soak_deep_nested_bundle_stops_at_depth_cap() {
        let dir = std::env::temp_dir().join(format!(
            "loglens-test-deep-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        // Build a chain deeper than MAX_DIR_DEPTH with a log at the bottom.
        let mut cur = dir.clone();
        fs::create_dir_all(&cur).unwrap();
        for i in 0..(MAX_DIR_DEPTH + 8) {
            cur = cur.join(format!("d{i}"));
            fs::create_dir_all(&cur).unwrap();
        }
        fs::write(cur.join("deep.log"), b"connection refused\n").unwrap();
        // Also plant a reachable log near the surface.
        fs::write(dir.join("top.log"), b"certificate validation failed\n").unwrap();

        let targets = collect_from_dir(&dir, &dir);
        assert!(
            targets.iter().any(|t| t.name == "top.log"),
            "shallow log must be collected"
        );
        assert!(
            targets.iter().all(|t| !t.name.ends_with("deep.log")),
            "log beyond MAX_DIR_DEPTH must be skipped: {:?}",
            targets.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
        fs::remove_dir_all(&dir).ok();
    }
}
