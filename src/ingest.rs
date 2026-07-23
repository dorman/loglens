use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Skip files larger than this when auto-collecting logs from a folder/bundle,
/// to avoid pulling in huge binaries or database files.
const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Extraction caps guarding against zip bombs: a small archive must not be
/// allowed to expand into unbounded disk usage.
const MAX_EXTRACT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACT_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACT_ENTRIES: usize = 10_000;

/// Directory recursion depth cap (defensive; sane bundles are shallow).
const MAX_DIR_DEPTH: usize = 32;

/// One resolved log file ready to open: a real path on disk plus the display
/// name shown in the tab bar (relative path when it came from a folder/bundle).
pub struct LoadTarget {
    pub path: PathBuf,
    pub name: String,
}

/// Resolve a user-supplied path into concrete log files.
///
/// - a plain file  -> that file
/// - a `.zip`      -> every text log extracted from the archive
/// - a directory   -> every text log found recursively inside it
pub fn resolve(input: &Path) -> Result<Vec<LoadTarget>> {
    if input.is_dir() {
        return Ok(collect_from_dir(input, input));
    }
    if is_zip(input) {
        return extract_zip(input);
    }
    if input.is_file() {
        let name = file_name(input);
        return Ok(vec![LoadTarget {
            path: input.to_path_buf(),
            name,
        }]);
    }
    anyhow::bail!("no such file or directory: {}", input.display());
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn is_zip(path: &Path) -> bool {
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
    if depth > MAX_DIR_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
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
            out.push(LoadTarget { path, name: display });
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

/// Extract text logs from a zip archive into a unique temp directory, then
/// collect them. Extracted files persist for the session under the OS temp dir.
///
/// Hardened against hostile archives: `mangled_name` defeats zip-slip path
/// traversal, and per-file / total-size / entry-count caps defeat zip bombs.
fn extract_zip(path: &Path) -> Result<Vec<LoadTarget>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open archive '{}'", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("'{}' is not a valid zip archive", path.display()))?;

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "bundle".to_string());
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
        // zip-slip path traversal.
        let out_path = root.join(zf.mangled_name());
        if let Some(parent) = out_path.parent() {
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

    Ok(collect_from_dir(&root, &root))
}
