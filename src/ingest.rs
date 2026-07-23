use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Skip files larger than this when auto-collecting logs from a folder/bundle,
/// to avoid pulling in huge binaries or database files.
const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

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
    collect_inner(dir, base, &mut out);
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn collect_inner(dir: &Path, base: &Path, out: &mut Vec<LoadTarget>) {
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
        if path.is_dir() {
            collect_inner(&path, base, out);
        } else if looks_like_text(&path) {
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
    use io::Read;
    let mut buf = [0u8; 8192];
    match file.read(&mut buf) {
        Ok(n) => !buf[..n].contains(&0),
        Err(_) => false,
    }
}

/// Extract text logs from a zip archive into a unique temp directory, then
/// collect them. Extracted files persist for the session under the OS temp dir.
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

    for i in 0..archive.len() {
        let mut zf = archive.by_index(i)?;
        if zf.is_dir() {
            continue;
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
        io::copy(&mut zf, &mut out_file).ok();
    }

    Ok(collect_from_dir(&root, &root))
}
