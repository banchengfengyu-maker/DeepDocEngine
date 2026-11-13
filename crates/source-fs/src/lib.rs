use deepdoc_protocol::ScanOptions;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Win32 volume enumeration unavailable for `{0}` (requires NTFS + privilege)")]
    UsnUnavailable(String),
}

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub disk_path: PathBuf,
    pub file_name: String,
    pub ext_lower: String,
    pub byte_size: u64,
    pub mtime_ns: i64,
}

/// Compute BLAKE3 hex digest for an in-memory byte slice.
pub fn blake3_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Compute BLAKE3 hex digest streaming from disk (64 KiB buffer).
pub fn blake3_file(path: &Path) -> Result<String, SourceError> {
    let mut file = File::open(path).map_err(|e| SourceError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| SourceError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn is_hidden_win(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
        let attrs = meta.file_attributes();
        (attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

/// Enumerate files under `roots`. When a root is an NTFS drive root (`X:\`) and `prefer_usn` is true,
/// attempts Win32 `FSCTL_ENUM_USN_DATA` first for rapid MFT enumeration and falls back to `WalkDir`.
pub fn enumerate_roots(
    roots: &[String],
    include_hidden: bool,
    prefer_usn: bool,
) -> Vec<DiscoveredFile> {
    let mut opts = ScanOptions::default();
    opts.include_hidden = include_hidden;
    opts.use_usn_if_available = prefer_usn;
    enumerate_roots_with_options(roots, &opts)
}

/// Enumerate files applying directory exclusion, filename glob exclusion, extension allowlist,
/// hidden/system filtering, and min/max file size limits.
pub fn enumerate_roots_with_options(roots: &[String], opts: &ScanOptions) -> Vec<DiscoveredFile> {
    let mut out = Vec::new();
    for root_str in roots {
        stream_root_with_options(root_str, opts, |entry| {
            out.push(entry);
            true
        });
    }
    out
}

/// Stream discovered files under `root_str` immediately as they are found (pruned MFT first,
/// falling back to multi-threaded `WalkDir` fan-out across top-level subdirectories).
/// Returning `false` from `emit` cancels remaining traversal promptly.
pub fn stream_root_with_options(
    root_str: &str,
    opts: &ScanOptions,
    mut emit: impl FnMut(DiscoveredFile) -> bool,
) {
    let root = PathBuf::from(root_str);
    if !root.exists() {
        return;
    }
    if root.is_file() {
        if let Ok(meta) = root.metadata() {
            let entry = make_entry(root, &meta);
            if matches_scan_filter(&entry, &meta, opts) {
                let _ = emit(entry);
            }
        }
        return;
    }
    if opts.use_usn_if_available && is_drive_root(&root) {
        if try_enumerate_ntfs_usn_streaming(&root, opts, &mut emit).is_ok() {
            return;
        }
    }

    let Ok(rd) = std::fs::read_dir(&root) else {
        return;
    };
    let mut top_dirs = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if let Ok(ft) = ent.file_type() {
            if ft.is_file() {
                if let Ok(meta) = ent.metadata() {
                    let disc = make_entry(p, &meta);
                    if matches_scan_filter(&disc, &meta, opts) && !emit(disc) {
                        return;
                    }
                }
            } else if ft.is_dir() {
                let excluded = (!opts.include_hidden
                    && ent.metadata().is_ok_and(|m| is_hidden_win(&m)))
                    || is_excluded_path(&p, opts);
                if !excluded {
                    top_dirs.push(p);
                }
            }
        }
    }
    if top_dirs.is_empty() {
        return;
    }

    let worker_threads = top_dirs.len().min(4);
    let next_idx = std::sync::atomic::AtomicUsize::new(0);
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::sync_channel::<DiscoveredFile>(1024);

    std::thread::scope(|scope| {
        for _ in 0..worker_threads {
            let tx_w = tx.clone();
            let dirs_ref = &top_dirs;
            let idx_ref = &next_idx;
            let cancel_ref = &cancelled;
            scope.spawn(move || loop {
                if cancel_ref.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let idx = idx_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(dir) = dirs_ref.get(idx) else {
                    break;
                };
                let walker = WalkDir::new(dir)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| {
                        !cancel_ref.load(std::sync::atomic::Ordering::Relaxed)
                            && (e.depth() == 0 || !is_dir_entry_excluded(e, opts))
                    });
                for entry in walker.flatten() {
                    if cancel_ref.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    if let Ok(meta) = entry.metadata() {
                        let disc = make_entry(entry.into_path(), &meta);
                        if matches_scan_filter(&disc, &meta, opts) && tx_w.send(disc).is_err() {
                            cancel_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        }
        drop(tx);

        for disc in rx {
            if !emit(disc) {
                cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    });
}

fn is_dir_entry_excluded(entry: &walkdir::DirEntry, opts: &ScanOptions) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    if !opts.include_hidden {
        if let Ok(meta) = entry.metadata() {
            if is_hidden_win(&meta) {
                return true;
            }
        }
    }
    is_excluded_path(entry.path(), opts)
}

fn is_dir_name_excluded(dir_name: &str, opts: &ScanOptions) -> bool {
    let lower = dir_name.to_ascii_lowercase();
    if !opts.include_hidden
        && matches!(
            lower.as_str(),
            "$recycle.bin" | "system volume information"
        )
    {
        return true;
    }
    opts.excluded_dirs.iter().any(|ex| {
        let ex_l = ex.trim().to_ascii_lowercase();
        !ex_l.is_empty()
            && !ex_l.contains('\\')
            && !ex_l.contains('/')
            && (lower == ex_l || wildcard_match_ci(&ex_l, &lower))
    })
}

pub fn is_excluded_path(path: &Path, opts: &ScanOptions) -> bool {
    for comp in path.components() {
        if let std::path::Component::Normal(seg) = comp {
            if is_dir_name_excluded(&seg.to_string_lossy(), opts) {
                return true;
            }
        }
    }
    if opts
        .excluded_dirs
        .iter()
        .any(|ex| ex.contains('\\') || ex.contains('/'))
    {
        let norm_path = path.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
        for ex in &opts.excluded_dirs {
            let ex_norm = ex.trim().replace('/', "\\").trim_matches('\\').to_ascii_lowercase();
            if ex_norm.is_empty() || !ex_norm.contains('\\') {
                continue;
            }
            let mid = format!("\\{ex_norm}\\");
            let end = format!("\\{ex_norm}");
            if norm_path.contains(&mid) || norm_path.ends_with(&end) {
                return true;
            }
        }
    }
    false
}

pub fn matches_scan_filter(
    entry: &DiscoveredFile,
    meta: &std::fs::Metadata,
    opts: &ScanOptions,
) -> bool {
    if !opts.include_hidden && is_hidden_win(meta) {
        return false;
    }
    if is_excluded_path(&entry.disk_path, opts) {
        return false;
    }
    matches_name_ext_size(entry, opts)
}

fn matches_name_ext_only(file_name: &str, ext_lower: &str, opts: &ScanOptions) -> bool {
    let fname_lower = file_name.to_ascii_lowercase();
    for pat in &opts.excluded_name_globs {
        let p = pat.trim().to_ascii_lowercase();
        if !p.is_empty() && wildcard_match_ci(&p, &fname_lower) {
            return false;
        }
    }
    if !opts.include_extensions.is_empty() {
        let allowed = opts.include_extensions.iter().any(|e| {
            let clean = e.trim().trim_start_matches('.').to_ascii_lowercase();
            !clean.is_empty() && clean == ext_lower
        });
        if !allowed {
            return false;
        }
    }
    true
}

fn matches_name_ext_size(entry: &DiscoveredFile, opts: &ScanOptions) -> bool {
    if !matches_name_ext_only(&entry.file_name, &entry.ext_lower, opts) {
        return false;
    }
    if let Some(min_sz) = opts.min_byte_size {
        if entry.byte_size < min_sz {
            return false;
        }
    }
    if let Some(max_sz) = opts.max_byte_size {
        if entry.byte_size > max_sz {
            return false;
        }
    }
    true
}

fn wildcard_match_ci(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub(crate) fn make_entry(disk_path: PathBuf, meta: &std::fs::Metadata) -> DiscoveredFile {
    let file_name = disk_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext_lower = disk_path
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    DiscoveredFile {
        disk_path,
        file_name,
        ext_lower,
        byte_size: meta.len(),
        mtime_ns,
    }
}

pub fn is_drive_root_path(path: &Path) -> bool {
    is_drive_root(path)
}

#[derive(Debug, Clone)]
pub struct UsnDelta {
    pub journal_id: u64,
    pub next_usn: i64,
    pub upserts: Vec<DiscoveredFile>,
    pub removed_paths: Vec<PathBuf>,
}

fn is_drive_root(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let bytes = s.as_bytes();
    (bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || (bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

#[cfg(windows)]
pub fn query_ntfs_usn_state(drive_root: &Path) -> Option<(u64, i64)> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{FSCTL_QUERY_USN_JOURNAL, USN_JOURNAL_DATA_V0};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    if !is_drive_root(drive_root) {
        return None;
    }
    let ch = drive_root.to_string_lossy().chars().next()?;
    let vol_path = format!(r"\\.\{ch}:");
    let wide: Vec<u16> = OsStr::new(&vol_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    const GENERIC_READ_FLAG: u32 = 0x8000_0000;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ_FLAG,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let mut journal = USN_JOURNAL_DATA_V0::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            &mut journal as *mut _ as *mut _,
            std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };
    (ok != 0).then_some((journal.UsnJournalID, journal.NextUsn))
}

#[cfg(not(windows))]
pub fn query_ntfs_usn_state(_drive_root: &Path) -> Option<(u64, i64)> {
    None
}

/// Read incremental NTFS USN changes since `(expected_journal_id, start_usn)` without crawling
/// the full directory tree or MFT. Falls back cleanly with `UsnUnavailable` if unprivileged.
#[cfg(windows)]
pub fn try_read_ntfs_usn_delta(
    drive_root: &Path,
    expected_journal_id: u64,
    start_usn: i64,
    opts: &ScanOptions,
) -> Result<UsnDelta, SourceError> {
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileIdType, GetFinalPathNameByHandleW, OpenFileById, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::Ioctl::{
        FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0,
        USN_JOURNAL_DATA_V0, USN_REASON_FILE_DELETE, USN_RECORD_V2,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let s = drive_root.to_string_lossy();
    let drive_letter = s
        .chars()
        .next()
        .ok_or_else(|| SourceError::UsnUnavailable(s.to_string()))?;
    let vol_path = format!(r"\\.\{drive_letter}:");
    let wide: Vec<u16> = OsStr::new(&vol_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    const GENERIC_READ_FLAG: u32 = 0x8000_0000;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ_FLAG,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(SourceError::UsnUnavailable(vol_path));
    }
    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _vol_guard = HandleGuard(handle);

    let mut journal = USN_JOURNAL_DATA_V0::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            &mut journal as *mut _ as *mut _,
            std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0
        || journal.UsnJournalID != expected_journal_id
        || start_usn < journal.LowestValidUsn
    {
        return Err(SourceError::UsnUnavailable("journal reset or expired".into()));
    }

    let mut read_data = READ_USN_JOURNAL_DATA_V0 {
        StartUsn: start_usn,
        ReasonMask: 0xFFFF_FFFF,
        ReturnOnlyOnClose: 1,
        Timeout: 0,
        BytesToWaitFor: 0,
        UsnJournalID: expected_journal_id,
    };
    let mut buffer = vec![0u8; 256 * 1024];
    let mut parent_cache: HashMap<u64, Option<PathBuf>> = HashMap::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let mut upserts = Vec::new();
    let mut removed_paths = Vec::new();
    let mut cur_usn = start_usn;

    let mut resolve_parent = |parent_frn: u64| -> Option<PathBuf> {
        if let Some(cached) = parent_cache.get(&parent_frn) {
            return cached.clone();
        }
        let desc = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                FileId: parent_frn as i64,
            },
        };
        let ph = unsafe {
            OpenFileById(
                handle,
                &desc,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if ph == INVALID_HANDLE_VALUE || ph.is_null() {
            parent_cache.insert(parent_frn, None);
            return None;
        }
        let mut pbuf = vec![0u16; 4096];
        let len = unsafe {
            GetFinalPathNameByHandleW(ph, pbuf.as_mut_ptr(), pbuf.len() as u32, VOLUME_NAME_DOS)
        };
        unsafe { CloseHandle(ph) };
        if len == 0 || len as usize >= pbuf.len() {
            parent_cache.insert(parent_frn, None);
            return None;
        }
        let raw = String::from_utf16_lossy(&pbuf[..len as usize]);
        let clean = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
        let pb = Some(PathBuf::from(clean));
        parent_cache.insert(parent_frn, pb.clone());
        pb
    };

    while cur_usn < journal.NextUsn {
        read_data.StartUsn = cur_usn;
        let mut bytes_ret = 0u32;
        let rok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                &mut read_data as *mut _ as *mut _,
                std::mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_ret,
                std::ptr::null_mut(),
            )
        };
        if rok == 0 || bytes_ret <= 8 {
            break;
        }
        let next_usn_page = i64::from_le_bytes(buffer[0..8].try_into().unwrap());
        let mut offset = 8usize;
        while offset + std::mem::size_of::<USN_RECORD_V2>() <= bytes_ret as usize {
            let rec = unsafe { &*(buffer.as_ptr().add(offset) as *const USN_RECORD_V2) };
            if rec.RecordLength == 0 || offset + rec.RecordLength as usize > bytes_ret as usize {
                break;
            }
            if rec.MajorVersion == 2 && (rec.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                let is_hidden =
                    (rec.FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
                if opts.include_hidden || !is_hidden {
                    let name_len = rec.FileNameLength as usize / 2;
                    let name_ptr =
                        unsafe { buffer.as_ptr().add(offset + rec.FileNameOffset as usize) as *const u16 };
                    let name = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(name_ptr, name_len)
                    });
                    if let Some(parent_dir) = resolve_parent(rec.ParentFileReferenceNumber) {
                        let full = parent_dir.join(name);
                        if seen_paths.insert(full.clone()) {
                            if (rec.Reason & USN_REASON_FILE_DELETE) != 0 || !full.exists() {
                                removed_paths.push(full);
                            } else if let Ok(meta) = full.metadata() {
                                if meta.is_file() {
                                    let entry = make_entry(full, &meta);
                                    if matches_scan_filter(&entry, &meta, opts) {
                                        upserts.push(entry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            offset += rec.RecordLength as usize;
        }
        if next_usn_page <= cur_usn {
            break;
        }
        cur_usn = next_usn_page;
    }

    Ok(UsnDelta {
        journal_id: journal.UsnJournalID,
        next_usn: journal.NextUsn,
        upserts,
        removed_paths,
    })
}

#[cfg(not(windows))]
pub fn try_read_ntfs_usn_delta(
    drive_root: &Path,
    _expected_journal_id: u64,
    _start_usn: i64,
    _opts: &ScanOptions,
) -> Result<UsnDelta, SourceError> {
    Err(SourceError::UsnUnavailable(drive_root.display().to_string()))
}

/// Fast Win32 NTFS USN/MFT enumeration via `FSCTL_ENUM_USN_DATA` (read-only volume handle).
/// Automatically falls back if current process lacks elevated volume privilege.
#[cfg(windows)]
pub fn try_enumerate_ntfs_usn(
    drive_root: &Path,
    include_hidden: bool,
) -> Result<Vec<DiscoveredFile>, SourceError> {
    let mut opts = ScanOptions::default();
    opts.include_hidden = include_hidden;
    let mut out = Vec::new();
    try_enumerate_ntfs_usn_streaming(drive_root, &opts, &mut |f| {
        out.push(f);
        true
    })?;
    Ok(out)
}

#[cfg(windows)]
fn resolve_mft_dir_cached(
    dir_id: u64,
    root_prefix: &Path,
    dirs: &HashMap<u64, (u64, String)>,
    opts: &ScanOptions,
    cache: &mut HashMap<u64, Option<PathBuf>>,
    depth: usize,
) -> Option<PathBuf> {
    if let Some(cached) = cache.get(&dir_id) {
        return cached.clone();
    }
    if depth > 64 {
        return None;
    }
    let resolved = match dirs.get(&dir_id) {
        Some((parent_id, name)) => {
            if is_dir_name_excluded(name, opts) {
                None
            } else {
                let parent_path = if *parent_id == dir_id || !dirs.contains_key(parent_id) {
                    Some(root_prefix.to_path_buf())
                } else {
                    resolve_mft_dir_cached(*parent_id, root_prefix, dirs, opts, cache, depth + 1)
                };
                parent_path.and_then(|mut p| {
                    p.push(name);
                    if is_excluded_path(&p, opts) {
                        None
                    } else {
                        Some(p)
                    }
                })
            }
        }
        None => Some(root_prefix.to_path_buf()),
    };
    cache.insert(dir_id, resolved.clone());
    resolved
}

/// Fast Win32 NTFS USN/MFT streaming enumeration via `FSCTL_ENUM_USN_DATA` (read-only volume handle).
/// Prunes excluded directories in memory using memoized directory paths BEFORE invoking any disk `metadata()`.
#[cfg(windows)]
fn try_enumerate_ntfs_usn_streaming(
    drive_root: &Path,
    opts: &ScanOptions,
    emit: &mut dyn FnMut(DiscoveredFile) -> bool,
) -> Result<(), SourceError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        FSCTL_ENUM_USN_DATA, MFT_ENUM_DATA_V0, USN_RECORD_V2,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let s = drive_root.to_string_lossy();
    let drive_letter = s
        .chars()
        .next()
        .ok_or_else(|| SourceError::UsnUnavailable(s.to_string()))?;
    let vol_path = format!(r"\\.\{drive_letter}:");
    let wide: Vec<u16> = OsStr::new(&vol_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    const GENERIC_READ_FLAG: u32 = 0x8000_0000;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ_FLAG,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(SourceError::UsnUnavailable(vol_path));
    }

    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    let mut med = MFT_ENUM_DATA_V0 {
        StartFileReferenceNumber: 0,
        LowUsn: 0,
        HighUsn: i64::MAX,
    };
    let mut buffer = vec![0u8; 256 * 1024];
    let mut dirs: HashMap<u64, (u64, String)> = HashMap::new();
    let mut files: Vec<(u64, String)> = Vec::new();

    loop {
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_ENUM_USN_DATA,
                &mut med as *mut _ as *mut _,
                std::mem::size_of::<MFT_ENUM_DATA_V0>() as u32,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || bytes_returned <= 8 {
            break;
        }
        let next_ref = i64::from_le_bytes(buffer[0..8].try_into().unwrap()) as u64;
        let mut offset = 8usize;
        while offset + std::mem::size_of::<USN_RECORD_V2>() <= bytes_returned as usize {
            let rec = unsafe { &*(buffer.as_ptr().add(offset) as *const USN_RECORD_V2) };
            if rec.RecordLength == 0 || offset + rec.RecordLength as usize > bytes_returned as usize {
                break;
            }
            if rec.MajorVersion == 2 {
                let name_bytes = rec.FileNameLength as usize / 2;
                let name_ptr = unsafe { buffer.as_ptr().add(offset + rec.FileNameOffset as usize) as *const u16 };
                let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, name_bytes) };
                let name = String::from_utf16_lossy(name_slice);
                let is_dir = (rec.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                let is_hidden = (rec.FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
                if opts.include_hidden || !is_hidden {
                    if is_dir {
                        dirs.insert(rec.FileReferenceNumber, (rec.ParentFileReferenceNumber, name));
                    } else {
                        files.push((rec.ParentFileReferenceNumber, name));
                    }
                }
            }
            offset += rec.RecordLength as usize;
        }
        med.StartFileReferenceNumber = next_ref;
    }

    let root_path = PathBuf::from(format!(r"{}:\", drive_letter.to_ascii_uppercase()));
    let mut dir_cache: HashMap<u64, Option<PathBuf>> = HashMap::with_capacity(dirs.len().min(65536));
    for (parent_id, name) in files {
        let ext_lower = Path::new(&name)
            .extension()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !matches_name_ext_only(&name, &ext_lower, opts) {
            continue;
        }
        let Some(mut full) = resolve_mft_dir_cached(parent_id, &root_path, &dirs, opts, &mut dir_cache, 0) else {
            continue;
        };
        full.push(&name);
        if let Ok(meta) = full.metadata() {
            if meta.is_file() {
                let disc = make_entry(full, &meta);
                if matches_name_ext_size(&disc, opts) && !emit(disc) {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn try_enumerate_ntfs_usn_streaming(
    drive_root: &Path,
    _opts: &ScanOptions,
    _emit: &mut dyn FnMut(DiscoveredFile) -> bool,
) -> Result<(), SourceError> {
    Err(SourceError::UsnUnavailable(drive_root.display().to_string()))
}

#[cfg(not(windows))]
pub fn try_enumerate_ntfs_usn(
    drive_root: &Path,
    _include_hidden: bool,
) -> Result<Vec<DiscoveredFile>, SourceError> {
    Err(SourceError::UsnUnavailable(drive_root.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_dirs_matches_both_component_names_and_subpaths() {
        let mut opts = ScanOptions::default();
        opts.excluded_dirs = vec![
            "node_modules".into(),
            "Windows\\WinSxS".into(),
            "AppData\\Local\\Temp".into(),
            ".cargo\\registry".into(),
        ];

        assert!(is_excluded_path(Path::new(r"C:\Windows\WinSxS\amd64\foo.manifest"), &opts));
        assert!(is_excluded_path(Path::new(r"C:\Users\YR\AppData\Local\Temp\abc.tmp"), &opts));
        assert!(is_excluded_path(Path::new(r"C:\Users\YR\.cargo\registry\src\a.rs"), &opts));
        assert!(is_excluded_path(Path::new(r"D:\repo\web\node_modules\pkg\index.js"), &opts));
        assert!(!is_excluded_path(Path::new(r"D:\repo\src\main.rs"), &opts));
        assert!(!is_excluded_path(Path::new(r"C:\Users\YR\Documents\contract.docx"), &opts));

        let mut stream_opts = ScanOptions::default();
        stream_opts.excluded_dirs = vec!["node_modules".into()];
        let tmp = std::env::temp_dir().join(format!("deepdoc_stream_fs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("docs")).unwrap();
        std::fs::create_dir_all(tmp.join("node_modules/pkg")).unwrap();
        std::fs::write(tmp.join("docs/a.txt"), b"ok").unwrap();
        std::fs::write(tmp.join("node_modules/pkg/skip.txt"), b"no").unwrap();
        let mut streamed = Vec::new();
        stream_root_with_options(&tmp.to_string_lossy(), &stream_opts, |f| {
            streamed.push(f.file_name);
            true
        });
        assert_eq!(streamed, vec!["a.txt"]);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
