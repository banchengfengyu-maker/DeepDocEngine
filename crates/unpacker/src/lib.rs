use deepdoc_protocol::ParseOptions;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::Command;
use thiserror::Error;

// unrar_sys C++ Win32 calls (RegOpenKeyExW / CryptGenRandom / OpenProcessToken) require advapi32
#[cfg_attr(target_os = "windows", link(name = "advapi32"))]
extern "C" {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Zip,
    SevenZ,
    Rar,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Gzip,
    Bzip2,
    Xz,
    Zst,
    Cab,
    Iso,
}

#[derive(Debug, Error)]
pub enum UnpackError {
    #[error("zip bomb tripped: {0}")]
    ZipBomb(String),
    #[error("archive encrypted: {0}")]
    Encrypted(String),
    #[error("corrupted archive: {0}")]
    Corrupted(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct UnpackedEntry {
    pub inner_path: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct UnpackOutcome {
    pub entries: Vec<UnpackedEntry>,
    pub encrypted_entries: Vec<String>,
    pub warnings: Vec<String>,
    pub archive_encrypted: bool,
    pub zip_bomb_tripped: bool,
}

pub struct UnpackBudget {
    pub total_extracted: u64,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
    pub max_expansion_ratio: u64,
}

impl UnpackBudget {
    pub fn from_options(opts: &ParseOptions) -> Self {
        Self {
            total_extracted: 0,
            max_total_bytes: opts.max_uncompressed_bytes,
            max_single_file_bytes: opts.max_single_file_bytes,
            max_expansion_ratio: opts.max_expansion_ratio.max(1) as u64,
        }
    }

    pub fn check_claim(&mut self, compressed_size: u64, raw_len: u64, label: &str) -> Result<(), UnpackError> {
        if raw_len > self.max_single_file_bytes {
            return Err(UnpackError::ZipBomb(format!(
                "{label}: size {raw_len} exceeds single-file cap {}",
                self.max_single_file_bytes
            )));
        }
        let denom = compressed_size.max(1024);
        if raw_len / denom > self.max_expansion_ratio && raw_len > 10 * 1024 * 1024 {
            return Err(UnpackError::ZipBomb(format!(
                "{label}: expansion ratio {}x exceeds cap {}x",
                raw_len / denom,
                self.max_expansion_ratio
            )));
        }
        if self.total_extracted.saturating_add(raw_len) > self.max_total_bytes {
            return Err(UnpackError::ZipBomb(format!(
                "{label}: cumulative extracted bytes exceed cap {}",
                self.max_total_bytes
            )));
        }
        self.total_extracted += raw_len;
        Ok(())
    }
}

fn read_bounded<R: Read>(
    reader: R,
    compressed_hint: u64,
    label: &str,
    budget: &mut UnpackBudget,
) -> Result<Vec<u8>, UnpackError> {
    let cap = budget
        .max_single_file_bytes
        .min(budget.max_total_bytes.saturating_sub(budget.total_extracted));
    let mut limited = reader.take(cap.saturating_add(1));
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(UnpackError::ZipBomb(format!(
            "{label}: stream exceeded remaining budget {cap} bytes"
        )));
    }
    budget.check_claim(compressed_hint, buf.len() as u64, label)?;
    Ok(buf)
}

pub fn detect_archive_kind(bytes: &[u8], file_name: &str) -> Option<ArchiveKind> {
    if bytes.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some(ArchiveKind::SevenZ);
    }
    if bytes.starts_with(b"Rar!\x1A\x07") {
        return Some(ArchiveKind::Rar);
    }
    if bytes.starts_with(b"\x1F\x8B") {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            return Some(ArchiveKind::TarGz);
        }
        return Some(ArchiveKind::Gzip);
    }
    if bytes.starts_with(b"BZh") {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
            return Some(ArchiveKind::TarBz2);
        }
        return Some(ArchiveKind::Bzip2);
    }
    if bytes.starts_with(b"\xFD7zXZ\x00") {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
            return Some(ArchiveKind::TarXz);
        }
        return Some(ArchiveKind::Xz);
    }
    if bytes.starts_with(b"\x28\xB5\x2F\xFD") {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
            return Some(ArchiveKind::TarZst);
        }
        return Some(ArchiveKind::Zst);
    }
    if bytes.starts_with(b"MSCF") && bytes.len() > 36 {
        return Some(ArchiveKind::Cab);
    }
    if bytes.len() > 32774 && &bytes[32769..32774] == b"CD001" {
        return Some(ArchiveKind::Iso);
    }
    if bytes.len() > 265 && &bytes[257..262] == b"ustar" {
        return Some(ArchiveKind::Tar);
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return Some(ArchiveKind::Zip);
    }
    None
}

pub fn unpack_archive(
    kind: ArchiveKind,
    data: &[u8],
    archive_name: &str,
    passwords: &[String],
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    match kind {
        ArchiveKind::Zip => unpack_zip(data, passwords, budget),
        ArchiveKind::SevenZ => unpack_7z(data, passwords, budget),
        ArchiveKind::Tar => unpack_tar(Cursor::new(data), data.len() as u64, budget),
        ArchiveKind::TarGz => {
            let dec = flate2::read::GzDecoder::new(Cursor::new(data));
            unpack_tar(dec, data.len() as u64, budget)
        }
        ArchiveKind::TarBz2 => {
            let dec = bzip2::read::BzDecoder::new(Cursor::new(data));
            unpack_tar(dec, data.len() as u64, budget)
        }
        ArchiveKind::TarXz => {
            let dec = xz2::read::XzDecoder::new(Cursor::new(data));
            unpack_tar(dec, data.len() as u64, budget)
        }
        ArchiveKind::TarZst => {
            let dec = zstd::stream::read::Decoder::new(Cursor::new(data))
                .map_err(|e| UnpackError::Corrupted(format!("zstd decoder: {e}")))?;
            unpack_tar(dec, data.len() as u64, budget)
        }
        ArchiveKind::Gzip => {
            let dec = flate2::read::GzDecoder::new(Cursor::new(data));
            unpack_single_stream(dec, data.len() as u64, archive_name, ".gz", budget)
        }
        ArchiveKind::Bzip2 => {
            let dec = bzip2::read::BzDecoder::new(Cursor::new(data));
            unpack_single_stream(dec, data.len() as u64, archive_name, ".bz2", budget)
        }
        ArchiveKind::Xz => {
            let dec = xz2::read::XzDecoder::new(Cursor::new(data));
            unpack_single_stream(dec, data.len() as u64, archive_name, ".xz", budget)
        }
        ArchiveKind::Zst => {
            let dec = zstd::stream::read::Decoder::new(Cursor::new(data))
                .map_err(|e| UnpackError::Corrupted(format!("zstd decoder: {e}")))?;
            unpack_single_stream(dec, data.len() as u64, archive_name, ".zst", budget)
        }
        ArchiveKind::Cab => unpack_cab(data, budget),
        ArchiveKind::Iso => unpack_iso9660(data, budget),
        ArchiveKind::Rar => unpack_rar(data, archive_name, passwords, budget),
    }
}

/// Decode raw archive entry filename bytes: keeps valid UTF-8, otherwise decodes
/// legacy Windows/DOS CJK codepages (defaulting to GB18030 for non-UTF-8 CJK entries).
fn decode_archive_entry_name(raw: &[u8]) -> String {
    let text = if let Ok(s) = std::str::from_utf8(raw) {
        s.to_string()
    } else {
        let mut det = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
        det.feed(raw, true);
        let enc = det.guess(None, chardetng::Utf8Detection::Allow);
        // Legacy Chinese Windows ZIP headers are almost always CP936/GBK/GB18030 even when heuristic says Windows-1252.
        let chosen = if enc == encoding_rs::WINDOWS_1252 || enc == encoding_rs::UTF_8 {
            encoding_rs::GB18030
        } else {
            enc
        };
        let (gb, gb_bad) = encoding_rs::GB18030.decode_without_bom_handling(raw);
        if !gb_bad {
            gb.into_owned()
        } else {
            let (dec, _) = chosen.decode_without_bom_handling(raw);
            dec.into_owned()
        }
    };
    text.replace('\\', "/")
        .trim_start_matches('/')
        .trim_end_matches('\0')
        .to_string()
}

fn unpack_zip(
    data: &[u8],
    passwords: &[String],
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|e| UnpackError::Corrupted(format!("zip open failed: {e}")))?;
    let mut outcome = UnpackOutcome::default();

    for idx in 0..archive.len() {
        let (name, is_dir, comp_size, raw_size) = {
            let f = archive
                .by_index_raw(idx)
                .map_err(|e| UnpackError::Corrupted(format!("zip entry {idx}: {e}")))?;
            (
                decode_archive_entry_name(f.name_raw()),
                f.is_dir(),
                f.compressed_size(),
                f.size(),
            )
        };
        if is_dir {
            continue;
        }
        // Pre-flight size check before allocating
        if raw_size > budget.max_single_file_bytes {
            outcome.zip_bomb_tripped = true;
            return Err(UnpackError::ZipBomb(format!(
                "{name}: declared uncompressed size {raw_size} exceeds cap"
            )));
        }

        enum ZipStep {
            Got(Vec<u8>),
            NeedDecrypt,
            Skip(String),
        }
        let step = match archive.by_index(idx) {
            Ok(file) => ZipStep::Got(read_bounded(file, comp_size, &name, budget)?),
            Err(zip::result::ZipError::UnsupportedArchive(_)) => ZipStep::NeedDecrypt,
            Err(e) => ZipStep::Skip(format!("zip entry `{name}` skipped: {e}")),
        };
        match step {
            ZipStep::Got(bytes) => {
                outcome.entries.push(UnpackedEntry {
                    inner_path: name,
                    data: bytes,
                });
            }
            ZipStep::NeedDecrypt => {
                let mut decrypted = None;
                for pwd in passwords {
                    if let Ok(file) = archive.by_index_decrypt(idx, pwd.as_bytes()) {
                        if let Ok(bytes) = read_bounded(file, comp_size, &name, budget) {
                            decrypted = Some(bytes);
                            break;
                        }
                    }
                }
                if let Some(bytes) = decrypted {
                    outcome.entries.push(UnpackedEntry {
                        inner_path: name,
                        data: bytes,
                    });
                } else {
                    outcome.archive_encrypted = true;
                    outcome.encrypted_entries.push(name);
                }
            }
            ZipStep::Skip(w) => {
                outcome.warnings.push(w);
            }
        }
    }
    Ok(outcome)
}

fn unpack_7z(
    data: &[u8],
    passwords: &[String],
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let mut outcome = UnpackOutcome::default();
    let mut pwds: Vec<Option<sevenz_rust2::Password>> = vec![None];
    for p in passwords {
        pwds.push(Some(sevenz_rust2::Password::from(p.as_str())));
    }

    for pwd_opt in pwds {
        let cursor = Cursor::new(data);
        let reader_res = match &pwd_opt {
            None => sevenz_rust2::ArchiveReader::new(cursor, sevenz_rust2::Password::empty()),
            Some(p) => sevenz_rust2::ArchiveReader::new(cursor, p.clone()),
        };
        let mut reader = match reader_res {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                if msg.to_ascii_lowercase().contains("password")
                    || msg.to_ascii_lowercase().contains("encrypted")
                {
                    continue;
                }
                return Err(UnpackError::Corrupted(format!("7z open failed: {msg}")));
            }
        };

        let res = reader.for_each_entries(|entry, rdr| {
            if entry.is_directory() {
                return Ok(true);
            }
            let name = entry.name().to_string();
            let raw_size = entry.size();
            if raw_size > budget.max_single_file_bytes {
                return Err(sevenz_rust2::Error::Other(
                    format!("ZIPBOMB:{name}:{raw_size}").into(),
                ));
            }
            match read_bounded(rdr, (data.len() as u64).max(1), &name, budget) {
                Ok(bytes) => {
                    outcome.entries.push(UnpackedEntry {
                        inner_path: name,
                        data: bytes,
                    });
                    Ok(true)
                }
                Err(UnpackError::ZipBomb(msg)) => {
                    Err(sevenz_rust2::Error::Other(format!("ZIPBOMB:{msg}").into()))
                }
                Err(e) => {
                    outcome.warnings.push(format!("7z `{name}` skipped: {e}"));
                    Ok(true)
                }
            }
        });

        match res {
            Ok(()) => return Ok(outcome),
            Err(e) => {
                let s = e.to_string();
                if s.starts_with("ZIPBOMB:") {
                    outcome.zip_bomb_tripped = true;
                    return Err(UnpackError::ZipBomb(s));
                }
                if s.to_ascii_lowercase().contains("password")
                    || s.to_ascii_lowercase().contains("crc")
                    || s.to_ascii_lowercase().contains("encrypt")
                {
                    outcome.entries.clear();
                    continue;
                }
                return Err(UnpackError::Corrupted(format!("7z read failed: {s}")));
            }
        }
    }

    outcome.archive_encrypted = true;
    Err(UnpackError::Encrypted("7z archive encrypted or wrong password".into()))
}

fn unpack_tar<R: Read>(
    reader: R,
    compressed_size: u64,
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let mut tar = tar::Archive::new(reader);
    let mut outcome = UnpackOutcome::default();
    let entries = tar
        .entries()
        .map_err(|e| UnpackError::Corrupted(format!("tar entries failed: {e}")))?;

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                outcome.warnings.push(format!("tar entry error: {e}"));
                continue;
            }
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path_bytes = entry.path_bytes();
        let path = decode_archive_entry_name(path_bytes.as_ref());
        let bytes = read_bounded(entry, compressed_size, &path, budget)?;
        outcome.entries.push(UnpackedEntry {
            inner_path: path,
            data: bytes,
        });
    }
    Ok(outcome)
}

fn unpack_single_stream<R: Read>(
    reader: R,
    compressed_size: u64,
    archive_name: &str,
    suffix: &str,
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let inner_name = archive_name
        .strip_suffix(suffix)
        .unwrap_or("decompressed.bin")
        .to_string();
    let bytes = read_bounded(reader, compressed_size, &inner_name, budget)?;
    let mut outcome = UnpackOutcome::default();
    outcome.entries.push(UnpackedEntry {
        inner_path: inner_name,
        data: bytes,
    });
    Ok(outcome)
}

/// Built-in native UnRAR extractor (supports RAR3 / RAR4 / RAR5, encrypted headers, and Zip-Bomb checks)
/// with automatic external CLI fallback (`libs/UnRAR.exe` / `libs/7z.exe`).
fn unpack_rar(
    data: &[u8],
    archive_name: &str,
    passwords: &[String],
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return unpack_rar_external(data, archive_name, passwords, budget);
    };
    if std::io::Write::write_all(&mut tmp, data).is_err() {
        return unpack_rar_external(data, archive_name, passwords, budget);
    }

    let try_pwds: Vec<Option<&str>> = std::iter::once(None)
        .chain(passwords.iter().map(|p| Some(p.as_str())))
        .collect();
    let mut saw_encrypted = false;

    for pwd in try_pwds {
        let mut outcome = UnpackOutcome::default();
        let saved_total = budget.total_extracted;
        let arc = match pwd {
            Some(p) => unrar::Archive::with_password(tmp.path(), p.as_bytes()),
            None => unrar::Archive::new(tmp.path()),
        };

        let mut cursor = match arc.open_for_processing() {
            Ok(c) => c,
            Err(e) => {
                if matches!(
                    e.code,
                    unrar::error::Code::MissingPassword
                        | unrar::error::Code::BadPassword
                        | unrar::error::Code::BadData
                ) {
                    saw_encrypted = true;
                    continue;
                }
                break;
            }
        };

        let mut entry_pwd_failed = false;
        let mut unrecoverable_err: Option<String> = None;
        loop {
            match cursor.read_header() {
                Ok(Some(header_cur)) => {
                    let hdr = header_cur.entry();
                    let name = hdr.filename.to_string_lossy().replace('\\', "/");
                    let raw_size = hdr.unpacked_size;
                    let is_dir = hdr.is_directory();
                    let is_enc = hdr.is_encrypted();

                    if is_dir {
                        match header_cur.skip() {
                            Ok(next) => {
                                cursor = next;
                                continue;
                            }
                            Err(e) => {
                                unrecoverable_err = Some(e.to_string());
                                break;
                            }
                        }
                    }

                    if let Err(zerr) = budget.check_claim((data.len() as u64).max(1), raw_size, &name) {
                        return Err(zerr);
                    }

                    match header_cur.read() {
                        Ok((bytes, next)) => {
                            outcome.entries.push(UnpackedEntry {
                                inner_path: name,
                                data: bytes,
                            });
                            cursor = next;
                        }
                        Err(e) => {
                            if is_enc
                                || matches!(
                                    e.code,
                                    unrar::error::Code::MissingPassword
                                        | unrar::error::Code::BadPassword
                                        | unrar::error::Code::BadData
                                )
                            {
                                saw_encrypted = true;
                                entry_pwd_failed = true;
                                outcome.encrypted_entries.push(name);
                                break;
                            }
                            unrecoverable_err = Some(format!("rar entry `{name}` read failed: {e}"));
                            break;
                        }
                    }
                }
                Ok(None) => return Ok(outcome),
                Err(e) => {
                    if matches!(
                        e.code,
                        unrar::error::Code::MissingPassword
                            | unrar::error::Code::BadPassword
                            | unrar::error::Code::BadData
                    ) {
                        saw_encrypted = true;
                        entry_pwd_failed = true;
                        break;
                    }
                    unrecoverable_err = Some(format!("rar header failed: {e}"));
                    break;
                }
            }
        }

        budget.total_extracted = saved_total;
        if entry_pwd_failed {
            continue;
        }
        if let Some(err_msg) = unrecoverable_err {
            if !outcome.entries.is_empty() {
                outcome.warnings.push(err_msg);
                return Ok(outcome);
            }
            break;
        }
    }

    if saw_encrypted {
        return Err(UnpackError::Encrypted(
            "RAR archive is password protected".into(),
        ));
    }

    unpack_rar_external(data, archive_name, passwords, budget)
}

/// Optional external UnRAR plugin slot (`libs/UnRAR.exe` or `libs/7z.exe` next to worker binary).
fn unpack_rar_external(
    data: &[u8],
    archive_name: &str,
    passwords: &[String],
    budget: &mut UnpackBudget,
) -> Result<UnpackOutcome, UnpackError> {
    let mut outcome = UnpackOutcome::default();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let tool = exe_dir.as_ref().and_then(|d| {
        [
            d.join("libs").join("UnRAR.exe"),
            d.join("libs").join("7z.exe"),
            d.join("7z.exe"),
        ]
        .into_iter()
        .find(|p| p.exists())
    });

    let Some(tool_path) = tool else {
        outcome.warnings.push(
            "RAR archive detected; deploy `libs/UnRAR.exe` or `libs/7z.exe` to enable RAR5 extraction".into(),
        );
        return Ok(outcome);
    };

    let tmp_root = std::env::temp_dir().join(format!(
        "deepdoc_rar_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::create_dir_all(&tmp_root);
    let in_file = tmp_root.join(Path::new(archive_name).file_name().unwrap_or_default());
    let out_dir = tmp_root.join("out");
    let _ = std::fs::create_dir_all(&out_dir);
    if let Err(e) = std::fs::write(&in_file, data) {
        let _ = std::fs::remove_dir_all(&tmp_root);
        return Err(UnpackError::Io(e));
    }

    let is_unrar = tool_path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase().contains("unrar"))
        .unwrap_or(false);

    let mut extracted_ok = false;
    let try_pwds: Vec<Option<&str>> = std::iter::once(None)
        .chain(passwords.iter().map(|p| Some(p.as_str())))
        .collect();

    for pwd in try_pwds {
        let mut cmd = Command::new(&tool_path);
        if is_unrar {
            cmd.arg("x").arg("-y").arg("-inul");
            if let Some(p) = pwd {
                cmd.arg(format!("-p{p}"));
            } else {
                cmd.arg("-p-");
            }
            cmd.arg(&in_file).arg(&out_dir);
        } else {
            cmd.arg("x").arg("-y");
            if let Some(p) = pwd {
                cmd.arg(format!("-p{p}"));
            } else {
                cmd.arg("-p");
            }
            cmd.arg(format!("-o{}", out_dir.display())).arg(&in_file);
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                extracted_ok = true;
                break;
            }
        }
    }

    if extracted_ok {
        collect_dir_bounded(&out_dir, &out_dir, data.len() as u64, budget, &mut outcome)?;
    } else {
        outcome.archive_encrypted = true;
        outcome
            .warnings
            .push("RAR extraction failed or password protected".into());
    }

    let _ = std::fs::remove_dir_all(&tmp_root);
    Ok(outcome)
}

fn unpack_cab(data: &[u8], budget: &mut UnpackBudget) -> Result<UnpackOutcome, UnpackError> {
    let mut cabinet = cab::Cabinet::new(Cursor::new(data))
        .map_err(|e| UnpackError::Corrupted(format!("cab open failed: {e}")))?;
    let files: Vec<(String, u64)> = cabinet
        .folder_entries()
        .flat_map(|f| f.file_entries())
        .map(|e| (e.name().to_string(), e.uncompressed_size() as u64))
        .collect();

    let mut outcome = UnpackOutcome::default();
    for (name, raw_size) in files {
        if raw_size > budget.max_single_file_bytes {
            outcome.zip_bomb_tripped = true;
            return Err(UnpackError::ZipBomb(format!(
                "{name}: cab entry size {raw_size} exceeds cap"
            )));
        }
        match cabinet.read_file(&name) {
            Ok(rdr) => {
                let bytes = read_bounded(rdr, (data.len() as u64).max(1), &name, budget)?;
                outcome.entries.push(UnpackedEntry {
                    inner_path: name.replace('\\', "/"),
                    data: bytes,
                });
            }
            Err(e) => {
                outcome
                    .warnings
                    .push(format!("cab entry `{name}` skipped: {e}"));
            }
        }
    }
    Ok(outcome)
}

/// Pure-Rust ISO-9660 & Joliet (UTF-16BE) optical disc image extractor with Zip-Bomb budget guards.
fn unpack_iso9660(data: &[u8], budget: &mut UnpackBudget) -> Result<UnpackOutcome, UnpackError> {
    const SECTOR: usize = 2048;
    let mut outcome = UnpackOutcome::default();
    let mut pvd_root: Option<(u32, u32)> = None;
    let mut joliet_root: Option<(u32, u32)> = None;

    for sec in 16..64usize {
        let off = sec * SECTOR;
        if off + SECTOR > data.len() {
            break;
        }
        let vd = &data[off..off + SECTOR];
        if &vd[1..6] != b"CD001" {
            break;
        }
        let vd_type = vd[0];
        if vd_type == 255 {
            break;
        }
        if vd_type == 1 && vd.len() >= 190 {
            let lba = u32::from_le_bytes([vd[156 + 2], vd[156 + 3], vd[156 + 4], vd[156 + 5]]);
            let size = u32::from_le_bytes([vd[156 + 10], vd[156 + 11], vd[156 + 12], vd[156 + 13]]);
            pvd_root = Some((lba, size));
        } else if vd_type == 2 && vd.len() >= 190 {
            let esc = &vd[88..91];
            if esc == b"%/@" || esc == b"%/C" || esc == b"%/E" {
                let lba = u32::from_le_bytes([vd[156 + 2], vd[156 + 3], vd[156 + 4], vd[156 + 5]]);
                let size = u32::from_le_bytes([vd[156 + 10], vd[156 + 11], vd[156 + 12], vd[156 + 13]]);
                joliet_root = Some((lba, size));
            }
        }
    }

    let (root_lba, root_size, is_joliet) = if let Some((l, s)) = joliet_root {
        (l, s, true)
    } else if let Some((l, s)) = pvd_root {
        (l, s, false)
    } else {
        return Err(UnpackError::Corrupted("no valid ISO9660 volume descriptor".into()));
    };

    walk_iso_dir(data, root_lba, root_size, "", is_joliet, 0, budget, &mut outcome)?;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn walk_iso_dir(
    data: &[u8],
    lba: u32,
    dir_size: u32,
    prefix: &str,
    is_joliet: bool,
    depth: u32,
    budget: &mut UnpackBudget,
    outcome: &mut UnpackOutcome,
) -> Result<(), UnpackError> {
    const SECTOR: usize = 2048;
    if depth > 16 {
        return Ok(());
    }
    let start = (lba as usize).saturating_mul(SECTOR);
    let end = start.saturating_add(dir_size as usize).min(data.len());
    let mut pos = start;

    while pos < end {
        let rec_len = data[pos] as usize;
        if rec_len == 0 {
            let next_sec = ((pos / SECTOR) + 1) * SECTOR;
            if next_sec >= end {
                break;
            }
            pos = next_sec;
            continue;
        }
        if pos + rec_len > end || rec_len < 34 {
            break;
        }
        let rec = &data[pos..pos + rec_len];
        let ext_lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]);
        let ext_len = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]);
        let flags = rec[25];
        let id_len = rec[32] as usize;
        if 33 + id_len <= rec_len {
            let raw_id = &rec[33..33 + id_len];
            if !(id_len == 1 && (raw_id[0] == 0 || raw_id[0] == 1)) {
                let name = if is_joliet {
                    let units: Vec<u16> = raw_id
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&units)
                } else {
                    decode_archive_entry_name(raw_id)
                };
                let clean_name = name.split(';').next().unwrap_or(&name).to_string();
                let full_path = if prefix.is_empty() {
                    clean_name.clone()
                } else {
                    format!("{prefix}/{clean_name}")
                };

                if (flags & 0x02) != 0 {
                    walk_iso_dir(data, ext_lba, ext_len, &full_path, is_joliet, depth + 1, budget, outcome)?;
                } else {
                    let f_start = (ext_lba as usize).saturating_mul(SECTOR);
                    let f_len = ext_len as usize;
                    if f_start + f_len <= data.len() {
                        budget.check_claim((f_len as u64).max(1), f_len as u64, &full_path)?;
                        outcome.entries.push(UnpackedEntry {
                            inner_path: full_path,
                            data: data[f_start..f_start + f_len].to_vec(),
                        });
                    }
                }
            }
        }
        pos += rec_len;
    }
    Ok(())
}

fn collect_dir_bounded(
    base: &Path,
    dir: &Path,
    comp_hint: u64,
    budget: &mut UnpackBudget,
    outcome: &mut UnpackOutcome,
) -> Result<(), UnpackError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_dir_bounded(base, &p, comp_hint, budget, outcome)?;
        } else if p.is_file() {
            let rel = decode_archive_entry_name(
                p.strip_prefix(base).unwrap_or(&p).as_os_str().as_encoded_bytes(),
            );
            let bytes = std::fs::read(&p)?;
            budget.check_claim(comp_hint, bytes.len() as u64, &rel)?;
            outcome.entries.push(UnpackedEntry {
                inner_path: rel,
                data: bytes,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_gbk_non_utf8_archive_entry_names() {
        let (gbk_bytes, _, _) = encoding_rs::GB18030.encode(r"申请\报告-新.docx");
        assert_eq!(decode_archive_entry_name(&gbk_bytes), "申请/报告-新.docx");
        assert_eq!(
            decode_archive_entry_name("正常目录/测试文件.pdf".as_bytes()),
            "正常目录/测试文件.pdf"
        );
    }
}
