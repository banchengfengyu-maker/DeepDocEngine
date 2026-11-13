use crate::sniffer::DetectedFormat;
use crate::text::build_head_tail_segment;
use deepdoc_protocol::{SegmentScope, TextSegment};
use lopdf::{Document, Object};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct TempDirGuard(pub PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn new_sandbox_temp_dir(tag: &str) -> std::io::Result<TempDirGuard> {
    let dir = std::env::temp_dir().join(format!(
        "deepdoc_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(TempDirGuard(dir))
}

pub fn find_native_asset(env_var: &str, rel_candidates: &[&str]) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|d| d.to_path_buf());
        for _ in 0..5 {
            if let Some(dir) = cur {
                roots.push(dir.clone());
                roots.push(dir.join("native_deps"));
                cur = dir.parent().map(|p| p.to_path_buf());
            } else {
                break;
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut cur = Some(cwd);
        for _ in 0..4 {
            if let Some(dir) = cur {
                roots.push(dir.clone());
                roots.push(dir.join("native_deps"));
                cur = dir.parent().map(|p| p.to_path_buf());
            } else {
                break;
            }
        }
    }
    for root in roots {
        for rel in rel_candidates {
            let candidate = root.join(rel);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn find_x2t_binary() -> Option<PathBuf> {
    find_native_asset(
        "ONLYOFFICE_X2T_PATH",
        &["libs\\x2t\\x2t.exe", "libs\\x2t.exe", "x2t.exe"],
    )
}

pub fn find_pdfium_dll() -> Option<PathBuf> {
    find_native_asset("PDFIUM_DLL_PATH", &["libs\\pdfium.dll", "pdfium.dll"])
}

/// Attempt `[MS-OFFCRYPTO]` decryption of an encrypted OOXML or legacy binary Office container
/// using empty password `""` (restricted-edit/open) plus configured passwords.
pub fn try_decrypt_ms_office(
    bytes: &[u8],
    is_ooxml_or_unknown: bool,
    passwords: &[String],
) -> Option<Vec<u8>> {
    let candidates: Vec<&str> = std::iter::once("")
        .chain(passwords.iter().map(|s| s.as_str()))
        .collect();

    for pwd in candidates {
        if is_ooxml_or_unknown {
            if let Ok(dec) = msoffice_crypto::decrypt_ooxml(bytes, pwd) {
                return Some(dec);
            }
        }
        if let Ok(dec) = msoffice_crypto::decrypt_binary_office(bytes, pwd) {
            return Some(dec);
        }
    }
    None
}

pub fn convert_via_onlyoffice_x2t(
    bytes: &[u8],
    format: &DetectedFormat,
) -> Result<(DetectedFormat, Vec<u8>), String> {
    let Some(x2t_path) = find_x2t_binary() else {
        return Err("missing_x2t".into());
    };

    let (in_ext, out_fmt, out_ext) = match format {
        DetectedFormat::Doc => ("doc", DetectedFormat::Docx, "docx"),
        DetectedFormat::Wps => ("wps", DetectedFormat::Docx, "docx"),
        DetectedFormat::Ppt => ("ppt", DetectedFormat::Pptx, "pptx"),
        DetectedFormat::Dps => ("dps", DetectedFormat::Pptx, "pptx"),
        DetectedFormat::Et => ("et", DetectedFormat::Xlsx, "xlsx"),
        _ => return Err("unsupported format for x2t".into()),
    };

    let guard = new_sandbox_temp_dir("x2t").map_err(|e| format!("temp dir failed: {e}"))?;
    let in_file = guard.0.join(format!("input.{in_ext}"));
    let out_file = guard.0.join(format!("output.{out_ext}"));
    let params_xml = guard.0.join("params.xml");

    std::fs::write(&in_file, bytes).map_err(|e| format!("write x2t input: {e}"))?;
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <TaskQueueDataConvert xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n\
           <m_sFileFrom>{}</m_sFileFrom>\n\
           <m_sFileTo>{}</m_sFileTo>\n\
           <m_bIsNoBase64>true</m_bIsNoBase64>\n\
         </TaskQueueDataConvert>",
        in_file.display(),
        out_file.display()
    );
    std::fs::write(&params_xml, xml).map_err(|e| format!("write x2t params: {e}"))?;

    let output = Command::new(&x2t_path)
        .arg(&params_xml)
        .current_dir(x2t_path.parent().unwrap_or_else(|| Path::new(".")))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("spawn x2t.exe failed: {e}"))?;

    if !output.status.success() || !out_file.exists() {
        let err_tail = String::from_utf8_lossy(&output.stderr);
        return Err(format!("x2t.exe exited with status {} ({})", output.status, err_tail.trim()));
    }

    let converted = std::fs::read(&out_file).map_err(|e| format!("read x2t output: {e}"))?;
    Ok((out_fmt, converted))
}

pub struct PdfParseOutcome {
    pub segments: Vec<TextSegment>,
    pub embedded_images: Vec<(String, Vec<u8>)>,
    pub deferred_scan_pages: Vec<usize>,
    pub encrypted_locked: bool,
    pub warnings: Vec<String>,
}

/// Unified PDF extractor:
/// 1. Uses `libs/pdfium.dll` dynamically when deployed (including page rendering for scanned pages);
/// 2. Otherwise uses `lopdf` (FlateDecode streams, ToUnicode CJK, Info metadata, password unlock,
///    and embedded XObject image extraction);
/// 3. Falls back to raw stream scanner if `lopdf` hits a malformed PDF.
pub fn parse_pdf_document(bytes: &[u8], passwords: &[String]) -> PdfParseOutcome {
    parse_pdf_document_mode(bytes, passwords, true)
}

/// Parse PDF with explicit control over whether scanned pages (< 20 text chars) are bitmap-rendered
/// immediately (`render_scan_pages = true`) or recorded as `deferred_scan_pages` for Stage-2 OCR.
pub fn parse_pdf_document_mode(
    bytes: &[u8],
    passwords: &[String],
    render_scan_pages: bool,
) -> PdfParseOutcome {
    parse_pdf_document_mode_ext(bytes, passwords, render_scan_pages, true)
}

fn decode_pdf_raw_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) && bytes.len() >= 2 {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn extract_pdf_with_pdf_oxide(
    bytes: &[u8],
    passwords: &[String],
) -> Result<PdfParseOutcome, String> {
    let doc = pdf_oxide::PdfDocument::from_bytes(bytes.to_vec())
        .map_err(|e| format!("pdf_oxide init error: {e}"))?;

    if doc.is_encrypted() {
        let mut unlocked = false;
        for pw in passwords {
            if doc.authenticate(pw.as_bytes()).unwrap_or(false) {
                unlocked = true;
                break;
            }
        }
        if !unlocked {
            return Ok(PdfParseOutcome {
                segments: Vec::new(),
                embedded_images: Vec::new(),
                deferred_scan_pages: Vec::new(),
                encrypted_locked: true,
                warnings: vec!["PDF 已加密受保护，未提供匹配密码（pdf_oxide）".into()],
            });
        }
    }

    let page_count = doc.page_count().unwrap_or(0);
    if page_count == 0 {
        return Err("empty pages".into());
    }

    let mut segments = Vec::new();
    let mut deferred_scan_pages = Vec::new();

    // Extract Document Information (Title, Author, Subject, Keywords, Creator, Producer)
    let mut meta_lines = Vec::new();
    if let Some(trailer_dict) = doc.trailer().as_dict() {
        if let Some(info_obj) = trailer_dict.get("Info") {
            if let Ok(resolved_info) = doc.resolve_references(info_obj, 3) {
                if let Some(info_dict) = resolved_info.as_dict() {
                    for key in ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"] {
                        if let Some(val_obj) = info_dict.get(key) {
                            if let Ok(resolved_val) = doc.resolve_references(val_obj, 3) {
                                if let Some(bytes) = resolved_val.as_string() {
                                    let s = decode_pdf_raw_bytes(bytes);
                                    let trimmed = s.trim();
                                    if !trimmed.is_empty() {
                                        meta_lines.push(format!("{key}: {trimmed}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !meta_lines.is_empty() {
        segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "PDF 文档信息".into(),
            text: meta_lines.join("\n"),
        });
    }

    for page_idx in 0..page_count {
        let text = doc.extract_text(page_idx).unwrap_or_default();
        let trimmed = text.trim();
        let char_count = trimmed.chars().count();

        if char_count < 20 {
            deferred_scan_pages.push(page_idx);
        }

        if !trimmed.is_empty() {
            segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: format!("第 {} 页", page_idx + 1),
                text,
            });
        }
    }

    if let Some(first_seg) = segments.iter().find(|s| s.scope == SegmentScope::Body) {
        if let Some(ht) = build_head_tail_segment(&first_seg.text) {
            segments.insert(0, ht);
        }
    }

    Ok(PdfParseOutcome {
        segments,
        embedded_images: Vec::new(),
        deferred_scan_pages,
        encrypted_locked: false,
        warnings: Vec::new(),
    })
}

pub fn parse_pdf_document_mode_ext(
    bytes: &[u8],
    passwords: &[String],
    render_scan_pages: bool,
    extract_images: bool,
) -> PdfParseOutcome {
    // 1. Ultra-fast pure-Rust pdf_oxide parser (0.8ms mean, zero C++ DLL / lock contention)
    if let Ok(mut outcome) = extract_pdf_with_pdf_oxide(bytes, passwords) {
        if outcome.encrypted_locked {
            return outcome;
        }

        #[cfg(windows)]
        if render_scan_pages && !outcome.deferred_scan_pages.is_empty() {
            if let Ok(rendered) = render_pdf_scan_pages(bytes, passwords, &outcome.deferred_scan_pages) {
                outcome.embedded_images.extend(rendered);
            }
        }

        #[cfg(windows)]
        if extract_images
            && bytes.len() <= 16 * 1024 * 1024
            && outcome.embedded_images.is_empty()
        {
            if let Ok(doc) = load_lopdf_with_passwords(bytes, passwords) {
                collect_lopdf_xobject_images(&doc, &mut outcome.embedded_images);
            }
        }

        if !outcome.segments.is_empty() || !outcome.deferred_scan_pages.is_empty() {
            return outcome;
        }
    }

    #[cfg(windows)]
    if let Some(dll_path) = find_pdfium_dll() {
        match extract_pdf_with_pdfium(&dll_path, bytes, passwords, render_scan_pages) {
            Ok(mut outcome) => {
                // Only run secondary lopdf XObject image inspection when image/OCR extraction is actually requested
                if extract_images
                    && !outcome.encrypted_locked
                    && bytes.len() <= 16 * 1024 * 1024
                    && outcome.embedded_images.is_empty()
                    && outcome.deferred_scan_pages.is_empty()
                {
                    if let Ok(doc) = load_lopdf_with_passwords(bytes, passwords) {
                        collect_lopdf_xobject_images(&doc, &mut outcome.embedded_images);
                    }
                }
                return outcome;
            }
            Err(err) => {
                let mut fb = extract_pdf_with_lopdf(bytes, passwords);
                fb.warnings
                    .insert(0, format!("pdfium.dll 调用失败 ({err})，已切换 lopdf 内置解析"));
                return fb;
            }
        }
    }

    extract_pdf_with_lopdf(bytes, passwords)
}

/// Render specific 0-based PDF page indices to PNGs for Stage-2 OCR (shared PDFium pipeline).
pub fn render_pdf_scan_pages(
    bytes: &[u8],
    passwords: &[String],
    page_indices: &[usize],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    #[cfg(windows)]
    {
        let Some(dll_path) = find_pdfium_dll() else {
            return Ok(Vec::new());
        };
        let _pdfium_guard = PDFIUM_LOCK
            .lock()
            .map_err(|_| "pdfium lock poisoned".to_string())?;
        let api = get_pdfium_api(&dll_path)?;
        let Some(doc) = open_pdfium_mem_doc(api, bytes, passwords)? else {
            return Ok(Vec::new());
        };
        let page_count = unsafe { (api.count_pages)(doc) }.max(0) as usize;
        let mut out = Vec::with_capacity(page_indices.len());
        for &idx in page_indices {
            if idx >= page_count {
                continue;
            }
            let page = unsafe { (api.load_page)(doc, idx as std::ffi::c_int) };
            if page.is_null() {
                continue;
            }
            if let Some(png) = render_pdfium_page_png(api, page) {
                out.push((format!("pdf_scan_page_{}.png", idx + 1), png));
            }
            unsafe { (api.close_page)(page) };
        }
        unsafe { (api.close_doc)(doc) };
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        let _ = (bytes, passwords, page_indices);
        Ok(Vec::new())
    }
}

fn load_lopdf_with_passwords(bytes: &[u8], passwords: &[String]) -> Result<Document, String> {
    match Document::load_mem(bytes) {
        Ok(doc) => {
            if !doc.is_encrypted() {
                return Ok(doc);
            }
            for pwd in std::iter::once("").chain(passwords.iter().map(|s| s.as_str())) {
                let mut d = doc.clone();
                if d.decrypt(pwd).is_ok() {
                    return Ok(d);
                }
            }
            Err("encrypted_locked".into())
        }
        Err(e) => {
            for pwd in std::iter::once("").chain(passwords.iter().map(|s| s.as_str())) {
                if let Ok(d) = Document::load_mem_with_options(bytes, lopdf::LoadOptions::with_password(pwd)) {
                    return Ok(d);
                }
            }
            Err(e.to_string())
        }
    }
}

fn extract_pdf_with_lopdf(bytes: &[u8], passwords: &[String]) -> PdfParseOutcome {
    let mut outcome = PdfParseOutcome {
        segments: Vec::new(),
        embedded_images: Vec::new(),
        deferred_scan_pages: Vec::new(),
        encrypted_locked: false,
        warnings: Vec::new(),
    };

    let doc = match load_lopdf_with_passwords(bytes, passwords) {
        Ok(d) => d,
        Err(e) if e == "encrypted_locked" => {
            outcome.encrypted_locked = true;
            outcome.warnings.push("PDF 受密码保护且未能解密".into());
            return outcome;
        }
        Err(e) => {
            let mut raw = extract_pdf_fallback_streams(bytes);
            if bytes[..bytes.len().min(128 * 1024)]
                .windows(8)
                .any(|w| w == b"/Encrypt")
            {
                raw.encrypted_locked = true;
            }
            raw.warnings
                .push(format!("lopdf 解析受限 ({e})，已使用基础文本流回退"));
            return raw;
        }
    };

    // 1. /Info metadata
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok((_, Object::Dictionary(dict))) = doc.dereference(info_ref) {
            let mut meta_lines = Vec::new();
            for key in [b"Title".as_slice(), b"Author", b"Subject", b"Keywords", b"Creator"] {
                if let Ok(obj) = dict.get(key) {
                    if let Ok(s) = decode_pdf_string_obj(&doc, obj) {
                        if !s.trim().is_empty() {
                            meta_lines.push(format!("{}: {}", String::from_utf8_lossy(key), s.trim()));
                        }
                    }
                }
            }
            if !meta_lines.is_empty() {
                outcome.segments.push(TextSegment {
                    scope: SegmentScope::Metadata,
                    location_label: "PDF 文档信息".into(),
                    text: meta_lines.join("\n"),
                });
            }
        }
    }

    // 2. Per-page text extraction
    let pages = doc.get_pages();
    let mut all_text = String::new();
    for (&page_num, &_page_id) in &pages {
        if let Ok(txt) = doc.extract_text_with_limit(&[page_num], 16 * 1024 * 1024) {
            let trimmed = txt.trim();
            if !trimmed.is_empty() {
                all_text.push_str(trimmed);
                all_text.push('\n');
                outcome.segments.push(TextSegment {
                    scope: SegmentScope::Body,
                    location_label: format!("PDF 第{page_num}页"),
                    text: trimmed.to_string(),
                });
            }
        }
    }

    if let Some(ht) = build_head_tail_segment(&all_text) {
        outcome.segments.insert(0, ht);
    }

    // 3. Embedded XObject image extraction for OCR (bounded on moderate PDFs)
    if bytes.len() <= 32 * 1024 * 1024 {
        collect_lopdf_xobject_images(&doc, &mut outcome.embedded_images);
    }

    outcome
}

fn decode_pdf_string_obj(doc: &Document, obj: &Object) -> Result<String, ()> {
    let (_, resolved) = doc.dereference(obj).map_err(|_| ())?;
    if let Object::String(bytes, _) = resolved {
        if bytes.starts_with(&[0xFE, 0xFF]) && bytes.len() >= 2 {
            let units: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            return Ok(String::from_utf16_lossy(&units));
        }
        return Ok(String::from_utf8_lossy(bytes).into_owned());
    }
    Err(())
}

fn collect_lopdf_xobject_images(doc: &Document, out: &mut Vec<(String, Vec<u8>)>) {
    let pages = doc.get_pages();
    for (&page_num, &page_id) in &pages {
        let Ok(imgs) = doc.get_page_images(page_id) else {
            continue;
        };
        for (idx, im) in imgs.into_iter().enumerate() {
            if im.width < 24 || im.height < 24 {
                continue;
            }
            let filters = im.filters.unwrap_or_default();
            if filters.iter().any(|f| f == "DCTDecode") {
                out.push((format!("pdf_p{page_num}_img{}.jpg", idx + 1), im.content.to_vec()));
            } else if filters.iter().any(|f| f == "FlateDecode")
                && im.bits_per_component.unwrap_or(8) == 8
                && im.width > 0
                && im.height > 0
            {
                let dec = flate2::read::ZlibDecoder::new(Cursor::new(im.content));
                let mut raw = Vec::new();
                if dec.take(32 * 1024 * 1024).read_to_end(&mut raw).is_ok() {
                    let w = im.width as u32;
                    let h = im.height as u32;
                    let cs = im.color_space.as_deref().unwrap_or("");
                    let dyn_opt = if cs.contains("RGB") && raw.len() == (w * h * 3) as usize {
                        image::RgbImage::from_raw(w, h, raw).map(image::DynamicImage::ImageRgb8)
                    } else if cs.contains("Gray") && raw.len() == (w * h) as usize {
                        image::GrayImage::from_raw(w, h, raw).map(image::DynamicImage::ImageLuma8)
                    } else {
                        None
                    };
                    if let Some(di) = dyn_opt {
                        let mut png_buf = Cursor::new(Vec::new());
                        if di.write_to(&mut png_buf, image::ImageFormat::Png).is_ok() {
                            out.push((format!("pdf_p{page_num}_img{}.png", idx + 1), png_buf.into_inner()));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
struct PdfiumApi {
    _hmod: windows_sys::Win32::Foundation::HMODULE,
    load_mem: unsafe extern "C" fn(
        *const std::ffi::c_void,
        std::ffi::c_int,
        *const std::ffi::c_char,
    ) -> *mut std::ffi::c_void,
    close_doc: unsafe extern "C" fn(*mut std::ffi::c_void),
    count_pages: unsafe extern "C" fn(*mut std::ffi::c_void) -> std::ffi::c_int,
    get_meta: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *const std::ffi::c_char,
        *mut std::ffi::c_void,
        std::ffi::c_ulong,
    ) -> std::ffi::c_ulong,
    load_page: unsafe extern "C" fn(*mut std::ffi::c_void, std::ffi::c_int) -> *mut std::ffi::c_void,
    close_page: unsafe extern "C" fn(*mut std::ffi::c_void),
    page_w: unsafe extern "C" fn(*mut std::ffi::c_void) -> f64,
    page_h: unsafe extern "C" fn(*mut std::ffi::c_void) -> f64,
    text_load: unsafe extern "C" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void,
    text_close: unsafe extern "C" fn(*mut std::ffi::c_void),
    text_count: unsafe extern "C" fn(*mut std::ffi::c_void) -> std::ffi::c_int,
    text_get: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        std::ffi::c_int,
        std::ffi::c_int,
        *mut u16,
    ) -> std::ffi::c_int,
    bmp_create: unsafe extern "C" fn(
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
    ) -> *mut std::ffi::c_void,
    bmp_fill: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
        u32,
    ),
    bmp_render: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
        std::ffi::c_int,
    ),
    bmp_buf: unsafe extern "C" fn(*mut std::ffi::c_void) -> *const u8,
    bmp_stride: unsafe extern "C" fn(*mut std::ffi::c_void) -> std::ffi::c_int,
    bmp_destroy: unsafe extern "C" fn(*mut std::ffi::c_void),
    last_err: unsafe extern "C" fn() -> std::ffi::c_uint,
}

#[cfg(windows)]
// SAFETY: All calls through `PdfiumApi` are serialized by `PDFIUM_LOCK` below.
unsafe impl Send for PdfiumApi {}
#[cfg(windows)]
// SAFETY: All calls through `PdfiumApi` are serialized by `PDFIUM_LOCK` below.
unsafe impl Sync for PdfiumApi {}

#[cfg(windows)]
fn get_pdfium_api(dll_path: &Path) -> Result<&'static PdfiumApi, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    static PDFIUM_API: OnceLock<Result<PdfiumApi, String>> = OnceLock::new();

    PDFIUM_API
        .get_or_init(|| {
            let wide: Vec<u16> = OsStr::new(dll_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let hmod = unsafe { LoadLibraryW(wide.as_ptr()) };
            if hmod.is_null() {
                return Err("LoadLibraryW failed".into());
            }

            macro_rules! load_fn {
                ($name:literal, $ty:ty) => {{
                    let ptr = unsafe { GetProcAddress(hmod, concat!($name, "\0").as_ptr()) };
                    if ptr.is_none() {
                        return Err(format!("missing symbol {}", $name));
                    }
                    unsafe { std::mem::transmute::<_, $ty>(ptr.unwrap()) }
                }};
            }

            type FnInit = unsafe extern "C" fn();
            let f_init = load_fn!("FPDF_InitLibrary", FnInit);
            let api = PdfiumApi {
                _hmod: hmod,
                load_mem: load_fn!("FPDF_LoadMemDocument", _),
                close_doc: load_fn!("FPDF_CloseDocument", _),
                count_pages: load_fn!("FPDF_GetPageCount", _),
                get_meta: load_fn!("FPDF_GetMetaText", _),
                load_page: load_fn!("FPDF_LoadPage", _),
                close_page: load_fn!("FPDF_ClosePage", _),
                page_w: load_fn!("FPDF_GetPageWidth", _),
                page_h: load_fn!("FPDF_GetPageHeight", _),
                text_load: load_fn!("FPDFText_LoadPage", _),
                text_close: load_fn!("FPDFText_ClosePage", _),
                text_count: load_fn!("FPDFText_CountChars", _),
                text_get: load_fn!("FPDFText_GetText", _),
                bmp_create: load_fn!("FPDFBitmap_Create", _),
                bmp_fill: load_fn!("FPDFBitmap_FillRect", _),
                bmp_render: load_fn!("FPDF_RenderPageBitmap", _),
                bmp_buf: load_fn!("FPDFBitmap_GetBuffer", _),
                bmp_stride: load_fn!("FPDFBitmap_GetStride", _),
                bmp_destroy: load_fn!("FPDFBitmap_Destroy", _),
                last_err: load_fn!("FPDF_GetLastError", _),
            };
            // Initialize once per worker process to avoid repeated FreeLibrary/FPDF_DestroyLibrary churn.
            unsafe { f_init() };
            Ok(api)
        })
        .as_ref()
        .map_err(|e| e.clone())
}

#[cfg(windows)]
static PDFIUM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(windows)]
fn open_pdfium_mem_doc(
    api: &PdfiumApi,
    bytes: &[u8],
    passwords: &[String],
) -> Result<Option<*mut std::ffi::c_void>, String> {
    use std::ffi::{c_int, c_void, CString};
    let mut doc = unsafe { (api.load_mem)(bytes.as_ptr() as *const c_void, bytes.len() as c_int, std::ptr::null()) };
    let mut last_err = if doc.is_null() { unsafe { (api.last_err)() } } else { 0 };

    if doc.is_null() && last_err == 4 {
        for pwd in std::iter::once("").chain(passwords.iter().map(|s| s.as_str())) {
            if let Ok(cpwd) = CString::new(pwd) {
                doc = unsafe {
                    (api.load_mem)(
                        bytes.as_ptr() as *const c_void,
                        bytes.len() as c_int,
                        cpwd.as_ptr(),
                    )
                };
                if !doc.is_null() {
                    last_err = 0;
                    break;
                }
                last_err = unsafe { (api.last_err)() };
            }
        }
    }

    if doc.is_null() {
        if last_err == 4 {
            return Ok(None);
        }
        return Err(format!("FPDF_LoadMemDocument error code {last_err}"));
    }
    Ok(Some(doc))
}

#[cfg(windows)]
fn render_pdfium_page_png(api: &PdfiumApi, page: *mut std::ffi::c_void) -> Option<Vec<u8>> {
    use std::ffi::c_int;
    let pw = unsafe { (api.page_w)(page) };
    let ph = unsafe { (api.page_h)(page) };
    let scale = 1.5f64;
    let bw = (pw * scale).round().clamp(64.0, 1800.0) as c_int;
    let bh = (ph * scale).round().clamp(64.0, 2400.0) as c_int;
    let bmp = unsafe { (api.bmp_create)(bw, bh, 0) };
    if bmp.is_null() {
        return None;
    }
    let png_out = unsafe {
        (api.bmp_fill)(bmp, 0, 0, bw, bh, 0xFFFF_FFFF);
        (api.bmp_render)(bmp, page, 0, 0, bw, bh, 0, 0);
        let ptr = (api.bmp_buf)(bmp);
        let stride = (api.bmp_stride)(bmp) as usize;
        let mut res = None;
        if !ptr.is_null() && stride >= (bw as usize) * 4 {
            let raw = std::slice::from_raw_parts(ptr, stride * (bh as usize));
            let mut rgba = Vec::with_capacity((bw as usize) * (bh as usize) * 4);
            for y in 0..(bh as usize) {
                let row = &raw[y * stride..y * stride + (bw as usize) * 4];
                for bgra in row.chunks_exact(4) {
                    rgba.extend_from_slice(&[bgra[2], bgra[1], bgra[0], bgra[3]]);
                }
            }
            if let Some(im) = image::RgbaImage::from_raw(bw as u32, bh as u32, rgba) {
                let mut png_buf = Cursor::new(Vec::new());
                if image::DynamicImage::ImageRgba8(im)
                    .write_to(&mut png_buf, image::ImageFormat::Png)
                    .is_ok()
                {
                    res = Some(png_buf.into_inner());
                }
            }
        }
        (api.bmp_destroy)(bmp);
        res
    };
    png_out
}

#[cfg(windows)]
fn extract_pdf_with_pdfium(
    dll_path: &Path,
    bytes: &[u8],
    passwords: &[String],
    render_scan_pages: bool,
) -> Result<PdfParseOutcome, String> {
    use std::ffi::{c_int, c_void, CString};

    // PDFium library init/destroy and page state are not re-entrant across concurrent threads.
    let _pdfium_guard = PDFIUM_LOCK.lock().map_err(|_| "pdfium lock poisoned".to_string())?;
    let api = get_pdfium_api(dll_path)?;

    let f_close_doc = api.close_doc;
    let f_count_pages = api.count_pages;
    let f_get_meta = api.get_meta;
    let f_load_page = api.load_page;
    let f_close_page = api.close_page;
    let f_text_load = api.text_load;
    let f_text_close = api.text_close;
    let f_text_count = api.text_count;
    let f_text_get = api.text_get;

    let Some(doc) = open_pdfium_mem_doc(api, bytes, passwords)? else {
        return Ok(PdfParseOutcome {
            segments: Vec::new(),
            embedded_images: Vec::new(),
            deferred_scan_pages: Vec::new(),
            encrypted_locked: true,
            warnings: vec!["PDF 受密码保护，配置密码均未解锁（PDFium）".into()],
        });
    };

    let page_count = unsafe { f_count_pages(doc) }.max(0) as usize;
    let mut segments = Vec::new();
    let mut embedded_images = Vec::new();
    let mut deferred_scan_pages = Vec::new();
    let warnings = Vec::new();
    let mut all_text = String::new();

    let mut meta_lines = Vec::new();
    for tag in ["Title", "Author", "Subject", "Keywords", "Creator"] {
        if let Ok(ctag) = CString::new(tag) {
            let need_bytes = unsafe { f_get_meta(doc, ctag.as_ptr(), std::ptr::null_mut(), 0) };
            if need_bytes > 2 && need_bytes <= 65536 {
                let mut u16_buf = vec![0u16; (need_bytes as usize) / 2 + 1];
                let got = unsafe {
                    f_get_meta(
                        doc,
                        ctag.as_ptr(),
                        u16_buf.as_mut_ptr() as *mut c_void,
                        need_bytes,
                    )
                };
                if got > 2 {
                    let s = String::from_utf16_lossy(&u16_buf[..((got as usize) / 2).saturating_sub(1)]);
                    if !s.trim().is_empty() {
                        meta_lines.push(format!("{tag}: {}", s.trim()));
                    }
                }
            }
        }
    }
    if !meta_lines.is_empty() {
        segments.push(TextSegment {
            scope: SegmentScope::Metadata,
            location_label: "PDF 文档属性 (PDFium)".into(),
            text: meta_lines.join("\n"),
        });
    }

    for i in 0..page_count {
        let page = unsafe { f_load_page(doc, i as c_int) };
        if page.is_null() {
            continue;
        }
        let tp = unsafe { f_text_load(page) };
        let mut page_text = String::new();
        if !tp.is_null() {
            let nchars = unsafe { f_text_count(tp) };
            if nchars > 0 {
                let mut u16_buf = vec![0u16; (nchars as usize) + 2];
                let written = unsafe { f_text_get(tp, 0, nchars, u16_buf.as_mut_ptr()) };
                if written > 1 {
                    page_text = String::from_utf16_lossy(&u16_buf[..(written as usize - 1)]);
                }
            }
            unsafe { f_text_close(tp) };
        }

        let trimmed = page_text.trim();
        if trimmed.chars().filter(|c| !c.is_whitespace()).count() < 20 {
            if render_scan_pages {
                if let Some(png) = render_pdfium_page_png(api, page) {
                    embedded_images.push((format!("pdf_scan_page_{}.png", i + 1), png));
                }
            } else {
                deferred_scan_pages.push(i);
            }
        }
        unsafe { f_close_page(page) };

        if !trimmed.is_empty() {
            all_text.push_str(trimmed);
            all_text.push('\n');
            segments.push(TextSegment {
                scope: SegmentScope::Body,
                location_label: format!("PDF 第{}页", i + 1),
                text: trimmed.to_string(),
            });
        }
    }

    if let Some(ht) = build_head_tail_segment(&all_text) {
        let insert_idx = usize::from(!meta_lines.is_empty());
        segments.insert(insert_idx, ht);
    }

    unsafe {
        f_close_doc(doc);
    }

    Ok(PdfParseOutcome {
        segments,
        embedded_images,
        deferred_scan_pages,
        encrypted_locked: false,
        warnings,
    })
}

fn extract_pdf_fallback_streams(bytes: &[u8]) -> PdfParseOutcome {
    let mut segments = Vec::new();
    let mut text = String::new();
    let mut i = 0usize;
    let mut in_paren = false;
    let mut escaped = false;
    let mut cur = Vec::<u8>::new();

    while i < bytes.len() {
        let b = bytes[i];
        if !in_paren {
            if b == b'(' {
                in_paren = true;
                cur.clear();
            }
        } else if escaped {
            let pushed = match b {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                other => other,
            };
            cur.push(pushed);
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b')' {
            in_paren = false;
            let tail = &bytes[(i + 1)..bytes.len().min(i + 16)];
            if tail.windows(2).any(|w| w == b"Tj" || w == b"TJ") {
                if cur.starts_with(&[0xFE, 0xFF]) && cur.len() > 2 {
                    let units: Vec<u16> = cur[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    let s = String::from_utf16_lossy(&units);
                    if !s.trim().is_empty() {
                        text.push_str(s.trim());
                        text.push(' ');
                    }
                } else if let Ok(s) = std::str::from_utf8(&cur) {
                    if s.chars().all(|c| !c.is_control() || c.is_whitespace()) && !s.trim().is_empty() {
                        text.push_str(s.trim());
                        text.push(' ');
                    }
                }
            }
        } else {
            cur.push(b);
        }
        i += 1;
    }

    if let Some(ht) = build_head_tail_segment(&text) {
        segments.push(ht);
    }
    if !text.trim().is_empty() {
        segments.push(TextSegment {
            scope: SegmentScope::Body,
            location_label: "PDF 文本流".into(),
            text: text.trim().to_string(),
        });
    }
    PdfParseOutcome {
        segments,
        embedded_images: Vec::new(),
        deferred_scan_pages: Vec::new(),
        encrypted_locked: false,
        warnings: Vec::new(),
    }
}
