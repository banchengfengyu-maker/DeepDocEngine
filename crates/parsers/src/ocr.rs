use crate::adapters::find_native_asset;
use deepdoc_protocol::{SegmentScope, TextSegment};
use deepdoc_source_fs::blake3_bytes;
use image::imageops::FilterType;
use image::DynamicImage;
use ort::{
    environment::Environment,
    session::Session,
    value::Tensor,
};
use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone)]
pub enum ImageStageCheck {
    Skip,
    Cached(Option<TextSegment>),
    NeedsOcr(String),
}

#[derive(Debug, Clone)]
pub struct ImageFilterOutcome {
    pub img_blake3: String,
    pub width: u32,
    pub height: u32,
    pub skip_reason: Option<&'static str>,
}

static ORT_ENV: OnceLock<Result<Environment, String>> = OnceLock::new();

fn ensure_ort_env(dll_path: &Path) -> Result<&'static Environment, String> {
    let res = ORT_ENV.get_or_init(|| {
        ort::init_from(dll_path)
            .map_err(|e| format!("ort::init_from({}) failed: {e}", dll_path.display()))?
            .with_name("deepdoc_ppocr")
            .build()
            .map_err(|e| format!("ort Environment::build failed: {e}"))
    });
    res.as_ref().map_err(|e| e.clone())
}

struct PpOcrEngine {
    det: Session,
    cls: Option<Session>,
    rec: Session,
    dict: Vec<String>,
    gpu_vram_bytes: Option<u64>,
}

enum OnnxEngineState {
    Uninitialized,
    Ready(PpOcrEngine),
    Failed(String),
}

/// Shared worker-local BLAKE3 OCR cache + Dual Offline OCR Engine:
/// 1. Primary: ONNX Runtime (`libs/onnxruntime.dll`) + PP-OCRv4 (`models/{det,cls,rec}.onnx` + `ppocr_keys_v1.txt`)
/// 2. Built-in Windows fallback: WinRT `Windows::Media::Ocr::OcrEngine` (zero external DLL/model files)
pub struct OcrPipeline {
    pub onnx_dll: Option<PathBuf>,
    pub model_dir: Option<PathBuf>,
    pub directml_ready: bool,
    pub winrt_available: bool,
    onnx_engine: Mutex<OnnxEngineState>,
    pub cache: Mutex<HashMap<String, String>>,
    pending_new_cache: Mutex<Vec<(String, u32, u32, String)>>,
}

impl OcrPipeline {
    pub fn discover() -> Self {
        let onnx_dll = find_native_asset(
            "ORT_DYLIB_PATH",
            &["libs\\onnxruntime.dll", "onnxruntime.dll"],
        );

        let model_dir = find_native_asset(
            "DEEPDOC_OCR_MODEL_DIR",
            &["models\\det.onnx", "libs\\models\\det.onnx"],
        )
        .and_then(|det_path| {
            let dir = if det_path.is_dir() {
                det_path
            } else {
                det_path.parent()?.to_path_buf()
            };
            if dir.join("det.onnx").exists() && dir.join("rec.onnx").exists() {
                Some(dir)
            } else {
                None
            }
        });

        #[cfg(windows)]
        let directml_ready = should_use_directml_gpu().is_some()
            && onnx_dll.as_ref().is_some_and(|p| {
                p.parent()
                    .is_some_and(|dir| dir.join("DirectML.dll").exists())
                    || Path::new(r"C:\Windows\System32\DirectML.dll").exists()
            });
        #[cfg(not(windows))]
        let directml_ready = false;

        #[cfg(windows)]
        let winrt_available = probe_winrt_ocr();
        #[cfg(not(windows))]
        let winrt_available = false;

        Self {
            onnx_dll,
            model_dir,
            directml_ready,
            winrt_available,
            onnx_engine: Mutex::new(OnnxEngineState::Uninitialized),
            cache: Mutex::new(HashMap::new()),
            pending_new_cache: Mutex::new(Vec::new()),
        }
    }

    /// Pre-load persistent OCR cache entries (`img_blake3 -> recognized_text`) from daemon SQLite.
    pub fn warm_cache(&self, entries: &[(String, String)]) {
        if let Ok(mut guard) = self.cache.lock() {
            for (h, txt) in entries {
                if guard.len() >= 16384 {
                    break;
                }
                guard.entry(h.clone()).or_insert_with(|| txt.clone());
            }
        }
    }

    /// Drain newly inferred OCR results so `engine-daemon` can persist them to `ocr_image_cache`.
    pub fn take_new_cache_entries(&self) -> Vec<(String, u32, u32, String)> {
        self.pending_new_cache
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    pub fn has_onnx_ready(&self) -> bool {
        self.onnx_dll.is_some() && self.model_dir.is_some()
    }

    pub fn is_ready(&self) -> bool {
        self.has_onnx_ready() || self.winrt_available
    }

    pub fn backend_label(&self) -> &'static str {
        match (self.has_onnx_ready(), self.directml_ready, self.winrt_available) {
            (true, true, true) => "ocr:onnx-ppocrv4(directml-gpu)+winrt",
            (true, true, false) => "ocr:onnx-ppocrv4(directml-gpu)",
            (true, false, true) => "ocr:onnx-ppocrv4+winrt",
            (true, false, false) => "ocr:onnx-ppocrv4",
            (false, _, true) => "ocr:winrt-builtin",
            (false, _, false) => "ocr:prefilter+blake3-dedup",
        }
    }

    /// Filter out `< min_dim` icons and near-solid-color decorative images before OCR,
    /// deduplicate by `img_blake3`, extract EXIF/PNG metadata, and run offline OCR.
    pub fn process_image(
        &self,
        label: &str,
        bytes: &[u8],
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Vec<TextSegment> {
        let mut out = Vec::new();

        if let Some(meta_txt) = extract_image_metadata(bytes) {
            out.push(TextSegment {
                scope: SegmentScope::Metadata,
                location_label: format!("{label} (EXIF/文本块元数据)"),
                text: meta_txt,
            });
        }

        if bytes.starts_with(b"II*\x00") || bytes.starts_with(b"MM\x00*") {
            if let Some(segs) = self.process_multiframe_tiff(label, bytes, min_dim, warnings) {
                out.extend(segs);
                return out;
            }
        }

        if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            if let Some(segs) = self.process_multiframe_gif(label, bytes, min_dim, warnings) {
                out.extend(segs);
                return out;
            }
        }

        out.extend(self.process_single_frame(label, bytes, min_dim, warnings));
        out
    }

    /// Lightweight Stage-1 check: rejects tiny UI icons / strips / pixel bombs without full RGB decode,
    /// and reuses persistent `ocr_image_cache` if already recognized.
    pub fn check_stage1_image(&self, label: &str, bytes: &[u8], min_dim: u32) -> ImageStageCheck {
        const MAX_IMAGE_PIXELS: u64 = 120_000_000;
        if let Ok(reader) = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format() {
            if let Ok((w, h)) = reader.into_dimensions() {
                if w < min_dim || h < min_dim {
                    return ImageStageCheck::Skip;
                }
                let min_s = w.min(h).max(1);
                let max_s = w.max(h);
                if min_s < 40 && (max_s / min_s) > 40 {
                    return ImageStageCheck::Skip;
                }
                if (w as u64).saturating_mul(h as u64) > MAX_IMAGE_PIXELS {
                    return ImageStageCheck::Skip;
                }
            }
        }
        let img_blake3 = blake3_bytes(bytes);
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.get(&img_blake3) {
                if cached.is_empty() {
                    return ImageStageCheck::Cached(None);
                }
                return ImageStageCheck::Cached(Some(TextSegment {
                    scope: SegmentScope::Ocr,
                    location_label: format!("{label} (OCR缓存复用)"),
                    text: cached.clone(),
                }));
            }
        }
        ImageStageCheck::NeedsOcr(img_blake3)
    }

    fn process_single_frame(
        &self,
        label: &str,
        bytes: &[u8],
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Vec<TextSegment> {
        // Inspect header dimensions BEFORE allocating huge RGBA/RGB pixel buffers to prevent decompression OOMs on large images.
        const MAX_IMAGE_PIXELS: u64 = 120_000_000;
        if let Ok(reader) = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format() {
            if let Ok((w, h)) = reader.into_dimensions() {
                if w < min_dim || h < min_dim {
                    return Vec::new();
                }
                let min_s = w.min(h).max(1);
                let max_s = w.max(h);
                if min_s < 40 && (max_s / min_s) > 40 {
                    return Vec::new();
                }
                if (w as u64).saturating_mul(h as u64) > MAX_IMAGE_PIXELS {
                    warnings.push(format!(
                        "图像 `{label}` 分辨率超过安全上限 ({w}x{h} > 1.2亿像素)，已跳过解码防内存溢出"
                    ));
                    return Vec::new();
                }
            }
        }
        let Some(img) = image::load_from_memory(bytes).ok() else {
            return Vec::new();
        };
        let whole_hash = blake3_bytes(bytes);
        self.process_image_native_or_tiled(label, &img, &whole_hash, min_dim, warnings)
    }

    fn process_image_native_or_tiled(
        &self,
        label: &str,
        img: &DynamicImage,
        img_blake3: &str,
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Vec<TextSegment> {
        const TILE_THRESHOLD: u32 = 2560;
        const TILE_SIZE: u32 = 2048;
        const TILE_OVERLAP: u32 = 192;

        if img.width() <= TILE_THRESHOLD && img.height() <= TILE_THRESHOLD {
            return self
                .process_dynamic_image(label, img, img_blake3, min_dim, warnings)
                .into_iter()
                .collect();
        }

        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.get(img_blake3) {
                if cached.is_empty() {
                    return Vec::new();
                }
                return vec![TextSegment {
                    scope: SegmentScope::Ocr,
                    location_label: format!("{label} (大图切分OCR缓存复用)"),
                    text: cached.clone(),
                }];
            }
        }

        if !self.is_ready() {
            return Vec::new();
        }

        // Preserve full 1:1 native sharpness on large terrain/CAD maps by overlapping tiles instead of shrinking.
        let tiles = compute_ocr_tiles(img.width(), img.height(), TILE_SIZE, TILE_OVERLAP);
        let mut seen_lines = std::collections::HashSet::new();
        let mut collected_blocks = Vec::new();

        for (row, col, x, y, tw, th) in tiles {
            if tw < min_dim || th < min_dim {
                continue;
            }
            let tile = img.crop_imm(x, y, tw, th);
            if is_solid_color_block(&tile) {
                continue;
            }
            let raw = self.recognize_image(&tile, warnings);
            let mut tile_lines = Vec::new();
            for line in raw.lines() {
                let clean = line.trim();
                if !clean.is_empty() && seen_lines.insert(clean.to_string()) {
                    tile_lines.push(clean.to_string());
                }
            }
            if !tile_lines.is_empty() {
                collected_blocks.push(format!(
                    "[分块 R{}C{}] {}",
                    row + 1,
                    col + 1,
                    tile_lines.join("\n")
                ));
            }
        }

        let merged = collected_blocks.join("\n");
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= 16384 {
                guard.clear();
            }
            guard.insert(img_blake3.to_string(), merged.clone());
        }
        if let Ok(mut pend) = self.pending_new_cache.lock() {
            if pend.len() < 512 {
                pend.push((
                    img_blake3.to_string(),
                    img.width(),
                    img.height(),
                    merged.clone(),
                ));
            }
        }

        if merged.trim().is_empty() {
            Vec::new()
        } else {
            vec![TextSegment {
                scope: SegmentScope::Ocr,
                location_label: format!("{label} ({}x{} 大图分块OCR)", img.width(), img.height()),
                text: merged,
            }]
        }
    }

    fn process_dynamic_image(
        &self,
        label: &str,
        img: &DynamicImage,
        img_blake3: &str,
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Option<TextSegment> {
        let width = img.width();
        let height = img.height();
        if width < min_dim || height < min_dim {
            return None;
        }
        if is_solid_color_block(img) {
            return None;
        }

        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.get(img_blake3) {
                if cached.is_empty() {
                    return None;
                }
                return Some(TextSegment {
                    scope: SegmentScope::Ocr,
                    location_label: format!("{label} (OCR缓存复用)"),
                    text: cached.clone(),
                });
            }
        }

        if !self.is_ready() {
            warnings.push(format!(
                "图像 `{label}` ({width}x{height}, blake3={}) 已通过预过滤；当前环境未检测到 ONNX/WinRT OCR 引擎",
                &img_blake3[..12]
            ));
            return None;
        }

        let recognized = self.recognize_image(img, warnings);
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= 16384 {
                guard.clear();
            }
            guard.insert(img_blake3.to_string(), recognized.clone());
        }
        if let Ok(mut pend) = self.pending_new_cache.lock() {
            if pend.len() < 512 {
                pend.push((img_blake3.to_string(), width, height, recognized.clone()));
            }
        }

        if recognized.trim().is_empty() {
            None
        } else {
            Some(TextSegment {
                scope: SegmentScope::Ocr,
                location_label: format!("{label} (离线OCR)"),
                text: recognized,
            })
        }
    }

    fn recognize_image(&self, img: &DynamicImage, warnings: &mut Vec<String>) -> String {
        if self.has_onnx_ready() {
            match self.run_onnx_ppocr(img) {
                Ok(text) if !text.trim().is_empty() => return text,
                Ok(_) => {}
                Err(e) => {
                    warnings.push(format!("PP-OCRv4 推理异常，已尝试系统兜底 OCR: {e}"));
                }
            }
        }

        #[cfg(windows)]
        if self.winrt_available {
            if let Ok(text) = run_windows_winrt_ocr(img) {
                if !text.trim().is_empty() {
                    return text;
                }
            }
        }

        String::new()
    }

    fn run_onnx_ppocr(&self, img: &DynamicImage) -> Result<String, String> {
        let mut guard = self
            .onnx_engine
            .lock()
            .map_err(|_| "ocr engine mutex poisoned".to_string())?;

        if matches!(&*guard, OnnxEngineState::Uninitialized) {
            let dll = self.onnx_dll.as_ref().ok_or("missing onnxruntime.dll")?;
            let model_dir = self.model_dir.as_ref().ok_or("missing model_dir")?;
            match PpOcrEngine::load(dll, model_dir) {
                Ok(engine) => *guard = OnnxEngineState::Ready(engine),
                Err(e) => {
                    *guard = OnnxEngineState::Failed(e.clone());
                    return Err(e);
                }
            }
        }

        match &mut *guard {
            OnnxEngineState::Ready(engine) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    engine.recognize(img)
                })) {
                    Ok(res) => res,
                    Err(_) => Err("onnx ocr runtime panicked (safely isolated)".into()),
                }
            }
            OnnxEngineState::Failed(e) => Err(e.clone()),
            OnnxEngineState::Uninitialized => unreachable!(),
        }
    }

    fn process_multiframe_tiff(
        &self,
        label: &str,
        bytes: &[u8],
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Option<Vec<TextSegment>> {
        let mut dec = tiff::decoder::Decoder::new(Cursor::new(bytes)).ok()?;
        let mut segs = Vec::new();
        let mut page = 1usize;
        loop {
            if page > 200 {
                break;
            }
            if let (Ok((w, h)), Ok(img_res)) = (dec.dimensions(), dec.read_image()) {
                let dyn_img = tiff_result_to_dynamic(w, h, img_res);
                if let Some(di) = dyn_img {
                    let frame_hash = blake3_bytes(di.as_bytes());
                    if let Some(seg) = self.process_dynamic_image(
                        &format!("{label} 第{page}页"),
                        &di,
                        &frame_hash,
                        min_dim,
                        warnings,
                    ) {
                        segs.push(seg);
                    }
                }
            }
            if !dec.more_images() || dec.next_image().is_err() {
                break;
            }
            page += 1;
        }
        Some(segs)
    }

    fn process_multiframe_gif(
        &self,
        label: &str,
        bytes: &[u8],
        min_dim: u32,
        warnings: &mut Vec<String>,
    ) -> Option<Vec<TextSegment>> {
        let mut opts = gif::DecodeOptions::new();
        opts.set_color_output(gif::ColorOutput::RGBA);
        let mut dec = opts.read_info(Cursor::new(bytes)).ok()?;
        let w = dec.width() as u32;
        let h = dec.height() as u32;
        if w < min_dim || h < min_dim {
            return Some(Vec::new());
        }
        let mut segs = Vec::new();
        let mut frame_idx = 0usize;
        while let Ok(Some(frame)) = dec.read_next_frame() {
            frame_idx += 1;
            if frame_idx > 30 {
                break;
            }
            if frame_idx != 1 && frame_idx % 5 != 0 {
                continue;
            }
            if let Some(rgba) =
                image::RgbaImage::from_raw(frame.width as u32, frame.height as u32, frame.buffer.to_vec())
            {
                let di = DynamicImage::ImageRgba8(rgba);
                let frame_hash = blake3_bytes(di.as_bytes());
                if let Some(seg) = self.process_dynamic_image(
                    &format!("{label} 帧{frame_idx}"),
                    &di,
                    &frame_hash,
                    min_dim,
                    warnings,
                ) {
                    segs.push(seg);
                }
            }
        }
        Some(segs)
    }
}

#[cfg(windows)]
fn has_discrete_dxgi_gpu() -> Option<u64> {
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE,
    };

    let factory = unsafe { CreateDXGIFactory1::<IDXGIFactory1>() }.ok()?;
    let mut best_vram: Option<u64> = None;
    let mut idx = 0u32;
    while let Ok(adapter) = unsafe { factory.EnumAdapters1(idx) } {
        idx += 1;
        if let Ok(desc) = unsafe { adapter.GetDesc1() } {
            let is_sw = (desc.Flags & (DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32)) != 0;
            // Integrated Intel/AMD GPUs share system RAM (small dedicated VRAM), where batched CPU
            // outperforms DirectML and avoids 15s+ shader-compile stalls; enable auto-GPU for >=1 GiB dGPUs.
            let vram = desc.DedicatedVideoMemory as u64;
            if !is_sw && vram >= 1024 * 1024 * 1024 {
                best_vram = Some(best_vram.map_or(vram, |prev| prev.max(vram)));
            }
        }
    }
    best_vram
}

/// Returns `Some(vram_bytes)` if DirectML GPU acceleration should be used, or `None` for CPU mode.
fn should_use_directml_gpu() -> Option<u64> {
    match std::env::var("DEEPDOC_OCR_DEVICE") {
        Ok(v) if v.eq_ignore_ascii_case("cpu") => None,
        Ok(v) if v.eq_ignore_ascii_case("directml") || v.eq_ignore_ascii_case("gpu") => {
            #[cfg(windows)]
            {
                Some(has_discrete_dxgi_gpu().unwrap_or(2 * 1024 * 1024 * 1024))
            }
            #[cfg(not(windows))]
            {
                None
            }
        }
        _ => {
            #[cfg(windows)]
            {
                has_discrete_dxgi_gpu()
            }
            #[cfg(not(windows))]
            {
                None
            }
        }
    }
}

#[cfg(windows)]
struct GpuSlotGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for GpuSlotGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseSemaphore(self.0, 1, std::ptr::null_mut());
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Cap concurrent DirectML GPU OCR workers across all processes via a named Windows Semaphore
/// so 1-2 GiB legacy desktop GPUs do not exhaust VRAM under 6-worker parallel scans.
#[cfg(windows)]
fn acquire_gpu_ocr_slot(vram_bytes: u64) -> Option<GpuSlotGuard> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CreateSemaphoreW, WaitForSingleObject, INFINITE,
    };

    let max_slots = if vram_bytes >= 3 * 1024 * 1024 * 1024 {
        2
    } else {
        1
    };
    let wide: Vec<u16> = OsStr::new(r"Local\DeepDocEngine_DirectML_GpuSlots")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let h = unsafe { CreateSemaphoreW(std::ptr::null(), max_slots, max_slots, wide.as_ptr()) };
    if h.is_null() {
        return None;
    }
    let wait_res = unsafe { WaitForSingleObject(h, INFINITE) };
    if wait_res != 0 {
        unsafe { CloseHandle(h) };
        return None;
    }
    Some(GpuSlotGuard(h))
}

fn build_ort_session(
    env: &Environment,
    model_path: &Path,
    prefer_gpu: bool,
) -> Result<(Session, bool), String> {
    #[cfg(windows)]
    if prefer_gpu {
        use ort::ep::ExecutionProvider;
        if ort::ep::DirectML::is_available().unwrap_or(false) {
            let dml = ort::ep::DirectML::default()
                .with_performance_preference(
                    ort::ep::directml::PerformancePreference::HighPerformance,
                )
                .build();
            if let Ok(b) = Session::builder(env) {
                if let Ok(b) = b.with_memory_pattern(false) {
                    if let Ok(b) = b.with_parallel_execution(false) {
                        if let Ok(mut b) = b.with_execution_providers([dml]) {
                            if let Ok(sess) = b.commit_from_file(model_path) {
                                return Ok((sess, true));
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = prefer_gpu;
    let sess = Session::builder(env)
        .map_err(|e| format!("session builder: {e}"))?
        .with_intra_threads(2)
        .map_err(|e| format!("session threads: {e}"))?
        .commit_from_file(model_path)
        .map_err(|e| format!("load {}: {e}", model_path.display()))?;
    Ok((sess, false))
}

impl PpOcrEngine {
    fn load(dll_path: &Path, model_dir: &Path) -> Result<Self, String> {
        let env = ensure_ort_env(dll_path)?;
        let gpu_vram = should_use_directml_gpu();
        let prefer_gpu = gpu_vram.is_some();

        let (det, det_gpu) = build_ort_session(env, &model_dir.join("det.onnx"), prefer_gpu)?;
        let cls = if model_dir.join("cls.onnx").exists() {
            build_ort_session(env, &model_dir.join("cls.onnx"), prefer_gpu)
                .ok()
                .map(|(s, _)| s)
        } else {
            None
        };
        let (rec, rec_gpu) = build_ort_session(env, &model_dir.join("rec.onnx"), prefer_gpu)?;

        let dict = load_ppocr_dictionary(&rec, model_dir)?;
        Ok(Self {
            det,
            cls,
            rec,
            dict,
            gpu_vram_bytes: if det_gpu || rec_gpu { gpu_vram } else { None },
        })
    }

    fn recognize(&mut self, img: &DynamicImage) -> Result<String, String> {
        #[cfg(windows)]
        let _gpu_slot = self.gpu_vram_bytes.and_then(acquire_gpu_ocr_slot);

        let rgb = img.to_rgb8();
        let (orig_w, orig_h) = (rgb.width(), rgb.height());
        if orig_w == 0 || orig_h == 0 {
            return Ok(String::new());
        }

        let mut boxes = self.detect_boxes(&rgb)?;
        if boxes.is_empty() && orig_w <= 2048 && orig_h <= 1024 {
            // Single-line cropped banner / dense heading fallback
            boxes.push([0, 0, orig_w, orig_h]);
        }

        let mut crops = Vec::new();
        for [x0, y0, x1, y1] in boxes.into_iter().take(120) {
            let cw = x1.saturating_sub(x0);
            let ch = y1.saturating_sub(y0);
            if cw < 4 || ch < 4 {
                continue;
            }
            crops.push(image::imageops::crop_imm(&rgb, x0, y0, cw, ch).to_image());
        }
        if crops.is_empty() {
            return Ok(String::new());
        }

        let flips = self.needs_rotate_180_batch(&crops);
        for (crop, flip) in crops.iter_mut().zip(flips.into_iter()) {
            if flip {
                *crop = image::imageops::rotate180(crop);
            }
        }

        let texts = self.recognize_crops_batched(&crops)?;
        let lines: Vec<String> = texts
            .into_iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        Ok(lines.join("\n"))
    }

    fn detect_boxes(&mut self, rgb: &image::RgbImage) -> Result<Vec<[u32; 4]>, String> {
        let (w, h) = (rgb.width(), rgb.height());
        let max_side = w.max(h) as f32;
        let scale = if max_side > 960.0 {
            960.0 / max_side
        } else {
            1.0
        };
        // Align detection dimensions to 64px multiples so DirectML reuses compiled GPU kernels across pages.
        let rw = (((w as f32 * scale) / 64.0).round() as u32).max(1) * 64;
        let rh = (((h as f32 * scale) / 64.0).round() as u32).max(1) * 64;

        let resized = DynamicImage::ImageRgb8(rgb.clone()).resize_exact(rw, rh, FilterType::Triangle).to_rgb8();
        let plane_len = (rw * rh) as usize;
        let mut chw = vec![0.0f32; 3 * plane_len];
        const MEAN: [f32; 3] = [0.485, 0.456, 0.406];
        const STD: [f32; 3] = [0.229, 0.224, 0.225];
        for (i, px) in resized.pixels().enumerate() {
            // PaddleOCR expects BGR channel order
            let b = px[2] as f32 / 255.0;
            let g = px[1] as f32 / 255.0;
            let r = px[0] as f32 / 255.0;
            chw[i] = (b - MEAN[0]) / STD[0];
            chw[plane_len + i] = (g - MEAN[1]) / STD[1];
            chw[2 * plane_len + i] = (r - MEAN[2]) / STD[2];
        }

        let in_name = self
            .det
            .inputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "x".to_string());
        let tensor = Tensor::<f32>::from_array(([1usize, 3, rh as usize, rw as usize], chw))
            .map_err(|e| format!("det tensor: {e}"))?;
        let outputs = self
            .det
            .run(ort::inputs![in_name.as_str() => tensor])
            .map_err(|e| format!("det run: {e}"))?;
        let (_, out_val) = outputs.iter().next().ok_or("det missing output")?;
        let (shape, prob_map) = out_val
            .try_extract_tensor::<f32>()
            .map_err(|e| format!("det output extract: {e}"))?;

        let (mh, mw) = if shape.len() >= 4 {
            (shape[2] as usize, shape[3] as usize)
        } else if shape.len() == 3 {
            (shape[1] as usize, shape[2] as usize)
        } else {
            return Ok(Vec::new());
        };
        if prob_map.len() < mh * mw {
            return Ok(Vec::new());
        }

        // DBNet connected-component box extraction (threshold = 0.30)
        let mut visited = vec![false; mh * mw];
        let mut boxes = Vec::new();
        let ratio_x = w as f32 / mw as f32;
        let ratio_y = h as f32 / mh as f32;
        let mut queue = VecDeque::new();

        for y in 0..mh {
            for x in 0..mw {
                let idx = y * mw + x;
                if visited[idx] || prob_map[idx] <= 0.30 {
                    continue;
                }
                visited[idx] = true;
                queue.clear();
                queue.push_back((x, y));
                let (mut min_x, mut max_x, mut min_y, mut max_y) = (x, x, y, y);
                let mut area = 0usize;
                let mut sum_prob = 0.0f32;

                while let Some((cx, cy)) = queue.pop_front() {
                    let c_idx = cy * mw + cx;
                    area += 1;
                    sum_prob += prob_map[c_idx];
                    min_x = min_x.min(cx);
                    max_x = max_x.max(cx);
                    min_y = min_y.min(cy);
                    max_y = max_y.max(cy);

                    let nbrs = [
                        cx.checked_sub(1).map(|nx| (nx, cy)),
                        if cx + 1 < mw { Some((cx + 1, cy)) } else { None },
                        cy.checked_sub(1).map(|ny| (cx, ny)),
                        if cy + 1 < mh { Some((cx, cy + 1)) } else { None },
                    ];
                    for n in nbrs.into_iter().flatten() {
                        let ni = n.1 * mw + n.0;
                        if !visited[ni] && prob_map[ni] > 0.30 {
                            visited[ni] = true;
                            queue.push_back(n);
                        }
                    }
                }

                let mean_score = sum_prob / area.max(1) as f32;
                let bw_map = max_x - min_x + 1;
                let bh_map = max_y - min_y + 1;
                if area < 9 || bw_map < 3 || bh_map < 3 || mean_score < 0.45 {
                    continue;
                }

                // DBNet unclip approximation
                let orig_bw = bw_map as f32 * ratio_x;
                let orig_bh = bh_map as f32 * ratio_y;
                let pad_x = (orig_bh * 0.40).clamp(2.0, 28.0);
                let pad_y = (orig_bh * 0.30).clamp(2.0, 22.0);
                if orig_bw < 3.0 || orig_bh < 3.0 {
                    continue;
                }

                let bx0 = ((min_x as f32 * ratio_x - pad_x).max(0.0)).floor() as u32;
                let by0 = ((min_y as f32 * ratio_y - pad_y).max(0.0)).floor() as u32;
                let bx1 = (((max_x + 1) as f32 * ratio_x + pad_x).min(w as f32)).ceil() as u32;
                let by1 = (((max_y + 1) as f32 * ratio_y + pad_y).min(h as f32)).ceil() as u32;
                if bx1 > bx0 && by1 > by0 {
                    boxes.push([bx0, by0, bx1, by1]);
                }
            }
        }

        // Reading-order sort: top-to-bottom bands (tolerance ~ half median height), left-to-right
        boxes.sort_by(|a, b| {
            let ha = a[3].saturating_sub(a[1]);
            let hb = b[3].saturating_sub(b[1]);
            let tol = (ha.min(hb) / 2).max(6);
            if a[1].abs_diff(b[1]) <= tol {
                a[0].cmp(&b[0])
            } else {
                a[1].cmp(&b[1])
            }
        });
        Ok(boxes)
    }

    fn needs_rotate_180_batch(&mut self, crops: &[image::RgbImage]) -> Vec<bool> {
        let mut flips = vec![false; crops.len()];
        let Some(ref mut cls) = self.cls else {
            return flips;
        };
        let in_name = cls
            .inputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "x".to_string());

        const CLS_CHUNK: usize = 16;
        let plane = 48 * 192;
        for (chunk_idx, chunk) in crops.chunks(CLS_CHUNK).enumerate() {
            let b = chunk.len();
            let mut chw = vec![0.0f32; b * 3 * plane];
            for (bi, crop) in chunk.iter().enumerate() {
                let resized = DynamicImage::ImageRgb8(crop.clone())
                    .resize_exact(192, 48, FilterType::Triangle)
                    .to_rgb8();
                let base = bi * 3 * plane;
                for (i, px) in resized.pixels().enumerate() {
                    chw[base + i] = (px[2] as f32 / 255.0 - 0.5) / 0.5;
                    chw[base + plane + i] = (px[1] as f32 / 255.0 - 0.5) / 0.5;
                    chw[base + 2 * plane + i] = (px[0] as f32 / 255.0 - 0.5) / 0.5;
                }
            }
            let Ok(tensor) = Tensor::<f32>::from_array(([b, 3, 48, 192], chw)) else {
                continue;
            };
            let Ok(outputs) = cls.run(ort::inputs![in_name.as_str() => tensor]) else {
                continue;
            };
            let Some((_, out_val)) = outputs.iter().next() else {
                continue;
            };
            if let Ok((shape, probs)) = out_val.try_extract_tensor::<f32>() {
                let cols = shape.last().copied().unwrap_or(2) as usize;
                for bi in 0..b {
                    let off = bi * cols;
                    if off + 1 < probs.len() && probs[off + 1] > probs[off] && probs[off + 1] > 0.90 {
                        flips[chunk_idx * CLS_CHUNK + bi] = true;
                    }
                }
            }
        }
        flips
    }

    fn recognize_crops_batched(&mut self, crops: &[image::RgbImage]) -> Result<Vec<String>, String> {
        const REC_BUCKETS: [u32; 9] = [96, 160, 256, 384, 512, 768, 1024, 1536, 2048];
        const H_TARGET: u32 = 48;
        const REC_BATCH: usize = 16;

        let mut results = vec![String::new(); crops.len()];
        let mut by_bucket: HashMap<u32, Vec<(usize, u32, image::RgbImage)>> = HashMap::new();

        for (orig_idx, crop) in crops.iter().enumerate() {
            let (cw, ch) = (crop.width(), crop.height());
            let scaled_w = ((cw as f32 * (H_TARGET as f32 / ch.max(1) as f32)).ceil() as u32)
                .clamp(16, 2048);
            let bucket_w = REC_BUCKETS
                .iter()
                .copied()
                .find(|&b| b >= scaled_w)
                .unwrap_or(2048);
            let resized = DynamicImage::ImageRgb8(crop.clone())
                .resize_exact(scaled_w, H_TARGET, FilterType::CatmullRom)
                .to_rgb8();
            by_bucket
                .entry(bucket_w)
                .or_default()
                .push((orig_idx, scaled_w, resized));
        }

        let in_name = self
            .rec
            .inputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "x".to_string());

        for (bucket_w, items) in by_bucket {
            let plane = (H_TARGET * bucket_w) as usize;
            for chunk in items.chunks(REC_BATCH) {
                let b = chunk.len();
                let mut chw = vec![0.0f32; b * 3 * plane];
                for (bi, (_, scaled_w, resized)) in chunk.iter().enumerate() {
                    let base = bi * 3 * plane;
                    for y in 0..H_TARGET {
                        for x in 0..*scaled_w {
                            let px = resized.get_pixel(x, y);
                            let idx = (y * bucket_w + x) as usize;
                            chw[base + idx] = (px[2] as f32 / 255.0 - 0.5) / 0.5;
                            chw[base + plane + idx] = (px[1] as f32 / 255.0 - 0.5) / 0.5;
                            chw[base + 2 * plane + idx] = (px[0] as f32 / 255.0 - 0.5) / 0.5;
                        }
                    }
                }

                let tensor = Tensor::<f32>::from_array(([b, 3, H_TARGET as usize, bucket_w as usize], chw))
                    .map_err(|e| format!("rec tensor: {e}"))?;
                let outputs = self
                    .rec
                    .run(ort::inputs![in_name.as_str() => tensor])
                    .map_err(|e| format!("rec run: {e}"))?;
                let (_, out_val) = outputs.iter().next().ok_or("rec missing output")?;
                let (shape, logits) = out_val
                    .try_extract_tensor::<f32>()
                    .map_err(|e| format!("rec output extract: {e}"))?;

                if shape.len() < 3 {
                    continue;
                }
                let steps = shape[1] as usize;
                let num_classes = shape[2] as usize;
                if num_classes == 0 || logits.len() < b * steps * num_classes {
                    continue;
                }

                for (bi, (orig_idx, _, _)) in chunk.iter().enumerate() {
                    let sample_logits = &logits[bi * steps * num_classes..(bi + 1) * steps * num_classes];
                    results[*orig_idx] = decode_ctc_greedy(&self.dict, sample_logits, steps, num_classes);
                }
            }
        }
        Ok(results)
    }
}

fn decode_ctc_greedy(dict: &[String], logits: &[f32], steps: usize, num_classes: usize) -> String {
    let mut result = String::new();
    let mut prev_idx = 0usize;
    for t in 0..steps {
        let row = &logits[t * num_classes..(t + 1) * num_classes];
        let mut best_idx = 0usize;
        let mut best_val = f32::NEG_INFINITY;
        for (c, &v) in row.iter().enumerate() {
            if v > best_val {
                best_val = v;
                best_idx = c;
            }
        }
        if best_idx != 0 && best_idx != prev_idx {
            let d_idx = best_idx - 1;
            if d_idx < dict.len() {
                result.push_str(&dict[d_idx]);
            } else if d_idx == dict.len() {
                result.push(' ');
            }
        }
        prev_idx = best_idx;
    }
    result
}

fn load_ppocr_dictionary(rec: &Session, model_dir: &Path) -> Result<Vec<String>, String> {
    if let Ok(meta) = rec.metadata() {
        if let Some(ch_map) = meta.custom("character") {
            let chars: Vec<String> = ch_map
                .lines()
                .map(|l| l.trim_end_matches('\r').to_string())
                .collect();
            if chars.len() >= 100 {
                return Ok(chars);
            }
        }
    }
    for name in ["ppocr_keys_v1.txt", "dict.txt"] {
        let p = model_dir.join(name);
        if p.exists() {
            let raw = std::fs::read_to_string(&p)
                .map_err(|e| format!("read dictionary {}: {e}", p.display()))?;
            let mut chars: Vec<String> = raw
                .split('\n')
                .map(|l| l.trim_end_matches('\r').to_string())
                .collect();
            while chars.last().is_some_and(|s| s.is_empty()) {
                chars.pop();
            }
            if !chars.is_empty() {
                return Ok(chars);
            }
        }
    }
    Err("missing PP-OCRv4 character dictionary (ppocr_keys_v1.txt or ONNX metadata)".into())
}

#[cfg(windows)]
fn probe_winrt_ocr() -> bool {
    use windows::core::HSTRING;
    use windows::Globalization::Language;
    use windows::Media::Ocr::OcrEngine;

    if let Ok(lang) = Language::CreateLanguage(&HSTRING::from("zh-Hans-CN")) {
        if OcrEngine::TryCreateFromLanguage(&lang).is_ok() {
            return true;
        }
    }
    OcrEngine::TryCreateFromUserProfileLanguages().is_ok()
}

#[cfg(windows)]
fn run_windows_winrt_ocr(img: &DynamicImage) -> Result<String, String> {
    use windows::core::HSTRING;
    use windows::Globalization::Language;
    use windows::Graphics::Imaging::{BitmapPixelFormat, SoftwareBitmap};
    use windows::Media::Ocr::OcrEngine;
    use windows::Storage::Streams::DataWriter;

    let engine = Language::CreateLanguage(&HSTRING::from("zh-Hans-CN"))
        .ok()
        .and_then(|lang| OcrEngine::TryCreateFromLanguage(&lang).ok())
        .or_else(|| OcrEngine::TryCreateFromUserProfileLanguages().ok())
        .ok_or_else(|| "Windows WinRT OcrEngine unavailable".to_string())?;

    // Ensure minimum comfortable resolution so WinRT OCR reliably sees characters
    let scaled = if img.width() < 128 || img.height() < 48 {
        img.resize_exact(
            (img.width() * 2).max(160),
            (img.height() * 2).max(64),
            FilterType::Triangle,
        )
    } else {
        img.clone()
    };

    let rgba = scaled.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    let mut bgra = Vec::with_capacity((w * h * 4) as usize);
    for px in rgba.pixels() {
        bgra.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
    }

    let writer = DataWriter::new().map_err(|e| format!("DataWriter::new: {e}"))?;
    writer
        .WriteBytes(&bgra)
        .map_err(|e| format!("WriteBytes: {e}"))?;
    let ibuf = writer
        .DetachBuffer()
        .map_err(|e| format!("DetachBuffer: {e}"))?;

    let bmp = SoftwareBitmap::CreateCopyFromBuffer(
        &ibuf,
        BitmapPixelFormat::Bgra8,
        w as i32,
        h as i32,
    )
    .map_err(|e| format!("SoftwareBitmap: {e}"))?;

    let result = engine
        .RecognizeAsync(&bmp)
        .map_err(|e| format!("RecognizeAsync: {e}"))?
        .get()
        .map_err(|e| format!("RecognizeAsync get: {e}"))?;

    let mut out_lines = Vec::new();
    if let Ok(lines) = result.Lines() {
        for line in lines {
            if let Ok(t) = line.Text() {
                let s = t.to_string_lossy();
                if !s.trim().is_empty() {
                    out_lines.push(s.trim().to_string());
                }
            }
        }
    }
    if out_lines.is_empty() {
        if let Ok(t) = result.Text() {
            return Ok(t.to_string_lossy().trim().to_string());
        }
    }
    Ok(out_lines.join("\n"))
}

fn tiff_result_to_dynamic(
    w: u32,
    h: u32,
    res: tiff::decoder::DecodingResult,
) -> Option<DynamicImage> {
    match res {
        tiff::decoder::DecodingResult::U8(v) => {
            if v.len() == (w * h) as usize {
                image::GrayImage::from_raw(w, h, v).map(DynamicImage::ImageLuma8)
            } else if v.len() == (w * h * 3) as usize {
                image::RgbImage::from_raw(w, h, v).map(DynamicImage::ImageRgb8)
            } else if v.len() == (w * h * 4) as usize {
                image::RgbaImage::from_raw(w, h, v).map(DynamicImage::ImageRgba8)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_solid_color_block(img: &DynamicImage) -> bool {
    let gray = img.thumbnail(64, 64).into_luma8();
    let pixels = gray.as_raw();
    if pixels.is_empty() {
        return true;
    }
    let mean = pixels.iter().map(|&p| p as f64).sum::<f64>() / pixels.len() as f64;
    let var = pixels
        .iter()
        .map(|&p| {
            let d = p as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / pixels.len() as f64;
    var < 4.0
}

pub fn inspect_image(bytes: &[u8], min_dim: u32) -> Result<ImageFilterOutcome, ()> {
    let img = image::load_from_memory(bytes).map_err(|_| ())?;
    let width = img.width();
    let height = img.height();
    let img_blake3 = blake3_bytes(bytes);

    if width < min_dim || height < min_dim {
        return Ok(ImageFilterOutcome {
            img_blake3,
            width,
            height,
            skip_reason: Some("below_min_dimensions"),
        });
    }
    if is_solid_color_block(&img) {
        return Ok(ImageFilterOutcome {
            img_blake3,
            width,
            height,
            skip_reason: Some("solid_color_block"),
        });
    }
    Ok(ImageFilterOutcome {
        img_blake3,
        width,
        height,
        skip_reason: None,
    })
}

/// Extract EXIF metadata (JPEG/TIFF/WebP/HEIF) and PNG `tEXt`/`iTXt` embedded comments.
pub fn extract_image_metadata(bytes: &[u8]) -> Option<String> {
    let mut lines = Vec::new();

    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let dec = png::Decoder::new(Cursor::new(bytes));
        if let Ok(reader) = dec.read_info() {
            let info = reader.info();
            for t in &info.uncompressed_latin1_text {
                if !t.text.trim().is_empty() {
                    lines.push(format!("{}: {}", t.keyword, t.text.trim()));
                }
            }
            for t in &info.utf8_text {
                if let Ok(txt) = t.get_text() {
                    if !txt.trim().is_empty() {
                        lines.push(format!("{}: {}", t.keyword, txt.trim()));
                    }
                }
            }
        }
    }

    if let Ok(exif) = exif::Reader::new().read_from_container(&mut Cursor::new(bytes)) {
        for f in exif.fields() {
            let tag_s = format!("{}", f.tag);
            if matches!(
                tag_s.as_str(),
                "ImageDescription"
                    | "Artist"
                    | "Copyright"
                    | "Software"
                    | "UserComment"
                    | "DateTime"
                    | "Make"
                    | "Model"
                    | "GPSLatitude"
                    | "GPSLongitude"
            ) {
                let val = f.display_value().with_unit(&exif).to_string();
                if !val.trim().is_empty() {
                    lines.push(format!("{tag_s}: {}", val.trim()));
                }
            }
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ctc_and_selects_device_policy() {
        let dict = vec!["测".into(), "试".into()];
        // 3 steps, 4 classes (0=blank, 1='测', 2='试', 3=' ')
        let logits = vec![
            0.1, 0.9, 0.0, 0.0, // '测'
            0.1, 0.8, 0.0, 0.0, // repeated '测' collapsed
            0.0, 0.1, 0.9, 0.0, // '试'
        ];
        assert_eq!(decode_ctc_greedy(&dict, &logits, 3, 4), "测试");
        let _ = should_use_directml_gpu();
    }

    #[test]
    fn computes_overlapping_tiles_covering_edges() {
        let tiles = compute_ocr_tiles(5000, 4200, 2048, 192);
        assert!(tiles.len() >= 6);
        let max_x_end = tiles.iter().map(|t| t.2 + t.4).max().unwrap();
        let max_y_end = tiles.iter().map(|t| t.3 + t.5).max().unwrap();
        assert_eq!(max_x_end, 5000);
        assert_eq!(max_y_end, 4200);
        assert!(tiles.iter().all(|t| t.4 <= 2048 && t.5 <= 2048));
    }
}

fn compute_ocr_tiles(
    width: u32,
    height: u32,
    tile_size: u32,
    overlap: u32,
) -> Vec<(usize, usize, u32, u32, u32, u32)> {
    let step = tile_size.saturating_sub(overlap).max(256);
    let mut xs = Vec::new();
    let mut x = 0u32;
    loop {
        let rem = width.saturating_sub(x);
        if rem <= tile_size {
            let start = width.saturating_sub(tile_size).min(x);
            if xs.last().copied() != Some(start) {
                xs.push(start);
            }
            break;
        }
        xs.push(x);
        x = x.saturating_add(step);
    }

    let mut ys = Vec::new();
    let mut y = 0u32;
    loop {
        let rem = height.saturating_sub(y);
        if rem <= tile_size {
            let start = height.saturating_sub(tile_size).min(y);
            if ys.last().copied() != Some(start) {
                ys.push(start);
            }
            break;
        }
        ys.push(y);
        y = y.saturating_add(step);
    }

    let mut out = Vec::with_capacity(xs.len() * ys.len());
    for (row, &ty) in ys.iter().enumerate() {
        let th = height.saturating_sub(ty).min(tile_size);
        for (col, &tx) in xs.iter().enumerate() {
            let tw = width.saturating_sub(tx).min(tile_size);
            out.push((row, col, tx, ty, tw, th));
        }
    }
    out
}
