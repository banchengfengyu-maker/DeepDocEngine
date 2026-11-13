use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SegmentScope {
    FileName,
    HeadTail,
    Body,
    Ocr,
    Table,
    Metadata,
    Comment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextSegment {
    pub scope: SegmentScope,
    pub location_label: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedDocument {
    pub virtual_path: String,
    pub file_name: String,
    pub detected_format: String,
    pub blake3_hex: String,
    pub byte_size: u64,
    pub encrypted: bool,
    pub segments: Vec<TextSegment>,
    pub metadata: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseOptions {
    pub max_extract_depth: u32,
    pub max_uncompressed_bytes: u64,
    pub max_single_file_bytes: u64,
    pub max_expansion_ratio: u32,
    pub enable_ocr: bool,
    pub ocr_min_image_dim: u32,
    pub enable_x2t: bool,
    pub passwords: Vec<String>,
    #[serde(default)]
    pub extract_deferred_images: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_extract_depth: 6,
            max_uncompressed_bytes: 512 * 1024 * 1024,
            max_single_file_bytes: 256 * 1024 * 1024,
            max_expansion_ratio: 100,
            enable_ocr: true,
            ocr_min_image_dim: 24,
            enable_x2t: false,
            passwords: Vec::new(),
            extract_deferred_images: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredOcrImage {
    pub doc_virtual_path: String,
    pub label: String,
    pub img_blake3: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    #[serde(default)]
    pub staged_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkerRequest {
    HealthCheck,
    ParseFile {
        task_id: u64,
        disk_path: String,
        virtual_path: String,
        options: ParseOptions,
    },
    ParseBytes {
        task_id: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        virtual_path: String,
        hint_ext: Option<String>,
        options: ParseOptions,
    },
    WarmOcrCache {
        entries: Vec<(String, String)>,
    },
    OcrImageBytes {
        task_id: u64,
        label: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        min_dim: u32,
    },
    OcrPdfPages {
        task_id: u64,
        disk_path: String,
        passwords: Vec<String>,
        page_indices: Vec<usize>,
        min_dim: u32,
    },
    ParseFilesBatch {
        task_id: u64,
        items: Vec<(String, String)>, // (disk_path, virtual_path)
        options: ParseOptions,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureKind {
    Encrypted,
    Corrupted,
    ZipBombTripped,
    Timeout,
    Unsupported,
    IoError,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub worker_kind: String,
    pub license_tier: String,
    pub engines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkerResponse {
    Health {
        capabilities: WorkerCapabilities,
    },
    OcrCacheWarmed {
        loaded: usize,
    },
    Parsed {
        task_id: u64,
        doc: ExtractedDocument,
        child_docs: Vec<ExtractedDocument>,
        #[serde(default)]
        new_ocr_entries: Vec<(String, u32, u32, String)>,
        #[serde(default)]
        deferred_images: Vec<DeferredOcrImage>,
        #[serde(default)]
        deferred_pdf_pages: Vec<usize>,
    },
    OcrCompleted {
        task_id: u64,
        segments: Vec<TextSegment>,
        #[serde(default)]
        warnings: Vec<String>,
        #[serde(default)]
        new_ocr_entries: Vec<(String, u32, u32, String)>,
    },
    Failed {
        task_id: u64,
        virtual_path: String,
        kind: FailureKind,
        detail: String,
    },
    ParsedBatch {
        task_id: u64,
        items: Vec<WorkerResponse>,
    },
}

/// Extensions whose contents are non-document OS/compiler binaries or oversized BIM/installer assets;
/// indexed purely by filename/path/size metadata without expensive disk reads or unpackers.
pub fn is_metadata_only_binary_ext(ext: &str) -> bool {
    matches!(
        ext,
        "dll" | "exe" | "sys" | "drv" | "ocx" | "cpl" | "tlb" | "pdb" | "lib" | "obj"
            | "o" | "a" | "cat" | "mui" | "winmd" | "pri" | "pnf" | "cdf-ms" | "mfl"
            | "msi" | "msu" | "msp" | "mst" | "mum" | "rvt" | "nwc" | "nwd" | "rfa"
            | "dwf" | "ttf" | "otf" | "woff" | "woff2" | "db-wal" | "db-shm"
            | "ico" | "sbx" | "shx" | "sbn"
    )
}

/// Pure raster image formats whose searchable content relies on OCR and can be deferred to Pass 2.
pub fn is_ocr_image_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png" | "jpg" | "jpeg" | "bmp" | "webp" | "tif" | "tiff" | "heic" | "heif" | "avif" | "gif"
    )
}

pub fn build_metadata_only_doc(
    file_name: String,
    virtual_path: &str,
    detected_format: &str,
    byte_size: u64,
    blake3_hex: String,
    warning: impl Into<String>,
) -> ExtractedDocument {
    ExtractedDocument {
        virtual_path: virtual_path.to_string(),
        file_name,
        detected_format: if detected_format.is_empty() {
            "bin".into()
        } else {
            detected_format.to_string()
        },
        blake3_hex,
        byte_size,
        encrypted: false,
        segments: Vec::new(),
        metadata: vec![("indexed_mode".into(), "metadata_only".into())],
        warnings: vec![warning.into()],
    }
}
