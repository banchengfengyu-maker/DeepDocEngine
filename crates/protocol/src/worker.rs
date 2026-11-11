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
        }
    }
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
    },
    Failed {
        task_id: u64,
        virtual_path: String,
        kind: FailureKind,
        detail: String,
    },
}
