use crate::rules::RuleSet;
use crate::worker::{ParseOptions, SegmentScope};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DeepDocEngine.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    pub include_hidden: bool,
    pub use_usn_if_available: bool,
    pub worker_count: usize,
    pub worker_timeout_ms: u64,
    pub parse: ParseOptions,
    #[serde(default)]
    pub excluded_dirs: Vec<String>,
    #[serde(default)]
    pub excluded_name_globs: Vec<String>,
    #[serde(default)]
    pub include_extensions: Vec<String>,
    #[serde(default)]
    pub min_byte_size: Option<u64>,
    #[serde(default)]
    pub max_byte_size: Option<u64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            use_usn_if_available: true,
            worker_count: std::thread::available_parallelism()
                .map(|n| n.get().clamp(2, 6))
                .unwrap_or(4),
            worker_timeout_ms: 45_000,
            parse: ParseOptions::default(),
            excluded_dirs: Vec::new(),
            excluded_name_globs: Vec::new(),
            include_extensions: Vec::new(),
            min_byte_size: None,
            max_byte_size: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub file_ext_filter: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub scope_filter: Option<SegmentScope>,
    pub use_regex: bool,
    #[serde(default = "default_true")]
    pub match_all_terms: bool,
    pub limit: usize,
    pub offset: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: String::new(),
            file_ext_filter: None,
            path_prefix: None,
            scope_filter: None,
            use_regex: false,
            match_all_terms: true,
            limit: 200,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientEnvelope {
    pub req_id: u64,
    pub request: ClientRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientRequest {
    Ping,
    StartScan {
        job_id: String,
        roots: Vec<String>,
        ruleset: Option<RuleSet>,
        options: ScanOptions,
    },
    /// Ephemeral direct search over `roots` without persisting documents to SQLite or Tantivy.
    DirectSearch {
        job_id: String,
        roots: Vec<String>,
        query: String,
        use_regex: bool,
        file_ext_filter: Option<String>,
        options: ScanOptions,
    },
    CancelScan {
        job_id: String,
    },
    Search {
        query: SearchQuery,
    },
    EvaluateRules {
        ruleset: RuleSet,
        doc_ids: Option<Vec<u64>>,
        #[serde(default)]
        path_prefix: Option<String>,
        #[serde(default)]
        file_ext_filter: Option<String>,
    },
    GetDocumentPreview {
        doc_id: u64,
        highlight_terms: Vec<String>,
        max_chars: usize,
    },
    GetStats,
    ClearIndex,
    /// Rebuild/reset document & Tantivy index while keeping persistent `ocr_image_cache`.
    ResetIndexKeepOcr,
    /// Gentle, AV-friendly multi-pass secure file erasure + index purge.
    DeepDeleteFiles {
        job_id: String,
        paths: Vec<String>,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitLocationSnippet {
    pub scope: SegmentScope,
    pub location_label: String,
    pub matched_term: String,
    pub snippet: String,
    pub match_start_char: usize,
    pub match_len_char: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitRecord {
    pub doc_id: u64,
    pub virtual_path: String,
    pub file_name: String,
    pub detected_format: String,
    pub blake3_hex: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub total_matches: usize,
    pub snippets: Vec<HitLocationSnippet>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHitItem {
    pub doc_id: u64,
    pub score: f32,
    pub virtual_path: String,
    pub file_name: String,
    pub detected_format: String,
    pub blake3_hex: String,
    pub byte_size: u64,
    pub snippets: Vec<HitLocationSnippet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewSegment {
    pub scope: SegmentScope,
    pub location_label: String,
    pub text: String,
    pub highlight_ranges: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentPreview {
    pub doc_id: u64,
    pub virtual_path: String,
    pub file_name: String,
    pub detected_format: String,
    pub blake3_hex: String,
    pub byte_size: u64,
    pub encrypted: bool,
    pub metadata: Vec<(String, String)>,
    pub segments: Vec<PreviewSegment>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub job_id: String,
    pub scanned_files: u64,
    pub parsed_ok: u64,
    pub child_docs_indexed: u64,
    pub skipped_cached: u64,
    pub encrypted_files: u64,
    pub failed_files: u64,
    pub rule_hits: u64,
    pub cancelled: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStats {
    pub total_documents: u64,
    pub unique_content_blobs: u64,
    pub ocr_cached_images: u64,
    pub encrypted_documents: u64,
    pub failed_documents: u64,
    pub total_raw_chars: u64,
    pub db_size_bytes: u64,
    pub tantivy_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonMessage {
    Pong {
        req_id: u64,
        daemon_version: String,
        worker_engines: Vec<String>,
        ext_worker_engines: Vec<String>,
        indexed_docs: u64,
    },
    Ack {
        req_id: u64,
        ok: bool,
        message: String,
    },
    ScanProgress {
        job_id: String,
        scanned_files: u64,
        parsed_ok: u64,
        skipped_cached: u64,
        encrypted_files: u64,
        failed_files: u64,
        current_path: String,
        elapsed_ms: u64,
    },
    ScanHit {
        job_id: String,
        hit: HitRecord,
    },
    ScanCompleted {
        job_id: String,
        summary: ScanSummary,
    },
    SearchResult {
        req_id: u64,
        total_hits: usize,
        took_ms: u64,
        items: Vec<SearchHitItem>,
    },
    RuleEvalResult {
        req_id: u64,
        took_ms: u64,
        hits: Vec<HitRecord>,
    },
    PreviewResult {
        req_id: u64,
        doc: DocumentPreview,
    },
    StatsResult {
        req_id: u64,
        stats: IndexStats,
    },
    DeepDeleteProgress {
        job_id: String,
        completed: u64,
        total: u64,
        current_path: String,
    },
    DeepDeleteCompleted {
        job_id: String,
        deleted_files: u64,
        purged_index_docs: u64,
        skipped_or_failed: u64,
        errors: Vec<String>,
    },
    Error {
        req_id: u64,
        code: String,
        message: String,
    },
}
