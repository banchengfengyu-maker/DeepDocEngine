using System.Text.Json.Serialization;

namespace DocSentinel.UI.Ipc;

public enum RuleMatchMode
{
    FirstHit,
    FullHits
}

public enum SegmentScope
{
    FileName,
    HeadTail,
    Body,
    Ocr,
    Table,
    Metadata,
    Comment
}

public sealed class RuleDefinitionDto
{
    [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("category")] public string Category { get; set; } = "常规";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "High";
    [JsonPropertyName("expression")] public string Expression { get; set; } = string.Empty;
    [JsonPropertyName("mode")] [JsonConverter(typeof(JsonStringEnumConverter))] public RuleMatchMode Mode { get; set; } = RuleMatchMode.FullHits;
}

public sealed class RuleSetDto
{
    [JsonPropertyName("ruleset_id")] public string RulesetId { get; set; } = "default";
    [JsonPropertyName("rules")] public List<RuleDefinitionDto> Rules { get; set; } = new();
}

public sealed class HitLocationSnippetDto
{
    [JsonPropertyName("scope")] [JsonConverter(typeof(JsonStringEnumConverter))] public SegmentScope Scope { get; set; }
    [JsonPropertyName("location_label")] public string LocationLabel { get; set; } = string.Empty;
    [JsonPropertyName("matched_term")] public string MatchedTerm { get; set; } = string.Empty;
    [JsonPropertyName("snippet")] public string Snippet { get; set; } = string.Empty;
    [JsonPropertyName("match_start_char")] public int MatchStartChar { get; set; }
    [JsonPropertyName("match_len_char")] public int MatchLenChar { get; set; }
}

public sealed class HitRecordDto
{
    [JsonPropertyName("doc_id")] public ulong DocId { get; set; }
    [JsonPropertyName("virtual_path")] public string VirtualPath { get; set; } = string.Empty;
    [JsonPropertyName("file_name")] public string FileName { get; set; } = string.Empty;
    [JsonPropertyName("detected_format")] public string DetectedFormat { get; set; } = string.Empty;
    [JsonPropertyName("blake3_hex")] public string Blake3Hex { get; set; } = string.Empty;
    [JsonPropertyName("rule_id")] public string RuleId { get; set; } = string.Empty;
    [JsonPropertyName("rule_name")] public string RuleName { get; set; } = string.Empty;
    [JsonPropertyName("severity")] public string Severity { get; set; } = string.Empty;
    [JsonPropertyName("total_matches")] public int TotalMatches { get; set; }
    [JsonPropertyName("snippets")] public List<HitLocationSnippetDto> Snippets { get; set; } = new();
}

public sealed class SearchHitItemDto
{
    [JsonPropertyName("doc_id")] public ulong DocId { get; set; }
    [JsonPropertyName("score")] public float Score { get; set; }
    [JsonPropertyName("virtual_path")] public string VirtualPath { get; set; } = string.Empty;
    [JsonPropertyName("file_name")] public string FileName { get; set; } = string.Empty;
    [JsonPropertyName("detected_format")] public string DetectedFormat { get; set; } = string.Empty;
    [JsonPropertyName("blake3_hex")] public string Blake3Hex { get; set; } = string.Empty;
    [JsonPropertyName("byte_size")] public ulong ByteSize { get; set; }
    [JsonPropertyName("snippets")] public List<HitLocationSnippetDto> Snippets { get; set; } = new();
}

public sealed class PreviewSegmentDto
{
    [JsonPropertyName("scope")] [JsonConverter(typeof(JsonStringEnumConverter))] public SegmentScope Scope { get; set; }
    [JsonPropertyName("location_label")] public string LocationLabel { get; set; } = string.Empty;
    [JsonPropertyName("text")] public string Text { get; set; } = string.Empty;
    [JsonPropertyName("highlight_ranges")] public List<int[]> HighlightRanges { get; set; } = new();
}

public sealed class DocumentPreviewDto
{
    [JsonPropertyName("doc_id")] public ulong DocId { get; set; }
    [JsonPropertyName("virtual_path")] public string VirtualPath { get; set; } = string.Empty;
    [JsonPropertyName("file_name")] public string FileName { get; set; } = string.Empty;
    [JsonPropertyName("detected_format")] public string DetectedFormat { get; set; } = string.Empty;
    [JsonPropertyName("blake3_hex")] public string Blake3Hex { get; set; } = string.Empty;
    [JsonPropertyName("byte_size")] public ulong ByteSize { get; set; }
    [JsonPropertyName("encrypted")] public bool Encrypted { get; set; }
    [JsonPropertyName("metadata")] public List<string[]> Metadata { get; set; } = new();
    [JsonPropertyName("segments")] public List<PreviewSegmentDto> Segments { get; set; } = new();
    [JsonPropertyName("truncated")] public bool Truncated { get; set; }
}

public sealed class IndexStatsDto
{
    [JsonPropertyName("total_documents")] public ulong TotalDocuments { get; set; }
    [JsonPropertyName("unique_content_blobs")] public ulong UniqueContentBlobs { get; set; }
    [JsonPropertyName("ocr_cached_images")] public ulong OcrCachedImages { get; set; }
    [JsonPropertyName("encrypted_documents")] public ulong EncryptedDocuments { get; set; }
    [JsonPropertyName("failed_documents")] public ulong FailedDocuments { get; set; }
    [JsonPropertyName("total_raw_chars")] public ulong TotalRawChars { get; set; }
    [JsonPropertyName("db_size_bytes")] public ulong DbSizeBytes { get; set; }
    [JsonPropertyName("tantivy_size_bytes")] public ulong TantivySizeBytes { get; set; }
}

public sealed class ScanSummaryDto
{
    [JsonPropertyName("job_id")] public string JobId { get; set; } = string.Empty;
    [JsonPropertyName("scanned_files")] public ulong ScannedFiles { get; set; }
    [JsonPropertyName("parsed_ok")] public ulong ParsedOk { get; set; }
    [JsonPropertyName("child_docs_indexed")] public ulong ChildDocsIndexed { get; set; }
    [JsonPropertyName("skipped_cached")] public ulong SkippedCached { get; set; }
    [JsonPropertyName("encrypted_files")] public ulong EncryptedFiles { get; set; }
    [JsonPropertyName("failed_files")] public ulong FailedFiles { get; set; }
    [JsonPropertyName("rule_hits")] public ulong RuleHits { get; set; }
    [JsonPropertyName("cancelled")] public bool Cancelled { get; set; }
    [JsonPropertyName("elapsed_ms")] public ulong ElapsedMs { get; set; }
}

/// <summary>
/// Unified display row for the WPF DataGrid (populated by both SearchResult and ScanHit/RuleEvalResult).
/// </summary>
public sealed class ResultRowItem
{
    public ulong DocId { get; set; }
    public string KindBadge { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public string RuleOrScore { get; set; } = string.Empty;
    public string LocationLabel { get; set; } = string.Empty;
    public string Snippet { get; set; } = string.Empty;
    public string VirtualPath { get; set; } = string.Empty;
    public List<string> HighlightTerms { get; set; } = new();
}
