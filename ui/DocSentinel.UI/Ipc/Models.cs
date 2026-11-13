using System.IO;
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
    [JsonPropertyName("byte_size")] public ulong ByteSize { get; set; }
    [JsonPropertyName("modified_unix_ms")] public long ModifiedUnixMs { get; set; }
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
    [JsonPropertyName("modified_unix_ms")] public long ModifiedUnixMs { get; set; }
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
/// Unified display row for the Everything-style WPF DataGrid (populated by Search, RuleEval, and DirectSearch).
/// </summary>
public sealed class ResultRowItem
{
    public ulong DocId { get; set; }
    public string KindBadge { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Directory { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public string FileTypeDisplay { get; set; } = string.Empty;
    public ulong ByteSize { get; set; }
    public string SizeDisplay { get; set; } = string.Empty;
    public long ModifiedUnixMs { get; set; }
    public string ModifiedDisplay { get; set; } = string.Empty;
    public string RuleOrScore { get; set; } = string.Empty;
    public string LocationLabel { get; set; } = string.Empty;
    public string Snippet { get; set; } = string.Empty;
    public string VirtualPath { get; set; } = string.Empty;
    public List<string> HighlightTerms { get; set; } = new();

    public static ResultRowItem FromSearchHit(SearchHitItemDto it, IReadOnlyList<string> queryTerms)
    {
        var firstSnip = it.Snippets.FirstOrDefault();
        var mergedTerms = MergeHighlightTerms(queryTerms, it.Snippets);
        return Create(
            docId: it.DocId,
            kindBadge: "检索",
            fileName: it.FileName,
            virtualPath: it.VirtualPath,
            detectedFormat: it.DetectedFormat,
            byteSize: it.ByteSize,
            modifiedUnixMs: it.ModifiedUnixMs,
            ruleOrScore: $"score {it.Score:F2}",
            locationLabel: firstSnip is null ? "-" : $"[{firstSnip.Scope}] {firstSnip.LocationLabel}",
            snippet: firstSnip?.Snippet ?? "",
            highlightTerms: mergedTerms);
    }

    public static ResultRowItem FromHitRecord(HitRecordDto hit, IReadOnlyList<string>? extraTerms = null)
    {
        var firstSnip = hit.Snippets.FirstOrDefault();
        var mergedTerms = MergeHighlightTerms(extraTerms ?? Array.Empty<string>(), hit.Snippets);
        return Create(
            docId: hit.DocId,
            kindBadge: hit.Severity,
            fileName: hit.FileName,
            virtualPath: hit.VirtualPath,
            detectedFormat: hit.DetectedFormat,
            byteSize: hit.ByteSize,
            modifiedUnixMs: hit.ModifiedUnixMs,
            ruleOrScore: $"{hit.RuleName} (×{hit.TotalMatches})",
            locationLabel: firstSnip is null ? "-" : $"[{firstSnip.Scope}] {firstSnip.LocationLabel}",
            snippet: firstSnip?.Snippet ?? "",
            highlightTerms: mergedTerms);
    }

    private static ResultRowItem Create(
        ulong docId,
        string kindBadge,
        string fileName,
        string virtualPath,
        string detectedFormat,
        ulong byteSize,
        long modifiedUnixMs,
        string ruleOrScore,
        string locationLabel,
        string snippet,
        List<string> highlightTerms)
    {
        string ext = ExtractExtensionUpper(fileName, detectedFormat);
        return new ResultRowItem
        {
            DocId = docId,
            KindBadge = kindBadge,
            FileName = fileName,
            Directory = ExtractDirectory(virtualPath),
            Format = string.IsNullOrWhiteSpace(detectedFormat) ? ext.ToLowerInvariant() : detectedFormat,
            FileTypeDisplay = ext,
            ByteSize = byteSize,
            SizeDisplay = FormatByteSize(byteSize),
            ModifiedUnixMs = modifiedUnixMs,
            ModifiedDisplay = FormatModifiedTime(modifiedUnixMs),
            RuleOrScore = ruleOrScore,
            LocationLabel = locationLabel,
            Snippet = snippet,
            VirtualPath = virtualPath,
            HighlightTerms = highlightTerms
        };
    }

    private static List<string> MergeHighlightTerms(IEnumerable<string> baseTerms, IEnumerable<HitLocationSnippetDto> snippets)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        foreach (var s in snippets)
        {
            if (!string.IsNullOrWhiteSpace(s.MatchedTerm) && set.Add(s.MatchedTerm))
                list.Add(s.MatchedTerm);
        }
        foreach (var t in baseTerms)
        {
            if (!string.IsNullOrWhiteSpace(t) && set.Add(t))
                list.Add(t);
        }
        return list;
    }

    private static string ExtractDirectory(string virtualPath)
    {
        if (string.IsNullOrWhiteSpace(virtualPath)) return string.Empty;
        int bang = virtualPath.IndexOf("!/", StringComparison.Ordinal);
        if (bang >= 0)
        {
            string host = virtualPath[..bang];
            string inner = virtualPath[(bang + 2)..];
            int lastSlash = inner.LastIndexOf('/');
            return lastSlash >= 0 ? $"{host}!/{inner[..lastSlash]}" : host;
        }
        return Path.GetDirectoryName(virtualPath) ?? virtualPath;
    }

    private static string ExtractExtensionUpper(string fileName, string detectedFormat)
    {
        string ext = Path.GetExtension(fileName).TrimStart('.');
        if (!string.IsNullOrEmpty(ext)) return ext.ToUpperInvariant();
        if (!string.IsNullOrWhiteSpace(detectedFormat)) return detectedFormat.ToUpperInvariant();
        return "文件";
    }

    public static string FormatByteSize(ulong bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return $"{kb:F1} KB";
        double mb = kb / 1024.0;
        if (mb < 1024) return $"{mb:F2} MB";
        return $"{mb / 1024.0:F2} GB";
    }

    public static string FormatModifiedTime(long unixMs)
    {
        if (unixMs <= 0) return "-";
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(unixMs).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        }
        catch
        {
            return "-";
        }
    }
}
