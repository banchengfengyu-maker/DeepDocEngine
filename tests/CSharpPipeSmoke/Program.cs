using DocSentinel.UI.Ipc;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage: CSharpPipeSmoke <path-to-engine-daemon.exe>");
    return 1;
}

string daemonExe = Path.GetFullPath(args[0]);
string tmpRoot = Path.Combine(Path.GetTempPath(), $"deepdoc_cs_e2e_{Environment.ProcessId}");
Directory.CreateDirectory(tmpRoot);
string docsDir = Path.Combine(tmpRoot, "docs");
string dataDir = Path.Combine(tmpRoot, "data");
Directory.CreateDirectory(docsDir);

File.WriteAllText(Path.Combine(docsDir, "budget.md"), "# 内部采购方案\n绝密 ★ 10年\n预算金额 3200万元。\n");
string pipeName = $"DeepDocEngine.cs.{Environment.ProcessId}";

using var daemon = Process.Start(new ProcessStartInfo(daemonExe)
{
    Arguments = $"--pipe \\\\.\\pipe\\{pipeName} --data-dir \"{dataDir}\" --workers 1",
    WorkingDirectory = Path.GetDirectoryName(daemonExe)!,
    UseShellExecute = false,
    CreateNoWindow = true,
})!;

try
{
    using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    await pipe.ConnectAsync(8000);

    // 1. Ping
    await MsgPackCodec.WriteFrameAsync(pipe, new JsonObject
    {
        ["req_id"] = 1,
        ["request"] = new JsonObject { ["type"] = "Ping" }
    }, CancellationToken.None);

    var pong = (await MsgPackCodec.ReadFrameAsync(pipe, CancellationToken.None))!.AsObject();
    if (pong["type"]?.GetValue<string>() != "Pong")
        throw new Exception($"Expected Pong, got {pong}");
    Console.WriteLine($"[C# IPC] Pong OK: engines={pong["worker_engines"]?.AsArray().Count}, ext={pong["ext_worker_engines"]?.AsArray().Count}");

    // 2. StartScan with RuleSet
    var rules = new JsonArray
    {
        JsonSerializer.SerializeToNode(new RuleDefinitionDto
        {
            Id = "r1",
            Name = "涉密预算",
            Category = "涉密",
            Severity = "Critical",
            Expression = "scope:head_tail(re:/绝密\\s*★/) & \"预算金额\"",
            Mode = RuleMatchMode.FullHits
        })
    };

    await MsgPackCodec.WriteFrameAsync(pipe, new JsonObject
    {
        ["req_id"] = 2,
        ["request"] = new JsonObject
        {
            ["type"] = "StartScan",
            ["job_id"] = "cs-job-1",
            ["roots"] = new JsonArray { docsDir },
            ["ruleset"] = new JsonObject { ["ruleset_id"] = "cs-rs", ["rules"] = rules },
            ["options"] = new JsonObject
            {
                ["include_hidden"] = false,
                ["use_usn_if_available"] = false,
                ["worker_count"] = 1,
                ["worker_timeout_ms"] = 15000,
                ["parse"] = new JsonObject
                {
                    ["max_extract_depth"] = 4,
                    ["max_uncompressed_bytes"] = 64L * 1024 * 1024,
                    ["max_single_file_bytes"] = 32L * 1024 * 1024,
                    ["max_expansion_ratio"] = 50,
                    ["enable_ocr"] = true,
                    ["ocr_min_image_dim"] = 24,
                    ["enable_x2t"] = true,
                    ["passwords"] = new JsonArray()
                }
            }
        }
    }, CancellationToken.None);

    int hits = 0;
    ScanSummaryDto? summary = null;
    while (true)
    {
        var msg = (await MsgPackCodec.ReadFrameAsync(pipe, CancellationToken.None))!.AsObject();
        var t = msg["type"]?.GetValue<string>();
        if (t == "ScanHit")
        {
            var hit = msg["hit"]!.Deserialize<HitRecordDto>()!;
            hits++;
            Console.WriteLine($"[C# IPC] Streamed Hit: {hit.FileName} rule={hit.RuleName} loc={hit.Snippets.FirstOrDefault()?.LocationLabel}");
        }
        else if (t == "ScanCompleted")
        {
            summary = msg["summary"]!.Deserialize<ScanSummaryDto>()!;
            break;
        }
    }
    if (summary is null || summary.ParsedOk != 1 || hits != 1)
        throw new Exception($"Unexpected scan result: parsed={summary?.ParsedOk}, hits={hits}");

    // 3. Search + Preview
    await MsgPackCodec.WriteFrameAsync(pipe, new JsonObject
    {
        ["req_id"] = 3,
        ["request"] = new JsonObject
        {
            ["type"] = "Search",
            ["query"] = new JsonObject
            {
                ["text"] = "3200",
                ["file_ext_filter"] = null,
                ["scope_filter"] = null,
                ["use_regex"] = false,
                ["limit"] = 50,
                ["offset"] = 0
            }
        }
    }, CancellationToken.None);
    var searchResp = (await MsgPackCodec.ReadFrameAsync(pipe, CancellationToken.None))!.AsObject();
    var items = searchResp["items"]!.Deserialize<List<SearchHitItemDto>>()!;
    if (items.Count != 1) throw new Exception($"Expected 1 search item, got {items.Count}");

    await MsgPackCodec.WriteFrameAsync(pipe, new JsonObject
    {
        ["req_id"] = 4,
        ["request"] = new JsonObject
        {
            ["type"] = "GetDocumentPreview",
            ["doc_id"] = items[0].DocId,
            ["highlight_terms"] = new JsonArray { "3200" },
            ["max_chars"] = 50000
        }
    }, CancellationToken.None);
    var prevResp = (await MsgPackCodec.ReadFrameAsync(pipe, CancellationToken.None))!.AsObject();
    var preview = prevResp["doc"]!.Deserialize<DocumentPreviewDto>()!;
    if (!preview.Segments.Any(s => s.HighlightRanges.Count > 0))
        throw new Exception("Expected highlighted ranges in preview");

    Console.WriteLine($"[C# IPC] Search & Preview OK: doc_id={preview.DocId}, segments={preview.Segments.Count}");

    // 4. Verify DaemonPipeClient (exact WPF async client used by App.UI)
    await using (var ipcClient = new DaemonPipeClient())
    {
        if (!await ipcClient.TryConnectOnceAsync(pipeName, 5000, CancellationToken.None))
            throw new Exception("DaemonPipeClient.TryConnectOnceAsync failed");
        var ipcPong = await ipcClient.SendAsync(new JsonObject { ["type"] = "Ping" });
        if (ipcPong["type"]?.AsStr() != "Pong")
            throw new Exception($"DaemonPipeClient Ping failed: {ipcPong}");
        var ipcStats = await ipcClient.SendAsync(new JsonObject { ["type"] = "GetStats" });
        if (ipcStats["stats"] is null)
            throw new Exception("DaemonPipeClient GetStats returned null");
        var ipcSearch = await ipcClient.SendAsync(new JsonObject
        {
            ["type"] = "Search",
            ["query"] = new JsonObject
            {
                ["text"] = "3200",
                ["file_ext_filter"] = null,
                ["scope_filter"] = null,
                ["use_regex"] = false,
                ["limit"] = 10,
                ["offset"] = 0
            }
        });
        var ipcItems = ipcSearch["items"]!.Deserialize<List<SearchHitItemDto>>()!;
        if (ipcItems.Count != 1 || ipcItems[0].ModifiedUnixMs <= 0 || ipcItems[0].ByteSize == 0)
            throw new Exception($"DaemonPipeClient Search failed metadata check: count={ipcItems.Count}");
        Console.WriteLine($"[C# IPC] DaemonPipeClient verified OK: mtimeMs={ipcItems[0].ModifiedUnixMs}, size={ipcItems[0].ByteSize}");
    }

    // 5. Shutdown
    await MsgPackCodec.WriteFrameAsync(pipe, new JsonObject
    {
        ["req_id"] = 5,
        ["request"] = new JsonObject { ["type"] = "Shutdown" }
    }, CancellationToken.None);
    _ = await MsgPackCodec.ReadFrameAsync(pipe, CancellationToken.None);
    Console.WriteLine("[C# IPC] FULL CROSS-LANGUAGE E2E PASSED!");
    return 0;
}
finally
{
    try { if (!daemon.HasExited) daemon.Kill(true); } catch { }
    try { Directory.Delete(tmpRoot, true); } catch { }
}
