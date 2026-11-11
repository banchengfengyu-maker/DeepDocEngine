using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DocSentinel.UI.Ipc;

public sealed class DaemonPipeClient : IAsyncDisposable
{
    private const string PipeName = "DeepDocEngine.v1";
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _cts;
    private Task? _readLoop;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private ulong _nextReqId = 1;
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<JsonObject>> _pending = new();

    public event Action<JsonObject>? OnScanProgress;
    public event Action<HitRecordDto>? OnScanHit;
    public event Action<ScanSummaryDto>? OnScanCompleted;
    public event Action<JsonObject>? OnDeepDeleteProgress;
    public event Action<JsonObject>? OnDeepDeleteCompleted;
    public event Action<string>? OnDisconnected;

    public bool IsConnected => _pipe is { IsConnected: true };

    public async Task ConnectOrStartDaemonAsync(CancellationToken ct = default)
    {
        if (await TryConnectOnceAsync(1500, ct))
            return;

        // Auto-spawn sibling engine-daemon.exe if available
        string baseDir = AppContext.BaseDirectory;
        string? daemonExe = new[]
        {
            Path.Combine(baseDir, "engine-daemon.exe"),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "target", "release", "engine-daemon.exe")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "target", "debug", "engine-daemon.exe")),
        }.FirstOrDefault(File.Exists);

        if (daemonExe is not null)
        {
            var psi = new ProcessStartInfo(daemonExe)
            {
                WorkingDirectory = Path.GetDirectoryName(daemonExe)!,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            Process.Start(psi);
        }

        if (!await TryConnectOnceAsync(6000, ct))
            throw new TimeoutException("无法连接到后台引擎命名管道 `\\\\.\\pipe\\DeepDocEngine.v1`。请先启动 engine-daemon.exe。");
    }

    private async Task<bool> TryConnectOnceAsync(int timeoutMs, CancellationToken ct)
    {
        var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await client.ConnectAsync(timeoutMs, ct);
            _pipe = client;
            _cts = new CancellationTokenSource();
            _readLoop = Task.Run(() => ReadLoopAsync(_cts.Token));
            return true;
        }
        catch
        {
            await client.DisposeAsync();
            return false;
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _pipe is { IsConnected: true })
            {
                var node = await MsgPackCodec.ReadFrameAsync(_pipe, ct);
                if (node is null) break;
                if (node is not JsonObject obj) continue;

                string? type = obj["type"]?.GetValue<string>();
                if (type == "ScanProgress")
                {
                    OnScanProgress?.Invoke(obj);
                    continue;
                }
                if (type == "ScanHit")
                {
                    var hit = obj["hit"]?.Deserialize<HitRecordDto>();
                    if (hit is not null) OnScanHit?.Invoke(hit);
                    continue;
                }
                if (type == "ScanCompleted")
                {
                    var summary = obj["summary"]?.Deserialize<ScanSummaryDto>();
                    if (summary is not null) OnScanCompleted?.Invoke(summary);
                    continue;
                }
                if (type == "DeepDeleteProgress")
                {
                    OnDeepDeleteProgress?.Invoke(obj);
                    continue;
                }
                if (type == "DeepDeleteCompleted")
                {
                    OnDeepDeleteCompleted?.Invoke(obj);
                    continue;
                }

                if (obj["req_id"] is JsonValue reqVal && reqVal.TryGetValue<ulong>(out var reqId))
                {
                    if (_pending.TryRemove(reqId, out var tcs))
                        tcs.TrySetResult(obj);
                }
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            OnDisconnected?.Invoke(ex.Message);
        }
        finally
        {
            foreach (var kv in _pending)
            {
                if (_pending.TryRemove(kv.Key, out var tcs))
                    tcs.TrySetCanceled();
            }
        }
    }

    public async Task<JsonObject> SendAsync(JsonObject requestObj, CancellationToken ct = default)
    {
        if (_pipe is null || !_pipe.IsConnected)
            throw new InvalidOperationException("Daemon pipe not connected");

        ulong reqId = Interlocked.Increment(ref _nextReqId);
        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[reqId] = tcs;

        var env = new JsonObject
        {
            ["req_id"] = reqId,
            ["request"] = requestObj
        };

        await _writeLock.WaitAsync(ct);
        try
        {
            await MsgPackCodec.WriteFrameAsync(_pipe, env, ct);
        }
        finally
        {
            _writeLock.Release();
        }

        using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
        var resp = await tcs.Task;
        if (resp["type"]?.GetValue<string>() == "Error")
        {
            throw new InvalidOperationException($"{resp["code"]}: {resp["message"]}");
        }
        return resp;
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync();
            _cts.Dispose();
        }
        if (_pipe is not null)
            await _pipe.DisposeAsync();
        if (_readLoop is not null)
            try { await _readLoop; } catch { }
        _writeLock.Dispose();
    }
}
