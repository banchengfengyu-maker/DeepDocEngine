using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DocSentinel.UI.Ipc;

public sealed class DaemonPipeClient : IAsyncDisposable
{
    public const string DefaultPipeName = "DeepDocEngine.v1";
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _cts;
    private Task? _readLoop;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private ulong _nextReqId = 1;
    private readonly ConcurrentDictionary<ulong, TaskCompletionSource<JsonObject>> _pending = new();

    public event Action<JsonObject>? OnScanProgress;
    public event Action<JsonObject>? OnScanFastPassCompleted;
    public event Action<HitRecordDto>? OnScanHit;
    public event Action<ScanSummaryDto>? OnScanCompleted;
    public event Action<JsonObject>? OnDeepDeleteProgress;
    public event Action<JsonObject>? OnDeepDeleteCompleted;
    public event Action<string>? OnDisconnected;
    public event Action? OnReconnected;

    public bool IsConnected => _pipe is { IsConnected: true };

    private string _lastPipeName = DefaultPipeName;
    private string? _lastDataDir;
    private CancellationTokenSource? _reconnectCts;

    public async Task ConnectOrStartDaemonAsync(string pipeName = DefaultPipeName, string? dataDir = null, bool forceReconnect = false, CancellationToken ct = default)
    {
        _lastPipeName = pipeName;
        _lastDataDir = dataDir;

        if (!forceReconnect && IsConnected)
            return;

        if (forceReconnect)
            await ResetConnectionAsync();

        bool isDefaultPipe = string.Equals(pipeName, DefaultPipeName, StringComparison.OrdinalIgnoreCase);
        bool alreadyRunning = isDefaultPipe && Process.GetProcessesByName("engine-daemon").Length > 0;
        var connStatus = await TryConnectWithStatusAsync(pipeName, alreadyRunning ? 1500 : 120, ct);
        if (connStatus == PipeTryConnectResult.Connected)
        {
            CancelReconnectLoop();
            return;
        }
        if (connStatus == PipeTryConnectResult.AccessDenied)
            throw new UnauthorizedAccessException("检测到后台 engine-daemon 正在以管理员权限运行，当前普通权限窗口无权连接（请退出旧管理员进程或升级重启后再试）。");

        // If alreadyRunning is true, but connecting failed, the existing engine-daemon is an unresponsive zombie
        // from an abnormal crash, kill or pipe hang. Clean it up so the fresh daemon can bind the pipe and database cleanly.
        if (alreadyRunning && connStatus != PipeTryConnectResult.Connected)
        {
            try
            {
                foreach (var p in Process.GetProcessesByName("engine-daemon"))
                {
                    try { p.Kill(entireProcessTree: true); p.WaitForExit(1000); } catch { }
                }
                foreach (var p in Process.GetProcessesByName("parser-worker"))
                {
                    try { p.Kill(); } catch { }
                }
                foreach (var p in Process.GetProcessesByName("ext-worker"))
                {
                    try { p.Kill(); } catch { }
                }
            }
            catch { }
            await Task.Delay(300, ct); // Allow OS kernel to release pipe and socket handles
        }

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
            if (!isDefaultPipe)
            {
                psi.ArgumentList.Add("--pipe");
                psi.ArgumentList.Add($@"\\.\pipe\{pipeName}");
            }
            if (!string.IsNullOrWhiteSpace(dataDir))
            {
                psi.ArgumentList.Add("--data-dir");
                psi.ArgumentList.Add(dataDir);
            }
            Process.Start(psi);
        }

        var spawnConn = await TryConnectWithStatusAsync(pipeName, 8000, ct);
        if (spawnConn == PipeTryConnectResult.AccessDenied)
            throw new UnauthorizedAccessException("后台 engine-daemon 管道访问被系统 UAC 拒绝（可能已存在高权限旧实例）。");
        if (spawnConn != PipeTryConnectResult.Connected)
            throw new TimeoutException($"无法连接到本机后台引擎管道 `\\\\.\\pipe\\{pipeName}`。请确认 engine-daemon.exe 可正常启动。");
    }

    private enum PipeTryConnectResult { Connected, Unavailable, AccessDenied }

    public async Task<bool> TryConnectOnceAsync(string pipeName, int timeoutMs, CancellationToken ct) =>
        await TryConnectWithStatusAsync(pipeName, timeoutMs, ct) == PipeTryConnectResult.Connected;

    private async Task<PipeTryConnectResult> TryConnectWithStatusAsync(string pipeName, int timeoutMs, CancellationToken ct)
    {
        var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await client.ConnectAsync(timeoutMs, ct);
            await ResetConnectionAsync();
            _pipe = client;
            _cts = new CancellationTokenSource();
            _readLoop = Task.Run(() => ReadLoopAsync(_cts.Token));
            return PipeTryConnectResult.Connected;
        }
        catch (UnauthorizedAccessException)
        {
            await client.DisposeAsync();
            return PipeTryConnectResult.AccessDenied;
        }
        catch
        {
            await client.DisposeAsync();
            return PipeTryConnectResult.Unavailable;
        }
    }

    private async Task ResetConnectionAsync()
    {
        var cts = Interlocked.Exchange(ref _cts, null);
        if (cts is not null)
        {
            await cts.CancelAsync();
            cts.Dispose();
        }
        var pipe = Interlocked.Exchange(ref _pipe, null);
        if (pipe is not null)
            await pipe.DisposeAsync();
        var readLoop = Interlocked.Exchange(ref _readLoop, null);
        if (readLoop is not null)
            try { await readLoop; } catch { }
        foreach (var kv in _pending)
        {
            if (_pending.TryRemove(kv.Key, out var tcs))
                tcs.TrySetCanceled();
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

                string? type = obj["type"]?.AsStr();
                if (type == "ScanProgress")
                {
                    OnScanProgress?.Invoke(obj);
                    continue;
                }
                if (type == "ScanFastPassCompleted")
                {
                    OnScanFastPassCompleted?.Invoke(obj);
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

                if (obj["req_id"] is not null)
                {
                    ulong reqId = obj["req_id"].AsUInt64(ulong.MaxValue);
                    if (reqId != ulong.MaxValue && _pending.TryRemove(reqId, out var tcs))
                        tcs.TrySetResult(obj);
                }
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            OnDisconnected?.Invoke(ex.Message);
            StartReconnectLoop();
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

    private void StartReconnectLoop()
    {
        CancelReconnectLoop();
        _reconnectCts = new CancellationTokenSource();
        var token = _reconnectCts.Token;

        _ = Task.Run(async () =>
        {
            int delayMs = 1000;
            while (!token.IsCancellationRequested && !IsConnected)
            {
                try
                {
                    await Task.Delay(delayMs, token);
                    await ConnectOrStartDaemonAsync(_lastPipeName, _lastDataDir, forceReconnect: true, ct: token);
                    if (IsConnected)
                    {
                        OnReconnected?.Invoke();
                        break;
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    delayMs = Math.Min(delayMs * 2, 5000);
                }
            }
        }, token);
    }

    private void CancelReconnectLoop()
    {
        var rcts = Interlocked.Exchange(ref _reconnectCts, null);
        if (rcts is not null)
        {
            try { rcts.Cancel(); rcts.Dispose(); } catch { }
        }
    }

    public async Task<JsonObject> SendAsync(JsonObject requestObj, CancellationToken ct = default, int timeoutMs = 15000)
    {
        if (_pipe is null || !_pipe.IsConnected)
            throw new InvalidOperationException("Daemon pipe not connected");

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeoutMs > 0)
            linkedCts.CancelAfter(timeoutMs);
        var effectiveCt = linkedCts.Token;

        ulong reqId = Interlocked.Increment(ref _nextReqId);
        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[reqId] = tcs;

        var env = new JsonObject
        {
            ["req_id"] = reqId,
            ["request"] = requestObj
        };

        await _writeLock.WaitAsync(effectiveCt);
        try
        {
            await MsgPackCodec.WriteFrameAsync(_pipe, env, effectiveCt);
        }
        finally
        {
            _writeLock.Release();
        }

        using var reg = effectiveCt.Register(() => tcs.TrySetCanceled(effectiveCt));
        var resp = await tcs.Task;
        if (resp["type"]?.AsStr() == "Error")
        {
            throw new InvalidOperationException($"{resp["code"]?.AsStr()}: {resp["message"]?.AsStr()}");
        }
        return resp;
    }

    public async ValueTask DisposeAsync()
    {
        CancelReconnectLoop();
        await ResetConnectionAsync();
        _writeLock.Dispose();
    }
}
