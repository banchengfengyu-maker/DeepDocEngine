using DocSentinel.UI.Dialogs;
using DocSentinel.UI.Integration;
using DocSentinel.UI.Ipc;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using System.Windows.Threading;

namespace DocSentinel.UI;

public partial class MainWindow : Window
{
    private readonly DaemonPipeClient _client = new();
    private readonly ObservableCollection<string> _roots = new();
    private readonly ObservableCollection<RuleDefinitionDto> _rules = new();
    private readonly ObservableCollection<ResultRowItem> _results = new();
    private readonly List<string> _recentDirs = new();
    private readonly List<Run> _hitRuns = new();
    private readonly DispatcherTimer _idleTimer = new() { Interval = TimeSpan.FromSeconds(30) };

    private CancellationTokenSource? _previewCts;
    private int _hitCursor = -1;
    private string? _activeJobId;
    private bool _daemonHasRunningJob;
    private DateTime _lastIdleScanUtc = DateTime.MinValue;
    private HashSet<string> _pendingDeleteTargets = new(StringComparer.OrdinalIgnoreCase);

    private const string DefaultSecretKeywords = "秘密 机密 绝密 内部文件 内部资料 不公开";
    private bool _deepCheckMode;
    private List<string> _deepCheckRoots = new();
    private bool _initialCmdDispatched;
    private readonly CancellationTokenSource _uiCmdCts = new();
    private readonly object _cmdBatchLock = new();
    private string? _pendingCmdAction;
    private readonly List<string> _pendingCmdPaths = new();
    private DispatcherTimer? _cmdBatchTimer;

    private string _includeExtsText = string.Empty;
    private string _passwordText = string.Empty;
    private string _customTypeExts = string.Empty;
    private string _scopeFilter = string.Empty;
    private bool _matchAllTerms = true;
    private bool _isUiReady;
    private bool _isConnecting;
    private bool _suppressTypeComboEvents;
    private bool _suppressDirComboEvents;
    private int _lastValidDirComboIndex;

    private readonly record struct ColumnMeta(string Key, string Header, bool DefaultVisible, double DefaultWidth, int DefaultOrder);

    private static readonly ColumnMeta[] ColumnDefs =
    {
        new("FileName", "名称", true, 190, 0),
        new("Modified", "修改日期", true, 125, 1),
        new("FileType", "类型", true, 68, 2),
        new("Directory", "所在目录", true, 210, 3),
        new("FileSize", "大小", true, 82, 4),
        new("Location", "命中来源", true, 125, 5),
        new("Snippet", "命中摘要", false, 220, 6),
        new("RuleOrScore", "匹配度/规则", false, 110, 7),
        new("VirtualPath", "完整路径", false, 260, 8),
    };

    private Dictionary<string, DataGridColumn> _colMap = new(StringComparer.Ordinal);

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHELLEXECUTEINFO
    {
        public int cbSize;
        public uint fMask;
        public nint hwnd;
        public string lpVerb;
        public string lpFile;
        public string? lpParameters;
        public string? lpDirectory;
        public int nShow;
        public nint hInstApp;
        public nint lpIDList;
        public string? lpClass;
        public nint hkeyClass;
        public uint dwHotKey;
        public nint hIcon;
        public nint hProcess;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO lpExecInfo);

    private static uint GetUserIdleSeconds()
    {
        var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref lii)) return 0;
        uint elapsedMs = unchecked((uint)Environment.TickCount) - lii.dwTime;
        return elapsedMs / 1000;
    }

    private static string PrefsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DeepDocEngine", "ui_prefs.json");

    public MainWindow()
    {
        InitializeComponent();
        var rawVer = Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "0.5.0";
        var plusIdx = rawVer.IndexOf('+');
        var appVer = plusIdx >= 0 ? rawVer[..plusIdx] : rawVer;
        Title = $"DeepDocEngine v{appVer} — 本地离线深度文档检索与文件搜索 (Everything 模式)";
        BuildColumnLookup();
        ResultsGrid.ItemsSource = _results;

        LoadOrSeedPreferences();
        RebuildQuickRulesMenu();
        RebuildColumnMenuItems();
        RefreshDirectoryDropdown(syncTextToSelection: false);
        UpdateSearchModeIndicators();
        WireClientEvents();

        _idleTimer.Tick += async (_, _) => await TryIdleIncrementalScanAsync();
        _idleTimer.Start();

        _ = string.IsNullOrWhiteSpace(App.OverridePipeName)
            ? Task.Run(() => UiCommandChannel.RunServerLoopAsync(EnqueueExternalUiCommandAsync, _uiCmdCts.Token))
            : Task.CompletedTask;

        SourceInitialized += (_, _) => CenterAndClampToWorkArea();
        Loaded += async (_, _) =>
        {
            _isUiReady = true;
            if (string.IsNullOrWhiteSpace(App.OverridePipeName))
                SyncShellContextMenuRegistration();
            TxtSearch.Focus();
            await ConnectSafeAsync();
            if (!_initialCmdDispatched && App.InitialCommand is { } initCmd)
            {
                _initialCmdDispatched = true;
                await DispatchExternalUiCommandAsync(initCmd);
            }
        };
        Closed += async (_, _) =>
        {
            _idleTimer.Stop();
            _cmdBatchTimer?.Stop();
            _uiCmdCts.Cancel();
            _uiCmdCts.Dispose();
            _previewCts?.Cancel();
            SavePreferences();
            await _client.DisposeAsync();
        };
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        bool hasWork = _activeJobId is not null || _daemonHasRunningJob;
        bool shouldShutdownDaemon = true;
        if (hasWork)
        {
            var choice = MessageBox.Show(
                this,
                "当前仍有后台扫描/索引或深度擦除任务正在执行，关闭界面时是否同步停止后台任务？\n\n" +
                "• 选【是】：停止全部后台任务并完全退出（推荐）\n" +
                "• 选【否】：仅关闭窗口，保留后台继续运行\n" +
                "• 选【取消】：留在软件中",
                "确认退出 DeepDocEngine",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question,
                MessageBoxResult.Cancel);
            if (choice == MessageBoxResult.Cancel)
            {
                e.Cancel = true;
                return;
            }
            shouldShutdownDaemon = (choice == MessageBoxResult.Yes);
        }
        else if (MenuConfirmClose.IsChecked)
        {
            var confirm = MessageBox.Show(
                this,
                "确定要关闭 DeepDocEngine 吗？",
                "确认退出 DeepDocEngine",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                return;
            }
        }

        if (shouldShutdownDaemon && _client.IsConnected)
        {
            Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(1800);
                    if (hasWork)
                        await _client.SendAsync(new JsonObject { ["type"] = "CancelScan", ["job_id"] = "*" }, cts.Token);
                    await _client.SendAsync(new JsonObject { ["type"] = "Shutdown" }, cts.Token);
                }
                catch { }
            }).Wait(2000);
        }
    }

    private void CenterAndClampToWorkArea()
    {
        var wa = SystemParameters.WorkArea;
        if (wa.Width <= 0 || wa.Height <= 0) return;

        double targetW = Math.Min(1020.0, Math.Max(MinWidth, wa.Width - 64.0));
        double targetH = Math.Min(620.0, Math.Max(MinHeight, wa.Height - 48.0));
        Width = Math.Min(targetW, wa.Width);
        Height = Math.Min(targetH, wa.Height);
        Left = wa.Left + Math.Max(0, (wa.Width - Width) / 2.0);
        Top = wa.Top + Math.Max(0, (wa.Height - Height) / 2.0);
        WindowStartupLocation = WindowStartupLocation.Manual;
    }

    private void BuildColumnLookup()
    {
        _colMap = new Dictionary<string, DataGridColumn>(StringComparer.Ordinal)
        {
            ["FileName"] = ColFileName,
            ["Modified"] = ColModified,
            ["FileType"] = ColFileType,
            ["Directory"] = ColDirectory,
            ["FileSize"] = ColFileSize,
            ["Location"] = ColLocation,
            ["Snippet"] = ColSnippet,
            ["RuleOrScore"] = ColRuleOrScore,
            ["VirtualPath"] = ColVirtualPath
        };
    }

    // ======================== Preferences ========================

    private void LoadOrSeedPreferences()
    {
        bool loadedRules = false;
        try
        {
            if (File.Exists(PrefsPath))
            {
                var node = JsonNode.Parse(File.ReadAllText(PrefsPath)) as JsonObject;
                if (node is not null)
                {
                    if (node["roots"] is JsonArray rArr)
                    {
                        foreach (var r in rArr)
                        {
                            var s = r.AsStr();
                            if (!string.IsNullOrWhiteSpace(s) && !_roots.Contains(s, StringComparer.OrdinalIgnoreCase))
                                _roots.Add(s);
                        }
                    }
                    if (node["recent_dirs"] is JsonArray rdArr)
                    {
                        foreach (var d in rdArr)
                        {
                            var s = d.AsStr();
                            if (!string.IsNullOrWhiteSpace(s) && !_recentDirs.Contains(s, StringComparer.OrdinalIgnoreCase))
                                _recentDirs.Add(s);
                        }
                    }
                    _includeExtsText = node["include_exts"]?.AsStr() ?? string.Empty;
                    TxtDirFilter.Text = node["dir_filter"]?.AsStr() ?? string.Empty;
                    _customTypeExts = node["custom_ext_filter"]?.AsStr() ?? string.Empty;

                    MenuEnableOcr.IsChecked = node["enable_ocr"]?.AsBool(true) ?? true;
                    MenuSkipTemp.IsChecked = node["skip_temp"]?.AsBool(true) ?? true;
                    MenuIdleIndex.IsChecked = node["idle_index"]?.AsBool(false) ?? false;
                    MenuLowResourceIndex.IsChecked = node["low_resource_index"]?.AsBool(false) ?? false;
                    MenuConfirmClose.IsChecked = node["confirm_close"]?.AsBool(true) ?? true;
                    MenuShellContextMenu.IsChecked = node["shell_context_menu"]?.AsBool(true) ?? true;
                    MenuTopmost.IsChecked = node["topmost"]?.AsBool(false) ?? false;
                    Topmost = MenuTopmost.IsChecked;

                    bool showPreview = node["show_preview"]?.AsBool(true) ?? true;
                    MenuTogglePreview.IsChecked = showPreview;
                    ApplyPreviewPaneVisibility(showPreview);

                    _matchAllTerms = node["match_all_terms"]?.AsBool(true) ?? true;
                    MenuMatchAnd.IsChecked = _matchAllTerms;
                    MenuMatchOr.IsChecked = !_matchAllTerms;
                    MenuUseRegex.IsChecked = node["use_regex"]?.AsBool(false) ?? false;
                    MenuUseExpr.IsChecked = node["expr_mode"]?.AsBool(false) ?? false;
                    SetScopeFilter(node["scope_filter"]?.AsStr() ?? string.Empty);

                    if (!string.IsNullOrWhiteSpace(_customTypeExts))
                    {
                        CmbTypeCustomItem.Content = $"自定义 ({_customTypeExts})";
                        CmbTypeCustomItem.Tag = _customTypeExts;
                    }
                    string presetTag = node["type_preset_tag"]?.AsStr() ?? string.Empty;
                    RestoreTypeComboSelection(presetTag);

                    if (node["columns"] is JsonArray colArr && colArr.Count > 0)
                    {
                        ApplySavedColumns(colArr);
                    }

                    if (node["saved_queries"] is JsonArray qArr && qArr.Count > 0)
                    {
                        foreach (var item in qArr)
                        {
                            var dto = item?.Deserialize<RuleDefinitionDto>();
                            if (dto is not null && !string.IsNullOrWhiteSpace(dto.Expression))
                                _rules.Add(dto);
                        }
                        loadedRules = _rules.Count > 0;
                    }
                }
            }
        }
        catch { }

        if (!loadedRules)
            SeedDefaultQueries();
    }

    private void ApplySavedColumns(JsonArray colArr)
    {
        var appliedKeys = new HashSet<string>(StringComparer.Ordinal);
        int displayIdx = 0;
        foreach (var item in colArr)
        {
            if (item is not JsonObject cObj) continue;
            string key = cObj["key"]?.AsStr() ?? string.Empty;
            if (!_colMap.TryGetValue(key, out var col)) continue;
            appliedKeys.Add(key);

            bool visible = cObj["visible"]?.AsBool(true) ?? true;
            double width = cObj["width"]?.AsUInt64(0) ?? 0;
            col.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (width >= 40 && width <= 1200)
                col.Width = new DataGridLength(width);
            if (displayIdx < ResultsGrid.Columns.Count)
                col.DisplayIndex = displayIdx++;
        }

        // Assign any newly introduced columns after saved ones
        foreach (var def in ColumnDefs)
        {
            if (appliedKeys.Contains(def.Key) || !_colMap.TryGetValue(def.Key, out var col)) continue;
            col.Visibility = def.DefaultVisible ? Visibility.Visible : Visibility.Collapsed;
            if (displayIdx < ResultsGrid.Columns.Count)
                col.DisplayIndex = displayIdx++;
        }

        EnsureAtLeastOneColumnVisible();
    }

    private void RestoreTypeComboSelection(string savedTag)
    {
        _suppressTypeComboEvents = true;
        try
        {
            for (int i = 0; i < CmbTypePreset.Items.Count; i++)
            {
                if (CmbTypePreset.Items[i] is ComboBoxItem ci && (ci.Tag as string ?? string.Empty) == savedTag)
                {
                    CmbTypePreset.SelectedIndex = i;
                    return;
                }
            }
            CmbTypePreset.SelectedIndex = 0;
        }
        finally
        {
            _suppressTypeComboEvents = false;
        }
    }

    private void SavePreferences()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PrefsPath)!);
            var colArr = new JsonArray();
            foreach (var col in ResultsGrid.Columns.OrderBy(c => c.DisplayIndex))
            {
                string? key = _colMap.FirstOrDefault(kv => ReferenceEquals(kv.Value, col)).Key;
                if (string.IsNullOrEmpty(key)) continue;
                double w = col.ActualWidth > 30 ? col.ActualWidth : col.Width.DisplayValue;
                colArr.Add(new JsonObject
                {
                    ["key"] = key,
                    ["visible"] = col.Visibility == Visibility.Visible,
                    ["width"] = Math.Round(w, 0)
                });
            }

            string presetTag = (CmbTypePreset.SelectedItem as ComboBoxItem)?.Tag as string ?? string.Empty;
            if (presetTag == "__CUSTOM__") presetTag = string.Empty;

            var obj = new JsonObject
            {
                ["roots"] = new JsonArray(_roots.Select(r => JsonValue.Create(r)).ToArray<JsonNode?>()),
                ["recent_dirs"] = new JsonArray(_recentDirs.Take(8).Select(r => JsonValue.Create(r)).ToArray<JsonNode?>()),
                ["include_exts"] = _includeExtsText,
                ["dir_filter"] = TxtDirFilter.Text.Trim(),
                ["custom_ext_filter"] = _customTypeExts,
                ["type_preset_tag"] = presetTag,
                ["enable_ocr"] = MenuEnableOcr.IsChecked,
                ["skip_temp"] = MenuSkipTemp.IsChecked,
                ["idle_index"] = MenuIdleIndex.IsChecked,
                ["low_resource_index"] = MenuLowResourceIndex.IsChecked,
                ["confirm_close"] = MenuConfirmClose.IsChecked,
                ["shell_context_menu"] = MenuShellContextMenu.IsChecked,
                ["topmost"] = MenuTopmost.IsChecked,
                ["show_preview"] = MenuTogglePreview.IsChecked,
                ["match_all_terms"] = _matchAllTerms,
                ["use_regex"] = MenuUseRegex.IsChecked,
                ["expr_mode"] = MenuUseExpr.IsChecked,
                ["scope_filter"] = _scopeFilter,
                ["columns"] = colArr,
                ["saved_queries"] = new JsonArray(_rules.Select(r => JsonSerializer.SerializeToNode(r)).ToArray())
            };
            File.WriteAllText(PrefsPath, obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private void SeedDefaultQueries()
    {
        _rules.Add(new RuleDefinitionDto
        {
            Id = "q-near",
            Name = "邻近共现示例",
            Category = "常用",
            Severity = "表达式",
            Expression = "NEAR(合同, 违约, 15)",
            Mode = RuleMatchMode.FullHits
        });
        _rules.Add(new RuleDefinitionDto
        {
            Id = "q-ocr",
            Name = "仅搜图片/内嵌图OCR",
            Category = "图像OCR",
            Severity = "OCR",
            Expression = "scope:ocr(预算 | 报价 | 专用章 | 参数)",
            Mode = RuleMatchMode.FullHits
        });
        _rules.Add(new RuleDefinitionDto
        {
            Id = "q-cad",
            Name = "CAD图纸检索",
            Category = "CAD",
            Severity = "图纸",
            Expression = "scope:filename(re:/\\.(dwg|dxf)$/i) & (设计 | 平面 | 总图)",
            Mode = RuleMatchMode.FullHits
        });
    }

    // ======================== Daemon IPC & Events ========================

    private void WireClientEvents()
    {
        _client.OnScanProgress += obj => Dispatcher.BeginInvoke(() =>
        {
            string msgJobId = obj["job_id"].AsStr();
            if (_activeJobId is not null && !string.IsNullOrEmpty(msgJobId) && !string.Equals(msgJobId, _activeJobId, StringComparison.Ordinal))
                return;
            ulong scanned = obj["scanned_files"].AsUInt64();
            ulong ok = obj["parsed_ok"].AsUInt64();
            ulong cached = obj["skipped_cached"].AsUInt64();
            ulong enc = obj["encrypted_files"].AsUInt64();
            ulong fail = obj["failed_files"].AsUInt64();
            string cur = obj["current_path"].AsStr();
            string phase = obj["phase"].AsStr();
            ulong ocrPending = obj["ocr_pending"].AsUInt64();
            ulong ocrDone = obj["ocr_done"].AsUInt64();

            if (phase == "ocr" && ocrPending > 0)
            {
                ScanProgressBar.IsIndeterminate = false;
                ScanProgressBar.Maximum = ocrPending;
                ScanProgressBar.Value = Math.Min(ocrDone, ocrPending);
                FooterStatusText.Text =
                    $"核心文档已可搜索 | 后台低负载 OCR 中 ({ocrDone:N0}/{ocrPending:N0}) — {cur}";
            }
            else if (phase == "other")
            {
                FooterStatusText.Text =
                    $"核心常用文档已可搜索 | 正在后台索引杂项/源码 ({ok:N0}) — {cur}";
            }
            else
            {
                FooterStatusText.Text =
                    $"扫描中: 发现 {scanned:N0} | 解析 {ok:N0} | 缓存跳过 {cached:N0} | 加密 {enc:N0} | 失败 {fail} | 待OCR {ocrPending:N0} — {cur}";
            }
        });

        _client.OnScanFastPassCompleted += obj => Dispatcher.Invoke(async () =>
        {
            ulong fastOk = obj["fast_parsed_ok"].AsUInt64();
            ulong cached = obj["skipped_cached"].AsUInt64();
            ulong deferredOcr = obj["deferred_ocr_count"].AsUInt64();

            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Maximum = Math.Max(1, deferredOcr);
            ScanProgressBar.Value = 0;

            FastPassBannerText.Text =
                $"✅ 核心常用文档（Word/Excel/PPT/PDF/TXT/DWG/压缩包，共 {fastOk:N0} 篇，缓存跳过 {cached:N0} 篇）已索引就绪，您现在就可以先开始搜索！" +
                $"其余文件及 {deferredOcr:N0} 项 OCR 将在后台低占用继续处理。";
            FastPassBanner.Visibility = Visibility.Visible;
            FooterStatusText.Text =
                $"核心文档已就绪可立即搜索 | 正在后台处理其余文件及 {deferredOcr:N0} 项 OCR...";

            await RefreshStatsSafeAsync();
            if (_results.Count == 0 && !string.IsNullOrWhiteSpace(TxtSearch.Text))
            {
                await ExecuteCurrentSearchAsync(limit: 200, silentEmpty: true);
            }
        });

        _client.OnScanHit += hit => Dispatcher.Invoke(() =>
        {
            _results.Add(ResultRowItem.FromHitRecord(hit));
            ResultsHeader.Text = $"当前命中 {_results.Count} 个文档（右键表头增删列，单击预览定位关键词，右键文件可打开/深度删除）";
        });

        _client.OnScanCompleted += summary => Dispatcher.Invoke(async () =>
        {
            if (_activeJobId is not null && !string.IsNullOrEmpty(summary.JobId) && !string.Equals(summary.JobId, _activeJobId, StringComparison.Ordinal))
                return;
            string? completedJob = summary.JobId;
            if (string.IsNullOrEmpty(completedJob)) completedJob = _activeJobId;
            _activeJobId = null;
            _daemonHasRunningJob = false;
            SetJobUiBusy(false);
            ScanProgressBar.Maximum = 100;
            ScanProgressBar.Value = 100;
            FastPassBanner.Visibility = Visibility.Collapsed;

            bool isDeepChk = completedJob is not null && completedJob.StartsWith("deepchk-", StringComparison.Ordinal);
            if (isDeepChk && !summary.Cancelled)
            {
                ResultsHeader.Text =
                    $"深度查密完成：共扫描 {summary.ScannedFiles:N0} 项，命中 {summary.RuleHits:N0} 处涉密记录 — 可继续在上方搜索框输入更多关键词按 Enter 查密";
                FooterStatusText.Text =
                    $"深度查密完成: 检查 {summary.ScannedFiles:N0} 个文件 (含子文档 {summary.ChildDocsIndexed:N0}), 加密 {summary.EncryptedFiles:N0}, 命中 {summary.RuleHits:N0} 处, 耗时 {summary.ElapsedMs} ms — 输入更多关键词按 Enter 可继续深查";
                TxtSearch.Focus();
                TxtSearch.SelectAll();
            }
            else
            {
                FooterStatusText.Text =
                    $"任务{(summary.Cancelled ? "已取消" : "完成")}: 文件 {summary.ScannedFiles}, 解析 {summary.ParsedOk}, 子文档 {summary.ChildDocsIndexed}, 缓存跳过 {summary.SkippedCached}, 加密 {summary.EncryptedFiles}, 失败 {summary.FailedFiles}, 命中 {summary.RuleHits}, 耗时 {summary.ElapsedMs} ms";
            }
            await RefreshStatsSafeAsync();

            if (completedJob is not null
                && !completedJob.StartsWith("direct-", StringComparison.Ordinal)
                && !isDeepChk
                && !summary.Cancelled
                && !_deepCheckMode)
            {
                await ExecuteCurrentSearchAsync(limit: 500, silentEmpty: true);
            }
        });

        _client.OnDeepDeleteProgress += obj => Dispatcher.BeginInvoke(() =>
        {
            ulong done = obj["completed"].AsUInt64();
            ulong total = obj["total"].AsUInt64();
            string cur = obj["current_path"].AsStr();
            FooterStatusText.Text = $"深度擦除中 ({done}/{total}) — 慢速低熵三遍覆写防杀软误报: {cur}";
        });

        _client.OnDeepDeleteCompleted += obj => Dispatcher.Invoke(async () =>
        {
            _activeJobId = null;
            _daemonHasRunningJob = false;
            SetJobUiBusy(false);
            ScanProgressBar.Maximum = 100;
            ScanProgressBar.Value = 100;
            ulong wiped = obj["deleted_files"].AsUInt64();
            ulong purged = obj["purged_index_docs"].AsUInt64();
            ulong skipped = obj["skipped_or_failed"].AsUInt64();
            var errs = obj["errors"]?.AsArray().Select(n => n?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s)).ToList() ?? new();

            if (wiped > 0 && _pendingDeleteTargets.Count > 0)
            {
                for (int i = _results.Count - 1; i >= 0; i--)
                {
                    if (MatchesAnyDeleteTarget(_results[i].VirtualPath, _pendingDeleteTargets))
                        _results.RemoveAt(i);
                }
                PreviewBox.Document.Blocks.Clear();
                PreviewHeader.Text = "文件内容预览";
                PreviewSubHeader.Text = "选中文件/目录已被深度擦除并从索引库抹除";
                HitNavText.Text = "0 / 0";
            }
            _pendingDeleteTargets.Clear();
            FooterStatusText.Text = $"深度擦除完成: 粉碎 {wiped} 个文件, 同步抹除索引 {purged} 条, 跳过/失败 {skipped} 条";
            await RefreshStatsSafeAsync();

            if (errs.Count > 0)
            {
                MessageBox.Show(string.Join("\n", errs.Take(10)), "部分文件/目录未擦除（安全保护或跳过）", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        });

        _client.OnDisconnected += msg => Dispatcher.Invoke(() =>
        {
            SetConnectedBadge(false, $"连接断开: {msg}（后台正在自动重连...）");
            FooterStatusText.Text = "与后台引擎的连接已断开，正在尝试自动重连...";
        });

        _client.OnReconnected += () => Dispatcher.Invoke(async () =>
        {
            SetConnectedBadge(true, "本机后台内核已自动重连恢复");
            FooterStatusText.Text = "后台引擎连接已自动恢复";
            try
            {
                var pong = await _client.SendAsync(new JsonObject { ["type"] = "Ping" });
                ulong activeJobs = pong["active_jobs"]?.AsUInt64() ?? 0;
                _daemonHasRunningJob = activeJobs > 0;
                if (!_daemonHasRunningJob && _activeJobId is not null)
                {
                    _activeJobId = null;
                    SetJobUiBusy(false);
                }
            }
            catch { }
        });
    }

    private void SetConnectedBadge(bool connected, string tooltip)
    {
        StatusBadge.Background = new SolidColorBrush(connected
            ? Color.FromRgb(22, 163, 74)
            : Color.FromRgb(220, 38, 38));
        StatusBadgeText.Text = connected ? "● 引擎已就绪" : "● 未连接";
        StatusBadge.ToolTip = tooltip;
    }

    private async Task ConnectSafeAsync(bool forceReconnect = false)
    {
        if (_isConnecting) return;
        _isConnecting = true;
        try
        {
            if (forceReconnect && (_activeJobId is not null || _daemonHasRunningJob))
            {
                FooterStatusText.Text = "后台任务正在执行，已保持当前引擎连接（如需重连请先等待或停止任务）";
                return;
            }
            FooterStatusText.Text = "正在启动并连接本机离线解析与检索内核（纯单机运行，无网络访问）...";
            string targetPipe = string.IsNullOrWhiteSpace(App.OverridePipeName)
                ? DaemonPipeClient.DefaultPipeName
                : App.OverridePipeName;
            await _client.ConnectOrStartDaemonAsync(targetPipe, App.OverrideDataDir, forceReconnect: forceReconnect);
            var pong = await _client.SendAsync(new JsonObject { ["type"] = "Ping" });
            var engines = pong["worker_engines"]?.AsArray().Select(n => n?.ToString() ?? "").ToList() ?? new();
            var extEngines = pong["ext_worker_engines"]?.AsArray().Select(n => n?.ToString() ?? "").ToList() ?? new();
            ulong activeJobs = pong["active_jobs"].AsUInt64();
            _daemonHasRunningJob = activeJobs > 0;
            SetConnectedBadge(true, $"本机离线核心已就绪（只读状态指示）\nparser-worker: {string.Join(", ", engines)}\next-worker: {string.Join(", ", extEngines)}");
            FooterStatusText.Text = _daemonHasRunningJob
                ? $"本机后台内核已连接 — 检测到 {activeJobs} 个后台索引任务仍在执行（可等待或点右侧【停止任务】）"
                : $"本机后台内核已就绪 (v{pong["daemon_version"]})";
            if (_daemonHasRunningJob)
                SetJobUiBusy(true);

            var st = await RefreshStatsSafeAsync();
            bool hasInitialAction = App.InitialCommand is not null && !_initialCmdDispatched;
            if (st is not null && st.TotalDocuments > 0 && _results.Count == 0 && !_daemonHasRunningJob && !hasInitialAction && !_deepCheckMode)
            {
                await ExecuteCurrentSearchAsync(limit: 200, silentEmpty: true);
            }
            else if (st is not null && st.TotalDocuments == 0 && !_daemonHasRunningJob)
            {
                FooterStatusText.Text = "引擎已就绪 — 当前索引库为空，请从菜单【文件 -> 添加索引文件夹】或【索引 -> 管理索引目录】添加路径并建立索引";
            }
        }
        catch (Exception ex)
        {
            SetConnectedBadge(false, ex.Message);
            FooterStatusText.Text = $"连接失败: {ex.Message}";
        }
        finally
        {
            _isConnecting = false;
        }
    }

    private async Task<IndexStatsDto?> RefreshStatsSafeAsync()
    {
        if (!_client.IsConnected) return null;
        try
        {
            var res = await _client.SendAsync(new JsonObject { ["type"] = "GetStats" });
            var st = res["stats"]?.Deserialize<IndexStatsDto>();
            if (st is not null)
            {
                double mb = (st.DbSizeBytes + st.TantivySizeBytes) / (1024.0 * 1024.0);
                StatsText.Text = $"已索引: {st.TotalDocuments:N0} 篇 | 索引占用: {mb:F1} MB";
                StatsText.ToolTip = $"文档: {st.TotalDocuments}\n去重正文块: {st.UniqueContentBlobs}\nOCR缓存图: {st.OcrCachedImages}\n加密: {st.EncryptedDocuments} | 失败: {st.FailedDocuments}";
            }
            return st;
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = $"获取统计失败: {ex.Message}";
            return null;
        }
    }

    private async void MenuReconnect_Click(object sender, RoutedEventArgs e) => await ConnectSafeAsync(forceReconnect: true);
    private async void MenuRefreshStats_Click(object sender, RoutedEventArgs e) => await RefreshStatsSafeAsync();

    // ======================== Search & Filters ========================

    private string? GetEffectiveExtFilter()
    {
        if (CmbTypePreset.SelectedItem is ComboBoxItem ci)
        {
            string tag = ci.Tag as string ?? string.Empty;
            if (tag == "__CUSTOM__")
                return string.IsNullOrWhiteSpace(_customTypeExts) ? null : _customTypeExts;
            return string.IsNullOrWhiteSpace(tag) ? null : tag;
        }
        return null;
    }

    private void TxtSearch_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            _ = ExecuteCurrentSearchAsync();
        }
    }

    private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        bool empty = string.IsNullOrEmpty(TxtSearch.Text);
        TxtSearchPlaceholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        BtnClearSearchText.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
    }

    private void BtnClearSearchText_Click(object sender, RoutedEventArgs e)
    {
        TxtSearch.Text = string.Empty;
        TxtSearch.Focus();
        if (_client.IsConnected && _isUiReady)
            _ = ExecuteCurrentSearchAsync(limit: 200, silentEmpty: true);
    }

    private void BtnSearch_Click(object sender, RoutedEventArgs e) => _ = ExecuteCurrentSearchAsync();

    private void CmbTypePreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressTypeComboEvents || !_isUiReady) return;
        if (CmbTypePreset.SelectedItem is ComboBoxItem ci && (ci.Tag as string) == "__CUSTOM__")
        {
            string? entered = SimpleInputDialog.Prompt(
                this,
                "自定义筛选文件后缀",
                "请输入要过滤的文件扩展名（多个请用逗号分隔，例如 pdf,docx,dwg）：",
                _customTypeExts);
            if (!string.IsNullOrWhiteSpace(entered))
            {
                _customTypeExts = string.Join(",", entered
                    .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim().TrimStart('.').ToLowerInvariant())
                    .Where(s => !string.IsNullOrEmpty(s))
                    .Distinct());
                CmbTypeCustomItem.Content = $"自定义 ({_customTypeExts})";
                CmbTypeCustomItem.Tag = _customTypeExts;
                SavePreferences();
            }
            else if (string.IsNullOrWhiteSpace(_customTypeExts))
            {
                RestoreTypeComboSelection(string.Empty);
                return;
            }
        }
        SavePreferences();
        if (_client.IsConnected && _activeJobId is null)
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
    }

    private void RefreshDirectoryDropdown(bool syncTextToSelection)
    {
        _suppressDirComboEvents = true;
        try
        {
            CmbDirSelect.Items.Clear();
            CmbDirSelect.Items.Add(new ComboBoxItem { Content = "全部已索引目录（不限路径）", Tag = string.Empty });

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in _roots)
            {
                if (seen.Add(root))
                    CmbDirSelect.Items.Add(new ComboBoxItem { Content = $"📁 {root}", Tag = root });
            }
            foreach (var dir in _recentDirs)
            {
                if (seen.Add(dir))
                    CmbDirSelect.Items.Add(new ComboBoxItem { Content = $"🕒 {dir}", Tag = dir });
            }

            string currentDir = TxtDirFilter.Text.Trim();
            if (!string.IsNullOrWhiteSpace(currentDir) && seen.Add(currentDir))
                CmbDirSelect.Items.Add(new ComboBoxItem { Content = $"📌 {currentDir}", Tag = currentDir });

            CmbDirSelect.Items.Add(new ComboBoxItem { Content = "📂 浏览选择文件夹...", Tag = "__BROWSE__" });

            int matchIdx = 0;
            if (!syncTextToSelection && !string.IsNullOrWhiteSpace(currentDir))
            {
                for (int i = 0; i < CmbDirSelect.Items.Count; i++)
                {
                    if (CmbDirSelect.Items[i] is ComboBoxItem ci &&
                        string.Equals(ci.Tag as string, currentDir, StringComparison.OrdinalIgnoreCase))
                    {
                        matchIdx = i;
                        break;
                    }
                }
            }
            CmbDirSelect.SelectedIndex = matchIdx;
            _lastValidDirComboIndex = matchIdx;
        }
        finally
        {
            _suppressDirComboEvents = false;
        }
    }

    private void RememberRecentDirectory(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return;
        _recentDirs.RemoveAll(d => string.Equals(d, dir, StringComparison.OrdinalIgnoreCase));
        _recentDirs.Insert(0, dir);
        if (_recentDirs.Count > 6)
            _recentDirs.RemoveRange(6, _recentDirs.Count - 6);
    }

    private void CmbDirSelect_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressDirComboEvents || !_isUiReady) return;
        if (CmbDirSelect.SelectedItem is not ComboBoxItem ci) return;

        string tag = ci.Tag as string ?? string.Empty;
        if (tag == "__BROWSE__")
        {
            var dlg = new OpenFolderDialog { Title = "选择限定搜索的文件目录", Multiselect = false };
            if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.FolderName))
            {
                TxtDirFilter.Text = dlg.FolderName;
                RememberRecentDirectory(dlg.FolderName);
                RefreshDirectoryDropdown(syncTextToSelection: false);
                SavePreferences();
                if (_client.IsConnected && _activeJobId is null)
                    _ = ExecuteCurrentSearchAsync(silentEmpty: true);
            }
            else
            {
                _suppressDirComboEvents = true;
                CmbDirSelect.SelectedIndex = Math.Clamp(_lastValidDirComboIndex, 0, Math.Max(0, CmbDirSelect.Items.Count - 2));
                _suppressDirComboEvents = false;
            }
            return;
        }

        _lastValidDirComboIndex = CmbDirSelect.SelectedIndex;
        TxtDirFilter.Text = tag;
        SavePreferences();
        if (_client.IsConnected && _activeJobId is null)
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
    }

    private void TxtDirFilter_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            string dir = TxtDirFilter.Text.Trim();
            if (!string.IsNullOrWhiteSpace(dir))
                RememberRecentDirectory(dir);
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            _ = ExecuteCurrentSearchAsync();
        }
    }

    private void TxtDirFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        bool empty = string.IsNullOrEmpty(TxtDirFilter.Text);
        TxtDirFilterPlaceholder.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        BtnClearDirFilter.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
    }

    private void BtnClearDirFilter_Click(object sender, RoutedEventArgs e)
    {
        TxtDirFilter.Text = string.Empty;
        RefreshDirectoryDropdown(syncTextToSelection: false);
        SavePreferences();
        if (_client.IsConnected && _activeJobId is null)
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
    }

    private void TxtDirFilter_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void TxtDirFilter_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            string target = Directory.Exists(paths[0]) ? paths[0] : (Path.GetDirectoryName(paths[0]) ?? paths[0]);
            TxtDirFilter.Text = target;
            RememberRecentDirectory(target);
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            if (_client.IsConnected && _activeJobId is null)
                _ = ExecuteCurrentSearchAsync(silentEmpty: true);
        }
    }

    private async Task ExecuteCurrentSearchAsync(int limit = 500, bool silentEmpty = false)
    {
        if (!_client.IsConnected)
        {
            if (silentEmpty) return;
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }

        string q = TxtSearch.Text.Trim();
        if (_deepCheckMode && _deepCheckRoots.Count > 0)
        {
            if (string.IsNullOrWhiteSpace(q))
            {
                if (!silentEmpty)
                {
                    TxtSearch.Focus();
                    FooterStatusText.Text = "当前处于【深度查密模式】：请输入更多关键词/正则按 Enter 深查，或点击上方【重查默认词】 / 【退出查密】";
                }
                return;
            }
            await StartDeepCheckAsync(_deepCheckRoots, q);
            return;
        }

        if (MenuUseExpr.IsChecked && !string.IsNullOrWhiteSpace(q))
        {
            await ExecuteExpressionSearchAsync(q, "即时表达式");
            return;
        }

        string? ext = GetEffectiveExtFilter();
        string? dirPrefix = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim();
        if (!string.IsNullOrWhiteSpace(dirPrefix))
            RememberRecentDirectory(dirPrefix);

        var req = new JsonObject
        {
            ["type"] = "Search",
            ["query"] = new JsonObject
            {
                ["text"] = q,
                ["file_ext_filter"] = ext,
                ["path_prefix"] = dirPrefix,
                ["scope_filter"] = string.IsNullOrEmpty(_scopeFilter) ? null : _scopeFilter,
                ["use_regex"] = MenuUseRegex.IsChecked,
                ["match_all_terms"] = _matchAllTerms,
                ["limit"] = limit,
                ["offset"] = 0
            }
        };

        try
        {
            var resp = await _client.SendAsync(req);
            int total = resp["total_hits"].AsInt32();
            ulong ms = resp["took_ms"].AsUInt64();
            var items = resp["items"]?.Deserialize<List<SearchHitItemDto>>() ?? new();

            _results.Clear();
            var terms = ParseHighlightTermsFromQuery(q, MenuUseRegex.IsChecked);
            foreach (var it in items)
                _results.Add(ResultRowItem.FromSearchHit(it, terms));

            if (string.IsNullOrWhiteSpace(q) && ext is null && dirPrefix is null)
            {
                ResultsHeader.Text = $"已索引文档总览（共 {total:N0} 篇，展示前 {_results.Count:N0} 篇，耗时 {ms} ms）";
                FooterStatusText.Text = $"就绪: 共 {total:N0} 篇已索引文档 ({ms} ms)";
            }
            else
            {
                ResultsHeader.Text = $"检索结果：共 {total:N0} 篇命中（展示 {_results.Count:N0} 篇，耗时 {ms} ms）";
                FooterStatusText.Text = $"搜索完成: 命中 {total:N0} 篇 ({ms} ms)";
            }

            if (_results.Count == 0 && !silentEmpty)
            {
                PreviewBox.Document.Blocks.Clear();
                PreviewHeader.Text = "文件内容预览";
                PreviewSubHeader.Text = "未找到匹配文件 — 可尝试切换 OR 逻辑、清除类型/目录限制或对新目录执行索引";
                HitNavText.Text = "0 / 0";
            }
        }
        catch (Exception ex)
        {
            if (!silentEmpty)
                MessageBox.Show(ex.Message, "检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static List<string> ParseHighlightTermsFromQuery(string q, bool useRegex)
    {
        if (useRegex || string.IsNullOrWhiteSpace(q)) return new();
        return q.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim('"'))
            .Where(t => !string.IsNullOrWhiteSpace(t) &&
                        !string.Equals(t, "AND", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(t, "OR", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(t, "NOT", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private async Task ExecuteExpressionSearchAsync(string expr, string label)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        try
        {
            var singleRule = new RuleDefinitionDto
            {
                Id = "adhoc-expr",
                Name = label,
                Category = "表达式",
                Severity = "命中",
                Expression = expr,
                Mode = RuleMatchMode.FullHits
            };
            var rs = new JsonObject
            {
                ["ruleset_id"] = "adhoc",
                ["rules"] = new JsonArray { JsonSerializer.SerializeToNode(singleRule) }
            };
            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "EvaluateRules",
                ["ruleset"] = rs,
                ["doc_ids"] = null,
                ["path_prefix"] = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim(),
                ["file_ext_filter"] = GetEffectiveExtFilter()
            });
            _results.Clear();
            var hits = resp["hits"]?.Deserialize<List<HitRecordDto>>() ?? new();
            foreach (var h in hits)
                _results.Add(ResultRowItem.FromHitRecord(h));

            ulong ms = resp["took_ms"].AsUInt64();
            ResultsHeader.Text = $"表达式检索结果：{hits.Count:N0} 篇命中（耗时 {ms} ms）";
            FooterStatusText.Text = $"表达式检索完成: 命中 {hits.Count:N0} 篇 ({ms} ms)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "表达式检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task RunAllSavedRulesAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            var arr = new JsonArray();
            foreach (var r in _rules.Where(r => !string.IsNullOrWhiteSpace(r.Expression)))
                arr.Add(JsonSerializer.SerializeToNode(r));

            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "EvaluateRules",
                ["ruleset"] = new JsonObject { ["ruleset_id"] = "ui-rules-v1", ["rules"] = arr },
                ["doc_ids"] = null,
                ["path_prefix"] = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim(),
                ["file_ext_filter"] = GetEffectiveExtFilter()
            });
            _results.Clear();
            var hits = resp["hits"]?.Deserialize<List<HitRecordDto>>() ?? new();
            foreach (var h in hits)
                _results.Add(ResultRowItem.FromHitRecord(h));

            ulong ms = resp["took_ms"].AsUInt64();
            ResultsHeader.Text = $"收藏表达式批量检索结果：命中 {hits.Count:N0} 篇（耗时 {ms} ms）";
            FooterStatusText.Text = $"批量表达式检索完成: 命中 {hits.Count:N0} 篇 ({ms} ms)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "批量表达式检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ======================== Focused Content Preview ========================

    private async void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row || !_client.IsConnected)
            return;

        _previewCts?.Cancel();
        _previewCts?.Dispose();
        _previewCts = new CancellationTokenSource();
        var ct = _previewCts.Token;

        var termsArr = new JsonArray();
        foreach (var t in row.HighlightTerms) termsArr.Add(t);

        PreviewHeader.Text = $"预览加载中: {row.FileName}...";
        try
        {
            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "GetDocumentPreview",
                ["doc_id"] = row.DocId,
                ["highlight_terms"] = termsArr,
                ["max_chars"] = 120000
            }, ct);
            if (ct.IsCancellationRequested) return;
            var preview = resp["doc"]?.Deserialize<DocumentPreviewDto>();
            if (preview is not null) RenderPreview(preview, row);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
                PreviewHeader.Text = $"预览加载失败: {ex.Message}";
        }
    }

    private void RenderPreview(DocumentPreviewDto doc, ResultRowItem row)
    {
        _hitRuns.Clear();
        _hitCursor = -1;
        HitNavText.Text = "0 / 0";

        string sizeStr = doc.Encrypted ? "[已加密]" : ResultRowItem.FormatByteSize(doc.ByteSize);
        PreviewHeader.Text = $"{doc.FileName}  |  {row.FileTypeDisplay}  |  {sizeStr}  |  修改: {row.ModifiedDisplay}";
        var flow = new FlowDocument { PagePadding = new Thickness(6), LineHeight = 20 };

        if (doc.Segments.Count == 0)
        {
            flow.Blocks.Add(new Paragraph(new Run("(无抽取文本段，可能为加密文件、纯二进制文件或仅文件名命中)"))
            {
                Foreground = Brushes.Gray
            });
            PreviewBox.Document = flow;
            PreviewSubHeader.Text = $"路径: {doc.VirtualPath}";
            return;
        }

        string? firstHitSegLabel = null;
        foreach (var seg in doc.Segments)
        {
            if (firstHitSegLabel is null && seg.HighlightRanges.Count > 0)
                firstHitSegLabel = $"[{seg.Scope}] {seg.LocationLabel}";

            var hdr = new Paragraph
            {
                Margin = new Thickness(0, 8, 0, 3),
                Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
                Padding = new Thickness(8, 3, 8, 3)
            };
            hdr.Inlines.Add(new Run($"[{seg.Scope}] {seg.LocationLabel}")
            {
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59))
            });
            flow.Blocks.Add(hdr);

            var bodyPara = new Paragraph { Margin = new Thickness(2, 2, 2, 6) };
            AppendHighlightedRuns(bodyPara, seg.Text, seg.HighlightRanges, _hitRuns);
            flow.Blocks.Add(bodyPara);
        }

        PreviewBox.Document = flow;
        PreviewBox.ScrollToHome();

        if (_hitRuns.Count > 0)
        {
            PreviewSubHeader.Text = $"🎯 已自动聚焦匹配关键字（共 {_hitRuns.Count} 处，首个位于 {firstHitSegLabel ?? row.LocationLabel}） — {(doc.Truncated ? "大文件已智能定位至命中片段 | " : "")}{doc.VirtualPath}";
            JumpToHit(0);
        }
        else
        {
            PreviewSubHeader.Text = $"命中来源: {row.LocationLabel}  |  路径: {doc.VirtualPath}";
        }
    }

    private void JumpToHit(int index)
    {
        if (_hitRuns.Count == 0) return;
        if (_hitCursor >= 0 && _hitCursor < _hitRuns.Count)
        {
            _hitRuns[_hitCursor].Background = new SolidColorBrush(Color.FromRgb(254, 240, 138));
        }
        _hitCursor = ((index % _hitRuns.Count) + _hitRuns.Count) % _hitRuns.Count;
        var active = _hitRuns[_hitCursor];
        active.Background = new SolidColorBrush(Color.FromRgb(251, 146, 60));
        HitNavText.Text = $"{_hitCursor + 1} / {_hitRuns.Count}";

        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            try
            {
                if (active.Parent is FrameworkContentElement fce)
                    fce.BringIntoView();
                PreviewBox.UpdateLayout();
                var rect = active.ContentStart.GetCharacterRect(LogicalDirection.Forward);
                if (!rect.IsEmpty)
                {
                    double target = Math.Max(0, PreviewBox.VerticalOffset + rect.Top - PreviewBox.ActualHeight * 0.28);
                    PreviewBox.ScrollToVerticalOffset(target);
                }
            }
            catch { }
        });
    }

    private void BtnPrevHit_Click(object sender, RoutedEventArgs e) => JumpToHit(_hitCursor - 1);
    private void BtnNextHit_Click(object sender, RoutedEventArgs e) => JumpToHit(_hitCursor + 1);

    private static void AppendHighlightedRuns(Paragraph para, string text, List<int[]> ranges, List<Run> hitRuns)
    {
        if (ranges.Count == 0)
        {
            para.Inlines.Add(new Run(text));
            return;
        }

        var merged = ranges
            .Where(r => r.Length >= 2 && r[1] > 0 && r[0] < text.Length)
            .OrderBy(r => r[0])
            .ToList();

        int cursor = 0;
        var hlBrush = new SolidColorBrush(Color.FromRgb(254, 240, 138));
        foreach (var r in merged)
        {
            int start = Math.Max(cursor, r[0]);
            int end = Math.Min(text.Length, r[0] + r[1]);
            if (end <= start) continue;
            if (start > cursor)
                para.Inlines.Add(new Run(text[cursor..start]));

            var hlRun = new Run(text[start..end])
            {
                Background = hlBrush,
                Foreground = Brushes.Black,
                FontWeight = FontWeights.SemiBold
            };
            para.Inlines.Add(hlRun);
            hitRuns.Add(hlRun);
            cursor = end;
        }
        if (cursor < text.Length)
            para.Inlines.Add(new Run(text[cursor..]));
    }

    // ======================== Column Customization (Add / Remove / Reorder) ========================

    private void EnsureAtLeastOneColumnVisible()
    {
        if (ResultsGrid.Columns.Any(c => c.Visibility == Visibility.Visible)) return;
        ColFileName.Visibility = Visibility.Visible;
    }

    private void ToggleColumnVisibility(string key, bool visible)
    {
        if (!_colMap.TryGetValue(key, out var col)) return;
        if (!visible && ResultsGrid.Columns.Count(c => c.Visibility == Visibility.Visible) <= 1 && col.Visibility == Visibility.Visible)
        {
            MessageBox.Show("文件表格至少需要保留一列可见。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            RebuildColumnMenuItems();
            return;
        }
        col.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        RebuildColumnMenuItems();
        SavePreferences();
    }

    private void RebuildColumnMenuItems()
    {
        MenuColumnToggles.Items.Clear();
        foreach (var col in ResultsGrid.Columns.OrderBy(c => c.DisplayIndex))
        {
            string? key = _colMap.FirstOrDefault(kv => ReferenceEquals(kv.Value, col)).Key;
            if (string.IsNullOrEmpty(key)) continue;
            var mi = new MenuItem
            {
                Header = col.Header?.ToString() ?? key,
                IsCheckable = true,
                IsChecked = col.Visibility == Visibility.Visible,
                Tag = key
            };
            mi.Click += (s, _) =>
            {
                if (s is MenuItem item && item.Tag is string k)
                    ToggleColumnVisibility(k, item.IsChecked);
            };
            MenuColumnToggles.Items.Add(mi);
        }
    }

    private void ResultsGrid_ColumnReordered(object? sender, DataGridColumnEventArgs e)
    {
        RebuildColumnMenuItems();
        SavePreferences();
    }

    private void MenuChooseColumns_Click(object sender, RoutedEventArgs e)
    {
        var current = ResultsGrid.Columns
            .OrderBy(c => c.DisplayIndex)
            .Select(col =>
            {
                string key = _colMap.FirstOrDefault(kv => ReferenceEquals(kv.Value, col)).Key ?? string.Empty;
                var def = ColumnDefs.FirstOrDefault(d => d.Key == key);
                return new ColumnConfigEntry
                {
                    Key = key,
                    Header = col.Header?.ToString() ?? key,
                    Visible = col.Visibility == Visibility.Visible,
                    DefaultVisible = def.DefaultVisible,
                    DefaultWidth = def.DefaultWidth,
                    DefaultOrder = def.DefaultOrder
                };
            })
            .Where(c => !string.IsNullOrEmpty(c.Key))
            .ToList();

        var dlg = new ColumnChooserWindow(current) { Owner = this };
        if (dlg.ShowDialog() != true) return;

        for (int i = 0; i < dlg.Entries.Count; i++)
        {
            var entry = dlg.Entries[i];
            if (!_colMap.TryGetValue(entry.Key, out var col)) continue;
            col.Visibility = entry.Visible ? Visibility.Visible : Visibility.Collapsed;
            col.DisplayIndex = i;
        }
        EnsureAtLeastOneColumnVisible();
        RebuildColumnMenuItems();
        SavePreferences();
    }

    private void MenuResetColumns_Click(object sender, RoutedEventArgs e)
    {
        foreach (var def in ColumnDefs)
        {
            if (!_colMap.TryGetValue(def.Key, out var col)) continue;
            col.Visibility = def.DefaultVisible ? Visibility.Visible : Visibility.Collapsed;
            col.Width = new DataGridLength(def.DefaultWidth);
            col.DisplayIndex = def.DefaultOrder;
        }
        RebuildColumnMenuItems();
        SavePreferences();
    }

    private static T? FindVisualAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T hit) return hit;
            if (current is Visual || current is Visual3D)
                current = VisualTreeHelper.GetParent(current);
            else
                current = LogicalTreeHelper.GetParent(current);
        }
        return null;
    }

    private void ResultsGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var menu = ResultsGrid.ContextMenu;
        if (menu is null) return;
        menu.Items.Clear();

        var dep = e.OriginalSource as DependencyObject;
        if (FindVisualAncestor<DataGridColumnHeader>(dep) is not null)
        {
            foreach (var col in ResultsGrid.Columns.OrderBy(c => c.DisplayIndex))
            {
                string? key = _colMap.FirstOrDefault(kv => ReferenceEquals(kv.Value, col)).Key;
                if (string.IsNullOrEmpty(key)) continue;
                var mi = new MenuItem
                {
                    Header = col.Header?.ToString() ?? key,
                    IsCheckable = true,
                    IsChecked = col.Visibility == Visibility.Visible,
                    Tag = key
                };
                mi.Click += (s, _) =>
                {
                    if (s is MenuItem item && item.Tag is string k)
                        ToggleColumnVisibility(k, item.IsChecked);
                };
                menu.Items.Add(mi);
            }
            menu.Items.Add(new Separator());
            var chooseItem = new MenuItem { Header = "选择显示列与顺序..." };
            chooseItem.Click += MenuChooseColumns_Click;
            menu.Items.Add(chooseItem);
            var resetItem = new MenuItem { Header = "恢复默认列" };
            resetItem.Click += MenuResetColumns_Click;
            menu.Items.Add(resetItem);
            return;
        }

        var rowContainer = FindVisualAncestor<DataGridRow>(dep);
        if (rowContainer is not null && rowContainer.Item is ResultRowItem clickedItem)
        {
            if (!rowContainer.IsSelected)
            {
                ResultsGrid.SelectedItems.Clear();
                rowContainer.IsSelected = true;
                ResultsGrid.SelectedItem = clickedItem;
            }

            int selCount = Math.Max(1, ResultsGrid.SelectedItems.Count);
            AddMenuAction(menu, "打开", MenuOpenFile_Click, bold: true);
            AddMenuAction(menu, "打开所在目录（在资源管理器中定位）", MenuOpenFolder_Click);
            menu.Items.Add(new Separator());
            AddMenuAction(menu, "对此文件执行深度查密（停其他任务）", MenuDeepCheckSelectedFile_Click, bold: true);
            AddMenuAction(menu, "对所在文件夹执行深度查密（停其他任务）", MenuDeepCheckSelectedFolder_Click);
            menu.Items.Add(new Separator());
            AddMenuAction(menu, selCount > 1 ? $"复制完整路径 ({selCount} 项)" : "复制完整路径", MenuCopyPath_Click);
            AddMenuAction(menu, "复制文件名", MenuCopyFileName_Click);
            AddMenuAction(menu, "复制所在目录", MenuCopyDir_Click);
            menu.Items.Add(new Separator());
            AddMenuAction(menu, "限定仅搜索该文件所在目录", MenuFilterByRowFolder_Click);
            AddMenuAction(menu, "将该目录加入索引范围...", MenuAddRowFolderToRoots_Click);
            AddMenuAction(menu, "在命令终端中打开该目录", MenuOpenTerminalHere_Click);
            menu.Items.Add(new Separator());
            AddMenuAction(menu, "文件属性", MenuProperties_Click);
            menu.Items.Add(new Separator());
            var del = new MenuItem
            {
                Header = selCount > 1
                    ? $"深度删除选中的 {selCount} 个文件（防杀软慢速三遍覆写粉碎）"
                    : "深度删除文件（防杀软慢速三遍覆写粉碎）",
                Foreground = new SolidColorBrush(Color.FromRgb(220, 38, 38)),
                FontWeight = FontWeights.SemiBold
            };
            del.Click += MenuDeepDeleteSelected_Click;
            menu.Items.Add(del);
            return;
        }

        e.Handled = true;
    }

    private static void AddMenuAction(ContextMenu menu, string header, RoutedEventHandler handler, bool bold = false)
    {
        var mi = new MenuItem { Header = header };
        if (bold) mi.FontWeight = FontWeights.SemiBold;
        mi.Click += handler;
        menu.Items.Add(mi);
    }

    // ======================== File Context Actions ========================

    private void ResultsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FindVisualAncestor<DataGridRow>(e.OriginalSource as DependencyObject) is not null)
            MenuOpenFile_Click(sender, e);
    }

    private void ResultsGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.None)
        {
            e.Handled = true;
            MenuOpenFile_Click(sender, e);
        }
        else if (e.Key == Key.System && e.SystemKey == Key.Enter && Keyboard.Modifiers == ModifierKeys.Alt)
        {
            e.Handled = true;
            MenuProperties_Click(sender, e);
        }
        else if (e.Key == Key.Delete && (Keyboard.Modifiers & (ModifierKeys.Control | ModifierKeys.Shift)) == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            e.Handled = true;
            MenuDeepDeleteSelected_Click(sender, e);
        }
        else if (e.Key == Key.C && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            e.Handled = true;
            MenuCopyPath_Click(sender, e);
        }
    }

    private List<ResultRowItem> GetSelectedRows()
    {
        var list = ResultsGrid.SelectedItems.OfType<ResultRowItem>().ToList();
        if (list.Count == 0 && ResultsGrid.SelectedItem is ResultRowItem single)
            list.Add(single);
        return list;
    }

    private static string ResolveDiskPath(string virtualPath) => virtualPath.Split("!/")[0];

    private void MenuOpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        bool isArchiveInner = row.VirtualPath.Contains("!/");
        string diskPath = ResolveDiskPath(row.VirtualPath);
        if (File.Exists(diskPath))
        {
            if (isArchiveInner)
                FooterStatusText.Text = $"命中文档位于压缩包内部，正在打开外层归档：{diskPath}";
            try { Process.Start(new ProcessStartInfo(diskPath) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show($"打开失败: {ex.Message}", "提示", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }
        else if (Directory.Exists(diskPath))
        {
            Process.Start("explorer.exe", $"\"{diskPath}\"");
        }
        else
        {
            MessageBox.Show($"磁盘文件已不存在：{diskPath}", "文件缺失", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void MenuOpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = ResolveDiskPath(row.VirtualPath);
        if (File.Exists(diskPath))
            Process.Start("explorer.exe", $"/select,\"{diskPath}\"");
        else if (Directory.Exists(diskPath))
            Process.Start("explorer.exe", $"\"{diskPath}\"");
        else
        {
            string? dir = Path.GetDirectoryName(diskPath);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                Process.Start("explorer.exe", $"\"{dir}\"");
        }
    }

    private void MenuCopyPath_Click(object sender, RoutedEventArgs e)
    {
        var rows = GetSelectedRows();
        if (rows.Count > 0)
            Clipboard.SetText(string.Join(Environment.NewLine, rows.Select(r => r.VirtualPath)));
    }

    private void MenuCopyFileName_Click(object sender, RoutedEventArgs e)
    {
        var rows = GetSelectedRows();
        if (rows.Count > 0)
            Clipboard.SetText(string.Join(Environment.NewLine, rows.Select(r => r.FileName)));
    }

    private void MenuCopyDir_Click(object sender, RoutedEventArgs e)
    {
        var rows = GetSelectedRows();
        if (rows.Count > 0)
            Clipboard.SetText(string.Join(Environment.NewLine, rows.Select(r => r.Directory).Distinct()));
    }

    private void MenuFilterByRowFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = ResolveDiskPath(row.VirtualPath);
        string? dir = Path.GetDirectoryName(diskPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            TxtDirFilter.Text = dir;
            RememberRecentDirectory(dir);
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
        }
    }

    private async void MenuAddRowFolderToRoots_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = ResolveDiskPath(row.VirtualPath);
        string? dir = Path.GetDirectoryName(diskPath);
        if (string.IsNullOrWhiteSpace(dir)) return;
        if (!_roots.Contains(dir, StringComparer.OrdinalIgnoreCase))
        {
            _roots.Add(dir);
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            if (MessageBox.Show($"已将目录加入索引列表：\n{dir}\n\n是否立即执行增量索引？", "已添加目录", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                await StartScanInternalAsync("inc", silentOnError: false);
        }
        else
        {
            FooterStatusText.Text = $"该目录已在索引列表中: {dir}";
        }
    }

    private void MenuOpenTerminalHere_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = ResolveDiskPath(row.VirtualPath);
        string? dir = File.Exists(diskPath) ? Path.GetDirectoryName(diskPath) : diskPath;
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start(new ProcessStartInfo("cmd.exe", $"/K cd /d \"{dir}\"") { UseShellExecute = true });
        }
    }

    private void MenuProperties_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = ResolveDiskPath(row.VirtualPath);
        if (!File.Exists(diskPath) && !Directory.Exists(diskPath)) return;

        var info = new SHELLEXECUTEINFO
        {
            cbSize = Marshal.SizeOf<SHELLEXECUTEINFO>(),
            fMask = 0x0000000C, // SEE_MASK_INVOKEIDLIST
            hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle,
            lpVerb = "properties",
            lpFile = diskPath,
            nShow = 5
        };
        ShellExecuteEx(ref info);
    }

    // ======================== Deep Confidentiality Check & Deep Erase ========================

    private void SyncShellContextMenuRegistration()
    {
        try
        {
            if (MenuShellContextMenu.IsChecked)
                ShellContextMenuRegistrar.EnsureRegistered();
        }
        catch
        {
        }
    }

    private void MenuShellContextMenu_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (MenuShellContextMenu.IsChecked)
            {
                ShellContextMenuRegistrar.EnsureRegistered();
                FooterStatusText.Text = "已在 Windows 资源管理器右键菜单注册【深度查密 / 深度擦除】";
            }
            else
            {
                ShellContextMenuRegistrar.Unregister();
                FooterStatusText.Text = "已从 Windows 资源管理器右键菜单移除【深度查密 / 深度擦除】";
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "更新 Windows 右键菜单失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        SavePreferences();
    }

    private void BringWindowToForeground()
    {
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
        if (!Topmost)
        {
            Topmost = true;
            Topmost = false;
        }
        Focus();
    }

    private Task EnqueueExternalUiCommandAsync(UiLaunchCommand cmd)
    {
        return Dispatcher.InvokeAsync(() =>
        {
            if (string.Equals(cmd.Action, "activate", StringComparison.OrdinalIgnoreCase))
            {
                BringWindowToForeground();
                return;
            }
            lock (_cmdBatchLock)
            {
                if (_pendingCmdAction is not null && !string.Equals(_pendingCmdAction, cmd.Action, StringComparison.OrdinalIgnoreCase))
                {
                    _pendingCmdPaths.Clear();
                }
                _pendingCmdAction = cmd.Action;
                foreach (var p in cmd.Paths)
                {
                    if (!_pendingCmdPaths.Contains(p, StringComparer.OrdinalIgnoreCase))
                        _pendingCmdPaths.Add(p);
                }
            }
            _cmdBatchTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
            _cmdBatchTimer.Stop();
            _cmdBatchTimer.Tick -= CmdBatchTimer_Tick;
            _cmdBatchTimer.Tick += CmdBatchTimer_Tick;
            _cmdBatchTimer.Start();
        }).Task;
    }

    private async void CmdBatchTimer_Tick(object? sender, EventArgs e)
    {
        _cmdBatchTimer?.Stop();
        UiLaunchCommand? batch = null;
        lock (_cmdBatchLock)
        {
            if (!string.IsNullOrEmpty(_pendingCmdAction))
            {
                batch = new UiLaunchCommand
                {
                    Action = _pendingCmdAction,
                    Paths = _pendingCmdPaths.ToList()
                };
            }
            _pendingCmdAction = null;
            _pendingCmdPaths.Clear();
        }
        if (batch is not null)
            await DispatchExternalUiCommandAsync(batch);
    }

    private async Task DispatchExternalUiCommandAsync(UiLaunchCommand cmd)
    {
        BringWindowToForeground();
        var validPaths = cmd.Paths
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrWhiteSpace(p) && (File.Exists(p) || Directory.Exists(p)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (validPaths.Count == 0)
            return;

        if (string.Equals(cmd.Action, "deep-check", StringComparison.OrdinalIgnoreCase))
            await StartDeepCheckAsync(validPaths, customQuery: null);
        else if (string.Equals(cmd.Action, "deep-erase", StringComparison.OrdinalIgnoreCase))
            await StartDeepDeleteAsync(validPaths, cancelActiveFirst: true);
    }

    private async Task StopAllActiveDaemonJobsAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            await _client.SendAsync(new JsonObject { ["type"] = "CancelScan", ["job_id"] = "*" });
            for (int i = 0; i < 30; i++)
            {
                var pong = await _client.SendAsync(new JsonObject { ["type"] = "Ping" });
                if (pong["active_jobs"].AsUInt64() == 0)
                    break;
                await Task.Delay(60);
            }
        }
        catch { }
        _activeJobId = null;
        _daemonHasRunningJob = false;
        SetJobUiBusy(false);
    }

    private async void MenuDeepCheckFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择要执行深度查密的文件夹", Multiselect = true };
        if (dlg.ShowDialog() == true && dlg.FolderNames.Length > 0)
            await StartDeepCheckAsync(dlg.FolderNames, customQuery: null);
    }

    private async void MenuDeepCheckFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择要执行深度查密的文件", Multiselect = true };
        if (dlg.ShowDialog() == true && dlg.FileNames.Length > 0)
            await StartDeepCheckAsync(dlg.FileNames, customQuery: null);
    }

    private async void MenuDeepCheckSelectedFile_Click(object sender, RoutedEventArgs e)
    {
        var files = GetSelectedRows()
            .Select(r => ResolveDiskPath(r.VirtualPath))
            .Where(p => File.Exists(p) || Directory.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (files.Count > 0)
            await StartDeepCheckAsync(files, customQuery: null);
    }

    private async void MenuDeepCheckSelectedFolder_Click(object sender, RoutedEventArgs e)
    {
        var dirs = GetSelectedRows()
            .Select(r => Path.GetDirectoryName(ResolveDiskPath(r.VirtualPath)))
            .Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (dirs.Count > 0)
            await StartDeepCheckAsync(dirs, customQuery: null);
    }

    private async void MenuDeepCheckRerunDefaults_Click(object sender, RoutedEventArgs e)
    {
        var targets = _deepCheckRoots.Count > 0
            ? _deepCheckRoots
            : _roots.Where(p => Directory.Exists(p) || File.Exists(p)).ToList();
        if (targets.Count == 0 && !string.IsNullOrWhiteSpace(TxtDirFilter.Text))
            targets = TxtDirFilter.Text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (targets.Count == 0)
        {
            MenuDeepCheckFolder_Click(sender, e);
            return;
        }
        await StartDeepCheckAsync(targets, customQuery: null);
    }

    private void BtnExitDeepCheck_Click(object sender, RoutedEventArgs e)
    {
        _deepCheckMode = false;
        _deepCheckRoots.Clear();
        DeepCheckBanner.Visibility = Visibility.Collapsed;
        MenuExitDeepCheck.IsEnabled = false;
        FooterStatusText.Text = "已退出深度查密模式，恢复常规全文检索";
        if (_client.IsConnected && _activeJobId is null)
            _ = ExecuteCurrentSearchAsync(limit: 200, silentEmpty: true);
    }

    private async Task StartDeepCheckAsync(IReadOnlyList<string> paths, string? customQuery)
    {
        BringWindowToForeground();
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }

        // 1. Stop all other background work cleanly before deep confidentiality inspection
        if (_activeJobId is not null || _daemonHasRunningJob)
        {
            FooterStatusText.Text = "正在停止软件其他后台扫描/索引任务，切换至深度查密...";
            await StopAllActiveDaemonJobsAsync();
        }

        _deepCheckMode = true;
        _deepCheckRoots = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        MenuExitDeepCheck.IsEnabled = true;

        TxtDirFilter.Text = string.Join(";", _deepCheckRoots);
        string queryToRun = string.IsNullOrWhiteSpace(customQuery) ? DefaultSecretKeywords : customQuery.Trim();
        if (customQuery is null)
        {
            TxtSearch.Text = DefaultSecretKeywords;
            _matchAllTerms = false;
            MenuMatchOr.IsChecked = true;
            MenuMatchAnd.IsChecked = false;
            MenuUseRegex.IsChecked = false;
            MenuUseExpr.IsChecked = false;
            UpdateSearchModeIndicators();
        }

        string summaryTarget = _deepCheckRoots.Count == 1
            ? _deepCheckRoots[0]
            : $"{_deepCheckRoots[0]} 等 {_deepCheckRoots.Count} 项";
        DeepCheckBannerText.Text =
            $"🔒 深度查密模式（已停止其他工作）| 目标: {summaryTarget} | 可直接在上方搜索框输入更多关键词/正则按 Enter 深查";
        DeepCheckBanner.Visibility = Visibility.Visible;
        FastPassBanner.Visibility = Visibility.Collapsed;

        _results.Clear();
        ResultsHeader.Text = "正在执行深度查密（停用其他任务，全面深挖文档/表格/CAD/压缩包与图片 OCR 涉密关键词）...";
        FooterStatusText.Text = $"深度查密启动: {summaryTarget} | 关键词: {queryToRun}";

        var opts = BuildScanOptionsJson();
        opts["include_hidden"] = true;
        if (opts["parse"] is JsonObject parseObj)
            parseObj["enable_ocr"] = true;
        // For targeted folder/file deep check (non-drive-root), do not skip nested temp/program folders inside target
        bool hasNonDriveTarget = _deepCheckRoots.Any(r => r.TrimEnd('\\', '/').Length > 2);
        if (hasNonDriveTarget)
            opts["excluded_dirs"] = new JsonArray();

        _activeJobId = $"deepchk-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);

        var rootsArr = new JsonArray(_deepCheckRoots.Select(r => JsonValue.Create(r)).ToArray<JsonNode?>());
        var req = new JsonObject
        {
            ["type"] = "DirectSearch",
            ["job_id"] = _activeJobId,
            ["roots"] = rootsArr,
            ["query"] = queryToRun,
            ["use_regex"] = MenuUseRegex.IsChecked,
            ["file_ext_filter"] = GetEffectiveExtFilter() ?? (string.IsNullOrWhiteSpace(_includeExtsText) ? null : _includeExtsText),
            ["options"] = opts,
            ["match_all_terms"] = _matchAllTerms,
            ["cancel_active_jobs"] = true
        };

        try
        {
            await _client.SendAsync(req);
        }
        catch (Exception ex)
        {
            _activeJobId = null;
            SetJobUiBusy(false);
            MessageBox.Show(ex.Message, "启动深度查密失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static bool MatchesAnyDeleteTarget(string virtualPath, HashSet<string> targets)
    {
        if (targets.Contains(virtualPath)) return true;
        foreach (var t in targets)
        {
            string trimmed = t.TrimEnd('\\', '/');
            if (string.IsNullOrEmpty(trimmed)) continue;
            if (virtualPath.StartsWith(trimmed + "\\", StringComparison.OrdinalIgnoreCase) ||
                virtualPath.StartsWith(trimmed + "/", StringComparison.OrdinalIgnoreCase) ||
                virtualPath.StartsWith(trimmed + "!", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private async void MenuDeepDeleteSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedRows().Select(r => r.VirtualPath).Distinct().ToList();
        if (selected.Count == 0) return;

        var innerWarnings = selected.Where(p => p.Contains("!/")).ToList();
        if (innerWarnings.Count == selected.Count)
        {
            MessageBox.Show(
                "选中的条目均位于压缩包内部，为防止误粉碎整个归档文件已阻止。\n如需彻底擦除外层压缩包，请从菜单【查密与擦除 -> 对文件执行深度擦除...】选取该归档。",
                "安全提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await StartDeepDeleteAsync(selected);
    }

    private async void MenuDeepDeletePicker_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择要深度擦除的文件（不进回收站，慢速防杀软三遍覆写）",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true && dlg.FileNames.Length > 0)
            await StartDeepDeleteAsync(dlg.FileNames);
    }

    private async void MenuDeepEraseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "选择要深度擦除的文件夹（将三遍覆写粉碎内部全部文件并清除目录，不可恢复）",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true && dlg.FolderNames.Length > 0)
            await StartDeepDeleteAsync(dlg.FolderNames, cancelActiveFirst: true);
    }

    private async Task StartDeepDeleteAsync(IReadOnlyList<string> paths, bool cancelActiveFirst = false)
    {
        BringWindowToForeground();
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        if (!cancelActiveFirst && _activeJobId is not null)
        {
            MessageBox.Show("当前已有扫描或删除任务正在执行，请先等待完成或点击停止。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var lines = paths.Take(8).Select(p => Directory.Exists(p) ? $"[文件夹及全部内部文件] {p}" : $"[文件] {p}").ToList();
        string previewList = string.Join("\n", lines);
        if (paths.Count > 8) previewList += $"\n... 等共 {paths.Count} 项";
        bool hasDir = paths.Any(Directory.Exists);
        string dirWarn = hasDir ? "\n⚠️ 注意：所选目标包含文件夹，将递归彻底擦除其下所有子文件夹与文件！\n" : "\n";

        if (MessageBox.Show(
                $"确定执行【深度擦除】以下 {paths.Count} 项目标？\n\n{previewList}\n{dirWarn}\n" +
                "• 采用 3 遍低熵值（0xAA → 0x55 → 0x00）温和慢速覆写并改名擦除，尽量避免触发杀毒软件拦截。\n" +
                "• 擦除后同步从 DeepDocEngine 本地索引库中彻底抹除（含 SQLite VACUUM 与倒排段合并），不进回收站且不可恢复！",
                "高危确认：深度擦除", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;

        if (_activeJobId is not null || _daemonHasRunningJob)
            await StopAllActiveDaemonJobsAsync();

        _pendingDeleteTargets = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
        _activeJobId = $"del-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);

        var pArr = new JsonArray();
        foreach (var p in paths) pArr.Add(p);

        try
        {
            await _client.SendAsync(new JsonObject
            {
                ["type"] = "DeepDeleteFiles",
                ["job_id"] = _activeJobId,
                ["paths"] = pArr,
                ["cancel_active_jobs"] = true
            });
        }
        catch (Exception ex)
        {
            _activeJobId = null;
            _pendingDeleteTargets.Clear();
            SetJobUiBusy(false);
            MessageBox.Show(ex.Message, "启动深度擦除失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ======================== Scanning & Index Management ========================

    private void BtnCloseFastPassBanner_Click(object sender, RoutedEventArgs e)
    {
        FastPassBanner.Visibility = Visibility.Collapsed;
    }

    private void SetJobUiBusy(bool busy)
    {
        MenuIncrementalScan.IsEnabled = !busy;
        MenuRebuildScan.IsEnabled = !busy;
        MenuRebuildLowResourceScan.IsEnabled = !busy;
        MenuDirectSearch.IsEnabled = !busy;
        MenuCancelJob.IsEnabled = busy;
        BtnFooterCancel.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        if (!busy)
        {
            BtnFooterCancel.Content = "停止任务";
            BtnFooterCancel.IsEnabled = true;
        }
        ScanProgressBar.IsIndeterminate = busy;

        if (busy)
        {
            DocSentinel.UI.Integration.PowerManager.PreventSleepAndEnableAwayMode();
        }
        else
        {
            DocSentinel.UI.Integration.PowerManager.RestoreNormalSleep();
        }
    }

    private JsonObject BuildScanOptionsJson(bool? lowResourceOverride = null)
    {
        bool lowResource = lowResourceOverride ?? MenuLowResourceIndex.IsChecked;
        var includeExtsArr = new JsonArray();
        foreach (var ex in _includeExtsText.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var clean = ex.Trim().TrimStart('.').ToLowerInvariant();
            if (!string.IsNullOrEmpty(clean)) includeExtsArr.Add(clean);
        }

        var excludedDirsArr = new JsonArray();
        var excludedGlobsArr = new JsonArray();
        if (MenuSkipTemp.IsChecked)
        {
            foreach (var d in new[]
            {
                "$Recycle.Bin", "System Volume Information",
                "Windows",
                "Program Files", "Program Files (x86)", "ProgramData",
                "AppData\\Local\\Temp", "AppData\\Local\\CrashDumps",
                "AppData\\Local\\Packages", "AppData\\Local\\Microsoft",
                ".git", ".cargo", ".rustup", "node_modules", "__pycache__", "site-packages", ".venv", "venv"
            })
                excludedDirsArr.Add(d);
            foreach (var g in new[]
            {
                "~$*", "*.tmp", "~*.tmp", "thumbs.db", "desktop.ini", "*.sock",
                "*.dll", "*.sys", "*.pdb", "*.o", "*.a", "*.obj", "*.lib",
                "*.cat", "*.mui", "*.mum", "*.winmd", "*.pri", "*.pnf", "*.cdf-ms", "*.mfl",
                "*.db-wal", "*.db-shm"
            })
                excludedGlobsArr.Add(g);
        }

        var pwArr = new JsonArray();
        if (!string.IsNullOrWhiteSpace(_passwordText))
            pwArr.Add(_passwordText.Trim());

        return new JsonObject
        {
            ["include_hidden"] = false,
            ["use_usn_if_available"] = true,
            ["worker_count"] = lowResource ? 1 : Math.Clamp(Environment.ProcessorCount, 2, 8),
            ["worker_timeout_ms"] = lowResource ? 90000 : 45000,
            ["low_resource_mode"] = lowResource,
            ["excluded_dirs"] = excludedDirsArr,
            ["excluded_name_globs"] = excludedGlobsArr,
            ["include_extensions"] = includeExtsArr,
            ["parse"] = new JsonObject
            {
                ["max_extract_depth"] = 6,
                ["max_uncompressed_bytes"] = 512L * 1024 * 1024,
                ["max_single_file_bytes"] = 256L * 1024 * 1024,
                ["max_expansion_ratio"] = 100,
                ["enable_ocr"] = MenuEnableOcr.IsChecked,
                ["ocr_min_image_dim"] = 48,
                ["enable_x2t"] = false,
                ["passwords"] = pwArr
            }
        };
    }

    private async Task StartScanInternalAsync(string prefix, bool silentOnError, bool? lowResourceOverride = null)
    {
        SavePreferences();
        FastPassBanner.Visibility = Visibility.Collapsed;
        bool lowRes = lowResourceOverride ?? MenuLowResourceIndex.IsChecked;
        _activeJobId = $"{prefix}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);
        if (lowRes)
        {
            FooterStatusText.Text = "正在以【低占用后台模式】建立索引（单路空闲优先级，不卡顿前台操作）...";
        }

        var rootsArr = new JsonArray(_roots.Select(r => JsonValue.Create(r)).ToArray<JsonNode?>());
        var req = new JsonObject
        {
            ["type"] = "StartScan",
            ["job_id"] = _activeJobId,
            ["roots"] = rootsArr,
            ["ruleset"] = null,
            ["options"] = BuildScanOptionsJson(lowRes)
        };

        try
        {
            await _client.SendAsync(req);
        }
        catch (Exception ex)
        {
            _activeJobId = null;
            SetJobUiBusy(false);
            if (!silentOnError)
                MessageBox.Show(ex.Message, "启动扫描失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task TryIdleIncrementalScanAsync()
    {
        if (!MenuIdleIndex.IsChecked || _activeJobId is not null || !_client.IsConnected || _roots.Count == 0)
            return;
        if (GetUserIdleSeconds() < 180 || (DateTime.UtcNow - _lastIdleScanUtc).TotalMinutes < 15)
            return;

        _lastIdleScanUtc = DateTime.UtcNow;
        FooterStatusText.Text = "检测到系统空闲超过 3 分钟，正在后台低优先级执行增量索引...";
        await StartScanInternalAsync("idle", silentOnError: true);
    }

    private async Task<bool> EnsureRootsOrPromptAsync()
    {
        if (_roots.Count > 0) return true;

        string dirInput = TxtDirFilter.Text.Trim();
        if (!string.IsNullOrEmpty(dirInput) && Directory.Exists(dirInput))
        {
            if (MessageBox.Show($"当前索引目录列表为空，是否将指定目录加入索引并扫描？\n{dirInput}", "添加索引目录", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _roots.Add(dirInput);
                RefreshDirectoryDropdown(syncTextToSelection: false);
                SavePreferences();
                return true;
            }
        }

        MenuOpenIndexSettings_Click(this, new RoutedEventArgs());
        return _roots.Count > 0;
    }

    private async void MenuIncrementalScan_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected) { await ConnectSafeAsync(); if (!_client.IsConnected) return; }
        if (!await EnsureRootsOrPromptAsync()) return;
        await StartScanInternalAsync("inc", silentOnError: false);
    }

    private async void MenuRebuildScan_Click(object sender, RoutedEventArgs e) =>
        await ExecuteManualRebuildAsync(forceLowResource: false);

    private async void MenuRebuildLowResourceScan_Click(object sender, RoutedEventArgs e) =>
        await ExecuteManualRebuildAsync(forceLowResource: true);

    private async Task ExecuteManualRebuildAsync(bool forceLowResource)
    {
        if (!_client.IsConnected) { await ConnectSafeAsync(); if (!_client.IsConnected) return; }
        if (!await EnsureRootsOrPromptAsync()) return;

        bool useLow = forceLowResource || MenuLowResourceIndex.IsChecked;
        string modeDesc = useLow
            ? "\n• 当前将以【低占用后台模式】执行（单并发 + Windows 空闲优先级 + I/O 间歇让步，省 CPU 与内存，可一边办公一边建库）。"
            : "\n• 如电脑正运行大型任务，也可取消后选择【索引 -> 手动重建索引 - 低占用模式】。";

        if (MessageBox.Show(
                $"确认执行【{(useLow ? "低占用" : "全量")}手动重建索引】？\n将清空当前文档记录与全文倒排索引后从头全量解析（自动保留图片 OCR 缓存）。{modeDesc}",
                useLow ? "确认低占用重建索引" : "确认重建索引",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            await _client.SendAsync(new JsonObject { ["type"] = "ResetIndexKeepOcr" });
            _results.Clear();
            PreviewBox.Document.Blocks.Clear();
            await StartScanInternalAsync(useLow ? "rebuild-low" : "rebuild", silentOnError: false, lowResourceOverride: useLow);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "重建索引失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void MenuDirectSearch_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected) { await ConnectSafeAsync(); if (!_client.IsConnected) return; }

        var targetRoots = _roots.ToList();
        string typedDir = TxtDirFilter.Text.Trim();
        if (!string.IsNullOrEmpty(typedDir) && (Directory.Exists(typedDir) || File.Exists(typedDir)))
            targetRoots = new List<string> { typedDir };

        if (targetRoots.Count == 0)
        {
            var dlg = new OpenFolderDialog { Title = "选择要临时直搜的文件夹/U盘目录", Multiselect = true };
            if (dlg.ShowDialog() == true && dlg.FolderNames.Length > 0)
                targetRoots.AddRange(dlg.FolderNames);
            else
                return;
        }

        string query = TxtSearch.Text.Trim();
        if (string.IsNullOrWhiteSpace(query))
        {
            TxtSearch.Focus();
            MessageBox.Show("请先在搜索框输入要临时直搜的关键词、正则或表达式。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SavePreferences();
        _results.Clear();
        ResultsHeader.Text = "正在执行临时直搜（不写入本地索引库）...";
        _activeJobId = $"direct-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);

        var rootsArr = new JsonArray(targetRoots.Select(r => JsonValue.Create(r)).ToArray<JsonNode?>());
        var req = new JsonObject
        {
            ["type"] = "DirectSearch",
            ["job_id"] = _activeJobId,
            ["roots"] = rootsArr,
            ["query"] = query,
            ["use_regex"] = MenuUseRegex.IsChecked,
            ["file_ext_filter"] = GetEffectiveExtFilter() ?? (string.IsNullOrWhiteSpace(_includeExtsText) ? null : _includeExtsText),
            ["options"] = BuildScanOptionsJson(),
            ["match_all_terms"] = _matchAllTerms,
            ["cancel_active_jobs"] = false
        };

        try
        {
            await _client.SendAsync(req);
        }
        catch (Exception ex)
        {
            _activeJobId = null;
            SetJobUiBusy(false);
            MessageBox.Show(ex.Message, "启动临时直搜失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void MenuCancelJob_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected)
        {
            _daemonHasRunningJob = false;
            _activeJobId = null;
            SetJobUiBusy(false);
            FooterStatusText.Text = "当前未连接引擎，已重置本地任务状态";
            return;
        }

        BtnFooterCancel.IsEnabled = false;
        BtnFooterCancel.Content = "正在停止...";
        MenuCancelJob.IsEnabled = false;
        FooterStatusText.Text = "已发送停止信号，正在等待引擎完成当前批次释放并安全退出...";

        try
        {
            // Send wildcard '*' cancellation to guarantee all active scan/index jobs stop
            await _client.SendAsync(new JsonObject { ["type"] = "CancelScan", ["job_id"] = "*" });
            _daemonHasRunningJob = false;
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = $"停止信号发送提示: {ex.Message}";
        }

        // Safety fallback timer: force unlock UI if daemon completion packet is delayed or dropped
        _ = Task.Run(async () =>
        {
            await Task.Delay(2500);
            await Dispatcher.InvokeAsync(() =>
            {
                if (_activeJobId is not null || _daemonHasRunningJob)
                {
                    _daemonHasRunningJob = false;
                    _activeJobId = null;
                    SetJobUiBusy(false);
                    BtnFooterCancel.Content = "停止任务";
                    BtnFooterCancel.IsEnabled = true;
                    FooterStatusText.Text = "任务已停止";
                }
            });
        });
    }

    private async void MenuClearIndex_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected) return;
        if (MessageBox.Show("确认清空全部已建索引与缓存原文吗？", "确认清空", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        try
        {
            await _client.SendAsync(new JsonObject { ["type"] = "ClearIndex" });
            _results.Clear();
            PreviewBox.Document.Blocks.Clear();
            PreviewHeader.Text = "文件内容预览";
            PreviewSubHeader.Text = "索引库与原文缓存已清空";
            HitNavText.Text = "0 / 0";
            await RefreshStatsSafeAsync();
            FooterStatusText.Text = "索引库与原文缓存已清空";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "清空失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void MenuOpenIndexSettings_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new IndexSettingsWindow(
            _roots,
            _includeExtsText,
            _passwordText,
            MenuEnableOcr.IsChecked,
            MenuSkipTemp.IsChecked,
            MenuIdleIndex.IsChecked,
            MenuLowResourceIndex.IsChecked)
        { Owner = this };

        if (dlg.ShowDialog() != true) return;

        _roots.Clear();
        foreach (var r in dlg.Roots) _roots.Add(r);
        _includeExtsText = dlg.IncludeExts;
        _passwordText = dlg.PasswordText;
        MenuEnableOcr.IsChecked = dlg.EnableOcr;
        MenuSkipTemp.IsChecked = dlg.SkipTemp;
        MenuIdleIndex.IsChecked = dlg.IdleIndex;
        MenuLowResourceIndex.IsChecked = dlg.LowResourceMode;

        RefreshDirectoryDropdown(syncTextToSelection: false);
        UpdateSearchModeIndicators();
        SavePreferences();

        if (dlg.RequestedAction == IndexSettingsAction.StartIncremental)
            MenuIncrementalScan_Click(sender, e);
        else if (dlg.RequestedAction == IndexSettingsAction.StartRebuild)
            await ExecuteManualRebuildAsync(forceLowResource: false);
        else if (dlg.RequestedAction == IndexSettingsAction.StartRebuildLowResource)
            await ExecuteManualRebuildAsync(forceLowResource: true);
    }

    // ======================== Menu Bar Commands ========================

    private void MenuAddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择要加入索引的文件夹", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            int added = 0;
            foreach (var p in dlg.FolderNames)
            {
                if (!_roots.Contains(p, StringComparer.OrdinalIgnoreCase))
                {
                    _roots.Add(p);
                    added++;
                }
            }
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            if (added > 0 && MessageBox.Show($"已添加 {added} 个文件夹到索引列表，是否立即增量扫描建立索引？", "添加成功", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                MenuIncrementalScan_Click(sender, e);
        }
    }

    private void MenuAddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择要加入索引的文件", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            foreach (var p in dlg.FileNames)
                if (!_roots.Contains(p, StringComparer.OrdinalIgnoreCase)) _roots.Add(p);
            RefreshDirectoryDropdown(syncTextToSelection: false);
            SavePreferences();
            FooterStatusText.Text = "已更新索引范围列表，可在菜单【索引 -> 立即增量索引】开始扫描";
        }
    }

    private void MenuAddFixedDrives_Click(object sender, RoutedEventArgs e)
    {
        int added = 0;
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Fixed && !_roots.Contains(d.Name, StringComparer.OrdinalIgnoreCase))
            {
                _roots.Add(d.Name);
                added++;
            }
        }
        RefreshDirectoryDropdown(syncTextToSelection: false);
        SavePreferences();
        FooterStatusText.Text = added > 0 ? $"已加入 {added} 个本地固定磁盘根目录" : "本机固定磁盘均已在索引列表中";
    }

    private void MenuAddUsbDrives_Click(object sender, RoutedEventArgs e)
    {
        int added = 0;
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Removable && !_roots.Contains(d.Name, StringComparer.OrdinalIgnoreCase))
            {
                _roots.Add(d.Name);
                added++;
            }
        }
        RefreshDirectoryDropdown(syncTextToSelection: false);
        SavePreferences();
        FooterStatusText.Text = added > 0 ? $"已加入 {added} 个可移动磁盘" : "未检测到新插入的可移动磁盘/U盘";
    }

    private void MenuExit_Click(object sender, RoutedEventArgs e) => Close();

    private void MenuSelectAll_Click(object sender, RoutedEventArgs e)
    {
        ResultsGrid.Focus();
        ResultsGrid.SelectAll();
    }

    private void MenuClearSearch_Click(object sender, RoutedEventArgs e)
    {
        TxtSearch.Text = string.Empty;
        TxtDirFilter.Text = string.Empty;
        RestoreTypeComboSelection(string.Empty);
        RefreshDirectoryDropdown(syncTextToSelection: false);
        SavePreferences();
        TxtSearch.Focus();
        if (_client.IsConnected)
            _ = ExecuteCurrentSearchAsync(limit: 200, silentEmpty: true);
    }

    // ======================== Search Flags & Mode Sync ========================

    private void UpdateSearchModeIndicators()
    {
        PillMultiLogic.Text = _matchAllTerms ? "多词: AND" : "多词: OR";
        PillMultiLogic.Background = new SolidColorBrush(Color.FromRgb(219, 234, 254));
        PillMultiLogic.Foreground = new SolidColorBrush(Color.FromRgb(30, 64, 175));

        string scopeLabel = _scopeFilter switch
        {
            "FileName" => "文件名",
            "HeadTail" => "首尾行",
            "Body" => "正文",
            "Ocr" => "OCR",
            "Table" => "表格",
            "Metadata" => "元数据",
            _ => "全部"
        };
        PillScope.Text = $"字段: {scopeLabel}";

        bool regexOn = MenuUseRegex.IsChecked;
        PillRegex.Background = new SolidColorBrush(regexOn ? Color.FromRgb(219, 234, 254) : Color.FromRgb(226, 232, 240));
        PillRegex.Foreground = new SolidColorBrush(regexOn ? Color.FromRgb(30, 64, 175) : Color.FromRgb(100, 116, 139));
        PillRegex.FontWeight = regexOn ? FontWeights.SemiBold : FontWeights.Normal;

        bool exprOn = MenuUseExpr.IsChecked;
        PillExpr.Background = new SolidColorBrush(exprOn ? Color.FromRgb(254, 243, 199) : Color.FromRgb(226, 232, 240));
        PillExpr.Foreground = new SolidColorBrush(exprOn ? Color.FromRgb(146, 64, 14) : Color.FromRgb(100, 116, 139));
        PillExpr.FontWeight = exprOn ? FontWeights.SemiBold : FontWeights.Normal;

        bool ocrOn = MenuEnableOcr.IsChecked;
        PillOcr.Text = ocrOn ? "OCR: 开" : "OCR: 关";
        PillOcr.Background = new SolidColorBrush(ocrOn ? Color.FromRgb(209, 250, 229) : Color.FromRgb(226, 232, 240));
        PillOcr.Foreground = new SolidColorBrush(ocrOn ? Color.FromRgb(6, 95, 70) : Color.FromRgb(100, 116, 139));
    }

    private void MenuMatchAnd_Click(object sender, RoutedEventArgs e)
    {
        _matchAllTerms = true;
        MenuMatchAnd.IsChecked = true;
        MenuMatchOr.IsChecked = false;
        UpdateSearchModeIndicators();
        SavePreferences();
    }

    private void MenuMatchOr_Click(object sender, RoutedEventArgs e)
    {
        _matchAllTerms = false;
        MenuMatchAnd.IsChecked = false;
        MenuMatchOr.IsChecked = true;
        UpdateSearchModeIndicators();
        SavePreferences();
    }

    private void MenuSearchFlag_Click(object sender, RoutedEventArgs e)
    {
        if (ReferenceEquals(sender, MenuUseRegex) && MenuUseRegex.IsChecked)
            MenuUseExpr.IsChecked = false;
        else if (ReferenceEquals(sender, MenuUseExpr) && MenuUseExpr.IsChecked)
            MenuUseRegex.IsChecked = false;

        UpdateSearchModeIndicators();
        SavePreferences();
    }

    private void SetScopeFilter(string scope)
    {
        _scopeFilter = scope;
        foreach (var obj in MenuScopeParent.Items)
        {
            if (obj is MenuItem mi)
                mi.IsChecked = (mi.Tag as string ?? string.Empty) == scope;
        }
    }

    private void MenuScopeItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi)
        {
            SetScopeFilter(mi.Tag as string ?? string.Empty);
            UpdateSearchModeIndicators();
            SavePreferences();
            if (_client.IsConnected && !string.IsNullOrWhiteSpace(TxtSearch.Text))
                _ = ExecuteCurrentSearchAsync(silentEmpty: true);
        }
    }

    private void PillMultiLogic_Click(object sender, MouseButtonEventArgs e)
    {
        if (_matchAllTerms) MenuMatchOr_Click(sender, e); else MenuMatchAnd_Click(sender, e);
        if (_client.IsConnected && !string.IsNullOrWhiteSpace(TxtSearch.Text))
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
    }

    private void PillScope_Click(object sender, MouseButtonEventArgs e)
    {
        string[] order = { "", "FileName", "Body", "Ocr", "Table", "HeadTail", "Metadata" };
        int idx = Array.IndexOf(order, _scopeFilter);
        string next = order[(idx + 1) % order.Length];
        SetScopeFilter(next);
        UpdateSearchModeIndicators();
        SavePreferences();
        if (_client.IsConnected && !string.IsNullOrWhiteSpace(TxtSearch.Text))
            _ = ExecuteCurrentSearchAsync(silentEmpty: true);
    }

    private void PillRegex_Click(object sender, MouseButtonEventArgs e)
    {
        MenuUseRegex.IsChecked = !MenuUseRegex.IsChecked;
        MenuSearchFlag_Click(MenuUseRegex, e);
    }

    private void PillExpr_Click(object sender, MouseButtonEventArgs e)
    {
        MenuUseExpr.IsChecked = !MenuUseExpr.IsChecked;
        MenuSearchFlag_Click(MenuUseExpr, e);
    }

    private void PillOcr_Click(object sender, MouseButtonEventArgs e)
    {
        MenuEnableOcr.IsChecked = !MenuEnableOcr.IsChecked;
        UpdateSearchModeIndicators();
        SavePreferences();
    }

    private void MenuOptionPref_Click(object sender, RoutedEventArgs e)
    {
        UpdateSearchModeIndicators();
        SavePreferences();
    }

    private void MenuCustomExts_Click(object sender, RoutedEventArgs e)
    {
        CmbTypePreset.SelectedItem = CmbTypeCustomItem;
    }

    private void MenuTopmost_Click(object sender, RoutedEventArgs e)
    {
        Topmost = MenuTopmost.IsChecked;
        SavePreferences();
    }

    // ======================== Saved Queries Menu & Dialog ========================

    private void RebuildQuickRulesMenu()
    {
        MenuQuickRules.Items.Clear();
        if (_rules.Count == 0)
        {
            MenuQuickRules.Items.Add(new MenuItem { Header = "(暂无收藏检索式)", IsEnabled = false });
            return;
        }
        foreach (var rule in _rules)
        {
            var mi = new MenuItem { Header = $"{rule.Name}   [{rule.Expression}]", Tag = rule };
            mi.Click += async (s, _) =>
            {
                if (s is MenuItem item && item.Tag is RuleDefinitionDto r)
                {
                    TxtSearch.Text = r.Expression;
                    MenuUseExpr.IsChecked = true;
                    MenuUseRegex.IsChecked = false;
                    UpdateSearchModeIndicators();
                    await ExecuteExpressionSearchAsync(r.Expression, r.Name);
                }
            };
            MenuQuickRules.Items.Add(mi);
        }
    }

    private void MenuSaveCurrentQuery_Click(object sender, RoutedEventArgs e)
    {
        string expr = TxtSearch.Text.Trim();
        if (string.IsNullOrWhiteSpace(expr))
        {
            MessageBox.Show("请先在搜索框输入检索关键词或表达式。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string? name = SimpleInputDialog.Prompt(this, "收藏检索式", "请为当前检索式输入名称：", expr.Length > 16 ? expr[..16] : expr);
        if (string.IsNullOrWhiteSpace(name)) return;

        _rules.Add(new RuleDefinitionDto
        {
            Id = $"q-{Guid.NewGuid():N}"[..10],
            Name = name.Trim(),
            Category = "收藏",
            Severity = "表达式",
            Expression = expr,
            Mode = RuleMatchMode.FullHits
        });
        RebuildQuickRulesMenu();
        SavePreferences();
        FooterStatusText.Text = $"已收藏表达式: {name.Trim()}";
    }

    private async void MenuManageSavedQueries_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SavedQueriesWindow(_rules, TxtSearch.Text.Trim()) { Owner = this };
        bool? ok = dlg.ShowDialog();
        RebuildQuickRulesMenu();
        SavePreferences();
        if (ok != true) return;

        if (dlg.SelectedRuleToRun is { } r)
        {
            TxtSearch.Text = r.Expression;
            MenuUseExpr.IsChecked = true;
            MenuUseRegex.IsChecked = false;
            UpdateSearchModeIndicators();
            await ExecuteExpressionSearchAsync(r.Expression, r.Name);
        }
        else if (dlg.BatchRunAllRequested)
        {
            await RunAllSavedRulesAsync();
        }
    }

    // ======================== View / Shortcuts / Help ========================

    private void ApplyPreviewPaneVisibility(bool visible)
    {
        if (visible)
        {
            PreviewColumn.Width = new GridLength(0.98, GridUnitType.Star);
            PreviewColumn.MinWidth = 310;
            SplitterColumn.Width = new GridLength(5);
            MainSplitter.Visibility = Visibility.Visible;
            PreviewContainer.Visibility = Visibility.Visible;
        }
        else
        {
            PreviewColumn.MinWidth = 0;
            PreviewColumn.Width = new GridLength(0);
            SplitterColumn.Width = new GridLength(0);
            MainSplitter.Visibility = Visibility.Collapsed;
            PreviewContainer.Visibility = Visibility.Collapsed;
        }
    }

    private void MenuTogglePreview_Click(object sender, RoutedEventArgs e)
    {
        ApplyPreviewPaneVisibility(MenuTogglePreview.IsChecked);
        SavePreferences();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F5)
        {
            e.Handled = true;
            MenuIncrementalScan_Click(sender, e);
        }
        else if (e.Key == Key.Escape && (_activeJobId is not null || _daemonHasRunningJob))
        {
            e.Handled = true;
            MenuCancelJob_Click(sender, e);
        }
        else if (e.Key == Key.F3)
        {
            e.Handled = true;
            if ((Keyboard.Modifiers & ModifierKeys.Shift) != 0) JumpToHit(_hitCursor - 1);
            else JumpToHit(_hitCursor + 1);
        }
        else if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            TxtSearch.Focus();
            TxtSearch.SelectAll();
        }
        else if (e.Key == Key.O && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            MenuAddFolder_Click(sender, e);
        }
        else if (e.Key == Key.B && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            MenuManageSavedQueries_Click(sender, e);
        }
        else if (e.SystemKey == Key.P && Keyboard.Modifiers == ModifierKeys.Alt)
        {
            e.Handled = true;
            MenuTogglePreview.IsChecked = !MenuTogglePreview.IsChecked;
            MenuTogglePreview_Click(sender, e);
        }
    }

    private void MenuHelpSyntax_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "【常用搜索语法与操作指南】\n\n" +
            "1. 普通全文检索：\n" +
            "   • 输入单个关键词或空格分隔多词（如：招标 违约金）\n" +
            "   • 底部状态栏或菜单【搜索】可切换【多词: AND / OR】\n\n" +
            "2. 类型与目录精确筛选：\n" +
            "   • 搜索框右侧下拉切换 文档 / 表格 / CAD / 图片 / 压缩包 或自定义后缀\n" +
            "   • 第二行左侧下拉选目录，右侧可手输路径或直接拖入文件夹\n\n" +
            "3. 高级布尔与邻近表达式（勾选【表达式】模式）：\n" +
            "   • NEAR(合同, 违约, 15) / ONEAR(甲, 乙, 10) / SAMELINE(A, B)\n" +
            "   • 逻辑运算：\"绝密\" & !\"样稿\"  |  (报价 | 预算)\n" +
            "   • 字段限定：scope:ocr(...)  scope:filename(...)  scope:table(...)\n\n" +
            "4. 快捷键：\n" +
            "   • Ctrl+L 聚焦搜索框 | F5 增量索引 | F3/Shift+F3 预览上下处高亮 | Alt+P 显隐预览 | Ctrl+Shift+Del 深度删除",
            "检索语法与快捷键指南", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void MenuAbout_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "DeepDocEngine (DocSentinel UI)\n\n" +
            "本地全格式文档深度解析（PDF / Office / WPS / DWG CAD / 压缩包 / PP-OCRv4）、\n" +
            "中文混合分词检索（Tantivy + Jieba + SQLite）与温和慢速防杀软深度粉碎擦除工具。",
            "关于 DeepDocEngine", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
