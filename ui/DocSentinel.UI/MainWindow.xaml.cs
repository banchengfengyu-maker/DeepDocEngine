using DocSentinel.UI.Ipc;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace DocSentinel.UI;

public partial class MainWindow : Window
{
    private readonly DaemonPipeClient _client = new();
    private readonly ObservableCollection<string> _roots = new();
    private readonly ObservableCollection<RuleDefinitionDto> _rules = new();
    private readonly ObservableCollection<ResultRowItem> _results = new();
    private readonly List<Run> _hitRuns = new();
    private readonly DispatcherTimer _idleTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private int _hitCursor = -1;
    private string? _activeJobId;
    private DateTime _lastIdleScanUtc = DateTime.MinValue;
    private HashSet<string> _pendingDeleteTargets = new(StringComparer.OrdinalIgnoreCase);

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

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
        RootsList.ItemsSource = _roots;
        RulesGrid.ItemsSource = _rules;
        ResultsGrid.ItemsSource = _results;

        LoadOrSeedPreferences();
        WireClientEvents();
        _idleTimer.Tick += async (_, _) => await TryIdleIncrementalScanAsync();
        _idleTimer.Start();
        Loaded += async (_, _) => await ConnectSafeAsync();
        Closed += async (_, _) =>
        {
            _idleTimer.Stop();
            SavePreferences();
            await _client.DisposeAsync();
        };
    }

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
                            if (!string.IsNullOrWhiteSpace(s) && !_roots.Contains(s))
                                _roots.Add(s);
                        }
                    }
                    if (node["include_exts"] is JsonValue exVal)
                        TxtIncludeExts.Text = exVal.AsStr();
                    if (node["dir_filter"] is JsonValue dirVal)
                        TxtDirFilter.Text = dirVal.AsStr();
                    if (node["enable_ocr"] is JsonValue ocrVal)
                        ChkEnableOcr.IsChecked = ocrVal.AsBool(true);
                    if (node["skip_temp"] is JsonValue skipVal)
                        ChkSkipTemp.IsChecked = skipVal.AsBool(true);
                    if (node["idle_index"] is JsonValue idleVal)
                        ChkIdleIndex.IsChecked = idleVal.AsBool(false);
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
        {
            SeedDefaultQueries();
        }
    }

    private void SavePreferences()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PrefsPath)!);
            var obj = new JsonObject
            {
                ["roots"] = new JsonArray(_roots.Select(r => JsonValue.Create(r)).ToArray<JsonNode?>()),
                ["include_exts"] = TxtIncludeExts.Text.Trim(),
                ["dir_filter"] = TxtDirFilter.Text.Trim(),
                ["enable_ocr"] = ChkEnableOcr.IsChecked == true,
                ["skip_temp"] = ChkSkipTemp.IsChecked == true,
                ["idle_index"] = ChkIdleIndex.IsChecked == true,
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
            Severity = "查询",
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

    private void WireClientEvents()
    {
        _client.OnScanProgress += obj => Dispatcher.Invoke(() =>
        {
            ulong scanned = obj["scanned_files"].AsUInt64();
            ulong ok = obj["parsed_ok"].AsUInt64();
            ulong cached = obj["skipped_cached"].AsUInt64();
            ulong enc = obj["encrypted_files"].AsUInt64();
            ulong fail = obj["failed_files"].AsUInt64();
            string cur = obj["current_path"].AsStr();
            FooterStatusText.Text = $"扫描中: 已发现 {scanned} | 解析 {ok} | 缓存跳过 {cached} | 加密 {enc} | 失败 {fail} — {cur}";
        });

        _client.OnScanHit += hit => Dispatcher.Invoke(() =>
        {
            AddHitRow(hit);
            ResultsHeader.Text = $"检索与规则命中结果（当前 {_results.Count} 条）";
        });

        _client.OnScanCompleted += summary => Dispatcher.Invoke(async () =>
        {
            _activeJobId = null;
            SetJobUiBusy(false);
            ScanProgressBar.Value = 100;
            FooterStatusText.Text =
                $"扫描{(summary.Cancelled ? "已取消" : "完成")}: 总文件 {summary.ScannedFiles}, 解析 {summary.ParsedOk}, 子文档 {summary.ChildDocsIndexed}, 缓存 {summary.SkippedCached}, 加密 {summary.EncryptedFiles}, 失败 {summary.FailedFiles}, 命中 {summary.RuleHits}, 耗时 {summary.ElapsedMs} ms";
            await RefreshStatsSafeAsync();
        });

        _client.OnDeepDeleteProgress += obj => Dispatcher.Invoke(() =>
        {
            ulong done = obj["completed"].AsUInt64();
            ulong total = obj["total"].AsUInt64();
            string cur = obj["current_path"].AsStr();
            FooterStatusText.Text = $"深度擦除中 ({done}/{total}) — 慢速安全覆写防杀软拦截: {cur}";
        });

        _client.OnDeepDeleteCompleted += obj => Dispatcher.Invoke(async () =>
        {
            _activeJobId = null;
            SetJobUiBusy(false);
            ScanProgressBar.Value = 100;
            ulong wiped = obj["deleted_files"].AsUInt64();
            ulong purged = obj["purged_index_docs"].AsUInt64();
            ulong skipped = obj["skipped_or_failed"].AsUInt64();
            var errs = obj["errors"]?.AsArray().Select(n => n?.ToString() ?? "").Where(s => !string.IsNullOrEmpty(s)).ToList() ?? new();

            if (wiped > 0 && _pendingDeleteTargets.Count > 0)
            {
                for (int i = _results.Count - 1; i >= 0; i--)
                {
                    if (_pendingDeleteTargets.Contains(_results[i].VirtualPath))
                        _results.RemoveAt(i);
                }
                PreviewBox.Document.Blocks.Clear();
                PreviewHeader.Text = "原文与 OCR 分段高亮预览";
            }
            _pendingDeleteTargets.Clear();
            FooterStatusText.Text = $"深度删除完成: 粉碎 {wiped} 个文件, 同步抹除索引 {purged} 条, 跳过/失败 {skipped} 条";
            await RefreshStatsSafeAsync();

            if (errs.Count > 0)
            {
                MessageBox.Show(string.Join("\n", errs.Take(10)), "部分文件未删除（安全保护或跳过）", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        });

        _client.OnDisconnected += msg => Dispatcher.Invoke(() =>
        {
            SetConnectedBadge(false, $"连接断开: {msg}");
        });
    }

    private void SetConnectedBadge(bool connected, string tooltip)
    {
        StatusBadge.Background = new SolidColorBrush(connected
            ? Color.FromRgb(22, 163, 74)
            : Color.FromRgb(220, 38, 38));
        StatusBadgeText.Text = connected ? "引擎已连接" : "未连接";
        StatusBadge.ToolTip = tooltip;
    }

    private async Task ConnectSafeAsync()
    {
        try
        {
            FooterStatusText.Text = "正在连接后台 Rust 引擎管道...";
            await _client.ConnectOrStartDaemonAsync();
            var pong = await _client.SendAsync(new JsonObject { ["type"] = "Ping" });
            var engines = pong["worker_engines"]?.AsArray().Select(n => n?.ToString() ?? "").ToList() ?? new();
            var extEngines = pong["ext_worker_engines"]?.AsArray().Select(n => n?.ToString() ?? "").ToList() ?? new();
            SetConnectedBadge(true, $"parser-worker: {string.Join(", ", engines)}\next-worker: {string.Join(", ", extEngines)}");
            FooterStatusText.Text = $"已连接到 engine-daemon (v{pong["daemon_version"]})";
            await RefreshStatsSafeAsync();
        }
        catch (Exception ex)
        {
            SetConnectedBadge(false, ex.Message);
            FooterStatusText.Text = $"连接失败: {ex.Message}";
        }
    }

    private async Task RefreshStatsSafeAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            var res = await _client.SendAsync(new JsonObject { ["type"] = "GetStats" });
            var st = res["stats"]?.Deserialize<IndexStatsDto>();
            if (st is not null)
            {
                double mb = (st.DbSizeBytes + st.TantivySizeBytes) / (1024.0 * 1024.0);
                StatsText.Text = $"文档: {st.TotalDocuments} | 去重正文块: {st.UniqueContentBlobs} | 加密: {st.EncryptedDocuments} | 失败: {st.FailedDocuments} | 索引占用: {mb:F2} MB";
            }
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = $"获取统计失败: {ex.Message}";
        }
    }

    private async void BtnConnect_Click(object sender, RoutedEventArgs e) => await ConnectSafeAsync();
    private async void BtnRefreshStats_Click(object sender, RoutedEventArgs e) => await RefreshStatsSafeAsync();

    private async void BtnClearIndex_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected) return;
        if (MessageBox.Show("确认清空全部已建索引与缓存原文吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        try
        {
            await _client.SendAsync(new JsonObject { ["type"] = "ClearIndex" });
            _results.Clear();
            PreviewBox.Document.Blocks.Clear();
            await RefreshStatsSafeAsync();
            FooterStatusText.Text = "索引库与原文缓存已清空";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "清空失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnAddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择需要解析与检索的目录", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            foreach (var p in dlg.FolderNames)
                if (!_roots.Contains(p)) _roots.Add(p);
        }
    }

    private void BtnAddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择文件", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            foreach (var p in dlg.FileNames)
                if (!_roots.Contains(p)) _roots.Add(p);
        }
    }

    private void BtnAddFixedDrives_Click(object sender, RoutedEventArgs e)
    {
        int added = 0;
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Fixed && !_roots.Contains(d.Name))
            {
                _roots.Add(d.Name);
                added++;
            }
        }
        FooterStatusText.Text = added > 0 ? $"已添加 {added} 个本地固定磁盘根目录" : "固定磁盘均已在列表中";
    }

    private void BtnAddUsbDrives_Click(object sender, RoutedEventArgs e)
    {
        int added = 0;
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Removable && !_roots.Contains(d.Name))
            {
                _roots.Add(d.Name);
                added++;
            }
        }
        FooterStatusText.Text = added > 0 ? $"已添加 {added} 个可移动磁盘" : "未检测到新插入的可移动磁盘/U盘";
    }

    private void BtnRemoveRoot_Click(object sender, RoutedEventArgs e)
    {
        if (RootsList.SelectedItem is string s) _roots.Remove(s);
    }

    private void RootsList_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void RootsList_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths)
        {
            foreach (var p in paths)
                if (!_roots.Contains(p)) _roots.Add(p);
        }
    }

    private void BtnAddRule_Click(object sender, RoutedEventArgs e)
    {
        string expr = string.IsNullOrWhiteSpace(TxtSearch.Text)
            ? "\"关键词A\" & !\"排除词\""
            : TxtSearch.Text.Trim();
        _rules.Add(new RuleDefinitionDto
        {
            Id = $"q-{Guid.NewGuid():N}"[..10],
            Name = expr.Length > 14 ? expr[..14] : expr,
            Category = "收藏",
            Severity = "查询",
            Expression = expr,
            Mode = RuleMatchMode.FullHits
        });
        SavePreferences();
    }

    private void BtnDeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleDefinitionDto r) _rules.Remove(r);
    }

    private JsonObject BuildRuleSetJson()
    {
        var arr = new JsonArray();
        foreach (var r in _rules)
        {
            if (string.IsNullOrWhiteSpace(r.Expression)) continue;
            arr.Add(JsonSerializer.SerializeToNode(r));
        }
        return new JsonObject
        {
            ["ruleset_id"] = "ui-rules-v1",
            ["rules"] = arr
        };
    }

    private JsonArray BuildRootsJson()
    {
        var rootsArr = new JsonArray();
        foreach (var r in _roots) rootsArr.Add(r);
        return rootsArr;
    }

    private JsonObject BuildScanOptionsJson()
    {
        var includeExtsArr = new JsonArray();
        foreach (var ex in TxtIncludeExts.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var clean = ex.Trim().TrimStart('.').ToLowerInvariant();
            if (!string.IsNullOrEmpty(clean)) includeExtsArr.Add(clean);
        }

        var excludedDirsArr = new JsonArray();
        var excludedGlobsArr = new JsonArray();
        if (ChkSkipTemp.IsChecked == true)
        {
            foreach (var d in new[] { "$Recycle.Bin", "System Volume Information", ".git", "node_modules", "__pycache__" })
                excludedDirsArr.Add(d);
            foreach (var g in new[] { "~$*", "*.tmp", "~*.tmp", "thumbs.db", "desktop.ini" })
                excludedGlobsArr.Add(g);
        }

        var pwArr = new JsonArray();
        if (!string.IsNullOrWhiteSpace(TxtPassword.Text))
            pwArr.Add(TxtPassword.Text.Trim());

        return new JsonObject
        {
            ["include_hidden"] = false,
            ["use_usn_if_available"] = true,
            ["worker_count"] = Math.Clamp(Environment.ProcessorCount, 2, 6),
            ["worker_timeout_ms"] = 45000,
            ["excluded_dirs"] = excludedDirsArr,
            ["excluded_name_globs"] = excludedGlobsArr,
            ["include_extensions"] = includeExtsArr,
            ["parse"] = new JsonObject
            {
                ["max_extract_depth"] = 6,
                ["max_uncompressed_bytes"] = 512L * 1024 * 1024,
                ["max_single_file_bytes"] = 256L * 1024 * 1024,
                ["max_expansion_ratio"] = 100,
                ["enable_ocr"] = ChkEnableOcr.IsChecked == true,
                ["ocr_min_image_dim"] = 24,
                ["enable_x2t"] = false,
                ["passwords"] = pwArr
            }
        };
    }

    private void SetJobUiBusy(bool busy)
    {
        BtnStartScan.IsEnabled = !busy;
        BtnRebuildScan.IsEnabled = !busy;
        BtnDirectSearch.IsEnabled = !busy;
        BtnDeepDeletePicker.IsEnabled = !busy;
        BtnCancelScan.IsEnabled = busy;
        ScanProgressBar.IsIndeterminate = busy;
    }

    private async Task TryIdleIncrementalScanAsync()
    {
        if (ChkIdleIndex.IsChecked != true || _activeJobId is not null || !_client.IsConnected || _roots.Count == 0)
            return;
        if (GetUserIdleSeconds() < 180)
            return;
        if ((DateTime.UtcNow - _lastIdleScanUtc).TotalMinutes < 15)
            return;

        _lastIdleScanUtc = DateTime.UtcNow;
        FooterStatusText.Text = "检测到系统空闲超过 3 分钟，正在后台低优先级执行增量索引...";
        await StartScanInternalAsync("idle", silentOnError: true);
    }

    private async Task StartScanInternalAsync(string prefix, bool silentOnError)
    {
        SavePreferences();
        _activeJobId = $"{prefix}-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);

        var req = new JsonObject
        {
            ["type"] = "StartScan",
            ["job_id"] = _activeJobId,
            ["roots"] = BuildRootsJson(),
            ["ruleset"] = null,
            ["options"] = BuildScanOptionsJson()
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

    private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        if (_roots.Count == 0)
        {
            MessageBox.Show("请先添加或拖入至少一个文件夹/文件。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await StartScanInternalAsync("inc", silentOnError: false);
    }

    private async void BtnRebuildScan_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        if (_roots.Count == 0)
        {
            MessageBox.Show("请先添加或拖入至少一个需要重建索引的目录或文件。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(
                "确认执行【手动重建索引】？\n将清空当前文档记录与全文倒排索引后从头全量解析（保留图片 OCR 缓存以节省时间）。",
                "确认重建索引", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            await _client.SendAsync(new JsonObject { ["type"] = "ResetIndexKeepOcr" });
            _results.Clear();
            PreviewBox.Document.Blocks.Clear();
            await StartScanInternalAsync("rebuild", silentOnError: false);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "重建索引失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void BtnDirectSearch_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        if (_roots.Count == 0)
        {
            MessageBox.Show("请先添加或拖入要临时直搜的文件夹/U盘目录。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string query = TxtSearch.Text.Trim();
        if (string.IsNullOrWhiteSpace(query))
        {
            TxtSearch.Focus();
            MessageBox.Show("请先在右侧搜索框输入要临时直搜的关键词、正则或表达式。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SavePreferences();
        _results.Clear();
        ResultsHeader.Text = "正在执行临时直搜（不写入本地索引库）...";
        _activeJobId = $"direct-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        SetJobUiBusy(true);

        string? extFilter = !string.IsNullOrWhiteSpace(TxtExtFilter.Text)
            ? TxtExtFilter.Text.Trim()
            : (string.IsNullOrWhiteSpace(TxtIncludeExts.Text) ? null : TxtIncludeExts.Text.Trim());

        var req = new JsonObject
        {
            ["type"] = "DirectSearch",
            ["job_id"] = _activeJobId,
            ["roots"] = BuildRootsJson(),
            ["query"] = query,
            ["use_regex"] = ChkRegexSearch.IsChecked == true,
            ["file_ext_filter"] = extFilter,
            ["options"] = BuildScanOptionsJson()
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

    private async void BtnCancelScan_Click(object sender, RoutedEventArgs e)
    {
        if (_activeJobId is null || !_client.IsConnected) return;
        try
        {
            await _client.SendAsync(new JsonObject
            {
                ["type"] = "CancelScan",
                ["job_id"] = _activeJobId
            });
        }
        catch { }
    }

    private async void RulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleDefinitionDto rule && !string.IsNullOrWhiteSpace(rule.Expression))
        {
            TxtSearch.Text = rule.Expression;
            ChkExprMode.IsChecked = true;
            await ExecuteExpressionSearchAsync(rule.Expression, rule.Name);
        }
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
            string? ext = string.IsNullOrWhiteSpace(TxtExtFilter.Text) ? null : TxtExtFilter.Text.Trim();
            string? dirPrefix = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim();
            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "EvaluateRules",
                ["ruleset"] = rs,
                ["doc_ids"] = null,
                ["path_prefix"] = dirPrefix,
                ["file_ext_filter"] = ext
            });
            _results.Clear();
            var hits = resp["hits"]?.Deserialize<List<HitRecordDto>>() ?? new();
            foreach (var h in hits) AddHitRow(h);
            ulong ms = resp["took_ms"].AsUInt64();
            ResultsHeader.Text = $"表达式检索命中（{hits.Count} 篇，耗时 {ms} ms）";
            FooterStatusText.Text = $"表达式检索完成: 命中 {hits.Count} 篇 ({ms} ms)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "表达式检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void BtnEvalRules_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected) return;
        try
        {
            string? ext = string.IsNullOrWhiteSpace(TxtExtFilter.Text) ? null : TxtExtFilter.Text.Trim();
            string? dirPrefix = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim();
            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "EvaluateRules",
                ["ruleset"] = BuildRuleSetJson(),
                ["doc_ids"] = null,
                ["path_prefix"] = dirPrefix,
                ["file_ext_filter"] = ext
            });
            _results.Clear();
            var hits = resp["hits"]?.Deserialize<List<HitRecordDto>>() ?? new();
            foreach (var h in hits) AddHitRow(h);
            ulong ms = resp["took_ms"].AsUInt64();
            ResultsHeader.Text = $"收藏表达式批量检索结果（命中 {hits.Count} 篇，耗时 {ms} ms）";
            FooterStatusText.Text = $"批量表达式检索完成: 命中 {hits.Count} 篇 ({ms} ms)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "表达式检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CmbTypePreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || TxtExtFilter is null) return;
        if (CmbTypePreset.SelectedItem is ComboBoxItem item)
        {
            TxtExtFilter.Text = (item.Tag as string) ?? string.Empty;
        }
    }

    private void BtnPickDirFilter_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择限定搜索目录", Multiselect = false };
        if (dlg.ShowDialog() == true)
        {
            TxtDirFilter.Text = dlg.FolderName;
            SavePreferences();
        }
    }

    private void BtnClearDirFilter_Click(object sender, RoutedEventArgs e)
    {
        TxtDirFilter.Text = string.Empty;
        SavePreferences();
    }

    private void TxtSearch_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) BtnSearch_Click(sender, e);
    }

    private async void BtnSearch_Click(object sender, RoutedEventArgs e)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        string q = TxtSearch.Text.Trim();
        if (ChkExprMode.IsChecked == true && !string.IsNullOrWhiteSpace(q))
        {
            await ExecuteExpressionSearchAsync(q, "即时表达式");
            return;
        }
        string? ext = string.IsNullOrWhiteSpace(TxtExtFilter.Text) ? null : TxtExtFilter.Text.Trim();
        string? dirPrefix = string.IsNullOrWhiteSpace(TxtDirFilter.Text) ? null : TxtDirFilter.Text.Trim();
        string? scopeTag = (CmbScopeFilter.SelectedItem as ComboBoxItem)?.Tag as string;
        string? scopeVal = string.IsNullOrEmpty(scopeTag) ? null : scopeTag;
        bool matchAll = (CmbMultiKeyword.SelectedItem as ComboBoxItem)?.Tag as string != "any";

        var req = new JsonObject
        {
            ["type"] = "Search",
            ["query"] = new JsonObject
            {
                ["text"] = q,
                ["file_ext_filter"] = ext,
                ["path_prefix"] = dirPrefix,
                ["scope_filter"] = scopeVal,
                ["use_regex"] = ChkRegexSearch.IsChecked == true,
                ["match_all_terms"] = matchAll,
                ["limit"] = 500,
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
            var terms = q.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(t => t.Trim('"'))
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();

            foreach (var it in items)
            {
                var firstSnip = it.Snippets.FirstOrDefault();
                _results.Add(new ResultRowItem
                {
                    DocId = it.DocId,
                    KindBadge = "检索",
                    FileName = it.FileName,
                    Format = it.DetectedFormat,
                    RuleOrScore = $"score {it.Score:F2}",
                    LocationLabel = firstSnip is null ? "-" : $"[{firstSnip.Scope}] {firstSnip.LocationLabel}",
                    Snippet = firstSnip?.Snippet ?? "",
                    VirtualPath = it.VirtualPath,
                    HighlightTerms = terms
                });
            }
            ResultsHeader.Text = $"全文检索结果（共 {total} 篇命中，展示 {_results.Count} 篇，耗时 {ms} ms）";
            FooterStatusText.Text = $"检索完成: {total} 篇命中 ({ms} ms)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "检索失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddHitRow(HitRecordDto hit)
    {
        var firstSnip = hit.Snippets.FirstOrDefault();
        var terms = hit.Snippets.Select(s => s.MatchedTerm).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct().ToList();
        _results.Add(new ResultRowItem
        {
            DocId = hit.DocId,
            KindBadge = hit.Severity,
            FileName = hit.FileName,
            Format = hit.DetectedFormat,
            RuleOrScore = $"{hit.RuleName} (×{hit.TotalMatches})",
            LocationLabel = firstSnip is null ? "-" : $"[{firstSnip.Scope}] {firstSnip.LocationLabel}",
            Snippet = firstSnip?.Snippet ?? "",
            VirtualPath = hit.VirtualPath,
            HighlightTerms = terms
        });
    }

    private async void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row || !_client.IsConnected)
            return;

        var termsArr = new JsonArray();
        foreach (var t in row.HighlightTerms) termsArr.Add(t);

        try
        {
            var resp = await _client.SendAsync(new JsonObject
            {
                ["type"] = "GetDocumentPreview",
                ["doc_id"] = row.DocId,
                ["highlight_terms"] = termsArr,
                ["max_chars"] = 120000
            });
            var preview = resp["doc"]?.Deserialize<DocumentPreviewDto>();
            if (preview is not null) RenderPreview(preview);
        }
        catch (Exception ex)
        {
            PreviewHeader.Text = $"预览加载失败: {ex.Message}";
        }
    }

    private void RenderPreview(DocumentPreviewDto doc)
    {
        _hitRuns.Clear();
        _hitCursor = -1;
        HitNavText.Text = "0 / 0";
        PreviewHeader.Text = $"预览: {doc.VirtualPath}  |  格式: {doc.DetectedFormat}  |  BLAKE3: {doc.Blake3Hex[..Math.Min(16, doc.Blake3Hex.Length)]}  |  {(doc.Encrypted ? "[已加密]" : $"{doc.ByteSize} B")}";
        var flow = new FlowDocument { PagePadding = new Thickness(8) };

        if (doc.Segments.Count == 0)
        {
            flow.Blocks.Add(new Paragraph(new Run("(无抽取文本段，可能为加密文件、纯二进制文件或待外部适配器解析)"))
            {
                Foreground = Brushes.Gray
            });
            PreviewBox.Document = flow;
            return;
        }

        foreach (var seg in doc.Segments)
        {
            var hdr = new Paragraph
            {
                Margin = new Thickness(0, 8, 0, 2),
                Background = new SolidColorBrush(Color.FromRgb(226, 232, 240)),
                Padding = new Thickness(6, 2, 6, 2)
            };
            hdr.Inlines.Add(new Run($"[{seg.Scope}] {seg.LocationLabel}")
            {
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59))
            });
            flow.Blocks.Add(hdr);

            var bodyPara = new Paragraph { Margin = new Thickness(0, 2, 0, 6) };
            AppendHighlightedRuns(bodyPara, seg.Text, seg.HighlightRanges, _hitRuns);
            flow.Blocks.Add(bodyPara);
        }

        PreviewBox.Document = flow;
        if (_hitRuns.Count > 0)
        {
            JumpToHit(0);
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
        Dispatcher.BeginInvoke(() =>
        {
            try
            {
                var rect = active.ContentStart.GetCharacterRect(LogicalDirection.Forward);
                if (!rect.IsEmpty)
                {
                    PreviewBox.ScrollToVerticalOffset(Math.Max(0, PreviewBox.VerticalOffset + rect.Top - PreviewBox.ActualHeight * 0.35));
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

    private void ResultsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => MenuOpenFile_Click(sender, e);

    private void MenuOpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        bool isArchiveInner = row.VirtualPath.Contains("!/");
        string diskPath = row.VirtualPath.Split("!/")[0];
        if (File.Exists(diskPath))
        {
            if (isArchiveInner)
                FooterStatusText.Text = $"命中文档位于压缩包内部，正在打开外层归档文件：{diskPath}";
            try { Process.Start(new ProcessStartInfo(diskPath) { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show($"打开失败: {ex.Message}", "提示", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }
        else if (Directory.Exists(diskPath))
        {
            Process.Start("explorer.exe", $"\"{diskPath}\"");
        }
    }

    private void MenuOpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = row.VirtualPath.Split("!/")[0];
        if (File.Exists(diskPath))
            Process.Start("explorer.exe", $"/select,\"{diskPath}\"");
        else if (Directory.Exists(diskPath))
            Process.Start("explorer.exe", $"\"{diskPath}\"");
    }

    private void MenuCopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is ResultRowItem row)
            Clipboard.SetText(row.VirtualPath);
    }

    private void MenuFilterByRowFolder_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not ResultRowItem row) return;
        string diskPath = row.VirtualPath.Split("!/")[0];
        string? dir = Path.GetDirectoryName(diskPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            TxtDirFilter.Text = dir;
            SavePreferences();
            FooterStatusText.Text = $"已将检索范围限定至目录: {dir}";
        }
    }

    private async void MenuDeepDeleteSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = ResultsGrid.SelectedItems.OfType<ResultRowItem>().Select(r => r.VirtualPath).Distinct().ToList();
        if (selected.Count == 0 && ResultsGrid.SelectedItem is ResultRowItem single)
            selected.Add(single.VirtualPath);
        if (selected.Count == 0) return;

        var innerWarnings = selected.Where(p => p.Contains("!/")).ToList();
        if (innerWarnings.Count == selected.Count)
        {
            MessageBox.Show(
                "选中的条目均位于压缩包内部，为防止误粉碎整个归档文件已阻止。\n如需彻底删除整个压缩包，请在上方点击【深度删除文件...】直接选取该压缩包文件。",
                "安全提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await StartDeepDeleteAsync(selected);
    }

    private async void BtnDeepDeletePicker_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择要深度碎纸彻底删除的文件（不进回收站，防杀软拦截慢速三遍覆写）",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true && dlg.FileNames.Length > 0)
        {
            await StartDeepDeleteAsync(dlg.FileNames);
        }
    }

    private async Task StartDeepDeleteAsync(IReadOnlyList<string> paths)
    {
        if (!_client.IsConnected)
        {
            await ConnectSafeAsync();
            if (!_client.IsConnected) return;
        }
        if (_activeJobId is not null)
        {
            MessageBox.Show("当前已有任务正在执行，请先等待完成或点击停止。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string previewList = string.Join("\n", paths.Take(8));
        if (paths.Count > 8) previewList += $"\n... 等共 {paths.Count} 项";
        if (MessageBox.Show(
                $"确定执行【深度删除】以下 {paths.Count} 项文件？\n\n{previewList}\n\n" +
                "• 采用 3 遍低熵值（0xAA→0x55→0x00）温和慢速覆写并改名擦除，尽量避免触发杀毒软件勒索误报，速度会故意偏慢。\n" +
                "• 删除后同步从 DeepDocEngine 本地索引库中彻底抹除，不进回收站且不可恢复！",
                "高危确认：深度粉碎删除", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

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
                ["paths"] = pArr
            });
        }
        catch (Exception ex)
        {
            _activeJobId = null;
            _pendingDeleteTargets.Clear();
            SetJobUiBusy(false);
            MessageBox.Show(ex.Message, "启动深度删除失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
