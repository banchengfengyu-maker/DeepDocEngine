using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace DocSentinel.UI.Dialogs;

public partial class DeepDeleteConfirmWindow : Window
{
    public bool Confirmed { get; private set; }
    public string WipeMode => RbZeroWipe.IsChecked == true ? "zero_wipe" : "direct";

    public DeepDeleteConfirmWindow(IReadOnlyList<string> paths)
    {
        InitializeComponent();

        int dirCount = 0;
        int fileCount = 0;
        var lines = new List<string>(paths.Count);
        foreach (var p in paths)
        {
            if (Directory.Exists(p))
            {
                dirCount++;
                lines.Add($"[目录及内部全部文件] {p}");
            }
            else
            {
                fileCount++;
                lines.Add($"[文件] {p}");
            }
        }

        string summary = $"待销毁目标：共 {paths.Count} 项";
        if (dirCount > 0 && fileCount > 0)
            summary += $"（包含 {dirCount} 个目录及其内部全部文件，{fileCount} 个独立文件）";
        else if (dirCount > 0)
            summary += $"（包含 {dirCount} 个目录及其内部全部文件）";
        else
            summary += $"（共 {fileCount} 个文件）";

        TxtSummary.Text = summary;
        TxtPathsList.Text = string.Join(Environment.NewLine, lines);
    }

    private void BtnConfirmDelete_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = true;
        DialogResult = true;
        Close();
    }
}
