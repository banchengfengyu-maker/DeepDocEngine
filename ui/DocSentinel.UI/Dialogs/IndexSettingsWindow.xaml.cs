using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;

namespace DocSentinel.UI.Dialogs;

public enum IndexSettingsAction
{
    SaveOnly,
    StartIncremental,
    StartRebuild,
    StartRebuildLowResource
}

public partial class IndexSettingsWindow : Window
{
    public ObservableCollection<string> Roots { get; } = new();
    public string IncludeExts => TxtIncludeExts.Text.Trim();
    public string PasswordText => TxtPassword.Text;
    public bool EnableOcr => ChkEnableOcr.IsChecked == true;
    public bool SkipTemp => ChkSkipTemp.IsChecked == true;
    public bool IdleIndex => ChkIdleIndex.IsChecked == true;
    public bool LowResourceMode => ChkLowResourceMode.IsChecked == true;
    public IndexSettingsAction RequestedAction { get; private set; } = IndexSettingsAction.SaveOnly;

    public IndexSettingsWindow(
        IEnumerable<string> roots,
        string includeExts,
        string passwordText,
        bool enableOcr,
        bool skipTemp,
        bool idleIndex,
        bool lowResourceMode)
    {
        InitializeComponent();
        foreach (var r in roots) Roots.Add(r);
        RootsList.ItemsSource = Roots;
        TxtIncludeExts.Text = includeExts;
        TxtPassword.Text = passwordText;
        ChkEnableOcr.IsChecked = enableOcr;
        ChkSkipTemp.IsChecked = skipTemp;
        ChkIdleIndex.IsChecked = idleIndex;
        ChkLowResourceMode.IsChecked = lowResourceMode;
    }

    private void BtnAddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择要加入索引的目录", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            foreach (var p in dlg.FolderNames)
                if (!Roots.Contains(p, StringComparer.OrdinalIgnoreCase)) Roots.Add(p);
        }
    }

    private void BtnAddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择要加入索引的文件", Multiselect = true };
        if (dlg.ShowDialog() == true)
        {
            foreach (var p in dlg.FileNames)
                if (!Roots.Contains(p, StringComparer.OrdinalIgnoreCase)) Roots.Add(p);
        }
    }

    private void BtnAddFixedDrives_Click(object sender, RoutedEventArgs e)
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Fixed && !Roots.Contains(d.Name, StringComparer.OrdinalIgnoreCase))
                Roots.Add(d.Name);
        }
    }

    private void BtnAddUsbDrives_Click(object sender, RoutedEventArgs e)
    {
        int added = 0;
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.IsReady && d.DriveType == DriveType.Removable && !Roots.Contains(d.Name, StringComparer.OrdinalIgnoreCase))
            {
                Roots.Add(d.Name);
                added++;
            }
        }
        if (added == 0)
            MessageBox.Show("当前未检测到新插入的可移动磁盘/U盘（或已在列表中）。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void BtnRemoveRoot_Click(object sender, RoutedEventArgs e)
    {
        var selected = RootsList.SelectedItems.Cast<string>().ToList();
        foreach (var item in selected) Roots.Remove(item);
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
                if (!Roots.Contains(p, StringComparer.OrdinalIgnoreCase)) Roots.Add(p);
        }
    }

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        RequestedAction = IndexSettingsAction.SaveOnly;
        DialogResult = true;
    }

    private void BtnSaveAndIncremental_Click(object sender, RoutedEventArgs e)
    {
        if (Roots.Count == 0)
        {
            MessageBox.Show("请先添加至少一个需要扫描的目录或文件。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        RequestedAction = IndexSettingsAction.StartIncremental;
        DialogResult = true;
    }

    private void BtnSaveAndRebuild_Click(object sender, RoutedEventArgs e)
    {
        if (Roots.Count == 0)
        {
            MessageBox.Show("请先添加至少一个需要重建索引的目录或文件。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        RequestedAction = IndexSettingsAction.StartRebuild;
        DialogResult = true;
    }

    private void BtnSaveAndLowRebuild_Click(object sender, RoutedEventArgs e)
    {
        if (Roots.Count == 0)
        {
            MessageBox.Show("请先添加至少一个需要低占用重建索引的目录或文件。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        RequestedAction = IndexSettingsAction.StartRebuildLowResource;
        DialogResult = true;
    }
}
