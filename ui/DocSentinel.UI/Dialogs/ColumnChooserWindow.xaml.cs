using System.Collections.ObjectModel;
using System.Windows;

namespace DocSentinel.UI.Dialogs;

public sealed class ColumnConfigEntry
{
    public required string Key { get; init; }
    public required string Header { get; init; }
    public bool Visible { get; set; }
    public bool DefaultVisible { get; init; }
    public double DefaultWidth { get; init; }
    public int DefaultOrder { get; init; }
}

public partial class ColumnChooserWindow : Window
{
    public ObservableCollection<ColumnConfigEntry> Entries { get; } = new();

    public ColumnChooserWindow(IEnumerable<ColumnConfigEntry> current)
    {
        InitializeComponent();
        foreach (var c in current)
        {
            Entries.Add(new ColumnConfigEntry
            {
                Key = c.Key,
                Header = c.Header,
                Visible = c.Visible,
                DefaultVisible = c.DefaultVisible,
                DefaultWidth = c.DefaultWidth,
                DefaultOrder = c.DefaultOrder
            });
        }
        ColumnsList.ItemsSource = Entries;
    }

    private void BtnMoveUp_Click(object sender, RoutedEventArgs e)
    {
        int idx = ColumnsList.SelectedIndex;
        if (idx <= 0) return;
        Entries.Move(idx, idx - 1);
        ColumnsList.SelectedIndex = idx - 1;
    }

    private void BtnMoveDown_Click(object sender, RoutedEventArgs e)
    {
        int idx = ColumnsList.SelectedIndex;
        if (idx < 0 || idx >= Entries.Count - 1) return;
        Entries.Move(idx, idx + 1);
        ColumnsList.SelectedIndex = idx + 1;
    }

    private void BtnSelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in Entries) item.Visible = true;
        ColumnsList.Items.Refresh();
    }

    private void BtnReset_Click(object sender, RoutedEventArgs e)
    {
        var sorted = Entries.OrderBy(c => c.DefaultOrder).ToList();
        Entries.Clear();
        foreach (var item in sorted)
        {
            item.Visible = item.DefaultVisible;
            Entries.Add(item);
        }
        ColumnsList.Items.Refresh();
    }

    private void BtnOk_Click(object sender, RoutedEventArgs e)
    {
        if (!Entries.Any(c => c.Visible))
        {
            var first = Entries.FirstOrDefault(c => c.Key == "FileName") ?? Entries.FirstOrDefault();
            if (first is not null) first.Visible = true;
        }
        DialogResult = true;
    }
}
