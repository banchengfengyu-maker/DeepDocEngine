using DocSentinel.UI.Ipc;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;

namespace DocSentinel.UI.Dialogs;

public partial class SavedQueriesWindow : Window
{
    private readonly ObservableCollection<RuleDefinitionDto> _rules;
    private readonly string _initialExpression;

    public RuleDefinitionDto? SelectedRuleToRun { get; private set; }
    public bool BatchRunAllRequested { get; private set; }

    public SavedQueriesWindow(ObservableCollection<RuleDefinitionDto> rules, string initialExpression)
    {
        InitializeComponent();
        _rules = rules;
        _initialExpression = initialExpression;
        RulesGrid.ItemsSource = _rules;
    }

    private void BtnAddRule_Click(object sender, RoutedEventArgs e)
    {
        string expr = string.IsNullOrWhiteSpace(_initialExpression)
            ? "\"关键词A\" & !\"排除词\""
            : _initialExpression.Trim();
        var item = new RuleDefinitionDto
        {
            Id = $"q-{Guid.NewGuid():N}"[..10],
            Name = expr.Length > 14 ? expr[..14] : expr,
            Category = "收藏",
            Severity = "表达式",
            Expression = expr,
            Mode = RuleMatchMode.FullHits
        };
        _rules.Add(item);
        RulesGrid.SelectedItem = item;
    }

    private void BtnDeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleDefinitionDto r)
            _rules.Remove(r);
    }

    private void RulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => BtnRunSingle_Click(sender, e);

    private void BtnRunSingle_Click(object sender, RoutedEventArgs e)
    {
        if (RulesGrid.SelectedItem is RuleDefinitionDto r && !string.IsNullOrWhiteSpace(r.Expression))
        {
            SelectedRuleToRun = r;
            DialogResult = true;
        }
    }

    private void BtnRunAll_Click(object sender, RoutedEventArgs e)
    {
        if (_rules.All(r => string.IsNullOrWhiteSpace(r.Expression)))
        {
            MessageBox.Show("当前没有可运行的表达式。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        BatchRunAllRequested = true;
        DialogResult = true;
    }
}
