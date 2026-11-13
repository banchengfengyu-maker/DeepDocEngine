using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace DocSentinel.UI.Dialogs;

public static class SimpleInputDialog
{
    public static string? Prompt(Window owner, string title, string message, string initialValue = "")
    {
        string? result = null;
        var win = new Window
        {
            Owner = owner,
            Title = title,
            Width = 460,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = System.Windows.Media.Brushes.White
        };

        var stack = new StackPanel { Margin = new Thickness(16) };
        stack.Children.Add(new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8),
            FontSize = 12.5
        });

        var txt = new TextBox
        {
            Text = initialValue,
            Padding = new Thickness(6, 5, 6, 5),
            FontSize = 12.5,
            Margin = new Thickness(0, 0, 0, 12)
        };
        txt.SelectAll();
        stack.Children.Add(txt);

        var btnBar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var okBtn = new Button
        {
            Content = "确定",
            Width = 76,
            IsDefault = true,
            Margin = new Thickness(0, 0, 8, 0)
        };
        okBtn.Click += (_, _) =>
        {
            result = txt.Text;
            win.DialogResult = true;
        };
        var cancelBtn = new Button
        {
            Content = "取消",
            Width = 76,
            IsCancel = true
        };
        btnBar.Children.Add(okBtn);
        btnBar.Children.Add(cancelBtn);
        stack.Children.Add(btnBar);

        win.Content = stack;
        win.Loaded += (_, _) =>
        {
            txt.Focus();
            Keyboard.Focus(txt);
        };

        return win.ShowDialog() == true ? result : null;
    }
}
