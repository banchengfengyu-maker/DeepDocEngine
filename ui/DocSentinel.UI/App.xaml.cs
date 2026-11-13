using DocSentinel.UI.Integration;
using System.Windows;

namespace DocSentinel.UI;

public partial class App : Application
{
    private Mutex? _singleInstanceMutex;
    public static UiLaunchCommand? InitialCommand { get; private set; }
    public static string? OverridePipeName { get; private set; }
    public static string? OverrideDataDir { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        var opts = UiCommandChannel.ParseLaunchOptions(e.Args);
        InitialCommand = opts.Command;
        OverridePipeName = opts.OverridePipeName;
        OverrideDataDir = opts.OverrideDataDir;

        if (!string.IsNullOrWhiteSpace(OverridePipeName))
        {
            base.OnStartup(e);
            return;
        }

        bool createdNew;
        try
        {
            _singleInstanceMutex = new Mutex(true, UiCommandChannel.MutexName, out createdNew);
        }
        catch
        {
            createdNew = true;
        }

        if (!createdNew)
        {
            var forward = InitialCommand ?? new UiLaunchCommand { Action = "activate" };
            if (UiCommandChannel.TryForwardToExistingInstance(forward, out bool accessDenied))
            {
                Shutdown(0);
                return;
            }
            if (accessDenied)
            {
                MessageBox.Show(
                    "检测到已有以管理员权限运行的 DeepDocEngine 窗口正在执行，当前普通权限右键启动被系统 UAC 跨权限策略拦截。\n\n" +
                    "• 如需立即执行，请直接在已打开窗口顶部菜单【查密与擦除】中选择目标；\n" +
                    "• 如为升级前的旧版本进程，请先退出已有软件并升级至最新版后再使用右键联动。",
                    "DeepDocEngine 跨权限联动提示",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                Shutdown(0);
                return;
            }
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _singleInstanceMutex?.ReleaseMutex();
            _singleInstanceMutex?.Dispose();
        }
        catch
        {
        }
        base.OnExit(e);
    }
}
