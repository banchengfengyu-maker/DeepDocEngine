using System.Runtime.InteropServices;

namespace DocSentinel.UI.Integration;

/// <summary>
/// Windows Power Management integration: Prevents system sleep and enables Away Mode
/// while background indexing / scanning tasks are in progress.
/// Allows display to turn off / low power operation without freezing the indexing engine.
/// </summary>
internal static class PowerManager
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint SetThreadExecutionState(uint esFlags);

    private const uint ES_CONTINUOUS = 0x80000000;
    private const uint ES_SYSTEM_REQUIRED = 0x00000001;
    private const uint ES_AWAYMODE_REQUIRED = 0x00000040;

    private static int _activeCount;

    public static void PreventSleepAndEnableAwayMode()
    {
        if (Interlocked.Increment(ref _activeCount) == 1)
        {
            try
            {
                SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
            }
            catch { }
        }
    }

    public static void RestoreNormalSleep()
    {
        if (Interlocked.Decrement(ref _activeCount) <= 0)
        {
            Interlocked.Exchange(ref _activeCount, 0);
            try
            {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
            catch { }
        }
    }
}
