using Microsoft.Win32.SafeHandles;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace DocSentinel.UI.Integration;

public sealed class UiLaunchCommand
{
    public string Action { get; init; } = "";
    public List<string> Paths { get; init; } = new();
}

public sealed class UiLaunchOptions
{
    public UiLaunchCommand? Command { get; init; }
    public string? OverridePipeName { get; init; }
    public string? OverrideDataDir { get; init; }
}

public static class UiCommandChannel
{
    public static string MutexName =>
        $@"Local\DeepDocEngine.UI.SingleInstance.{Environment.UserName}";

    public static string PipeName =>
        $"DeepDocEngine.UI.Cmd.v1.{SanitizeUser(Environment.UserName)}";

    private static string SanitizeUser(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
            sb.Append(char.IsLetterOrDigit(c) ? c : '_');
        return sb.ToString();
    }

    public static UiLaunchOptions ParseLaunchOptions(string[] args)
    {
        string? action = null;
        string? overridePipe = null;
        string? overrideDataDir = null;
        var paths = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].Trim();
            if (string.IsNullOrWhiteSpace(a)) continue;

            if (string.Equals(a, "--pipe", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                overridePipe = args[++i].Trim().Trim('"');
                if (overridePipe.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase))
                    overridePipe = overridePipe[@"\\.\pipe\".Length..];
                continue;
            }
            if (string.Equals(a, "--data-dir", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                overrideDataDir = args[++i].Trim().Trim('"');
                continue;
            }
            if (string.Equals(a, "--deep-check", StringComparison.OrdinalIgnoreCase))
            {
                action = "deep-check";
                continue;
            }
            if (string.Equals(a, "--deep-erase", StringComparison.OrdinalIgnoreCase))
            {
                action = "deep-erase";
                continue;
            }

            // Windows Explorer `%1` / `%V` on drive roots (`D:\`) with trailing `\"` quoting can pass `D:\"`
            string cleaned = a.Trim().Trim('"');
            if (cleaned.Length == 2 && char.IsLetter(cleaned[0]) && cleaned[1] == ':')
                cleaned += Path.DirectorySeparatorChar;
            if (!string.IsNullOrWhiteSpace(cleaned))
                paths.Add(cleaned);
        }

        return new UiLaunchOptions
        {
            Command = action is not null ? new UiLaunchCommand { Action = action, Paths = paths } : null,
            OverridePipeName = overridePipe,
            OverrideDataDir = overrideDataDir,
        };
    }

    public static UiLaunchCommand? ParseLaunchArgs(string[] args) => ParseLaunchOptions(args).Command;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        out UIntPtr SecurityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorSacl(
        IntPtr pSecurityDescriptor,
        out bool lpbSaclPresent,
        out IntPtr pSacl,
        out bool lpbSaclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        SafePipeHandle handle,
        uint ObjectType,
        uint SecurityInfo,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static bool TryForwardToExistingInstance(UiLaunchCommand command, out bool accessDenied)
    {
        accessDenied = false;
        foreach (int delayMs in new[] { 0, 120, 250 })
        {
            if (delayMs > 0) Thread.Sleep(delayMs);
            try
            {
                using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.Asynchronous);
                client.Connect(1200);
                string json = JsonSerializer.Serialize(command) + "\n";
                byte[] buf = Encoding.UTF8.GetBytes(json);
                client.Write(buf, 0, buf.Length);
                client.Flush();
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                accessDenied = true;
                return false;
            }
            catch
            {
            }
        }
        return false;
    }

    private static NamedPipeServerStream CreateCrossUacPipeServer()
    {
        try
        {
            var ps = new PipeSecurity();
            ps.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
            var curUser = WindowsIdentity.GetCurrent().User;
            if (curUser is not null)
            {
                ps.AddAccessRule(new PipeAccessRule(
                    curUser,
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
            }

            var server = NamedPipeServerStreamAcl.Create(
                PipeName,
                PipeDirection.In,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                0,
                0,
                ps);
            ApplyMediumMandatoryLabel(server.SafePipeHandle);
            return server;
        }
        catch
        {
            return new NamedPipeServerStream(
                PipeName,
                PipeDirection.In,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }
    }

    private static void ApplyMediumMandatoryLabel(SafePipeHandle handle)
    {
        const uint SDDL_REVISION_1 = 1;
        const uint SE_KERNEL_OBJECT = 6;
        const uint LABEL_SECURITY_INFORMATION = 0x00000010;
        IntPtr sd = IntPtr.Zero;
        try
        {
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(ML;;NW;;;ME)", SDDL_REVISION_1, out sd, out _)
                && sd != IntPtr.Zero
                && GetSecurityDescriptorSacl(sd, out bool present, out IntPtr sacl, out _)
                && present)
            {
                _ = SetSecurityInfo(handle, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            }
        }
        catch
        {
        }
        finally
        {
            if (sd != IntPtr.Zero) LocalFree(sd);
        }
    }

    public static async Task RunServerLoopAsync(Func<UiLaunchCommand, Task> onCommand, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = CreateCrossUacPipeServer();
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                using var reader = new StreamReader(server, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
                string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(line))
                {
                    var cmd = JsonSerializer.Deserialize<UiLaunchCommand>(line);
                    if (cmd is not null && !string.IsNullOrWhiteSpace(cmd.Action))
                    {
                        await onCommand(cmd).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(120, ct).ConfigureAwait(false);
            }
        }
    }
}
