using Microsoft.Win32;
using System.IO;

namespace DocSentinel.UI.Integration;

public static class ShellContextMenuRegistrar
{
    private const string VerbCheck = "DeepDocEngine.DeepCheck";
    private const string VerbErase = "DeepDocEngine.DeepErase";

    private static readonly (string BasePath, string Verb, string Label, string ArgFlag, string PathToken)[] Entries =
    {
        (@"Software\Classes\*\shell", VerbCheck, "深度查密 (DeepDocEngine)", "--deep-check", "%1"),
        (@"Software\Classes\*\shell", VerbErase, "深度擦除 (DeepDocEngine)", "--deep-erase", "%1"),
        (@"Software\Classes\Directory\shell", VerbCheck, "深度查密 (DeepDocEngine)", "--deep-check", "%1"),
        (@"Software\Classes\Directory\shell", VerbErase, "深度擦除 (DeepDocEngine)", "--deep-erase", "%1"),
        (@"Software\Classes\Directory\Background\shell", VerbCheck, "深度查密 (DeepDocEngine)", "--deep-check", "%V"),
        (@"Software\Classes\Directory\Background\shell", VerbErase, "深度擦除 (DeepDocEngine)", "--deep-erase", "%V"),
    };

    public static bool IsRegistered()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey($@"Software\Classes\*\shell\{VerbCheck}\command", writable: false);
            return k?.GetValue(null) is string s && !string.IsNullOrWhiteSpace(s);
        }
        catch
        {
            return false;
        }
    }

    public static void EnsureRegistered(string? exePath = null)
    {
        string targetExe = exePath ?? Environment.ProcessPath ?? string.Empty;
        if (string.IsNullOrWhiteSpace(targetExe) ||
            !File.Exists(targetExe) ||
            targetExe.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        foreach (var (basePath, verb, label, flag, token) in Entries)
        {
            string keyPath = $@"{basePath}\{verb}";
            using var verbKey = Registry.CurrentUser.CreateSubKey(keyPath, writable: true);
            verbKey.SetValue(null, label, RegistryValueKind.String);
            verbKey.SetValue("Icon", $"\"{targetExe}\",0", RegistryValueKind.String);

            using var cmdKey = verbKey.CreateSubKey("command", writable: true);
            cmdKey.SetValue(null, $"\"{targetExe}\" {flag} \"{token}\"", RegistryValueKind.String);
        }
    }

    public static void Unregister()
    {
        foreach (var (basePath, verb, _, _, _) in Entries)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree($@"{basePath}\{verb}", throwOnMissingSubKey: false);
            }
            catch
            {
            }
        }
    }
}
