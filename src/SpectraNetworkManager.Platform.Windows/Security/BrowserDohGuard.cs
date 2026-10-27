using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

public sealed record BrowserDohStatus(
    bool IsEnforced,
    bool ChromeBlocked,
    bool EdgeBlocked,
    bool BraveBlocked,
    bool FirefoxBlocked,
    string Details);

[SupportedOSPlatform("windows")]
public static class BrowserDohGuard
{
    private static readonly string BackupPath = EngineStoragePaths.BrowserDohBackupPath;
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private sealed class PolicyBackupRecord
    {
        public string Hive { get; set; } = "HKLM";
        public string SubKey { get; set; } = "";
        public string ValueName { get; set; } = "";
        public bool Existed { get; set; }
        public string? ValueKind { get; set; }
        public string? StringValue { get; set; }
        public int? IntValue { get; set; }
    }

    public static BrowserDohStatus GetStatus()
    {
        bool chrome = IsChromeDohBlocked();
        bool edge = IsEdgeDohBlocked();
        bool brave = IsBraveDohBlocked();
        bool firefox = IsFirefoxDohBlocked();

        bool isEnforced = chrome && edge && firefox;
        var parts = new List<string>();
        if (chrome) parts.Add("Chrome");
        if (edge) parts.Add("Edge");
        if (brave) parts.Add("Brave");
        if (firefox) parts.Add("Firefox");

        string desc = parts.Count > 0
            ? $"DoH bypass disabled for {string.Join(", ", parts)} (Forced to system DNS)"
            : "Browser DoH policies not enforced (Browsers may bypass system DNS)";

        return new BrowserDohStatus(isEnforced, chrome, edge, brave, firefox, desc);
    }

    public static async Task<(bool Success, string Message)> EnableGuardAsync()
    {
        return await Task.Run(async () =>
        {
            var backups = new List<PolicyBackupRecord>();

            // 1. Chrome
            BackupAndSet(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off", backups);
            BackupAndSet(Registry.CurrentUser, @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off", backups);

            // 2. Edge
            BackupAndSet(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off", backups);
            BackupAndSet(Registry.CurrentUser, @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off", backups);

            // 3. Brave
            BackupAndSet(Registry.LocalMachine, @"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off", backups);
            BackupAndSet(Registry.CurrentUser, @"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off", backups);

            // 4. Firefox
            BackupAndSetDword(Registry.LocalMachine, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDoH", 1, backups);
            BackupAndSetDword(Registry.CurrentUser, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDoH", 1, backups);

            SaveBackups(backups);

            // Fallback for non-admin: attempt elevated reg add if HKLM wasn't accessible
            if (!ElevationHelper.IsAdministrator())
            {
                await RunElevatedRegCommandAsync("add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v DnsOverHttpsMode /t REG_SZ /d off /f");
                await RunElevatedRegCommandAsync("add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\" /v DnsOverHttpsMode /t REG_SZ /d off /f");
                await RunElevatedRegCommandAsync("add \"HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox\" /v DisableDoH /t REG_DWORD /d 1 /f");
            }

            return (true, "Browser DoH Bypass Guard enabled. Chrome, Edge, Brave, and Firefox are now forced to use Spectra DNS Sinkhole.");
        });
    }

    public static async Task<(bool Success, string Message)> DisableGuardAsync()
    {
        return await Task.Run(async () =>
        {
            var backups = LoadBackups();
            if (backups.Count > 0)
            {
                foreach (var b in backups)
                {
                    try
                    {
                        var hive = b.Hive == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
                        using var key = hive.OpenSubKey(b.SubKey, writable: true);
                        if (key != null)
                        {
                            if (b.Existed)
                            {
                                if (b.IntValue.HasValue) key.SetValue(b.ValueName, b.IntValue.Value, RegistryValueKind.DWord);
                                else if (b.StringValue != null) key.SetValue(b.ValueName, b.StringValue, RegistryValueKind.String);
                            }
                            else
                            {
                                key.DeleteValue(b.ValueName, throwOnMissingValue: false);
                            }
                        }
                    }
                    catch { }
                }

                try { File.Delete(BackupPath); } catch { }
            }
            else
            {
                // Clean delete policies created by Spectra
                DeletePolicyValue(Registry.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode");
                DeletePolicyValue(Registry.CurrentUser, @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode");

                DeletePolicyValue(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode");
                DeletePolicyValue(Registry.CurrentUser, @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode");

                DeletePolicyValue(Registry.LocalMachine, @"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode");
                DeletePolicyValue(Registry.CurrentUser, @"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode");

                DeletePolicyValue(Registry.LocalMachine, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDoH");
                DeletePolicyValue(Registry.CurrentUser, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDoH");
            }

            if (!ElevationHelper.IsAdministrator())
            {
                await RunElevatedRegCommandAsync("delete \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v DnsOverHttpsMode /f");
                await RunElevatedRegCommandAsync("delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\" /v DnsOverHttpsMode /f");
                await RunElevatedRegCommandAsync("delete \"HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox\" /v DisableDoH /f");
            }

            return (true, "Browser DoH Bypass Guard disabled. Browsers can manage their own internal DoH settings.");
        });
    }

    private static bool IsChromeDohBlocked() =>
        CheckPolicyValue(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off");

    private static bool IsEdgeDohBlocked() =>
        CheckPolicyValue(@"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off");

    private static bool IsBraveDohBlocked() =>
        CheckPolicyValue(@"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off");

    private static bool IsFirefoxDohBlocked()
    {
        return CheckPolicyDword(@"SOFTWARE\Policies\Mozilla\Firefox", "DisableDoH", 1);
    }

    private static bool CheckPolicyValue(string subKey, string valueName, string expected)
    {
        try
        {
            using var k1 = Registry.LocalMachine.OpenSubKey(subKey);
            if (k1?.GetValue(valueName)?.ToString()?.Equals(expected, StringComparison.OrdinalIgnoreCase) == true)
                return true;

            using var k2 = Registry.CurrentUser.OpenSubKey(subKey);
            if (k2?.GetValue(valueName)?.ToString()?.Equals(expected, StringComparison.OrdinalIgnoreCase) == true)
                return true;
        }
        catch { }
        return false;
    }

    private static bool CheckPolicyDword(string subKey, string valueName, int expected)
    {
        try
        {
            using var k1 = Registry.LocalMachine.OpenSubKey(subKey);
            if (k1?.GetValue(valueName) is int val1 && val1 == expected) return true;

            using var k2 = Registry.CurrentUser.OpenSubKey(subKey);
            if (k2?.GetValue(valueName) is int val2 && val2 == expected) return true;
        }
        catch { }
        return false;
    }

    private static void BackupAndSet(RegistryKey hive, string subKey, string valueName, string newValue, List<PolicyBackupRecord> backups)
    {
        try
        {
            using var key = hive.CreateSubKey(subKey);
            if (key != null)
            {
                object? existing = key.GetValue(valueName);
                backups.Add(new PolicyBackupRecord
                {
                    Hive = hive == Registry.CurrentUser ? "HKCU" : "HKLM",
                    SubKey = subKey,
                    ValueName = valueName,
                    Existed = existing != null,
                    StringValue = existing?.ToString()
                });
                key.SetValue(valueName, newValue, RegistryValueKind.String);
            }
        }
        catch { }
    }

    private static void BackupAndSetDword(RegistryKey hive, string subKey, string valueName, int newValue, List<PolicyBackupRecord> backups)
    {
        try
        {
            using var key = hive.CreateSubKey(subKey);
            if (key != null)
            {
                object? existing = key.GetValue(valueName);
                backups.Add(new PolicyBackupRecord
                {
                    Hive = hive == Registry.CurrentUser ? "HKCU" : "HKLM",
                    SubKey = subKey,
                    ValueName = valueName,
                    Existed = existing != null,
                    IntValue = existing is int i ? i : null
                });
                key.SetValue(valueName, newValue, RegistryValueKind.DWord);
            }
        }
        catch { }
    }

    private static void DeletePolicyValue(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: true);
            key?.DeleteValue(valueName, throwOnMissingValue: false);
        }
        catch { }
    }

    private static void SaveBackups(List<PolicyBackupRecord> backups)
    {
        try
        {
            string? dir = Path.GetDirectoryName(BackupPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(BackupPath, JsonSerializer.Serialize(backups, JsonOpts));
        }
        catch { }
    }

    private static List<PolicyBackupRecord> LoadBackups()
    {
        try
        {
            if (File.Exists(BackupPath))
            {
                string json = File.ReadAllText(BackupPath);
                return JsonSerializer.Deserialize<List<PolicyBackupRecord>>(json, JsonOpts) ?? new List<PolicyBackupRecord>();
            }
        }
        catch { }
        return new List<PolicyBackupRecord>();
    }

    private static async Task RunElevatedRegCommandAsync(string regArguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = regArguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            var proc = Process.Start(psi);
            if (proc != null) await proc.WaitForExitAsync();
        }
        catch { }
    }
}
