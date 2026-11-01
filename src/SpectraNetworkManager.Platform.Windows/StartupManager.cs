using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

public enum StartupSourceKind
{
    HkcuRun,
    HkcuRunOnce,
    HklmRun,
    HklmRunOnce,
    HklmWow64Run,
    HklmWow64RunOnce,
    HkcuPoliciesRun,
    HklmPoliciesRun,
    UserStartupFolder,
    CommonStartupFolder,
    ScheduledTask,
    AppxStartupTask,
    WindowsService
}

public sealed record StartupEntry(
    string Id,
    string Name,
    string RawCommand,
    string ExecutablePath,
    string LocationDisplay,
    StartupSourceKind SourceKind,
    bool IsEnabled,
    bool RequiresAdmin,
    string? PublisherHint = null);

/// <summary>
/// Discovers and manages Windows auto-start programs across Registry Run/RunOnce/Policies keys
/// (HKCU, HKLM 64-bit, HKLM WOW6432Node 32-bit), Windows Startup folders, and Windows Task Scheduler.
/// </summary>
[SupportedOSPlatform("windows")]
public static class StartupManager
{
    private const string RunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceSubKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string Wow64RunSubKey = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string Wow64RunOnceSubKey = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string PoliciesRunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";

    private const string ApprovedRunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedRun32SubKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    private const string ApprovedFolderSubKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    private static string DisabledVaultPath => Path.Combine(EngineStoragePaths.BaseDirectory, "disabled-startup.json");

    private sealed class DisabledVaultItem
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string RawCommand { get; set; } = "";
        public StartupSourceKind SourceKind { get; set; }
        public string DisabledFilePath { get; set; } = "";
    }

    public static List<StartupEntry> GetAllEntries()
    {
        var entries = new Dictionary<string, StartupEntry>(StringComparer.OrdinalIgnoreCase);
        var vault = LoadVault();

        // 1. Registry sources
        ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, RunSubKey, ApprovedRunSubKey,
            StartupSourceKind.HkcuRun, @"Registry: HKCU\...\Run", requiresAdmin: false, entries);

        ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, RunOnceSubKey, null,
            StartupSourceKind.HkcuRunOnce, @"Registry: HKCU\...\RunOnce", requiresAdmin: false, entries);

        ScanRegistryKey(RegistryHive.CurrentUser, RegistryView.Default, PoliciesRunSubKey, null,
            StartupSourceKind.HkcuPoliciesRun, @"Registry: HKCU\...\Policies\Run", requiresAdmin: false, entries);

        ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, RunSubKey, ApprovedRunSubKey,
            StartupSourceKind.HklmRun, @"Registry: HKLM\...\Run", requiresAdmin: true, entries);

        ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, RunOnceSubKey, null,
            StartupSourceKind.HklmRunOnce, @"Registry: HKLM\...\RunOnce", requiresAdmin: true, entries);

        ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, PoliciesRunSubKey, null,
            StartupSourceKind.HklmPoliciesRun, @"Registry: HKLM\...\Policies\Run", requiresAdmin: true, entries);

        ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, Wow64RunSubKey, ApprovedRun32SubKey,
            StartupSourceKind.HklmWow64Run, @"Registry: HKLM (32-bit)\...\Run", requiresAdmin: true, entries);

        ScanRegistryKey(RegistryHive.LocalMachine, RegistryView.Registry64, Wow64RunOnceSubKey, null,
            StartupSourceKind.HklmWow64RunOnce, @"Registry: HKLM (32-bit)\...\RunOnce", requiresAdmin: true, entries);

        // 2. Startup Folders
        string userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        ScanStartupFolder(userStartup, RegistryHive.CurrentUser, ApprovedFolderSubKey,
            StartupSourceKind.UserStartupFolder, "Startup Folder (Current User)", requiresAdmin: false, entries);

        string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        ScanStartupFolder(commonStartup, RegistryHive.LocalMachine, ApprovedFolderSubKey,
            StartupSourceKind.CommonStartupFolder, "Startup Folder (All Users)", requiresAdmin: true, entries);

        // 3. Packaged MSIX / Store App StartupTasks (windows.startupTask, e.g. OpenAI Codex / ChatGPT, Claude, Windows Terminal, Spotify)
        ScanAppxStartupTasks(entries, vault);

        // 4. Scheduled Tasks (Logon / Boot / Third-party background tasks)
        ScanScheduledTasks(entries);

        // 5. Third-Party Auto-Start Windows Services (e.g. CodexSandboxService.OpenAI.Codex, VPNs, Updaters)
        ScanAutoStartServices(entries, vault);

        // 6. Merge items disabled in Spectra Vault
        foreach (var v in vault)
        {
            if (entries.TryGetValue(v.Id, out var existingEntry))
            {
                if (existingEntry.SourceKind is StartupSourceKind.AppxStartupTask or StartupSourceKind.WindowsService)
                {
                    entries[v.Id] = existingEntry with { IsEnabled = false };
                }
                continue;
            }

            string exe = ExtractExecutablePath(v.RawCommand);
            string loc = GetLocationDisplay(v.SourceKind);
            bool reqAdmin = IsAdminSource(v.SourceKind);
            entries[v.Id] = new StartupEntry(
                Id: v.Id,
                Name: v.Name,
                RawCommand: v.RawCommand,
                ExecutablePath: exe,
                LocationDisplay: loc,
                SourceKind: v.SourceKind,
                IsEnabled: false,
                RequiresAdmin: reqAdmin,
                PublisherHint: ResolvePublisherHint(exe, null));
        }

        return entries.Values
            .OrderByDescending(e => e.IsEnabled)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static async Task<(bool Success, string Message)> SetEnabledAsync(StartupEntry entry, bool enable)
    {
        return await Task.Run(async () =>
        {
            try
            {
                if (enable)
                {
                    return await EnableEntryCoreAsync(entry);
                }
                else
                {
                    return await DisableEntryCoreAsync(entry);
                }
            }
            catch (Exception ex)
            {
                return (false, $"Could not change startup state for '{entry.Name}': {ex.Message}");
            }
        });
    }

    public static async Task<(bool Success, string Message)> DeleteEntryAsync(StartupEntry entry)
    {
        return await Task.Run(async () =>
        {
            try
            {
                var vault = LoadVault();
                var vaultMatch = vault.FirstOrDefault(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
                if (vaultMatch != null)
                {
                    if (!string.IsNullOrWhiteSpace(vaultMatch.DisabledFilePath) && File.Exists(vaultMatch.DisabledFilePath))
                    {
                        try { File.Delete(vaultMatch.DisabledFilePath); } catch { }
                    }
                    vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
                    SaveVault(vault);
                }

                if (entry.SourceKind == StartupSourceKind.AppxStartupTask)
                {
                    var disabledRes = await DisableEntryCoreAsync(entry);
                    return (disabledRes.Success,
                        disabledRes.Success
                            ? $"Disabled Store / MSIX startup task '{entry.Name}'. (To uninstall the MSIX package completely, use Windows Installed Apps)."
                            : disabledRes.Message);
                }
                else if (entry.SourceKind == StartupSourceKind.WindowsService)
                {
                    var disabledRes = await DisableEntryCoreAsync(entry);
                    return (disabledRes.Success,
                        disabledRes.Success
                            ? $"Set Windows Service '{entry.Name}' to Manual start so it no longer starts at boot."
                            : disabledRes.Message);
                }
                else if (entry.SourceKind == StartupSourceKind.ScheduledTask)
                {
                    string taskPath = GetScheduledTaskPath(entry);
                    bool ok = await RunSchtasksAsync($"/Delete /TN \"{taskPath}\" /F");
                    if (!ok) return (false, "Administrator privileges were required or declined to delete the Scheduled Task.");
                    return (true, $"Permanently deleted Scheduled Task '{entry.Name}'.");
                }
                else if (entry.SourceKind is StartupSourceKind.UserStartupFolder or StartupSourceKind.CommonStartupFolder)
                {
                    if (File.Exists(entry.RawCommand))
                    {
                        try
                        {
                            File.Delete(entry.RawCommand);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            bool ok = await RunElevatedCmdAsync($"del /f /q \"{entry.RawCommand}\"");
                            if (!ok) return (false, "Administrator privileges were declined or failed to delete the startup file.");
                        }
                    }
                    var hive = entry.SourceKind == StartupSourceKind.CommonStartupFolder ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
                    TryDeleteRegistryValue(hive, ApprovedFolderSubKey, Path.GetFileName(entry.RawCommand));
                    return (true, $"Permanently removed startup item '{entry.Name}'.");
                }
                else
                {
                    var (hive, subKey, approvedSubKey) = GetRegistryMetadata(entry.SourceKind);
                    bool deleted = TryDeleteRegistryValue(hive, subKey, entry.Name);
                    if (!deleted && entry.RequiresAdmin)
                    {
                        string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                        bool ok = await RunElevatedCmdAsync($"reg delete \"{rootName}\\{subKey}\" /v \"{entry.Name}\" /f");
                        if (!ok) return (false, "Administrator privileges were required and declined.");
                    }
                    if (approvedSubKey != null)
                    {
                        TryDeleteRegistryValue(hive, approvedSubKey, entry.Name);
                    }
                    return (true, $"Permanently deleted startup registry entry '{entry.Name}'.");
                }
            }
            catch (Exception ex)
            {
                return (false, $"Failed to delete '{entry.Name}': {ex.Message}");
            }
        });
    }

    private static async Task<(bool Success, string Message)> DisableEntryCoreAsync(StartupEntry entry)
    {
        if (entry.SourceKind == StartupSourceKind.AppxStartupTask)
        {
            var (pfn, taskId) = GetAppxTaskIds(entry);
            bool regOk = TrySetAppxStartupTaskState(pfn, taskId, enabled: false);
            var appxVault = LoadVault();
            appxVault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            if (!regOk)
            {
                appxVault.Add(new DisabledVaultItem
                {
                    Id = entry.Id,
                    Name = entry.Name,
                    RawCommand = entry.RawCommand,
                    SourceKind = entry.SourceKind
                });
            }
            SaveVault(appxVault);
            return (true, $"Turned off Store / MSIX startup task '{entry.Name}'.");
        }

        if (entry.SourceKind == StartupSourceKind.WindowsService)
        {
            string svcName = GetServiceName(entry);
            bool ok = await RunScConfigAsync(svcName, "demand");
            if (!ok) return (false, $"Administrator permission is required to change service '{entry.Name}' startup mode.");
            var svcVault = LoadVault();
            svcVault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            svcVault.Add(new DisabledVaultItem
            {
                Id = entry.Id,
                Name = entry.Name,
                RawCommand = entry.RawCommand,
                SourceKind = entry.SourceKind
            });
            SaveVault(svcVault);
            return (true, $"Turned off auto-start for Windows Service '{entry.Name}' (set to Manual).");
        }

        if (entry.SourceKind == StartupSourceKind.ScheduledTask)
        {
            string taskPath = GetScheduledTaskPath(entry);
            bool ok = await RunSchtasksAsync($"/Change /TN \"{taskPath}\" /Disable");
            if (!ok) return (false, "Administrator permission is required to turn off this Scheduled Task.");
            return (true, $"Turned off Scheduled Task '{entry.Name}'.");
        }

        var vault = LoadVault();
        vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));

        if (entry.SourceKind is StartupSourceKind.UserStartupFolder or StartupSourceKind.CommonStartupFolder)
        {
            string fileName = Path.GetFileName(entry.RawCommand);
            var hive = entry.SourceKind == StartupSourceKind.CommonStartupFolder ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;

            // Use Windows' native StartupApproved\StartupFolder flag first so Task Manager and Spectra stay 100% synced
            if (TrySetStartupApprovedState(hive, ApprovedFolderSubKey, fileName, enabled: false))
            {
                SaveVault(vault);
                return (true, $"Turned off auto-start for '{entry.Name}'.");
            }

            if (entry.RequiresAdmin)
            {
                string hexDisabled = BuildStartupApprovedDisabledHex();
                bool ok = await RunElevatedCmdAsync($"reg add \"HKLM\\{ApprovedFolderSubKey}\" /v \"{fileName}\" /t REG_BINARY /d {hexDisabled} /f");
                if (ok)
                {
                    SaveVault(vault);
                    return (true, $"Turned off auto-start for '{entry.Name}'.");
                }
                return (false, "Administrator permission required to disable All-Users Startup folder item.");
            }

            return (false, $"Could not update startup state for '{entry.Name}'.");
        }
        else
        {
            var (hive, subKey, approvedSubKey) = GetRegistryMetadata(entry.SourceKind);

            // For standard Run keys with StartupApproved support, toggle Windows' native StartupApproved flag in-place
            if (approvedSubKey != null)
            {
                if (TrySetStartupApprovedState(hive, approvedSubKey, entry.Name, enabled: false))
                {
                    SaveVault(vault);
                    return (true, $"Turned off auto-start for '{entry.Name}'.");
                }

                if (entry.RequiresAdmin)
                {
                    string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                    string hexDisabled = BuildStartupApprovedDisabledHex();
                    bool ok = await RunElevatedCmdAsync($"reg add \"{rootName}\\{approvedSubKey}\" /v \"{entry.Name}\" /t REG_BINARY /d {hexDisabled} /f");
                    if (ok)
                    {
                        SaveVault(vault);
                        return (true, $"Turned off auto-start for '{entry.Name}'.");
                    }
                    return (false, "Administrator permission is required to turn off system-wide HKLM startup items.");
                }
            }

            // Fallback for RunOnce / Policies keys that do not have a Windows StartupApproved key: vault & remove
            vault.Add(new DisabledVaultItem
            {
                Id = entry.Id,
                Name = entry.Name,
                RawCommand = entry.RawCommand,
                SourceKind = entry.SourceKind
            });
            SaveVault(vault);

            bool deleted = TryDeleteRegistryValue(hive, subKey, entry.Name);
            if (!deleted && entry.RequiresAdmin)
            {
                string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                bool ok = await RunElevatedCmdAsync($"reg delete \"{rootName}\\{subKey}\" /v \"{entry.Name}\" /f");
                if (!ok)
                {
                    vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
                    SaveVault(vault);
                    return (false, "Administrator permission is required to turn off system-wide HKLM startup items.");
                }
            }

            return (true, $"Turned off auto-start for '{entry.Name}'.");
        }
    }

    private static async Task<(bool Success, string Message)> EnableEntryCoreAsync(StartupEntry entry)
    {
        if (entry.SourceKind == StartupSourceKind.AppxStartupTask)
        {
            var (pfn, taskId) = GetAppxTaskIds(entry);
            TrySetAppxStartupTaskState(pfn, taskId, enabled: true);
            var appxVault = LoadVault();
            appxVault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            SaveVault(appxVault);
            return (true, $"Turned on Store / MSIX startup task '{entry.Name}'.");
        }

        if (entry.SourceKind == StartupSourceKind.WindowsService)
        {
            string svcName = GetServiceName(entry);
            bool ok = await RunScConfigAsync(svcName, "auto");
            if (!ok) return (false, $"Administrator permission is required to enable auto-start for service '{entry.Name}'.");
            var svcVault = LoadVault();
            svcVault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            SaveVault(svcVault);
            return (true, $"Turned on Automatic startup for Windows Service '{entry.Name}'.");
        }

        if (entry.SourceKind == StartupSourceKind.ScheduledTask)
        {
            string taskPath = GetScheduledTaskPath(entry);
            bool ok = await RunSchtasksAsync($"/Change /TN \"{taskPath}\" /Enable");
            if (!ok) return (false, "Administrator permission is required to turn on this Scheduled Task.");
            return (true, $"Turned on Scheduled Task '{entry.Name}'.");
        }

        var vault = LoadVault();
        var vaultMatch = vault.FirstOrDefault(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));

        if (entry.SourceKind is StartupSourceKind.UserStartupFolder or StartupSourceKind.CommonStartupFolder)
        {
            if (vaultMatch != null && !string.IsNullOrWhiteSpace(vaultMatch.DisabledFilePath) && File.Exists(vaultMatch.DisabledFilePath))
            {
                try
                {
                    File.Copy(vaultMatch.DisabledFilePath, entry.RawCommand, overwrite: true);
                    File.Delete(vaultMatch.DisabledFilePath);
                }
                catch (UnauthorizedAccessException)
                {
                    bool ok = await RunElevatedCmdAsync($"copy /y \"{vaultMatch.DisabledFilePath}\" \"{entry.RawCommand}\"");
                    if (!ok) return (false, "Administrator permission required to restore All-Users Startup folder item.");
                    try { File.Delete(vaultMatch.DisabledFilePath); } catch { }
                }
            }

            string fileName = Path.GetFileName(entry.RawCommand);
            var hive = entry.SourceKind == StartupSourceKind.CommonStartupFolder ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
            if (!TrySetStartupApprovedState(hive, ApprovedFolderSubKey, fileName, enabled: true) && entry.RequiresAdmin)
            {
                bool ok = await RunElevatedCmdAsync($"reg add \"HKLM\\{ApprovedFolderSubKey}\" /v \"{fileName}\" /t REG_BINARY /d 020000000000000000000000 /f");
                if (!ok) return (false, "Administrator permission required to enable All-Users Startup folder item.");
            }

            vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            SaveVault(vault);
            return (true, $"Turned on auto-start for '{entry.Name}'.");
        }
        else
        {
            var (hive, subKey, approvedSubKey) = GetRegistryMetadata(entry.SourceKind);

            // If this entry was previously vaulted (or is a RunOnce/Policies key), ensure the Run registry value exists
            if (vaultMatch != null || approvedSubKey == null)
            {
                bool written = TrySetRegistryValue(hive, subKey, entry.Name, entry.RawCommand);
                if (!written && entry.RequiresAdmin)
                {
                    string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                    string escapedCmd = entry.RawCommand.Replace("\"", "\\\"");
                    bool ok = await RunElevatedCmdAsync($"reg add \"{rootName}\\{subKey}\" /v \"{entry.Name}\" /t REG_SZ /d \"{escapedCmd}\" /f");
                    if (!ok) return (false, "Administrator permission is required to enable system-wide HKLM startup items.");
                }
            }

            if (approvedSubKey != null)
            {
                if (!TrySetStartupApprovedState(hive, approvedSubKey, entry.Name, enabled: true) && entry.RequiresAdmin)
                {
                    string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                    bool ok = await RunElevatedCmdAsync($"reg add \"{rootName}\\{approvedSubKey}\" /v \"{entry.Name}\" /t REG_BINARY /d 020000000000000000000000 /f");
                    if (!ok) return (false, "Administrator permission is required to enable system-wide HKLM startup items.");
                }
            }

            vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            SaveVault(vault);
            return (true, $"Turned on auto-start for '{entry.Name}'.");
        }
    }

    private static void ScanRegistryKey(
        RegistryHive hive,
        RegistryView view,
        string subKeyPath,
        string? approvedSubKeyPath,
        StartupSourceKind kind,
        string locationDisplay,
        bool requiresAdmin,
        Dictionary<string, StartupEntry> target)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (key == null) return;

            var disabledByWindows = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (approvedSubKeyPath != null)
            {
                try
                {
                    using var appKey = baseKey.OpenSubKey(approvedSubKeyPath, writable: false);
                    if (appKey != null)
                    {
                        foreach (var valName in appKey.GetValueNames())
                        {
                            if (appKey.GetValue(valName) is byte[] bytes && bytes.Length > 0)
                            {
                                // In Windows StartupApproved, odd first byte (e.g. 0x03) indicates Disabled
                                if ((bytes[0] & 1) == 1)
                                {
                                    disabledByWindows.Add(valName);
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            foreach (var name in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(name)) continue;
                string rawCmd = key.GetValue(name)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(rawCmd)) continue;

                string id = $"{kind}|{name}";
                string exePath = ExtractExecutablePath(rawCmd);
                bool isEnabled = !disabledByWindows.Contains(name);

                target[id] = new StartupEntry(
                    Id: id,
                    Name: name,
                    RawCommand: rawCmd,
                    ExecutablePath: exePath,
                    LocationDisplay: locationDisplay,
                    SourceKind: kind,
                    IsEnabled: isEnabled,
                    RequiresAdmin: requiresAdmin,
                    PublisherHint: ResolvePublisherHint(exePath, null));
            }
        }
        catch { }
    }

    private static void ScanStartupFolder(
        string folderPath,
        RegistryHive hive,
        string approvedSubKeyPath,
        StartupSourceKind kind,
        string locationDisplay,
        bool requiresAdmin,
        Dictionary<string, StartupEntry> target)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath)) return;

            var disabledByWindows = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var appKey = baseKey.OpenSubKey(approvedSubKeyPath, writable: false);
                if (appKey != null)
                {
                    foreach (var valName in appKey.GetValueNames())
                    {
                        if (appKey.GetValue(valName) is byte[] bytes && bytes.Length > 0 && (bytes[0] & 1) == 1)
                        {
                            disabledByWindows.Add(valName);
                        }
                    }
                }
            }
            catch { }

            foreach (var file in Directory.EnumerateFiles(folderPath))
            {
                string fileName = Path.GetFileName(file);
                if (string.Equals(fileName, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                string name = Path.GetFileNameWithoutExtension(file);
                string id = $"{kind}|{fileName}";
                string exePath = ExtractExecutablePath(file);
                bool isEnabled = !disabledByWindows.Contains(fileName);

                target[id] = new StartupEntry(
                    Id: id,
                    Name: name,
                    RawCommand: file,
                    ExecutablePath: exePath,
                    LocationDisplay: locationDisplay,
                    SourceKind: kind,
                    IsEnabled: isEnabled,
                    RequiresAdmin: requiresAdmin,
                    PublisherHint: ResolvePublisherHint(exePath, null));
            }
        }
        catch { }
    }

    public static string ExtractExecutablePath(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return "";
        string expanded = Environment.ExpandEnvironmentVariables(rawCommand.Trim());
        string unquoted = expanded.Trim('"').Trim();

        // 1. If it's a .lnk shortcut file on disk, resolve the shortcut target path
        if (unquoted.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && File.Exists(unquoted))
        {
            string? resolved = TryResolveShortcutTarget(unquoted);
            if (!string.IsNullOrWhiteSpace(resolved)) return resolved;
            return unquoted;
        }

        // 2. If the entire unquoted string is already an existing file on disk (e.g. unquoted Startup Folder path with spaces like "OpenClaw Gateway.cmd"), return it directly!
        if (File.Exists(unquoted))
        {
            if (IsScriptExtension(unquoted))
            {
                string? innerExe = TryExtractTargetFromScriptFile(unquoted);
                if (!string.IsNullOrWhiteSpace(innerExe) && File.Exists(innerExe))
                {
                    return innerExe;
                }
            }
            return unquoted;
        }

        // 3. Quoted executable or script path: "C:\Program Files\App\app.exe" --args
        if (expanded.StartsWith('"'))
        {
            int closeQuote = expanded.IndexOf('"', 1);
            if (closeQuote > 1)
            {
                string candidate = expanded[1..closeQuote].Trim();
                return ResolveSystemPathIfNeeded(candidate);
            }
        }

        // 4. Unquoted path containing known executable/script extension (.exe, .cmd, .bat, .ps1, .vbs, .msc)
        foreach (string ext in new[] { ".exe", ".cmd", ".bat", ".ps1", ".vbs", ".msc", ".com" })
        {
            int extIdx = expanded.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (extIdx > 0)
            {
                int endIdx = extIdx + ext.Length;
                if (endIdx == expanded.Length || char.IsWhiteSpace(expanded[endIdx]) || expanded[endIdx] is '"' or ',' or '/')
                {
                    string candidate = expanded[..endIdx].Trim().Trim('"');
                    return ResolveSystemPathIfNeeded(candidate);
                }
            }
        }

        // 5. Fallback: first token
        int spaceIdx = expanded.IndexOf(' ');
        string firstToken = spaceIdx > 0 ? expanded[..spaceIdx] : expanded;
        return ResolveSystemPathIfNeeded(firstToken);
    }

    private static bool IsScriptExtension(string path)
    {
        string ext = Path.GetExtension(path);
        return ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".js", StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryExtractTargetFromScriptFile(string scriptPath)
    {
        try
        {
            foreach (var rawLine in File.ReadLines(scriptPath).Take(40))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("::", StringComparison.Ordinal) || line.StartsWith("REM ", StringComparison.OrdinalIgnoreCase) || line.StartsWith('#'))
                    continue;

                // Look for quoted path ending in .exe inside the script
                int exeIdx = line.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                if (exeIdx > 2)
                {
                    int start = Math.Max(0, exeIdx - 240);
                    for (int i = exeIdx - 1; i >= start; i--)
                    {
                        if (i + 2 < line.Length && char.IsLetter(line[i]) && line[i + 1] == ':' && line[i + 2] == '\\')
                        {
                            string candidate = Environment.ExpandEnvironmentVariables(line[i..(exeIdx + 4)].Trim('"'));
                            if (File.Exists(candidate) &&
                                !candidate.EndsWith(@"\cmd.exe", StringComparison.OrdinalIgnoreCase) &&
                                !candidate.EndsWith(@"\conhost.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                return candidate;
                            }
                            break;
                        }
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static string ResolveSystemPathIfNeeded(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        if (File.Exists(path)) return path;

        if (!Path.IsPathRooted(path))
        {
            string sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), path);
            if (File.Exists(sys32)) return sys32;
            if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(sys32 + ".exe"))
                return sys32 + ".exe";

            string winDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path);
            if (File.Exists(winDir)) return winDir;
        }
        return path;
    }

    private static string? TryResolveShortcutTarget(string lnkPath)
    {
        // 1. Primary: Native Windows Script Host COM ShellLink resolver
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                dynamic? shell = Activator.CreateInstance(shellType);
                if (shell != null)
                {
                    dynamic shortcut = shell.CreateShortcut(lnkPath);
                    string? targetPath = (string?)shortcut.TargetPath;
                    if (!string.IsNullOrWhiteSpace(targetPath))
                    {
                        string expanded = Environment.ExpandEnvironmentVariables(targetPath.Trim());
                        if (File.Exists(expanded)) return expanded;
                    }
                }
            }
        }
        catch { }

        // 2. Fallback: Fast binary .lnk scan for local executable path (e.g. "C:\...\*.exe")
        try
        {
            byte[] bytes = File.ReadAllBytes(lnkPath);
            string ascii = Encoding.Default.GetString(bytes);
            string unicode = Encoding.Unicode.GetString(bytes);

            foreach (var content in new[] { unicode, ascii })
            {
                int exePos = content.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                while (exePos > 2)
                {
                    // Walk backwards to find drive letter pattern "X:\"
                    int start = Math.Max(0, exePos - 240);
                    for (int i = exePos - 1; i >= start; i--)
                    {
                        if (i + 2 < content.Length &&
                            char.IsLetter(content[i]) &&
                            content[i + 1] == ':' &&
                            content[i + 2] == '\\')
                        {
                            string candidate = content[i..(exePos + 4)];
                            if (candidate.All(c => c >= 32 && c != '\0' && c != '"' && c != '<' && c != '>' && c != '|'))
                            {
                                string expanded = Environment.ExpandEnvironmentVariables(candidate);
                                if (File.Exists(expanded)) return expanded;
                            }
                            break;
                        }
                    }
                    exePos = content.IndexOf(".exe", exePos + 4, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        catch { }
        return null;
    }

    public static string? ResolvePublisherHint(string? exePath, string? explicitPublisher)
    {
        if (!string.IsNullOrWhiteSpace(explicitPublisher) &&
            !explicitPublisher.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase) &&
            !explicitPublisher.Contains("->", StringComparison.Ordinal))
        {
            return explicitPublisher.Trim();
        }

        if (string.IsNullOrWhiteSpace(exePath)) return null;

        try
        {
            if (File.Exists(exePath))
            {
                if (IsScriptExtension(exePath))
                {
                    string ext = Path.GetExtension(exePath).ToLowerInvariant();
                    return $"✓ Local Startup Script ({ext})";
                }

                var vi = FileVersionInfo.GetVersionInfo(exePath);
                if (!string.IsNullOrWhiteSpace(vi.CompanyName))
                {
                    return vi.CompanyName.Trim();
                }
            }
        }
        catch { }

        return null;
    }

    private static void ScanAppxStartupTasks(Dictionary<string, StartupEntry> target, List<DisabledVaultItem> vault)
    {
        var packageFolders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string windowsAppsRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");

        // Source A: HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages
        try
        {
            using var repoKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages", writable: false);
            if (repoKey != null)
            {
                foreach (var pkgFullName in repoKey.GetSubKeyNames())
                {
                    using var pkgKey = repoKey.OpenSubKey(pkgFullName, writable: false);
                    string? rootFolder = pkgKey?.GetValue("PackageRootFolder")?.ToString();
                    if (!string.IsNullOrWhiteSpace(rootFolder))
                    {
                        packageFolders[pkgFullName] = rootFolder;
                    }
                    else
                    {
                        packageFolders[pkgFullName] = Path.Combine(windowsAppsRoot, pkgFullName);
                    }
                }
            }
        }
        catch { }

        // Source B: HKCU\Software\Classes\Extensions\ContractId\*\PackageId (Always readable in Standard User & sandboxed contexts)
        try
        {
            using var contractRoot = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Extensions\ContractId", writable: false);
            if (contractRoot != null)
            {
                foreach (var contractName in contractRoot.GetSubKeyNames())
                {
                    try
                    {
                        using var pkgIdKey = contractRoot.OpenSubKey(contractName + @"\PackageId", writable: false);
                        if (pkgIdKey == null) continue;
                        foreach (var pkgFullName in pkgIdKey.GetSubKeyNames())
                        {
                            if (!packageFolders.ContainsKey(pkgFullName))
                            {
                                packageFolders[pkgFullName] = Path.Combine(windowsAppsRoot, pkgFullName);
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Source C: HKLM PackageRepository
        try
        {
            using var hklmRepo = Registry.LocalMachine.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages", writable: false);
            if (hklmRepo != null)
            {
                foreach (var pkgFullName in hklmRepo.GetSubKeyNames())
                {
                    if (!packageFolders.ContainsKey(pkgFullName))
                    {
                        using var pkgKey = hklmRepo.OpenSubKey(pkgFullName, writable: false);
                        string? path = pkgKey?.GetValue("Path")?.ToString();
                        packageFolders[pkgFullName] = !string.IsNullOrWhiteSpace(path)
                            ? path
                            : Path.Combine(windowsAppsRoot, pkgFullName);
                    }
                }
            }
        }
        catch { }

        // Source D: Direct WindowsApps directory listing (when running as Admin)
        try
        {
            if (Directory.Exists(windowsAppsRoot))
            {
                foreach (var dir in Directory.EnumerateDirectories(windowsAppsRoot))
                {
                    string folderName = Path.GetFileName(dir);
                    if (!packageFolders.ContainsKey(folderName))
                    {
                        packageFolders[folderName] = dir;
                    }
                }
            }
        }
        catch { }

        var highestVersionPerTask = new Dictionary<string, Version>(StringComparer.OrdinalIgnoreCase);

        foreach (var (pkgFullName, pkgFolder) in packageFolders)
        {
            try
            {
                string manifestPath = Path.Combine(pkgFolder, "AppxManifest.xml");
                if (!File.Exists(manifestPath)) continue;

                var doc = XDocument.Load(manifestPath);
                var root = doc.Root;
                if (root == null) continue;

                // Find all <Extension Category="windows.startupTask">
                var startupExtensions = root.Descendants()
                    .Where(e => e.Name.LocalName == "Extension" &&
                                string.Equals(e.Attribute("Category")?.Value, "windows.startupTask", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (startupExtensions.Count == 0) continue;

                var identityEl = root.Elements().FirstOrDefault(e => e.Name.LocalName == "Identity");
                string identityName = identityEl?.Attribute("Name")?.Value?.Trim() ?? pkgFullName;
                string versionStr = identityEl?.Attribute("Version")?.Value?.Trim() ?? "0.0.0.0";
                _ = Version.TryParse(versionStr, out var pkgVersion);
                pkgVersion ??= new Version(0, 0, 0, 0);

                string packageFamilyName = BuildPackageFamilyName(pkgFullName, identityName);

                var propsEl = root.Elements().FirstOrDefault(e => e.Name.LocalName == "Properties");
                string pkgDisplayName = propsEl?.Elements().FirstOrDefault(e => e.Name.LocalName == "DisplayName")?.Value?.Trim() ?? "";
                string pkgPublisherDisplay = propsEl?.Elements().FirstOrDefault(e => e.Name.LocalName == "PublisherDisplayName")?.Value?.Trim() ?? "";

                foreach (var extEl in startupExtensions)
                {
                    string? extExe = extEl.Attribute("Executable")?.Value?.Trim();
                    if (string.IsNullOrWhiteSpace(extExe))
                    {
                        var appEl = extEl.Ancestors().FirstOrDefault(a => a.Name.LocalName == "Application");
                        extExe = appEl?.Attribute("Executable")?.Value?.Trim();
                    }

                    var taskEls = extEl.Elements().Where(e => e.Name.LocalName == "StartupTask").ToList();
                    if (taskEls.Count == 0) continue;

                    foreach (var taskEl in taskEls)
                    {
                        string taskId = taskEl.Attribute("TaskId")?.Value?.Trim() ?? "StartupTask";
                        string taskDisplayName = taskEl.Attribute("DisplayName")?.Value?.Trim() ?? "";
                        string enabledAttr = taskEl.Attribute("Enabled")?.Value?.Trim() ?? "true";
                        bool manifestEnabled = !string.Equals(enabledAttr, "false", StringComparison.OrdinalIgnoreCase);

                        string entryId = $"{StartupSourceKind.AppxStartupTask}|{packageFamilyName}|{taskId}";
                        if (highestVersionPerTask.TryGetValue(entryId, out var prevVer) && prevVer > pkgVersion)
                        {
                            continue;
                        }
                        highestVersionPerTask[entryId] = pkgVersion;

                        string exeFullPath = !string.IsNullOrWhiteSpace(extExe)
                            ? Path.Combine(pkgFolder, extExe.Replace('/', '\\'))
                            : pkgFolder;

                        string friendlyName = !string.IsNullOrWhiteSpace(taskDisplayName) && !taskDisplayName.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)
                            ? taskDisplayName
                            : (!string.IsNullOrWhiteSpace(pkgDisplayName) && !pkgDisplayName.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase)
                                ? pkgDisplayName
                                : ResolveFriendlyNameFromExeOrIdentity(exeFullPath, identityName));

                        // If DisplayName differs from Identity Name (e.g. "ChatGPT" vs "OpenAI.Codex"), include both so searching either finds it immediately
                        string shortIdentity = identityName.Contains('.') ? identityName.Split('.').Last() : identityName;
                        if (!friendlyName.Contains(shortIdentity, StringComparison.OrdinalIgnoreCase) &&
                            !friendlyName.Equals(identityName, StringComparison.OrdinalIgnoreCase))
                        {
                            friendlyName = $"{friendlyName} ({identityName})";
                        }

                        bool isEnabled = ReadAppxStartupTaskEnabledState(packageFamilyName, taskId, manifestEnabled, entryId, vault);
                        string? publisherHint = ResolvePublisherHint(exeFullPath, pkgPublisherDisplay);

                        target[entryId] = new StartupEntry(
                            Id: entryId,
                            Name: friendlyName,
                            RawCommand: $"\"{exeFullPath}\" (MSIX StartupTask: {packageFamilyName} [{taskId}])",
                            ExecutablePath: exeFullPath,
                            LocationDisplay: "Store / MSIX App (StartupTask)",
                            SourceKind: StartupSourceKind.AppxStartupTask,
                            IsEnabled: isEnabled,
                            RequiresAdmin: false,
                            PublisherHint: publisherHint);
                    }
                }
            }
            catch { }
        }
    }

    private static string BuildPackageFamilyName(string packageFullName, string identityName)
    {
        // Standard PackageFullName format: <Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>
        int lastUnderscore = packageFullName.LastIndexOf('_');
        if (lastUnderscore > 0 && lastUnderscore + 1 < packageFullName.Length)
        {
            string publisherId = packageFullName[(lastUnderscore + 1)..];
            return $"{identityName}_{publisherId}";
        }
        return packageFullName;
    }

    private static string ResolveFriendlyNameFromExeOrIdentity(string exePath, string identityName)
    {
        try
        {
            if (File.Exists(exePath))
            {
                var vi = FileVersionInfo.GetVersionInfo(exePath);
                if (!string.IsNullOrWhiteSpace(vi.FileDescription)) return vi.FileDescription.Trim();
                if (!string.IsNullOrWhiteSpace(vi.ProductName)) return vi.ProductName.Trim();
            }
        }
        catch { }
        return identityName;
    }

    private static bool ReadAppxStartupTaskEnabledState(
        string packageFamilyName,
        string taskId,
        bool manifestDefaultEnabled,
        string entryId,
        List<DisabledVaultItem> vault)
    {
        try
        {
            string subKey = $@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\{packageFamilyName}\{taskId}";
            using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: false);
            if (key?.GetValue("State") is int state)
            {
                // Windows StartupTaskState: 0=Disabled, 1=DisabledByUser, 2=Enabled, 3=DisabledByPolicy, 4=EnabledByPolicy
                return state is 2 or 4;
            }
        }
        catch { }

        if (vault.Any(v => string.Equals(v.Id, entryId, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return manifestDefaultEnabled;
    }

    private static (string PackageFamilyName, string TaskId) GetAppxTaskIds(StartupEntry entry)
    {
        var parts = entry.Id.Split('|');
        if (parts.Length >= 3)
        {
            return (parts[1], parts[2]);
        }
        return (entry.Name, "App");
    }

    private static bool TrySetAppxStartupTaskState(string packageFamilyName, string taskId, bool enabled)
    {
        try
        {
            string subKey = $@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\{packageFamilyName}\{taskId}";
            using var key = Registry.CurrentUser.CreateSubKey(subKey, writable: true);
            if (key == null) return false;
            // 2 = Enabled, 1 = DisabledByUser
            key.SetValue("State", enabled ? 2 : 1, RegistryValueKind.DWord);
            key.SetValue("UserEnabledStartupOnce", 1, RegistryValueKind.DWord);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ScanAutoStartServices(Dictionary<string, StartupEntry> target, List<DisabledVaultItem> vault)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey == null) return;

            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svcKey == null) continue;

                    // Only user-mode Win32 services (0x10 = OwnProcess, 0x20 = ShareProcess), skip kernel/fs drivers (0x01, 0x02)
                    int type = svcKey.GetValue("Type") is int t ? t : 0;
                    if ((type & 0x30) == 0) continue;

                    int start = svcKey.GetValue("Start") is int s ? s : -1;
                    string entryId = $"{StartupSourceKind.WindowsService}|{svcName}";
                    bool inVault = vault.Any(v => string.Equals(v.Id, entryId, StringComparison.OrdinalIgnoreCase));

                    // Include Automatic (Start == 2) services, or Manual/Disabled (Start == 3 or 4) services that were disabled in Spectra or belong to packaged WindowsApps (like CodexSandboxService / CoworkVMService)
                    string rawImagePath = svcKey.GetValue("ImagePath")?.ToString()?.Trim() ?? "";
                    if (string.IsNullOrWhiteSpace(rawImagePath)) continue;

                    bool isWindowsAppService = rawImagePath.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase)
                                            || svcName.Contains("Codex", StringComparison.OrdinalIgnoreCase)
                                            || (type & 0x200) != 0;

                    if (start != 2 && !inVault && !(start is 3 or 4 && isWindowsAppService))
                        continue;

                    string exePath = ExtractExecutablePath(rawImagePath);
                    if (string.IsNullOrWhiteSpace(exePath)) continue;

                    // Skip built-in Windows OS services hosted in C:\Windows or Windows Defender / Security Health core services
                    if (exePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ||
                        exePath.Contains(@"Microsoft\Windows Defender", StringComparison.OrdinalIgnoreCase) ||
                        svcName.Equals("WinDefend", StringComparison.OrdinalIgnoreCase) ||
                        svcName.Equals("MDCoreSvc", StringComparison.OrdinalIgnoreCase) ||
                        svcName.Equals("WdNisSvc", StringComparison.OrdinalIgnoreCase) ||
                        svcName.Equals("Sense", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string? publisher = ResolvePublisherHint(exePath, null);
                    if (publisher != null &&
                        publisher.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) &&
                        !isWindowsAppService)
                    {
                        continue;
                    }

                    string displayName = svcKey.GetValue("DisplayName")?.ToString()?.Trim() ?? svcName;
                    if (displayName.StartsWith('@'))
                    {
                        displayName = svcName;
                    }
                    else if (!displayName.Contains(svcName, StringComparison.OrdinalIgnoreCase))
                    {
                        displayName = $"{displayName} ({svcName})";
                    }

                    bool isEnabled = start == 2 && !inVault;

                    target[entryId] = new StartupEntry(
                        Id: entryId,
                        Name: displayName,
                        RawCommand: rawImagePath,
                        ExecutablePath: exePath,
                        LocationDisplay: "Auto-Start Service (3rd-Party)",
                        SourceKind: StartupSourceKind.WindowsService,
                        IsEnabled: isEnabled,
                        RequiresAdmin: true,
                        PublisherHint: publisher);
                }
                catch { }
            }
        }
        catch { }
    }

    private static string GetServiceName(StartupEntry entry)
    {
        const string prefix = "WindowsService|";
        if (entry.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return entry.Id[prefix.Length..];
        }
        return entry.Name;
    }

    private static async Task<bool> RunScConfigAsync(string serviceName, string startMode)
    {
        bool enable = string.Equals(startMode, "auto", StringComparison.OrdinalIgnoreCase);
        int targetStartDword = enable ? 2 : 3; // 2 = SERVICE_AUTO_START, 3 = SERVICE_DEMAND_START (Manual)

        // 1. Try direct Registry update on HKLM\SYSTEM\CurrentControlSet\Services\<serviceName> first.
        // Packaged MSIX services (Type 0x210 like Claude's CoworkVMService and OpenAI's CodexSandboxService)
        // reject sc.exe OpenService/ChangeServiceConfig with Access Denied (Error 5), whereas BUILTIN\Administrators
        // has FullControl on the service registry key.
        bool regSuccess = false;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var svcKey = baseKey.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
            if (svcKey != null)
            {
                svcKey.SetValue("Start", targetStartDword, RegistryValueKind.DWord);
                regSuccess = true;
            }
        }
        catch { }

        // 2. Also notify Service Control Manager via sc.exe (succeeds for classic Win32 services)
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"config \"{serviceName}\" start= {startMode}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                await proc.WaitForExitAsync();
                if (proc.ExitCode == 0) return true;
            }
        }
        catch { }

        if (regSuccess)
        {
            return true;
        }

        // 3. Fallback when Spectra is running as Standard User (non-elevated): prompt UAC to update registry + sc config
        return await RunElevatedCmdAsync($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{serviceName}\" /v Start /t REG_DWORD /d {targetStartDword} /f");
    }

    private static void ScanScheduledTasks(Dictionary<string, StartupEntry> target)
    {
        int before = target.Count;

        // 1. Primary: Query Windows Task Scheduler COM API ("Schedule.Service") which works for both Standard Users and Admins
        try
        {
            Type? schedType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedType != null)
            {
                dynamic? service = Activator.CreateInstance(schedType);
                if (service != null)
                {
                    service.Connect();
                    dynamic rootFolder = service.GetFolder("\\");
                    ScanTaskSchedulerFolder(rootFolder, target);
                }
            }
        }
        catch { }

        // 2. Fallback: Direct XML scan of C:\Windows\System32\Tasks (works when elevated or for readable task files)
        if (target.Count == before)
        {
            try
            {
                string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                if (Directory.Exists(tasksRoot))
                {
                    ScanTasksDirectoryFallback(tasksRoot, tasksRoot, target);
                }
            }
            catch { }
        }
    }

    private static void ScanTaskSchedulerFolder(dynamic folder, Dictionary<string, StartupEntry> target)
    {
        try
        {
            string folderPath = (string)folder.Path;
            if (folderPath.StartsWith(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
            {
                return; // Skip built-in Windows OS internal maintenance tasks
            }

            dynamic tasks = folder.GetTasks(1); // 1 = TASK_ENUM_HIDDEN
            foreach (dynamic task in tasks)
            {
                try
                {
                    string name = (string)task.Name;
                    string path = (string)task.Path;
                    bool enabled = (bool)task.Enabled;
                    string xml = (string)task.Xml;

                    if (TryParseScheduledTaskXml(name, path, enabled, xml, out var entry) && entry != null)
                    {
                        target[entry.Id] = entry;
                    }
                }
                catch { }
            }

            dynamic subFolders = folder.GetFolders(0);
            foreach (dynamic sub in subFolders)
            {
                ScanTaskSchedulerFolder(sub, target);
            }
        }
        catch { }
    }

    private static void ScanTasksDirectoryFallback(string rootDir, string currentDir, Dictionary<string, StartupEntry> target)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(currentDir))
            {
                try
                {
                    string relPath = "\\" + Path.GetRelativePath(rootDir, file);
                    string name = Path.GetFileName(file);
                    string xml = File.ReadAllText(file);
                    if (TryParseScheduledTaskXml(name, relPath, null, xml, out var entry) && entry != null)
                    {
                        target[entry.Id] = entry;
                    }
                }
                catch { }
            }

            foreach (var dir in Directory.EnumerateDirectories(currentDir))
            {
                string relDir = "\\" + Path.GetRelativePath(rootDir, dir);
                if (relDir.StartsWith(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase)) continue;
                ScanTasksDirectoryFallback(rootDir, dir, target);
            }
        }
        catch { }
    }

    public static bool TryParseScheduledTaskXml(string name, string taskPath, bool? enabledOverride, string xml, out StartupEntry? entry)
    {
        entry = null;
        if (string.IsNullOrWhiteSpace(xml)) return false;

        try
        {
            var doc = XDocument.Parse(xml);
            var root = doc.Root;
            if (root == null) return false;
            XNamespace ns = root.Name.Namespace;

            var exec = root.Descendants(ns + "Exec").FirstOrDefault();
            if (exec == null) return false;

            string rawCmdElement = exec.Element(ns + "Command")?.Value?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(rawCmdElement)) return false;

            string argsElement = exec.Element(ns + "Arguments")?.Value?.Trim() ?? "";
            string workDirElement = exec.Element(ns + "WorkingDirectory")?.Value?.Trim() ?? "";

            bool isEnabled = enabledOverride ?? true;
            var enabledNode = root.Element(ns + "Settings")?.Element(ns + "Enabled");
            if (enabledOverride == null && enabledNode != null && bool.TryParse(enabledNode.Value.Trim(), out bool parsedEnabled))
            {
                isEnabled = parsedEnabled;
            }

            // Resolve executable path (combining WorkingDirectory + Command when Command is relative like "PurpleLauncher.exe")
            string expandedCmd = Environment.ExpandEnvironmentVariables(rawCmdElement.Trim('"'));
            string expandedWorkDir = Environment.ExpandEnvironmentVariables(workDirElement.Trim('"'));

            string exePath = ExtractExecutablePath(rawCmdElement);
            if ((!Path.IsPathRooted(exePath) || !File.Exists(exePath)) && !string.IsNullOrWhiteSpace(expandedWorkDir))
            {
                try
                {
                    string combined = Path.Combine(expandedWorkDir, expandedCmd);
                    if (File.Exists(combined))
                    {
                        exePath = combined;
                    }
                    else if (!combined.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(combined + ".exe"))
                    {
                        exePath = combined + ".exe";
                    }
                }
                catch { }
            }

            string displayCommand = !string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath)
                ? (string.IsNullOrWhiteSpace(argsElement) ? $"\"{exePath}\"" : $"\"{exePath}\" {argsElement}")
                : (string.IsNullOrWhiteSpace(argsElement) ? rawCmdElement : $"{rawCmdElement} {argsElement}");

            bool hasLogon = root.Descendants(ns + "LogonTrigger").Any();
            bool hasBoot = root.Descendants(ns + "BootTrigger").Any();
            string triggerKind = hasLogon
                ? "Task Scheduler (Logon)"
                : hasBoot
                    ? "Task Scheduler (Boot)"
                    : "Task Scheduler (Scheduled)";

            string normalizedPath = taskPath.StartsWith('\\') ? taskPath : "\\" + taskPath;
            string id = $"{StartupSourceKind.ScheduledTask}|{normalizedPath}";

            entry = new StartupEntry(
                Id: id,
                Name: name,
                RawCommand: displayCommand,
                ExecutablePath: exePath,
                LocationDisplay: triggerKind,
                SourceKind: StartupSourceKind.ScheduledTask,
                IsEnabled: isEnabled,
                RequiresAdmin: true,
                PublisherHint: ResolvePublisherHint(exePath, null));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string GetScheduledTaskPath(StartupEntry entry)
    {
        const string prefix = "ScheduledTask|";
        if (entry.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return entry.Id[prefix.Length..];
        }
        return entry.Name.StartsWith('\\') ? entry.Name : "\\" + entry.Name;
    }

    private static async Task<bool> RunSchtasksAsync(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                await proc.WaitForExitAsync();
                if (proc.ExitCode == 0) return true;
            }
        }
        catch { }

        return await RunElevatedCmdAsync($"schtasks {arguments}");
    }

    private static (RegistryHive Hive, string SubKey, string? ApprovedSubKey) GetRegistryMetadata(StartupSourceKind kind) => kind switch
    {
        StartupSourceKind.HkcuRun => (RegistryHive.CurrentUser, RunSubKey, ApprovedRunSubKey),
        StartupSourceKind.HkcuRunOnce => (RegistryHive.CurrentUser, RunOnceSubKey, null),
        StartupSourceKind.HkcuPoliciesRun => (RegistryHive.CurrentUser, PoliciesRunSubKey, null),
        StartupSourceKind.HklmRun => (RegistryHive.LocalMachine, RunSubKey, ApprovedRunSubKey),
        StartupSourceKind.HklmRunOnce => (RegistryHive.LocalMachine, RunOnceSubKey, null),
        StartupSourceKind.HklmPoliciesRun => (RegistryHive.LocalMachine, PoliciesRunSubKey, null),
        StartupSourceKind.HklmWow64Run => (RegistryHive.LocalMachine, Wow64RunSubKey, ApprovedRun32SubKey),
        StartupSourceKind.HklmWow64RunOnce => (RegistryHive.LocalMachine, Wow64RunOnceSubKey, null),
        _ => (RegistryHive.CurrentUser, RunSubKey, null)
    };

    private static string GetLocationDisplay(StartupSourceKind kind) => kind switch
    {
        StartupSourceKind.HkcuRun => @"Registry: HKCU\...\Run",
        StartupSourceKind.HkcuRunOnce => @"Registry: HKCU\...\RunOnce",
        StartupSourceKind.HkcuPoliciesRun => @"Registry: HKCU\...\Policies\Run",
        StartupSourceKind.HklmRun => @"Registry: HKLM\...\Run",
        StartupSourceKind.HklmRunOnce => @"Registry: HKLM\...\RunOnce",
        StartupSourceKind.HklmPoliciesRun => @"Registry: HKLM\...\Policies\Run",
        StartupSourceKind.HklmWow64Run => @"Registry: HKLM (32-bit)\...\Run",
        StartupSourceKind.HklmWow64RunOnce => @"Registry: HKLM (32-bit)\...\RunOnce",
        StartupSourceKind.UserStartupFolder => "Startup Folder (Current User)",
        StartupSourceKind.CommonStartupFolder => "Startup Folder (All Users)",
        StartupSourceKind.ScheduledTask => "Task Scheduler",
        StartupSourceKind.AppxStartupTask => "Store / MSIX App (StartupTask)",
        StartupSourceKind.WindowsService => "Auto-Start Service (3rd-Party)",
        _ => "Registry Run"
    };

    private static bool IsAdminSource(StartupSourceKind kind) => kind is
        StartupSourceKind.HklmRun or
        StartupSourceKind.HklmRunOnce or
        StartupSourceKind.HklmPoliciesRun or
        StartupSourceKind.HklmWow64Run or
        StartupSourceKind.HklmWow64RunOnce or
        StartupSourceKind.CommonStartupFolder or
        StartupSourceKind.ScheduledTask or
        StartupSourceKind.WindowsService;

    private static bool TryDeleteRegistryValue(RegistryHive hive, string subKey, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKey, writable: true);
            if (key == null) return true;
            if (key.GetValue(valueName) != null)
            {
                key.DeleteValue(valueName, throwOnMissingValue: false);
            }
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetRegistryValue(RegistryHive hive, string subKey, string valueName, string data)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(subKey, writable: true);
            if (key == null) return false;
            key.SetValue(valueName, data, RegistryValueKind.String);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetStartupApprovedState(RegistryHive hive, string approvedSubKey, string valueName, bool enabled)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(approvedSubKey, writable: true);
            if (key == null) return false;

            byte[] stateBytes = new byte[12];
            if (enabled)
            {
                stateBytes[0] = 0x02; // 0x02 = Enabled in Windows StartupApproved
            }
            else
            {
                stateBytes[0] = 0x03; // 0x03 = Disabled in Windows StartupApproved
                byte[] ft = BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());
                Buffer.BlockCopy(ft, 0, stateBytes, 4, Math.Min(8, ft.Length));
            }

            key.SetValue(valueName, stateBytes, RegistryValueKind.Binary);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildStartupApprovedDisabledHex()
    {
        byte[] stateBytes = new byte[12];
        stateBytes[0] = 0x03;
        byte[] ft = BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());
        Buffer.BlockCopy(ft, 0, stateBytes, 4, Math.Min(8, ft.Length));
        return Convert.ToHexString(stateBytes).ToLowerInvariant();
    }

    private static async Task<bool> RunElevatedCmdAsync(string command)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            await proc.WaitForExitAsync();
            return proc.ExitCode == 0;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static List<DisabledVaultItem> LoadVault()
    {
        try
        {
            string path = DisabledVaultPath;
            if (!File.Exists(path)) return new List<DisabledVaultItem>();
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<DisabledVaultItem>>(json) ?? new List<DisabledVaultItem>();
        }
        catch
        {
            return new List<DisabledVaultItem>();
        }
    }

    private static void SaveVault(List<DisabledVaultItem> items)
    {
        try
        {
            string path = DisabledVaultPath;
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            string json = JsonSerializer.Serialize(items, JsonOptions);
            File.WriteAllText(path, json);
        }
        catch { }
    }
}
