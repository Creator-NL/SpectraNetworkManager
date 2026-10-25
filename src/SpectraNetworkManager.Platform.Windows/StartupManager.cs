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
    ScheduledTask
}

public sealed record StartupEntry(
    string Id,
    string Name,
    string RawCommand,
    string ExecutablePath,
    string LocationDisplay,
    StartupSourceKind SourceKind,
    bool IsEnabled,
    bool RequiresAdmin);

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

        // 3. Scheduled Tasks (Logon / Boot / Third-party background tasks)
        ScanScheduledTasks(entries);

        // 4. Merge items disabled in Spectra Vault
        foreach (var v in vault)
        {
            if (!entries.ContainsKey(v.Id))
            {
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
                    RequiresAdmin: reqAdmin);
            }
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

                if (entry.SourceKind == StartupSourceKind.ScheduledTask)
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
            string sourceFile = entry.RawCommand;
            string folder = Path.GetDirectoryName(sourceFile) ?? "";
            string disabledDir = Path.Combine(EngineStoragePaths.BaseDirectory, "disabled-startup-files");
            Directory.CreateDirectory(disabledDir);
            string backupFile = Path.Combine(disabledDir, $"{Guid.NewGuid():N}_{Path.GetFileName(sourceFile)}");

            if (File.Exists(sourceFile))
            {
                File.Copy(sourceFile, backupFile, overwrite: true);
                try
                {
                    File.Delete(sourceFile);
                }
                catch (UnauthorizedAccessException)
                {
                    bool ok = await RunElevatedCmdAsync($"del /f /q \"{sourceFile}\"");
                    if (!ok) return (false, "Administrator permission required to disable All-Users Startup folder item.");
                }
            }

            vault.Add(new DisabledVaultItem
            {
                Id = entry.Id,
                Name = entry.Name,
                RawCommand = entry.RawCommand,
                SourceKind = entry.SourceKind,
                DisabledFilePath = backupFile
            });
            SaveVault(vault);
            return (true, $"Turned off auto-start for '{entry.Name}'.");
        }
        else
        {
            var (hive, subKey, approvedSubKey) = GetRegistryMetadata(entry.SourceKind);

            // Save to vault first so we can always restore it
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
                    // Revert vault if user canceled UAC
                    vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
                    SaveVault(vault);
                    return (false, "Administrator permission is required to turn off system-wide HKLM startup items.");
                }
            }

            if (approvedSubKey != null)
            {
                TryDeleteRegistryValue(hive, approvedSubKey, entry.Name);
            }

            return (true, $"Turned off auto-start for '{entry.Name}'.");
        }
    }

    private static async Task<(bool Success, string Message)> EnableEntryCoreAsync(StartupEntry entry)
    {
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

            // Also clear any Windows StartupApproved disable flag
            var hive = entry.SourceKind == StartupSourceKind.CommonStartupFolder ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
            TrySetStartupApprovedEnabled(hive, ApprovedFolderSubKey, Path.GetFileName(entry.RawCommand));

            vault.RemoveAll(v => string.Equals(v.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
            SaveVault(vault);
            return (true, $"Turned on auto-start for '{entry.Name}'.");
        }
        else
        {
            var (hive, subKey, approvedSubKey) = GetRegistryMetadata(entry.SourceKind);
            bool written = TrySetRegistryValue(hive, subKey, entry.Name, entry.RawCommand);
            if (!written && entry.RequiresAdmin)
            {
                string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                string escapedCmd = entry.RawCommand.Replace("\"", "\\\"");
                bool ok = await RunElevatedCmdAsync($"reg add \"{rootName}\\{subKey}\" /v \"{entry.Name}\" /t REG_SZ /d \"{escapedCmd}\" /f");
                if (!ok) return (false, "Administrator permission is required to enable system-wide HKLM startup items.");
            }

            if (approvedSubKey != null)
            {
                if (!TrySetStartupApprovedEnabled(hive, approvedSubKey, entry.Name) && entry.RequiresAdmin)
                {
                    string rootName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                    await RunElevatedCmdAsync($"reg delete \"{rootName}\\{approvedSubKey}\" /v \"{entry.Name}\" /f");
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
                    RequiresAdmin: requiresAdmin);
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
                    RequiresAdmin: requiresAdmin);
            }
        }
        catch { }
    }

    public static string ExtractExecutablePath(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return "";
        string expanded = Environment.ExpandEnvironmentVariables(rawCommand.Trim());

        // If it's a .lnk shortcut file on disk, try to resolve the target path
        if (expanded.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && File.Exists(expanded))
        {
            string? resolved = TryResolveShortcutTarget(expanded);
            if (!string.IsNullOrWhiteSpace(resolved)) return resolved;
            return expanded;
        }

        // Quoted executable path: "C:\Program Files\App\app.exe" --args
        if (expanded.StartsWith('"'))
        {
            int closeQuote = expanded.IndexOf('"', 1);
            if (closeQuote > 1)
            {
                string candidate = expanded[1..closeQuote].Trim();
                return ResolveSystemPathIfNeeded(candidate);
            }
        }

        // Unquoted path containing .exe
        int exeIdx = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
        {
            string candidate = expanded[..(exeIdx + 4)].Trim();
            return ResolveSystemPathIfNeeded(candidate);
        }

        // Fallback: first token
        int spaceIdx = expanded.IndexOf(' ');
        string firstToken = spaceIdx > 0 ? expanded[..spaceIdx] : expanded;
        return ResolveSystemPathIfNeeded(firstToken);
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
        try
        {
            // Fast binary .lnk scan for local executable path (e.g. "C:\...\*.exe")
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
                RequiresAdmin: true);
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
        _ => "Registry Run"
    };

    private static bool IsAdminSource(StartupSourceKind kind) => kind is
        StartupSourceKind.HklmRun or
        StartupSourceKind.HklmRunOnce or
        StartupSourceKind.HklmPoliciesRun or
        StartupSourceKind.HklmWow64Run or
        StartupSourceKind.HklmWow64RunOnce or
        StartupSourceKind.CommonStartupFolder or
        StartupSourceKind.ScheduledTask;

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

    private static bool TrySetStartupApprovedEnabled(RegistryHive hive, string approvedSubKey, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(approvedSubKey, writable: true);
            if (key == null) return true;
            if (key.GetValue(valueName) is byte[] bytes && bytes.Length >= 12)
            {
                byte[] enabledBytes = new byte[12];
                enabledBytes[0] = 0x02; // 0x02 = Enabled in Windows StartupApproved
                key.SetValue(valueName, enabledBytes, RegistryValueKind.Binary);
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
