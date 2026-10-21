namespace SpectraNetworkManager.Core;

public static class EngineStoragePaths
{
    private static readonly string CommonBase = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SpectraNetworkManager");

    private static readonly string UserBase = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SpectraNetworkManager");

    public static string BaseDirectory
    {
        get
        {
            try
            {
                if (!Directory.Exists(CommonBase))
                    Directory.CreateDirectory(CommonBase);
                return CommonBase;
            }
            catch
            {
                // If ProgramData is not writable (e.g. non-elevated standalone mode), fallback to LocalAppData
                if (!Directory.Exists(UserBase))
                    Directory.CreateDirectory(UserBase);
                return UserBase;
            }
        }
    }

    public static string RulesPath => GetMigratedPath("rules.json");
    public static string StrictModePath => GetMigratedPath("strict-mode.json");
    public static string SignatureCachePath => GetMigratedPath("signature-cache.json");
    public static string DnsSettingsPath => GetMigratedPath("dns-settings.json");
    public static string DnsHistoryPath => GetMigratedPath("dns-history.db");
    public static string NetworkHistoryPath => GetMigratedPath("network-history.db");
    public static string DnsBackupPath => GetMigratedPath("dns-backup.json");
    public static string AppSettingsPath => GetMigratedPath("app-settings.json");
    public static string LogsDirectory
    {
        get
        {
            string dir = Path.Combine(BaseDirectory, "logs");
            if (!Directory.Exists(dir))
            {
                try { Directory.CreateDirectory(dir); } catch { }
            }
            return dir;
        }
    }
    public static string LogFilePath => Path.Combine(LogsDirectory, "spectranetworkmanager.log");
    public static string BlocklistsDirectory
    {
        get
        {
            string dir = Path.Combine(BaseDirectory, "blocklists");
            if (!Directory.Exists(dir))
            {
                try { Directory.CreateDirectory(dir); } catch { }
            }

            try
            {
                if (Directory.Exists(dir) && !Directory.EnumerateFiles(dir).Any())
                {
                    MigrateBlocklistsFolder(dir);
                }
            }
            catch { }

            return dir;
        }
    }

    private static void MigrateBlocklistsFolder(string targetDir)
    {
        string[] candidates = new[]
        {
            Path.Combine(UserBase, "blocklists"),
            Path.Combine(CommonBase, "blocklists"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetSentinel", "blocklists"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel", "blocklists")
        };

        foreach (var source in candidates)
        {
            if (string.Equals(source, targetDir, StringComparison.OrdinalIgnoreCase)) continue;
            if (Directory.Exists(source))
            {
                var files = Directory.GetFiles(source, "*.txt");
                if (files.Length > 0)
                {
                    foreach (var file in files)
                    {
                        string dest = Path.Combine(targetDir, Path.GetFileName(file));
                        if (!File.Exists(dest))
                        {
                            try { File.Copy(file, dest, overwrite: false); } catch { }
                        }
                    }
                    break;
                }
            }
        }
    }

    private static string GetMigratedPath(string fileName)
    {
        string target = Path.Combine(BaseDirectory, fileName);
        if (!File.Exists(target))
        {
            string oldPath = Path.Combine(UserBase, fileName);
            if (File.Exists(oldPath))
            {
                try { File.Copy(oldPath, target, overwrite: false); return target; } catch { }
            }

            string legacyProgramData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetSentinel", fileName);
            if (File.Exists(legacyProgramData))
            {
                try { File.Copy(legacyProgramData, target, overwrite: false); return target; } catch { }
            }

            string legacyLocalAppData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel", fileName);
            if (File.Exists(legacyLocalAppData))
            {
                try { File.Copy(legacyLocalAppData, target, overwrite: false); return target; } catch { }
            }
        }
        return target;
    }
}
