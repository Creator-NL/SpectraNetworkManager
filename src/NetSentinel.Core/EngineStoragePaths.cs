namespace NetSentinel.Core;

public static class EngineStoragePaths
{
    private static readonly string CommonBase = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetSentinel");

    private static readonly string UserBase = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel");

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
    public static string DnsHistoryPath => Path.Combine(BaseDirectory, "dns-history.db");
    public static string DnsBackupPath => GetMigratedPath("dns-backup.json");
    public static string BlocklistsDirectory
    {
        get
        {
            string dir = Path.Combine(BaseDirectory, "blocklists");
            if (!Directory.Exists(dir))
            {
                try { Directory.CreateDirectory(dir); } catch { }
            }
            return dir;
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
                try
                {
                    File.Copy(oldPath, target, overwrite: false);
                }
                catch
                {
                    return oldPath;
                }
            }
        }
        return target;
    }
}
