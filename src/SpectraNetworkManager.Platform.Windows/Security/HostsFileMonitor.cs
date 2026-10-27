using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Platform.Windows;

public sealed record HostsFileStatus(
    bool Exists,
    bool IsClean,
    int TotalActiveEntries,
    IReadOnlyList<string> ActiveEntries,
    IReadOnlyList<string> SuspiciousEntries,
    string Sha256Hash,
    DateTimeOffset LastModifiedUtc);

[SupportedOSPlatform("windows")]
public sealed class HostsFileMonitor : IDisposable
{
    private static readonly string HostsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    private static readonly string[] SuspiciousDomains =
    {
        "microsoft.com", "windowsupdate.com", "update.microsoft.com", "virustotal.com",
        "kaspersky.com", "bitdefender.com", "malwarebytes.com", "eset.com", "avast.com",
        "symantec.com", "sophos.com", "mcafee.com", "trendmicro.com", "github.com"
    };

    private const string DefaultCleanTemplate =
@"# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
";

    private FileSystemWatcher? _watcher;
    private string _lastHash = "";
    private readonly object _gate = new();

    public event EventHandler<HostsFileStatus>? HostsFileChanged;

    public void StartMonitoring()
    {
        lock (_gate)
        {
            if (_watcher != null) return;
            string? dir = Path.GetDirectoryName(HostsPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            try
            {
                _lastHash = ComputeHash();
                _watcher = new FileSystemWatcher(dir, "hosts")
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnFileChanged;
                _watcher.Created += OnFileChanged;
                _watcher.Deleted += OnFileChanged;
                _watcher.Renamed += OnFileChanged;
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"HostsFileMonitor initialization failed: {ex.Message}");
            }
        }
    }

    public HostsFileStatus GetStatus()
    {
        if (!File.Exists(HostsPath))
        {
            return new HostsFileStatus(
                Exists: false,
                IsClean: true,
                TotalActiveEntries: 0,
                ActiveEntries: Array.Empty<string>(),
                SuspiciousEntries: Array.Empty<string>(),
                Sha256Hash: "",
                LastModifiedUtc: DateTimeOffset.MinValue);
        }

        try
        {
            string hash = ComputeHash();
            var lastMod = File.GetLastWriteTimeUtc(HostsPath);
            var active = new List<string>();
            var suspicious = new List<string>();

            foreach (var rawLine in File.ReadLines(HostsPath))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith(';'))
                    continue;

                active.Add(line);

                foreach (var dom in SuspiciousDomains)
                {
                    if (line.Contains(dom, StringComparison.OrdinalIgnoreCase))
                    {
                        suspicious.Add(line);
                        break;
                    }
                }
            }

            bool isClean = suspicious.Count == 0;

            return new HostsFileStatus(
                Exists: true,
                IsClean: isClean,
                TotalActiveEntries: active.Count,
                ActiveEntries: active,
                SuspiciousEntries: suspicious,
                Sha256Hash: hash,
                LastModifiedUtc: lastMod);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogWarn($"HostsFileMonitor read error: {ex.Message}");
            return new HostsFileStatus(true, true, 0, Array.Empty<string>(), Array.Empty<string>(), "", DateTimeOffset.UtcNow);
        }
    }

    public string ReadRawContent()
    {
        if (!File.Exists(HostsPath)) return "";
        try
        {
            return File.ReadAllText(HostsPath);
        }
        catch
        {
            return "";
        }
    }

    public async Task<(bool Success, string Message)> RestoreDefaultHostsFileAsync()
    {
        return await Task.Run(async () =>
        {
            try
            {
                // Create timestamped backup of the current hosts file before overwriting
                string backupDir = Path.Combine(EngineStoragePaths.BaseDirectory, "hosts-backups");
                if (!Directory.Exists(backupDir)) Directory.CreateDirectory(backupDir);

                string backupPath = Path.Combine(backupDir, $"hosts.bak-{DateTime.Now:yyyyMMdd-HHmmss}");
                if (File.Exists(HostsPath))
                {
                    File.Copy(HostsPath, backupPath, overwrite: true);
                }

                // Write clean default template
                if (ElevationHelper.IsAdministrator())
                {
                    // Ensure attributes aren't ReadOnly/Hidden
                    var attr = File.GetAttributes(HostsPath);
                    if ((attr & (FileAttributes.ReadOnly | FileAttributes.Hidden)) != 0)
                    {
                        File.SetAttributes(HostsPath, FileAttributes.Normal);
                    }

                    File.WriteAllText(HostsPath, DefaultCleanTemplate, Encoding.UTF8);
                }
                else
                {
                    // Run elevated powershell/cmd to write clean file
                    string tempCleanFile = Path.Combine(Path.GetTempPath(), "clean-hosts.txt");
                    File.WriteAllText(tempCleanFile, DefaultCleanTemplate, Encoding.UTF8);

                    var psi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c copy /y \"{tempCleanFile}\" \"{HostsPath}\"",
                        UseShellExecute = true,
                        Verb = "runas",
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    var proc = Process.Start(psi);
                    if (proc != null) await proc.WaitForExitAsync();
                    try { File.Delete(tempCleanFile); } catch { }
                }

                // Flush DNS Cache
                try
                {
                    var flushProc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "ipconfig.exe",
                        Arguments = "/flushdns",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    if (flushProc != null) await flushProc.WaitForExitAsync();
                }
                catch { }

                _lastHash = ComputeHash();
                return (true, $"Windows hosts file restored to clean default template. Backup saved at: {Path.GetFileName(backupPath)}");
            }
            catch (Exception ex)
            {
                return (false, $"Failed to restore hosts file: {ex.Message}");
            }
        });
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        // Debounce
        Thread.Sleep(200);
        string currentHash = ComputeHash();
        if (currentHash != _lastHash)
        {
            _lastHash = currentHash;
            var status = GetStatus();
            HostsFileChanged?.Invoke(this, status);
        }
    }

    private static string ComputeHash()
    {
        if (!File.Exists(HostsPath)) return "";
        try
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(HostsPath);
            byte[] hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash);
        }
        catch
        {
            return "";
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }
    }
}
