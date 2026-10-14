using System.Collections.Concurrent;
using System.Text;

namespace SpectraNetworkManager.Core;

public enum LogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
}

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Message, string? Exception);

/// <summary>
/// High-reliability rotating file logger writing to %ProgramData%\SpectraNetworkManager\logs\spectranetworkmanager.log.
/// Rotates at 10 MB, keeping up to 5 archived logs.
/// Also maintains an in-memory ring buffer for instant diagnostic support generation without disk contention.
/// </summary>
public sealed class RotatingFileLogger : IDisposable
{
    public const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB
    public const int MaxArchiveFiles = 5;
    public const int MaxRingBufferSize = 250;

    private static readonly Lazy<RotatingFileLogger> _lazy = new(() => new RotatingFileLogger());
    public static RotatingFileLogger Instance => _lazy.Value;

    private readonly string _logFilePath;
    private readonly object _syncLock = new();
    private readonly ConcurrentQueue<LogEntry> _recentEntries = new();
    private bool _disposed;

    public RotatingFileLogger(string? logFilePath = null)
    {
        _logFilePath = logFilePath ?? EngineStoragePaths.LogFilePath;
        EnsureDirectory();
    }

    public static void LogInfo(string message) => Instance.Log(LogLevel.Info, message);
    public static void LogWarn(string message) => Instance.Log(LogLevel.Warn, message);
    public static void LogError(string message, Exception? ex = null) => Instance.Log(LogLevel.Error, message, ex);

    public void Log(LogLevel level, string message, Exception? ex = null)
    {
        if (_disposed) return;

        var entry = new LogEntry(
            DateTimeOffset.UtcNow,
            level,
            message,
            ex?.ToString());

        // Maintain in-memory ring buffer
        _recentEntries.Enqueue(entry);
        while (_recentEntries.Count > MaxRingBufferSize && _recentEntries.TryDequeue(out _)) { }

        // Write to file under sync lock
        lock (_syncLock)
        {
            try
            {
                EnsureDirectory();
                RotateIfNeeded();

                var sb = new StringBuilder();
                sb.Append('[').Append(entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")).Append("] [")
                  .Append(entry.Level.ToString().ToUpperInvariant().PadRight(5)).Append("] ")
                  .Append(entry.Message);

                if (!string.IsNullOrEmpty(entry.Exception))
                {
                    sb.AppendLine().Append("  Exception: ").Append(entry.Exception);
                }
                sb.AppendLine();

                File.AppendAllText(_logFilePath, sb.ToString(), Encoding.UTF8);
            }
            catch
            {
                // Never crash the host process on logger write failure
            }
        }
    }

    public IReadOnlyList<LogEntry> GetRecentEntries(int count = 50)
    {
        return _recentEntries.TakeLast(count).ToList();
    }

    private void EnsureDirectory()
    {
        var dir = Path.GetDirectoryName(_logFilePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            try { Directory.CreateDirectory(dir); } catch { }
        }
    }

    private void RotateIfNeeded()
    {
        if (!File.Exists(_logFilePath)) return;

        var fi = new FileInfo(_logFilePath);
        if (fi.Length < MaxFileSizeBytes) return;

        // Shift existing archives: .4 -> .5, .3 -> .4, etc.
        for (int i = MaxArchiveFiles - 1; i >= 1; i--)
        {
            string src = GetArchiveName(i);
            string dst = GetArchiveName(i + 1);
            if (File.Exists(src))
            {
                try
                {
                    if (File.Exists(dst)) File.Delete(dst);
                    File.Move(src, dst);
                }
                catch { }
            }
        }

        // Move primary log to .1
        try
        {
            string first = GetArchiveName(1);
            if (File.Exists(first)) File.Delete(first);
            File.Move(_logFilePath, first);
        }
        catch { }
    }

    private string GetArchiveName(int index)
    {
        string dir = Path.GetDirectoryName(_logFilePath) ?? "";
        string name = Path.GetFileNameWithoutExtension(_logFilePath);
        string ext = Path.GetExtension(_logFilePath);
        return Path.Combine(dir, $"{name}.{index}{ext}");
    }

    public void Dispose()
    {
        _disposed = true;
    }
}
