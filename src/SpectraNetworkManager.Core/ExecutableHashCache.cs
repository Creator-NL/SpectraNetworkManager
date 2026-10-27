using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace SpectraNetworkManager.Core;

/// <summary>
/// Computes and caches cryptographic SHA-256 file hashes for executables.
/// An entry is reused while the file size and last-write timestamp remain unchanged.
/// </summary>
public sealed class ExecutableHashCache
{
    public sealed record HashEntry(long Length, long LastWriteUtcTicks, string Sha256, DateTimeOffset ComputedAt);

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly string _file;
    private readonly ConcurrentDictionary<string, HashEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _saveLock = new();
    private volatile bool _dirty;

    public ExecutableHashCache(string? file = null)
    {
        _file = file ?? EngineStoragePaths.HashCachePath;
        Load();
    }

    public static string DefaultPath => EngineStoragePaths.HashCachePath;

    /// <summary>
    /// Returns the cached SHA-256 hash if the file exists and its size/timestamp match the cache; otherwise null.
    /// </summary>
    public string? TryGetCached(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            if (!_entries.TryGetValue(path, out var entry)) return null;
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            if (fi.Length == entry.Length && fi.LastWriteTimeUtc.Ticks == entry.LastWriteUtcTicks && !string.IsNullOrWhiteSpace(entry.Sha256))
            {
                return entry.Sha256;
            }
        }
        catch
        {
            // Ignore file access errors on locked/system files
        }
        return null;
    }

    /// <summary>
    /// Synchronously retrieves the cached SHA-256 hash or computes it from disk.
    /// </summary>
    public string? GetSha256(string? path) => GetOrCompute(path);

    /// <summary>
    /// Synchronously retrieves the cached SHA-256 hash or computes it from disk.
    /// </summary>
    public string? GetOrCompute(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;

            long len = fi.Length;
            long ticks = fi.LastWriteTimeUtc.Ticks;

            if (_entries.TryGetValue(path, out var existing) &&
                existing.Length == len &&
                existing.LastWriteUtcTicks == ticks &&
                !string.IsNullOrWhiteSpace(existing.Sha256))
            {
                return existing.Sha256;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536);
            byte[] hashBytes = SHA256.HashData(stream);
            string sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();

            _entries[path] = new HashEntry(len, ticks, sha256, DateTimeOffset.UtcNow);
            _dirty = true;
            return sha256;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Asynchronously retrieves or computes the SHA-256 hash on a background thread.
    /// </summary>
    public Task<string?> GetOrComputeAsync(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return Task.FromResult<string?>(null);
        string? fast = TryGetCached(path);
        if (fast is not null) return Task.FromResult<string?>(fast);
        return Task.Run(() => GetOrCompute(path));
    }

    /// <summary>
    /// Builds the VirusTotal file lookup URL for a given SHA-256 hash (no file upload required).
    /// </summary>
    public static string GetVirusTotalUrl(string sha256)
    {
        string clean = (sha256 ?? "").Trim().ToLowerInvariant();
        return $"https://www.virustotal.com/gui/file/{Uri.EscapeDataString(clean)}";
    }

    public void SaveIfDirty()
    {
        if (!_dirty) return;
        Save();
    }

    public void Save()
    {
        lock (_saveLock)
        {
            try
            {
                var copy = new Dictionary<string, HashEntry>(_entries, StringComparer.OrdinalIgnoreCase);
                var dir = Path.GetDirectoryName(_file);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                string temp = _file + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(copy, Json));
                File.Move(temp, _file, overwrite: true);
                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Non-fatal
            }
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_file)) return;
            var loaded = JsonSerializer.Deserialize<Dictionary<string, HashEntry>>(File.ReadAllText(_file), Json);
            if (loaded is null) return;
            foreach (var (k, v) in loaded)
            {
                if (!string.IsNullOrWhiteSpace(v.Sha256))
                    _entries[k] = v;
            }
        }
        catch
        {
            _entries.Clear();
        }
    }
}
