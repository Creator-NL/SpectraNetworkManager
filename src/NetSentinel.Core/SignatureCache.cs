using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Core;

/// <summary>
/// Remembers signature checks between runs, so each program is verified once, not at every start.
/// An entry is only reused while the file is unchanged (same size and last-write time) and not older than 14 days.
/// </summary>
public sealed class SignatureCache
{
    public sealed record Entry(long Length, long LastWriteUtcTicks, DateTimeOffset CheckedAt, SignatureInfo Info);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly TimeSpan MaxAge = TimeSpan.FromDays(14);

    private readonly string _file;
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public SignatureCache(string file)
    {
        _file = file;
        Load();
    }

    public static string DefaultPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel", "signature-cache.json");

    public SignatureInfo? TryGet(string path, long length, long lastWriteUtcTicks, DateTimeOffset now)
    {
        lock (_lock)
        {
            return _entries.TryGetValue(path, out var e)
                && e.Length == length && e.LastWriteUtcTicks == lastWriteUtcTicks
                && now - e.CheckedAt < MaxAge
                    ? e.Info
                    : null;
        }
    }

    public void Put(string path, long length, long lastWriteUtcTicks, DateTimeOffset now, SignatureInfo info)
    {
        // "Unknown" means "the check did not work", so never remember it.
        if (info.Status == SignatureStatus.Unknown) return;
        lock (_lock) _entries[path] = new Entry(length, lastWriteUtcTicks, now, info);
    }

    public void Save()
    {
        try
        {
            Dictionary<string, Entry> copy;
            lock (_lock) copy = new Dictionary<string, Entry>(_entries);

            var dir = System.IO.Path.GetDirectoryName(_file);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            string temp = _file + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(copy, Json));
            File.Move(temp, _file, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A cache that cannot be saved just means more re-checking next time.
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_file)) return;
            var loaded = JsonSerializer.Deserialize<Dictionary<string, Entry>>(File.ReadAllText(_file), Json);
            if (loaded is null) return;
            foreach (var (k, v) in loaded) _entries[k] = v;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            _entries.Clear();
        }
    }
}
