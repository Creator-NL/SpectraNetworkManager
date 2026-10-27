using System.Text.Json;

namespace SpectraNetworkManager.Core;

public sealed class QuarantineVault
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private readonly string _filePath;
    private readonly object _gate = new();

    public static string DefaultPath => EngineStoragePaths.QuarantineVaultPath;

    public QuarantineVault(string? filePath = null)
    {
        _filePath = filePath ?? DefaultPath;
    }

    public List<QuarantineSnapshot> GetAll()
    {
        lock (_gate)
        {
            if (!File.Exists(_filePath)) return new List<QuarantineSnapshot>();
            try
            {
                string json = File.ReadAllText(_filePath);
                var list = JsonSerializer.Deserialize<List<QuarantineSnapshot>>(json, JsonOpts);
                return list ?? new List<QuarantineSnapshot>();
            }
            catch
            {
                return new List<QuarantineSnapshot>();
            }
        }
    }

    public List<QuarantineSnapshot> GetActive() =>
        GetAll().Where(s => !s.IsRestored).ToList();

    public QuarantineSnapshot? FindByPath(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return null;
        return GetAll().FirstOrDefault(s =>
            !s.IsRestored && string.Equals(s.ExecutablePath, executablePath, StringComparison.OrdinalIgnoreCase));
    }

    public void SaveSnapshot(QuarantineSnapshot snapshot)
    {
        lock (_gate)
        {
            var list = GetAll();
            int idx = list.FindIndex(s => s.Id == snapshot.Id);
            if (idx >= 0)
            {
                list[idx] = snapshot;
            }
            else
            {
                list.Add(snapshot);
            }
            PersistList(list);
        }
    }

    public void MarkRestored(string snapshotId)
    {
        lock (_gate)
        {
            var list = GetAll();
            var item = list.FirstOrDefault(s => s.Id == snapshotId);
            if (item != null)
            {
                item.IsRestored = true;
                item.RestoredAtUtc = DateTimeOffset.UtcNow;
                PersistList(list);
            }
        }
    }

    public void DeleteSnapshot(string snapshotId)
    {
        lock (_gate)
        {
            var list = GetAll();
            list.RemoveAll(s => s.Id == snapshotId);
            PersistList(list);
        }
    }

    private void PersistList(List<QuarantineSnapshot> list)
    {
        try
        {
            string? dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string tmp = _filePath + ".tmp";
            string json = JsonSerializer.Serialize(list, JsonOpts);
            File.WriteAllText(tmp, json);
            File.Move(tmp, _filePath, overwrite: true);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("QuarantineVault: Failed to persist quarantine vault", ex);
        }
    }
}
