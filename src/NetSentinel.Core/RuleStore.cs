using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Core;

/// <summary>
/// Remembers the user's decisions (allow / block per program) in a small JSON file.
/// A damaged file never crashes the app: it is set aside as rules.json.bad and the store starts empty.
/// </summary>
public sealed class RuleStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private sealed class FileModel
    {
        public int Version { get; set; } = 1;
        public List<ProgramRule> Rules { get; set; } = new();
        public List<string> TrustedPublishers { get; set; } = new();
    }

    private readonly string _file;
    private readonly Dictionary<string, ProgramRule> _rules = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trustedPublishers = new(StringComparer.OrdinalIgnoreCase);

    public RuleStore(string file)
    {
        _file = file;
        Load();
    }

    public static string DefaultPath => EngineStoragePaths.RulesPath;

    public IReadOnlyCollection<ProgramRule> All => _rules.Values;

    public IReadOnlyCollection<string> TrustedPublishers => _trustedPublishers;

    public bool IsTrustedPublisher(string? publisher) =>
        !string.IsNullOrWhiteSpace(publisher) && _trustedPublishers.Contains(publisher);

    public void TrustPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return;
        if (_trustedPublishers.Add(publisher)) Save();
    }

    public bool UntrustPublisher(string publisher)
    {
        bool removed = _trustedPublishers.Remove(publisher);
        if (removed) Save();
        return removed;
    }

    public ProgramRule? Find(string? path) =>
        !string.IsNullOrEmpty(path) && _rules.TryGetValue(path, out var rule) ? rule : null;

    public void Set(ProgramRule rule)
    {
        _rules[rule.Path] = rule;
        Save();
    }

    public bool Remove(string path)
    {
        bool removed = _rules.Remove(path);
        if (removed) Save();
        return removed;
    }

    public int RemoveWhere(Func<ProgramRule, bool> predicate)
    {
        var doomed = _rules.Values.Where(predicate).Select(r => r.Path).ToList();
        foreach (var p in doomed) _rules.Remove(p);
        if (doomed.Count > 0) Save();
        return doomed.Count;
    }

    private void Load()
    {
        if (!File.Exists(_file)) return;
        try
        {
            var model = JsonSerializer.Deserialize<FileModel>(File.ReadAllText(_file), Json);
            foreach (var r in model?.Rules ?? new())
                if (!string.IsNullOrWhiteSpace(r.Path)) _rules[r.Path] = r;
            foreach (var pub in model?.TrustedPublishers ?? new())
                if (!string.IsNullOrWhiteSpace(pub)) _trustedPublishers.Add(pub);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            try { File.Move(_file, _file + ".bad", overwrite: true); } catch (Exception) { /* nothing more we can do */ }
            _rules.Clear();
            _trustedPublishers.Clear();
        }
    }

    private void Save()
    {
        var dir = System.IO.Path.GetDirectoryName(_file);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var model = new FileModel
        {
            Rules = _rules.Values.OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList(),
            TrustedPublishers = _trustedPublishers.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList(),
        };
        string temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(model, Json));
        File.Move(temp, _file, overwrite: true);   // replace in one step so a crash can't leave half a file
    }
}
