using System.Text.Json;
using System.Text.Json.Serialization;

namespace SpectraNetworkManager.Core;

public sealed record AppSettings
{
    public bool FirstRunCompleted { get; init; }
    public string InitialOperatingMode { get; init; } = "WatchOnly"; // "WatchOnly", "AskMode", "StrictMode"
    public bool CheckForUpdatesOnStartup { get; init; } = true;
    public DateTimeOffset? LastUpdateCheck { get; init; }
}

public sealed class AppSettingsStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _file;

    public AppSettingsStore(string? file = null)
    {
        _file = file ?? DefaultPath;
        Settings = Load();
    }

    public static string DefaultPath => EngineStoragePaths.AppSettingsPath;

    public AppSettings Settings { get; private set; }

    public bool WasUnreadable { get; private set; }

    public void Save(AppSettings settings)
    {
        var dir = Path.GetDirectoryName(_file);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        string temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, Json));
        File.Move(temp, _file, overwrite: true);
        Settings = settings;
    }

    private AppSettings Load()
    {
        if (!File.Exists(_file)) return new AppSettings();
        try
        {
            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_file), Json) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            WasUnreadable = true;
            try { File.Move(_file, _file + ".bad", overwrite: true); } catch { /* best effort */ }
            return new AppSettings();
        }
    }
}
