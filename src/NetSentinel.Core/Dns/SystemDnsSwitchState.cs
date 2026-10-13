using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Sinkhole;

public enum DnsSwitchPhase
{
    Off = 0,
    /// <summary>Applied, but waiting for user confirmation within 60 seconds. Auto-reverted if unconfirmed.</summary>
    Pending = 1,
    /// <summary>Confirmed by the user.</summary>
    Active = 2,
}

/// <summary>
/// Preserved DNS server settings for a single network adapter before NetSentinel modified it.
/// </summary>
public sealed record AdapterDnsBackup(
    int InterfaceIndex,
    string Name,
    string Guid,
    IReadOnlyList<string> Ipv4Servers,
    bool Ipv4IsDhcp,
    IReadOnlyList<string> Ipv6Servers,
    bool Ipv6IsDhcp);

public sealed record SystemDnsSwitchState(
    DnsSwitchPhase Phase,
    DateTimeOffset? ConfirmDeadline,
    bool OnlyLocal,
    IReadOnlyList<AdapterDnsBackup> Backups)
{
    public static SystemDnsSwitchState Off { get; } = new(DnsSwitchPhase.Off, null, false, Array.Empty<AdapterDnsBackup>());
}

/// <summary>
/// Manages atomic persistence of system DNS switch states and backups in %LocalAppData%\NetSentinel.
/// Written BEFORE network adapters are touched to guarantee full recovery even in case of crash or power failure.
/// </summary>
public sealed class SystemDnsSwitchStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _stateFile;
    private readonly string _backupFile;

    public SystemDnsSwitchStore(string? stateFile = null, string? backupFile = null)
    {
        _stateFile = stateFile ?? Path.Combine(NetSentinel.Core.EngineStoragePaths.BaseDirectory, "dns-switch.json");
        _backupFile = backupFile ?? NetSentinel.Core.EngineStoragePaths.DnsBackupPath;
        State = Load();
    }

    public SystemDnsSwitchState State { get; private set; }
    public bool WasUnreadable { get; private set; }

    public void Save(SystemDnsSwitchState state)
    {
        var dir = Path.GetDirectoryName(_stateFile);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // Always write backup file first if there are backups
        if (state.Backups.Count > 0)
        {
            string tempBackup = _backupFile + ".tmp";
            File.WriteAllText(tempBackup, JsonSerializer.Serialize(state.Backups, Json));
            File.Move(tempBackup, _backupFile, overwrite: true);
        }

        string tempState = _stateFile + ".tmp";
        File.WriteAllText(tempState, JsonSerializer.Serialize(state, Json));
        File.Move(tempState, _stateFile, overwrite: true);
        State = state;
    }

    public IReadOnlyList<AdapterDnsBackup> LoadBackupFile()
    {
        if (!File.Exists(_backupFile)) return Array.Empty<AdapterDnsBackup>();
        try
        {
            return JsonSerializer.Deserialize<List<AdapterDnsBackup>>(File.ReadAllText(_backupFile), Json) ?? (IReadOnlyList<AdapterDnsBackup>)Array.Empty<AdapterDnsBackup>();
        }
        catch (Exception)
        {
            return Array.Empty<AdapterDnsBackup>();
        }
    }

    private SystemDnsSwitchState Load()
    {
        if (!File.Exists(_stateFile)) return SystemDnsSwitchState.Off;
        try
        {
            return JsonSerializer.Deserialize<SystemDnsSwitchState>(File.ReadAllText(_stateFile), Json) ?? SystemDnsSwitchState.Off;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            WasUnreadable = true;
            try { File.Move(_stateFile, _stateFile + ".bad", overwrite: true); } catch { }
            return SystemDnsSwitchState.Off;
        }
    }
}
