using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSentinel.Core;

public enum StrictPhase
{
    Off = 0,
    /// <summary>Switched on, but not yet confirmed by the user. Reverted automatically if never confirmed.</summary>
    Pending = 1,
    Active = 2,
}

/// <summary>Windows Firewall "default outbound action" per profile (0 = block, 1 = allow).</summary>
public sealed record ProfileDefaults(int Domain, int Private, int Public)
{
    public const int Block = 0;
    public const int Allow = 1;

    public static ProfileDefaults StandardWindows { get; } = new(Allow, Allow, Allow);
    public static ProfileDefaults AllBlock { get; } = new(Block, Block, Block);
}

public sealed record StrictModeState(StrictPhase Phase, DateTimeOffset? ConfirmDeadline, ProfileDefaults? Previous)
{
    public static StrictModeState Off { get; } = new(StrictPhase.Off, null, null);
}

/// <summary>
/// Remembers whether strict (block-by-default) mode is on, together with the firewall defaults to go back to.
/// It is written BEFORE anything is changed, so that even a crash cannot leave the PC locked down without a way back.
/// </summary>
public sealed class StrictModeStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _file;

    public StrictModeStore(string file)
    {
        _file = file;
        State = Load();
    }

    public static string DefaultPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSentinel", "strict-mode.json");

    public StrictModeState State { get; private set; }

    /// <summary>True if the file existed but could not be read, so the real state is unknown.</summary>
    public bool WasUnreadable { get; private set; }

    public void Save(StrictModeState state)
    {
        var dir = System.IO.Path.GetDirectoryName(_file);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        string temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, Json));
        File.Move(temp, _file, overwrite: true);
        State = state;
    }

    private StrictModeState Load()
    {
        if (!File.Exists(_file)) return StrictModeState.Off;
        try
        {
            return JsonSerializer.Deserialize<StrictModeState>(File.ReadAllText(_file), Json) ?? StrictModeState.Off;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            WasUnreadable = true;
            try { File.Move(_file, _file + ".bad", overwrite: true); } catch (Exception) { /* nothing more to do */ }
            return StrictModeState.Off;
        }
    }
}

/// <param name="ProgramPath">Full path of the program, or "System" for the Windows kernel.</param>
/// <param name="ServiceName">Windows service short name (for services that run in their own process).</param>
public sealed record AllowSpec(string Label, string? ProgramPath, string? ServiceName);

/// <summary>Works out which programs and services must stay allowed when everything else is blocked by default.</summary>
public static class StrictModePlanner
{
    /// <summary>
    /// The minimum for a working PC. Windows' own built-in "Core Networking" rules (DHCP, DNS, IPv6) stay in place;
    /// these add the programs and services that host most of Windows' network activity.
    /// </summary>
    public static IReadOnlyList<AllowSpec> Essentials(string windowsDirectory, string? ownExePath)
    {
        string win = windowsDirectory.TrimEnd('\\', '/');
        var list = new List<AllowSpec>
        {
            new("System", "System", null),
            new("svchost.exe (Windows services)", win + @"\System32\svchost.exe", null),
            new("lsass.exe (sign-in)", win + @"\System32\lsass.exe", null),
            new("Windows Defender service", null, "WinDefend"),
            new("Windows Defender network inspection", null, "WdNisSvc"),
            new("Windows Defender core service", null, "MDCoreSvc"),
        };

        if (!string.IsNullOrWhiteSpace(ownExePath))
            list.Add(new AllowSpec("NetSentinel itself", ownExePath, null));

        return list;
    }

    public static IReadOnlyList<AllowSpec> Plan(string windowsDirectory, string? ownExePath, IEnumerable<string> allowedProgramPaths)
    {
        var plan = new List<AllowSpec>(Essentials(windowsDirectory, ownExePath));
        var seen = new HashSet<string>(plan.Where(p => p.ProgramPath is not null).Select(p => p.ProgramPath!), StringComparer.OrdinalIgnoreCase);

        foreach (var path in allowedProgramPaths.Where(p => !string.IsNullOrWhiteSpace(p)))
            if (seen.Add(path))
                plan.Add(new AllowSpec(System.IO.Path.GetFileName(path), path, null));

        return plan;
    }
}
