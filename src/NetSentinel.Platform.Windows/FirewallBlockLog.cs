using System.Diagnostics;
using System.Runtime.Versioning;
using NetSentinel.Core;

namespace NetSentinel.Platform.Windows;

/// <summary>
/// Reads what Windows Firewall blocked, from the Security event log
/// (5157 = connection blocked, 5152 = individual packet dropped), using the built-in wevtutil tool.
///
/// Requirements (the app only READS; it never changes these settings itself):
///   1. Run as Administrator - the Security log is protected.
///   2. Auditing must be switched on once, from an elevated prompt:
///        auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
///        auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
///
/// Serves as the reliable fallback when direct WFP event subscription is unavailable.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallBlockLog : IBlockEventSource
{
    private readonly DevicePathConverter _paths = new();

    public event Action<BlockEvent>? BlockDetected;

    public bool IsNativeSubscribed => false;

    public IReadOnlyList<BlockEvent> ReadRecent(TimeSpan window, int max, bool includePacketDrops = false)
    {
        string xpath = $"*[System[({Ids(includePacketDrops)}) and TimeCreated[timediff(@SystemTime) <= {(long)window.TotalMilliseconds}]]]";
        return Query(xpath, max, newestFirst: true);
    }

    public IReadOnlyList<BlockEvent> ReadAfter(long lastRecordId, int max, bool includePacketDrops = false)
    {
        string xpath = $"*[System[({Ids(includePacketDrops)}) and EventRecordID > {lastRecordId}]]";
        return Query(xpath, max, newestFirst: false);
    }

    private static string Ids(bool packets) => packets ? "EventID=5157 or EventID=5152" : "EventID=5157";

    private IReadOnlyList<BlockEvent> Query(string xpath, int max, bool newestFirst)
    {
        var psi = new ProcessStartInfo("wevtutil.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("qe");
        psi.ArgumentList.Add("Security");
        psi.ArgumentList.Add("/q:" + xpath);
        psi.ArgumentList.Add("/f:xml");
        psi.ArgumentList.Add("/rd:" + (newestFirst ? "true" : "false"));
        psi.ArgumentList.Add("/c:" + max);

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start wevtutil.exe");
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();

        if (proc.ExitCode != 0)
        {
            if (stderr.Contains("denied", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Reading the Security log needs Administrator rights. Start the program as Administrator.");
            throw new InvalidOperationException($"wevtutil failed ({proc.ExitCode}): {stderr.Trim()}");
        }

        var results = BlockEventParser.Parse(stdout, _paths.ToDosPath);
        if (BlockDetected is not null)
        {
            foreach (var b in results)
            {
                BlockDetected.Invoke(b);
            }
        }
        return results;
    }

    public void Dispose()
    {
        // No unmanaged resources held
    }
}
