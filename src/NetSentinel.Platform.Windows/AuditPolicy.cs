using System.Diagnostics;
using System.Runtime.Versioning;

namespace NetSentinel.Platform.Windows;

/// <summary>
/// Switches on Windows' audit of BLOCKED connections ("Filtering Platform Connection", failures only), which is where
/// NetSentinel learns what strict mode blocked. Uses the subcategory's GUID, so it works on every Windows language
/// (the English names are translated on other languages). Needs Administrator.
/// </summary>
[SupportedOSPlatform("windows")]
public static class AuditPolicy
{
    /// <summary>Audit Filtering Platform Connection.</summary>
    public const string FilteringPlatformConnectionGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}";

    public static (bool Ok, string Output) EnableBlockedConnectionAuditing()
    {
        var psi = new ProcessStartInfo("auditpol.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("/set");
        psi.ArgumentList.Add("/subcategory:" + FilteringPlatformConnectionGuid);
        psi.ArgumentList.Add("/failure:enable");

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start auditpol.exe");
        string output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode == 0, output.Trim());
    }
}
