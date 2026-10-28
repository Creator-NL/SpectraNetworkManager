using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SpectraNetworkManager.Platform.Windows;

public sealed record QosLimitEntry(
    string ExePath,
    string ProgramName,
    long ThrottleRateBitsPerSec,
    string PolicyName,
    DateTime SetAtUtc)
{
    public string RateDisplay => ThrottleRateBitsPerSec switch
    {
        >= 1_000_000_000 => $"{ThrottleRateBitsPerSec / 1_000_000_000.0:F1} Gbps",
        >= 1_000_000 => $"{ThrottleRateBitsPerSec / 1_000_000.0:F1} Mbps",
        >= 1_000 => $"{ThrottleRateBitsPerSec / 1_000.0:F0} Kbps",
        _ => $"{ThrottleRateBitsPerSec} bps"
    };
}

public static class QosRateLimiter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly string StorePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SpectraNetworkManager",
        "qos-limits.json");

    public static string GeneratePolicyName(string exePath)
    {
        string name = Path.GetFileNameWithoutExtension(exePath);
        if (string.IsNullOrWhiteSpace(name)) name = "app";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(exePath.ToLowerInvariant()));
        string hex = Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
        return $"Spectra_QoS_{name}_{hex}";
    }

    public static async Task<bool> SetLimitAsync(string exePath, long bitsPerSec, CancellationToken ct = default)
    {
        string policyName = GeneratePolicyName(exePath);
        string exeName = Path.GetFileName(exePath);

        await RemoveLimitAsync(exePath, ct).ConfigureAwait(false);

        if (bitsPerSec <= 0) return true;

        string script =
            $"try {{ New-NetQosPolicy -Name '{policyName}' -AppPathNameMatchCondition '{exeName}' -ThrottleRateActionBitsPerSecond {bitsPerSec} -ErrorAction Stop | Out-Null; $true }} catch {{ Write-Error $_; $false }}";

        await RunPowerShellAsync(script, ct).ConfigureAwait(false);

        var list = LoadStore();
        list.RemoveAll(x => string.Equals(x.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
        list.Add(new QosLimitEntry(exePath, exeName, bitsPerSec, policyName, DateTime.UtcNow));
        SaveStore(list);
        return true;
    }

    public static async Task<bool> RemoveLimitAsync(string exePath, CancellationToken ct = default)
    {
        string policyName = GeneratePolicyName(exePath);
        string script = $"try {{ Remove-NetQosPolicy -Name '{policyName}' -Confirm:$false -ErrorAction SilentlyContinue }} catch {{ }}";
        await RunPowerShellAsync(script, ct).ConfigureAwait(false);

        var list = LoadStore();
        list.RemoveAll(x => string.Equals(x.ExePath, exePath, StringComparison.OrdinalIgnoreCase));
        SaveStore(list);
        return true;
    }

    public static async Task<int> RemoveAllLimitsAsync(CancellationToken ct = default)
    {
        string script = "try { Get-NetQosPolicy -PolicyStore ActiveStore | Where-Object { $_.Name -like 'Spectra_QoS_*' } | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue } catch { }";
        await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var list = LoadStore();
        int count = list.Count;
        list.Clear();
        SaveStore(list);
        return count;
    }

    public static async Task<int> ReapplySavedLimitsAsync(CancellationToken ct = default)
    {
        var list = LoadStore();
        if (list.Count == 0) return 0;
        int applied = 0;
        foreach (var entry in list)
        {
            if (entry.ThrottleRateBitsPerSec > 0 && File.Exists(entry.ExePath))
            {
                string policyName = entry.PolicyName;
                string exeName = Path.GetFileName(entry.ExePath);
                string script =
                    $"try {{ New-NetQosPolicy -Name '{policyName}' -AppPathNameMatchCondition '{exeName}' -ThrottleRateActionBitsPerSecond {entry.ThrottleRateBitsPerSec} -ErrorAction SilentlyContinue | Out-Null; $true }} catch {{ $false }}";
                await RunPowerShellAsync(script, ct).ConfigureAwait(false);
                applied++;
            }
        }
        return applied;
    }

    public static List<QosLimitEntry> LoadStore()
    {
        try
        {
            if (File.Exists(StorePath))
            {
                string json = File.ReadAllText(StorePath);
                return JsonSerializer.Deserialize<List<QosLimitEntry>>(json) ?? new List<QosLimitEntry>();
            }
        }
        catch { }
        return new List<QosLimitEntry>();
    }

    private static void SaveStore(List<QosLimitEntry> entries)
    {
        try
        {
            string? dir = Path.GetDirectoryName(StorePath);
            if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(StorePath, JsonSerializer.Serialize(entries, JsonOptions));
        }
        catch { }
    }

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

        using var proc = Process.Start(psi);
        if (proc is null) return "";
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(TimeSpan.FromSeconds(8));
        try
        {
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(linked.Token);
            await proc.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            return await stdoutTask.ConfigureAwait(false);
        }
        catch
        {
            return "";
        }
    }
}
