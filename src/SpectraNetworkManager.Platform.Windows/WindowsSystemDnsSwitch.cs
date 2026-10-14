using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows;

public sealed class WindowsSystemDnsSwitch : ISystemDnsSwitch
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<NetworkAdapterDnsInfo>> GetAdaptersAsync(CancellationToken ct = default)
    {
        const string script = @"
$ProgressPreference = 'SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual }
$result = @()
foreach ($a in $adapters) {
    $idx = $a.InterfaceIndex
    $alias = $a.Name
    $desc = $a.InterfaceDescription
    $guid = $a.InterfaceGuid

    $ipv4 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $v4Servers = if ($ipv4) { @($ipv4.ServerAddresses) } else { @() }

    $ipv6 = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue
    $v6Servers = if ($ipv6) { @($ipv6.ServerAddresses) } else { @() }

    $v4IsDhcp = $true
    try {
        $regV4 = Get-ItemProperty -Path ""HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"" -ErrorAction SilentlyContinue
        if ($regV4 -and $regV4.NameServer -and $regV4.NameServer.Trim().Length -gt 0) {
            $v4IsDhcp = $false
        }
    } catch {}

    $v6IsDhcp = $true
    try {
        $regV6 = Get-ItemProperty -Path ""HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid"" -ErrorAction SilentlyContinue
        if ($regV6 -and $regV6.NameServer -and $regV6.NameServer.Trim().Length -gt 0) {
            $v6IsDhcp = $false
        }
    } catch {}

    $isWireless = ($a.PhysicalMediaType -match 'Native 802.11' -or $a.MediaType -match 'Wireless' -or $a.NdisPhysicalMediaType -eq 9)

    $result += [PSCustomObject]@{
        InterfaceIndex = $idx
        Name = $alias
        Description = $desc
        Guid = $guid
        Status = [string]$a.Status
        IsVirtual = [bool]$a.Virtual
        IsWireless = [bool]$isWireless
        Ipv4Servers = $v4Servers
        Ipv4IsDhcp = $v4IsDhcp
        Ipv6Servers = $v6Servers
        Ipv6IsDhcp = $v6IsDhcp
    }
}
$result | ConvertTo-Json -Compress
";
        string output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        output = CleanJsonOutput(output);
        if (string.IsNullOrWhiteSpace(output)) return Array.Empty<NetworkAdapterDnsInfo>();

        try
        {
            if (output.StartsWith('['))
            {
                var list = JsonSerializer.Deserialize<List<NetworkAdapterDnsInfo>>(output);
                return list ?? (IReadOnlyList<NetworkAdapterDnsInfo>)Array.Empty<NetworkAdapterDnsInfo>();
            }
            else
            {
                var single = JsonSerializer.Deserialize<NetworkAdapterDnsInfo>(output);
                return single is not null ? new[] { single } : Array.Empty<NetworkAdapterDnsInfo>();
            }
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Could not parse network adapter information: {ex.Message}. Output: {output}", ex);
        }
    }

    public async Task ApplyDnsAsync(IEnumerable<int> interfaceIndexes, bool onlyLocal, IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
    {
        var backupMap = backups.ToDictionary(b => b.InterfaceIndex);
        var sb = new StringBuilder();
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");

        foreach (int idx in interfaceIndexes)
        {
            var servers = new List<string> { "127.0.0.1" };

            if (backupMap.TryGetValue(idx, out var b))
            {
                if (!onlyLocal)
                {
                    foreach (var s in b.Ipv4Servers)
                    {
                        if (!s.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) && !servers.Contains(s))
                            servers.Add(s);
                    }
                }

                if (b.Ipv6Servers.Count > 0)
                {
                    servers.Add("::1");
                    if (!onlyLocal)
                    {
                        foreach (var s in b.Ipv6Servers)
                        {
                            if (!s.Equals("::1", StringComparison.OrdinalIgnoreCase) && !servers.Contains(s))
                                servers.Add(s);
                        }
                    }
                }
            }

            string serverList = string.Join(",", servers.Select(s => $"'{s}'"));
            sb.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({serverList}) -ErrorAction Stop");
        }

        await RunPowerShellAsync(sb.ToString(), ct).ConfigureAwait(false);
    }

    public async Task RestoreDnsAsync(IReadOnlyList<AdapterDnsBackup> backups, CancellationToken ct = default)
    {
        if (backups.Count == 0) return;

        var sb = new StringBuilder();
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");

        foreach (var b in backups)
        {
            if (b.Ipv4IsDhcp && b.Ipv6IsDhcp)
            {
                // Full DHCP adapter: reset to automatic DHCP assignment
                sb.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ResetServerAddresses -ErrorAction SilentlyContinue");
            }
            else
            {
                // Static servers: restore original list
                var servers = b.Ipv4Servers.Concat(b.Ipv6Servers).ToList();
                if (servers.Count > 0)
                {
                    string serverList = string.Join(",", servers.Select(s => $"'{s}'"));
                    sb.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ServerAddresses @({serverList}) -ErrorAction SilentlyContinue");
                }
                else
                {
                    sb.AppendLine($"Set-DnsClientServerAddress -InterfaceIndex {b.InterfaceIndex} -ResetServerAddresses -ErrorAction SilentlyContinue");
                }
            }
        }

        await RunPowerShellAsync(sb.ToString(), ct).ConfigureAwait(false);
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

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProcessTimeout);

        try
        {
            await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("The PowerShell network command timed out.");
        }

        string stdout = await stdoutTask.ConfigureAwait(false);
        string stderr = await stderrTask.ConfigureAwait(false);

        if (proc.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
        {
            throw new InvalidOperationException($"PowerShell command failed (exit code {proc.ExitCode}): {stderr.Trim()}");
        }

        return stdout;
    }

    private static string CleanJsonOutput(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";

        int startArray = raw.IndexOf('[');
        int startObj = raw.IndexOf('{');

        int start = -1;
        if (startArray >= 0 && startObj >= 0) start = Math.Min(startArray, startObj);
        else if (startArray >= 0) start = startArray;
        else if (startObj >= 0) start = startObj;

        if (start < 0) return "";

        int endArray = raw.LastIndexOf(']');
        int endObj = raw.LastIndexOf('}');
        int end = Math.Max(endArray, endObj);

        if (end < start) return "";
        return raw.Substring(start, end - start + 1);
    }
}
