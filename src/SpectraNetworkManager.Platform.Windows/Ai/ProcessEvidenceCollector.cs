using System.Diagnostics;
using System.Runtime.Versioning;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ai;

namespace SpectraNetworkManager.Platform.Windows.Ai;

[SupportedOSPlatform("windows5.1.2600")]
public static class ProcessEvidenceCollector
{
    public static VerifiedProcessEvidence CollectForPid(
        int pid,
        ProcessResolver resolver,
        ExecutableHashCache hashCache,
        IReadOnlyList<StartupEntry>? startupEntries = null,
        IReadOnlyList<DiscoveredPort>? localSockets = null,
        IReadOnlyList<ConnectionHistoryRecord>? recentConnections = null)
    {
        var procInfo = resolver.Resolve(pid);
        string? path = procInfo.Path;
        string procName = !string.IsNullOrWhiteSpace(procInfo.Name) ? procInfo.Name : (path != null ? Path.GetFileName(path) : $"PID {pid}");

        return BuildEvidence(
            pid,
            procName,
            path,
            procInfo.StartTimeUtc,
            procInfo.ParentPid,
            procInfo.ParentName,
            procInfo.CommandLine,
            procInfo.ServiceNames,
            hashCache,
            startupEntries,
            localSockets,
            recentConnections);
    }

    public static VerifiedProcessEvidence CollectForPath(
        string path,
        ExecutableHashCache hashCache,
        IReadOnlyList<StartupEntry>? startupEntries = null,
        IReadOnlyList<DiscoveredPort>? localSockets = null,
        IReadOnlyList<ConnectionHistoryRecord>? recentConnections = null)
    {
        string procName = Path.GetFileName(path);
        return BuildEvidence(
            0,
            procName,
            path,
            null,
            null,
            null,
            null,
            null,
            hashCache,
            startupEntries,
            localSockets,
            recentConnections);
    }

    private static VerifiedProcessEvidence BuildEvidence(
        int pid,
        string processName,
        string? path,
        DateTimeOffset? startTimeUtc,
        int? parentPid,
        string? parentName,
        string? commandLine,
        string? serviceNames,
        ExecutableHashCache hashCache,
        IReadOnlyList<StartupEntry>? startupEntries,
        IReadOnlyList<DiscoveredPort>? localSockets,
        IReadOnlyList<ConnectionHistoryRecord>? recentConnections)
    {
        string? fileDescription = null;
        string? companyName = null;
        string? fileVersion = null;
        string? sha256 = null;
        SignatureInfo signature = new(SignatureStatus.Unknown, null, false);
        var services = new List<string>();
        var startups = new List<string>();
        var connections = new List<string>();
        var listeningPorts = new List<int>();
        var flags = new List<string>();

        if (!string.IsNullOrWhiteSpace(serviceNames))
        {
            foreach (var s in serviceNames.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                services.Add(s);
            }
        }

        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                fileDescription = vi.FileDescription;
                companyName = vi.CompanyName;
                fileVersion = vi.FileVersion;
            }
            catch { }

            try
            {
                sha256 = hashCache.GetSha256(path);
            }
            catch { }

            try
            {
                signature = NativeAuthenticodeVerifier.VerifyFile(path);
            }
            catch { }

            // Check associated startup entries
            if (startupEntries != null)
            {
                foreach (var entry in startupEntries)
                {
                    if (string.Equals(entry.ExecutablePath, path, StringComparison.OrdinalIgnoreCase))
                    {
                        startups.Add($"{entry.Name} ({entry.LocationDisplay})");
                    }
                }
            }

            // Check matching services if none assigned yet
            if (services.Count == 0 && pid > 0)
            {
                try
                {
                    var foundSvcs = WindowsServiceManager.GetServicesForPid(pid);
                    if (foundSvcs != null && foundSvcs.Count > 0)
                        services.AddRange(foundSvcs.Select(s => s.ServiceName));
                }
                catch { }
            }
        }

        // Match listening ports for this PID
        if (pid > 0 && localSockets != null)
        {
            foreach (var sock in localSockets)
            {
                if (sock.OwningPid == pid && !listeningPorts.Contains(sock.Port))
                {
                    listeningPorts.Add(sock.Port);
                }
            }
        }

        // Match recent network connections for this program/path
        if (recentConnections != null && !string.IsNullOrWhiteSpace(path))
        {
            foreach (var conn in recentConnections)
            {
                if (string.Equals(conn.Program, path, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(conn.Program, processName, StringComparison.OrdinalIgnoreCase))
                {
                    string entry = $"{conn.Proto} -> {conn.Remote}:{conn.Port}";
                    if (!connections.Contains(entry))
                        connections.Add(entry);
                    if (connections.Count >= 10) break;
                }
            }
        }

        // Location & Masquerade checks
        string safePath = path ?? "";
        bool inTemp = safePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                      safePath.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase);
        bool inDownloads = safePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase);
        bool inSystem32 = safePath.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
                          safePath.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase);

        string nameLower = processName.ToLowerInvariant();
        bool isKnownSystemName = nameLower is "svchost.exe" or "explorer.exe" or "csrss.exe" or "lsass.exe" or "services.exe";
        bool isMasquerading = isKnownSystemName && !inSystem32 && !safePath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);

        if (isMasquerading)
            flags.Add("NameMasquerade");
        if (inTemp)
            flags.Add("RunsFromTemp");
        if (inDownloads)
            flags.Add("RunsFromDownloads");
        if (services.Count > 0)
            flags.Add("RunsAsService");
        if (startups.Count > 0)
            flags.Add("AutoStartPersistence");
        if (listeningPorts.Count > 0 && !signature.IsValid)
            flags.Add("UnsignedNetworkListener");

        // Identity Verification Level determination
        IdentityVerificationLevel level;
        int confidence;

        if (isMasquerading || inTemp || inDownloads)
        {
            level = IdentityVerificationLevel.SuspiciousLocation;
            confidence = 85;
        }
        else if (signature.IsAlarming)
        {
            level = IdentityVerificationLevel.TamperedOrUntrusted;
            confidence = 90;
        }
        else if (signature is { IsValid: true, IsOsBinary: true })
        {
            level = IdentityVerificationLevel.VerifiedSystemBinary;
            confidence = 98;
        }
        else if (signature.IsValid)
        {
            level = IdentityVerificationLevel.VerifiedPublisherBinary;
            confidence = 92;
        }
        else if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            level = IdentityVerificationLevel.UnsignedOrUnverified;
            confidence = 60;
        }
        else
        {
            level = IdentityVerificationLevel.EphemeralOrExited;
            confidence = 30;
        }

        return new VerifiedProcessEvidence
        {
            Pid = pid,
            ProcessName = processName,
            ExecutablePath = path,
            ProcessStartTimeUtc = startTimeUtc,
            FileDescription = fileDescription,
            CompanyName = companyName,
            FileVersion = fileVersion,
            Sha256 = sha256,
            SignatureStatus = signature.Status,
            Publisher = signature.Publisher,
            IsOsBinary = signature.IsOsBinary,
            ParentPid = parentPid,
            ParentProcessName = parentName,
            CommandLine = PromptSanitizer.Sanitize(commandLine, 512),
            Services = services,
            StartupEntries = startups,
            ActiveConnections = connections,
            ListeningPorts = listeningPorts,
            VerificationLevel = level,
            DeterministicConfidenceScore = confidence,
            SecurityFlags = flags
        };
    }
}
