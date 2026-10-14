namespace SpectraNetworkManager.Core;

/// <summary>What one program is doing on the network right now. Firewall rules will be per program, so this is the natural unit.</summary>
public sealed record ProgramSummary(
    string Key,
    string Name,
    string? Path,
    int Processes,
    int Established,
    int Listening,
    int UdpEndpoints,
    int InternetPeers);

public static class ProgramAggregator
{
    public static IReadOnlyList<ProgramSummary> Summarize(IEnumerable<ConnectionView> views)
    {
        var groups = views
            .Where(v => v.Connection.ProcessId != 0)
            .Where(v => v.Connection.Protocol == Protocol.Udp || !Display.IsTeardownNoise(v.Connection.State))
            .GroupBy(v => v.Process.Path ?? v.Process.Name, StringComparer.OrdinalIgnoreCase);

        var result = new List<ProgramSummary>();
        foreach (var g in groups)
        {
            var first = g.First().Process;
            var internetPeers = g
                .Where(v => v.Connection.Protocol == Protocol.Tcp
                         && v.Connection.State is ConnectionState.Established or ConnectionState.SynSent
                         && v.Connection.Remote is not null
                         && !Display.IsLocalAddress(v.Connection.Remote.Address))
                .Select(v => v.Connection.Remote!.Address)
                .Distinct()
                .Count();

            result.Add(new ProgramSummary(
                Key: g.Key,
                Name: first.Name,
                Path: first.Path,
                Processes: g.Select(v => v.Connection.ProcessId).Distinct().Count(),
                Established: g.Count(v => v.Connection.Protocol == Protocol.Tcp && v.Connection.State == ConnectionState.Established),
                Listening: g.Count(v => v.Connection.Protocol == Protocol.Tcp && v.Connection.State == ConnectionState.Listen),
                UdpEndpoints: g.Count(v => v.Connection.Protocol == Protocol.Udp),
                InternetPeers: internetPeers));
        }

        return result.OrderByDescending(s => s.InternetPeers).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
