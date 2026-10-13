using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Sinkhole;

/// <summary>One answer received by <see cref="DnsSelfTest.QueryAsync"/>.</summary>
public sealed record DnsProbeAnswer(int Rcode, IReadOnlyList<IPAddress> Addresses, int Milliseconds);

/// <summary>Outcome of the "Test my DNS server" button: overall result plus one line per check.</summary>
public sealed record DnsSelfTestResult(bool Ok, IReadOnlyList<string> Lines)
{
    public string Summary => string.Join("\n", Lines);
}

/// <summary>
/// Sends real DNS queries to our own server, on whatever port it listens on.
/// Needed because Windows' nslookup ignores "-port=" (seen on Windows build 26300), so it cannot test a server on port 5353.
/// </summary>
public static class DnsSelfTest
{
    /// <summary>Where to send test queries: "listen on every address" becomes the loopback address of the same family.</summary>
    public static IPEndPoint TargetFor(IPEndPoint listen)
    {
        if (listen.Address.Equals(IPAddress.Any)) return new IPEndPoint(IPAddress.Loopback, listen.Port);
        if (listen.Address.Equals(IPAddress.IPv6Any)) return new IPEndPoint(IPAddress.IPv6Loopback, listen.Port);
        return listen;
    }

    /// <summary>Asks <paramref name="server"/> for the A record of <paramref name="name"/> over UDP. Returns null when nothing answered in time.</summary>
    public static async Task<DnsProbeAnswer?> QueryAsync(IPEndPoint server, string name, TimeSpan timeout, CancellationToken ct = default)
    {
        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server);

        ushort id = (ushort)Random.Shared.Next(1, 65536);
        byte[] query = DnsWire.BuildQuery(name, DnsType.A, id);
        var sw = Stopwatch.StartNew();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await udp.SendAsync(query, cts.Token).ConfigureAwait(false);
            while (true)
            {
                var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                byte[] r = result.Buffer;
                if (r.Length >= 12 && r[0] == query[0] && r[1] == query[1])
                    return new DnsProbeAnswer(DnsWire.ResponseRcode(r), DnsWire.AddressAnswers(r), (int)sw.ElapsedMilliseconds);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;                                            // timed out
        }
        catch (SocketException)
        {
            return null;                                            // nothing listens there ("port unreachable")
        }
    }

    /// <summary>
    /// Checks that the server answers a normal name and, when <paramref name="blockedSample"/> is given, that it blocks that name.
    /// </summary>
    public static async Task<DnsSelfTestResult> RunAsync(IPEndPoint listen, string? blockedSample, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var target = TargetFor(listen);
        var wait = timeout ?? TimeSpan.FromSeconds(5);
        var lines = new List<string> { $"Testing the DNS server at {target}:" };
        bool ok = true;

        const string normalName = "example.com";
        var normal = await QueryAsync(target, normalName, wait, ct).ConfigureAwait(false);
        if (normal is null)
        {
            ok = false;
            lines.Add($"FAIL  {normalName}: no answer within {wait.TotalSeconds:0} seconds.");
        }
        else if (normal.Rcode != DnsRcode.NoError || normal.Addresses.Count == 0)
        {
            ok = false;
            lines.Add($"FAIL  {normalName}: the server answered, but with {RcodeText(normal.Rcode)}. Are the upstream servers reachable?");
        }
        else
        {
            lines.Add($"OK    {normalName} -> {normal.Addresses[0]} ({normal.Milliseconds} ms)");
        }

        if (blockedSample is null)
        {
            lines.Add("SKIP  Blocking not tested: no block list or 'Always block' rule is loaded yet.");
        }
        else
        {
            var blocked = await QueryAsync(target, blockedSample, wait, ct).ConfigureAwait(false);
            bool isBlocked = blocked is not null &&
                             (blocked.Rcode == DnsRcode.NxDomain ||
                              (blocked.Rcode == DnsRcode.NoError && blocked.Addresses.Count > 0 && blocked.Addresses.All(IsNullAddress)));
            if (isBlocked)
                lines.Add($"OK    {blockedSample} is blocked ({(blocked!.Rcode == DnsRcode.NxDomain ? "does not exist" : "0.0.0.0")}).");
            else
            {
                ok = false;
                lines.Add(blocked is null
                    ? $"FAIL  {blockedSample}: no answer."
                    : $"FAIL  {blockedSample} should be blocked, but the answer was {(blocked.Addresses.Count > 0 ? blocked.Addresses[0].ToString() : RcodeText(blocked.Rcode))}.");
            }
        }

        if (target.Port != 53)
            lines.Add($"Note: Windows' nslookup always uses port 53, so it cannot test port {target.Port}. This button can.");

        return new DnsSelfTestResult(ok, lines);
    }

    private static bool IsNullAddress(IPAddress a) => a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any);

    private static string RcodeText(int rcode) => rcode switch
    {
        DnsRcode.NoError => "an empty answer",
        DnsRcode.FormErr => "'format error'",
        DnsRcode.ServFail => "'server failure'",
        DnsRcode.NxDomain => "'does not exist'",
        DnsRcode.NotImp => "'not implemented'",
        DnsRcode.Refused => "'refused'",
        _ => $"error code {rcode}",
    };
}
