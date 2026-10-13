using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Sinkhole;

/// <summary>
/// The DNS sinkhole: answers queries on UDP and TCP, blocks names on your lists, caches answers and forwards the rest
/// to your upstream servers. Every query ends up in <see cref="DnsActivity"/>.
/// </summary>
public sealed class DnsServer : IDisposable
{
    private const int MaxParallel = 256;
    private const string FirefoxCanary = "use-application-dns.net";
    private const uint BlockedTtl = 30;

    private readonly DnsSettings _settings;
    private readonly Func<DomainFilter> _filter;
    private readonly IUpstreamResolver _upstream;
    private readonly DnsCache _cache;
    private readonly DnsActivity _activity;
    private readonly SemaphoreSlim _slots = new(MaxParallel, MaxParallel);

    private CancellationTokenSource? _cts;
    private UdpClient? _udp;
    private TcpListener? _tcp;

    public DnsServer(DnsSettings settings, Func<DomainFilter> filter, IUpstreamResolver upstream, DnsCache cache, DnsActivity activity)
    {
        _settings = settings;
        _filter = filter;
        _upstream = upstream;
        _cache = cache;
        _activity = activity;
    }

    public bool IsRunning => _cts is not null;
    public IPEndPoint? LocalEndPoint { get; private set; }

    /// <summary>Raised for every answered query (on a background thread).</summary>
    public event Action<DnsLogEntry>? Queried;

    /// <summary>Binds the sockets and starts answering. Throws a SocketException when the address or port is already in use.</summary>
    public void Start()
    {
        if (IsRunning) return;

        var address = IPAddress.Parse(_settings.ListenAddress);
        var endpoint = new IPEndPoint(address, _settings.Port);

        var udp = new UdpClient(endpoint.AddressFamily);
        TcpListener? tcp = null;
        try
        {
            udp.Client.Bind(endpoint);
            if (OperatingSystem.IsWindows())
            {
                try { udp.Client.IOControl((IOControlCode)(-1744830452), new byte[] { 0 }, null); }   // SIO_UDP_CONNRESET: ignore "port unreachable" echoes
                catch (Exception) { /* not essential */ }
            }

            // With port 0 (tests) the system picks one; use the same one for TCP.
            var bound = (IPEndPoint)udp.Client.LocalEndPoint!;
            tcp = new TcpListener(bound.Address, bound.Port);
            tcp.Start();
        }
        catch
        {
            udp.Dispose();
            tcp?.Stop();
            throw;
        }

        _udp = udp;
        _tcp = tcp;
        LocalEndPoint = (IPEndPoint)udp.Client.LocalEndPoint!;
        _cts = new CancellationTokenSource();

        var ct = _cts.Token;
        _ = Task.Run(() => UdpLoopAsync(udp, ct));
        _ = Task.Run(() => TcpLoopAsync(tcp, ct));
    }

    public void Stop()
    {
        var cts = _cts;
        if (cts is null) return;
        _cts = null;

        cts.Cancel();
        try { _udp?.Dispose(); } catch (Exception) { }
        try { _tcp?.Stop(); } catch (Exception) { }
        _udp = null;
        _tcp = null;
        LocalEndPoint = null;
        cts.Dispose();
    }

    public void Dispose() => Stop();

    // ---- transport -------------------------------------------------------------------------

    private async Task UdpLoopAsync(UdpClient udp, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await udp.ReceiveAsync(ct);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }                   // e.g. a client vanished; keep serving

            if (!_slots.Wait(0)) continue;                          // overloaded: drop, the client will retry

            _ = Task.Run(async () =>
            {
                try
                {
                    byte[]? answer = await HandleAsync(packet.Buffer, packet.RemoteEndPoint, tcp: false, ct);
                    if (answer is not null) await udp.SendAsync(answer, packet.RemoteEndPoint, ct);
                }
                catch (Exception) { /* a single bad query must never stop the server */ }
                finally { _slots.Release(); }
            }, ct);
        }
    }

    private async Task TcpLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (SocketException) { continue; }

            _ = Task.Run(() => TcpClientAsync(client, ct), ct);
        }
    }

    private async Task TcpClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
                var stream = client.GetStream();
                var lenBuf = new byte[2];

                while (!ct.IsCancellationRequested)
                {
                    using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    idle.CancelAfter(TimeSpan.FromSeconds(10));

                    await stream.ReadExactlyAsync(lenBuf, idle.Token);
                    int len = (lenBuf[0] << 8) | lenBuf[1];
                    if (len < 12) return;

                    var query = new byte[len];
                    await stream.ReadExactlyAsync(query, idle.Token);

                    byte[]? answer = await HandleAsync(query, remote, tcp: true, ct);
                    if (answer is null) return;

                    var framed = new byte[answer.Length + 2];
                    framed[0] = (byte)(answer.Length >> 8);
                    framed[1] = (byte)answer.Length;
                    Buffer.BlockCopy(answer, 0, framed, 2, answer.Length);
                    await stream.WriteAsync(framed, ct);
                }
            }
            catch (Exception) { /* connection closed, idle timeout or garbage: just end this connection */ }
        }
    }

    // ---- the actual DNS logic --------------------------------------------------------------

    internal async Task<byte[]?> HandleAsync(byte[] raw, IPEndPoint client, bool tcp, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        if (!DnsQuery.TryParse(raw, out var q, out _) || q is null)
            return DnsWire.BuildFormatError(raw);

        string clientText = client.Address.IsIPv4MappedToIPv6 ? client.Address.MapToIPv4().ToString() : client.Address.ToString();
        string domain = q.Question.Name;
        string type = TypeName(q.Question.Type);

        void Log(DnsOutcome outcome, string? detail)
        {
            var entry = new DnsLogEntry(DateTimeOffset.Now, clientText, domain, type, outcome, detail, (int)sw.ElapsedMilliseconds);
            _activity.Add(entry);
            Queried?.Invoke(entry);
        }

        if (q.Opcode != 0)
        {
            Log(DnsOutcome.Refused, "unsupported request type");
            return DnsWire.BuildError(q, DnsRcode.NotImp);
        }
        if (q.Question.Class != DnsQuestion.ClassIn)
        {
            Log(DnsOutcome.Refused, "unsupported class");
            return DnsWire.BuildError(q, DnsRcode.Refused);
        }

        // Firefox asks this name to find out whether it may switch to its own DNS-over-HTTPS (which would bypass us).
        if (_settings.BlockBrowserDoh && domain == FirefoxCanary)
        {
            Log(DnsOutcome.Blocked, "browser DoH check (tells Firefox to keep using this DNS server)");
            return Fit(DnsWire.BuildError(q, DnsRcode.NxDomain), q, tcp);
        }

        var filter = _filter();
        var decision = filter.Decide(domain);
        if (decision.Action == FilterAction.Blocked)
        {
            Log(DnsOutcome.Blocked, decision.Reason);
            return Fit(BlockedAnswer(q), q, tcp);
        }

        string key = DnsCache.Key(q.Question);
        var cached = _cache.TryGet(key, q.Id, DateTimeOffset.Now);
        if (cached is not null)
        {
            Log(DnsOutcome.Cached, decision.Action == FilterAction.Allowed ? decision.Reason : null);
            return Fit(cached, q, tcp);
        }

        byte[]? answer;
        try
        {
            answer = await _upstream.ResolveAsync(raw, tcp, ct);
        }
        catch (OperationCanceledException) { return null; }

        if (answer is null)
        {
            Log(DnsOutcome.Failed, "no upstream server answered");
            return Fit(DnsWire.BuildError(q, DnsRcode.ServFail), q, tcp);
        }

        // A harmless-looking name that is only an alias for a blocked name is blocked too (unless you allowed the name itself).
        if (_settings.InspectCnames && decision.Action != FilterAction.Allowed)
        {
            foreach (var target in DnsWire.CnameTargets(answer))
            {
                var d = filter.Decide(target);
                if (d.Action == FilterAction.Blocked)
                {
                    Log(DnsOutcome.Blocked, $"alias of {target} ({d.Reason})");
                    return Fit(BlockedAnswer(q), q, tcp);
                }
            }
        }

        _cache.Put(key, answer, DateTimeOffset.Now);
        Log(DnsOutcome.Forwarded, decision.Action == FilterAction.Allowed ? decision.Reason : null);
        return Fit(answer, q, tcp);
    }

    private byte[] BlockedAnswer(DnsQuery q) =>
        _settings.BlockMode == BlockMode.NxDomain ? DnsWire.BuildError(q, DnsRcode.NxDomain) : DnsWire.BuildNullAnswer(q, BlockedTtl);

    // UDP answers that do not fit the client's size limit are replaced by a "truncated" answer, so the client retries over TCP.
    private static byte[] Fit(byte[] response, DnsQuery q, bool tcp) =>
        !tcp && response.Length > q.MaxUdpPayload ? DnsWire.Truncate(response, q) : response;

    private static string TypeName(ushort type) => type switch
    {
        DnsType.A => "A", DnsType.AAAA => "AAAA", DnsType.CNAME => "CNAME", DnsType.MX => "MX", DnsType.NS => "NS",
        DnsType.PTR => "PTR", DnsType.SOA => "SOA", DnsType.SRV => "SRV", DnsType.TXT => "TXT", DnsType.HTTPS => "HTTPS",
        DnsType.ANY => "ANY", _ => "TYPE" + type,
    };
}
