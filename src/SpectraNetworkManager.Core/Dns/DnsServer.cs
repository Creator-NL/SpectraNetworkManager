using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SpectraNetworkManager.Sinkhole;

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
    private readonly Func<bool>? _isBlockingPaused;
    private readonly ClientAccessPolicy _clientAccessPolicy;
    private readonly DnsRateLimiter _rateLimiter;
    private readonly ClientGroupManager _groupManager;
    private readonly ConditionalForwarder _conditionalForwarder;
    private readonly DnsHistoryDatabase? _historyDb;
    private readonly SemaphoreSlim _slots = new(MaxParallel, MaxParallel);

    private CancellationTokenSource? _cts;
    private UdpClient? _udp;
    private TcpListener? _tcp;

    public DnsServer(
        DnsSettings settings,
        Func<DomainFilter> filter,
        IUpstreamResolver upstream,
        DnsCache cache,
        DnsActivity activity,
        Func<bool>? isBlockingPaused = null,
        ClientAccessPolicy? clientAccessPolicy = null,
        DnsRateLimiter? rateLimiter = null,
        ClientGroupManager? groupManager = null,
        ConditionalForwarder? conditionalForwarder = null,
        DnsHistoryDatabase? historyDb = null)
    {
        _settings = settings;
        _filter = filter;
        _upstream = upstream;
        _cache = cache;
        _activity = activity;
        _isBlockingPaused = isBlockingPaused;
        _clientAccessPolicy = clientAccessPolicy ?? new ClientAccessPolicy(settings.RestrictClientsToLocalNetwork, settings.AllowedClientRanges);
        _rateLimiter = rateLimiter ?? new DnsRateLimiter(settings.RateLimitPerSecond);
        _groupManager = groupManager ?? new ClientGroupManager(settings.ClientGroups, filter);
        _conditionalForwarder = conditionalForwarder ?? new ConditionalForwarder(settings.ConditionalForwarding);
        _historyDb = historyDb;
    }

    public ClientAccessPolicy ClientAccess => _clientAccessPolicy;
    public DnsRateLimiter RateLimiter => _rateLimiter;
    public ClientGroupManager GroupManager => _groupManager;
    public ConditionalForwarder ConditionalForwarding => _conditionalForwarder;

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

    public void Dispose()
    {
        Stop();
        _conditionalForwarder.Dispose();
    }

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

            if (!_rateLimiter.TryAcquireQuery(packet.RemoteEndPoint.Address))
                continue;                                           // rate limited: drop silently to prevent amplification

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

            var remoteAddress = client.Client.RemoteEndPoint is IPEndPoint rep ? rep.Address : IPAddress.Loopback;
            if (!_rateLimiter.TryAcquireTcp(remoteAddress, out var lease) || lease is null)
            {
                client.Dispose();
                continue;
            }

            _ = Task.Run(async () =>
            {
                using (lease)
                {
                    await TcpClientAsync(client, ct);
                }
            }, ct);
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

                    if (!_rateLimiter.TryAcquireQuery(remote.Address))
                        return;                                     // client flooding queries over TCP: disconnect

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
            _historyDb?.Enqueue(entry, _settings.AnonymizeClientIps, _settings.DoNotStoreDomains);
            Queried?.Invoke(entry);
        }

        if (!_clientAccessPolicy.IsAllowed(client.Address))
        {
            Log(DnsOutcome.Refused, "query from public/untrusted client IP refused");
            return DnsWire.BuildError(q, DnsRcode.Refused);
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

        // F6: Answer loopback PTR queries locally with "localhost"
        if (DnsWire.IsLoopbackPtr(domain))
        {
            Log(DnsOutcome.Forwarded, "loopback PTR (localhost)");
            return Fit(DnsWire.BuildLoopbackPtrAnswer(q), q, tcp);
        }

        // Authoritative custom local records (A, AAAA, CNAME, PTR, TXT)
        if (_settings.LocalRecords.Count > 0)
        {
            var match = _settings.LocalRecords.FirstOrDefault(r => r.Enabled && string.Equals(r.Domain.Trim(), domain, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                byte[]? localAns = DnsWire.BuildLocalRecordAnswer(q, match);
                if (localAns is not null)
                {
                    Log(DnsOutcome.Forwarded, $"local {match.RecordType} record");
                    return Fit(localAns, q, tcp);
                }
            }
        }

        // Firefox asks this name to find out whether it may switch to its own DNS-over-HTTPS (which would bypass us).
        if (_settings.BlockBrowserDoh && domain == FirefoxCanary)
        {
            Log(DnsOutcome.Blocked, "browser DoH check (tells Firefox to keep using this DNS server)");
            return Fit(DnsWire.BuildError(q, DnsRcode.NxDomain), q, tcp);
        }

        bool paused = _isBlockingPaused?.Invoke() == true;
        var (group, groupFilter, groupBlocking) = _groupManager.GetGroupForClient(client.Address);
        bool effectiveBlocking = !paused && groupBlocking;

        var decision = effectiveBlocking
            ? groupFilter.Decide(domain)
            : new FilterDecision(FilterAction.Allowed, paused ? "blocking paused" : $"blocking disabled for {group.Name}");

        if (decision.Action == FilterAction.Blocked)
        {
            Log(DnsOutcome.Blocked, decision.Reason);
            return Fit(BlockedAnswer(q, group.BlockModeOverride ?? _settings.BlockMode), q, tcp);
        }

        // RFC 8482: return minimal HINFO response for ANY queries to mitigate amplification abuse
        if (q.Question.Type == DnsType.ANY)
        {
            Log(DnsOutcome.Forwarded, "RFC 8482 ANY minimal response");
            return Fit(DnsWire.BuildRfc8482Hinfo(q), q, tcp);
        }

        string key = DnsCache.Key(q.Question);
        var cached = _cache.TryGet(key, q.Id, DateTimeOffset.Now);
        if (cached is not null)
        {
            Log(DnsOutcome.Cached, decision.Action == FilterAction.Allowed ? decision.Reason : null);
            return Fit(cached, q, tcp);
        }

        byte[]? answer = null;
        try
        {
            // Conditional forwarding routes specific domain suffixes directly to local routers
            answer = await _conditionalForwarder.TryForwardAsync(domain, raw, tcp, ct).ConfigureAwait(false);
            if (answer is null)
            {
                answer = await _upstream.ResolveAsync(raw, tcp, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { return null; }

        if (answer is null)
        {
            Log(DnsOutcome.Failed, "no upstream server answered");
            return Fit(DnsWire.BuildError(q, DnsRcode.ServFail), q, tcp);
        }

        // A harmless-looking name that is only an alias for a blocked name is blocked too (unless you allowed the name itself or blocking is paused).
        if (_settings.InspectCnames && effectiveBlocking && decision.Action != FilterAction.Allowed)
        {
            foreach (var target in DnsWire.CnameTargets(answer))
            {
                var d = groupFilter.Decide(target);
                if (d.Action == FilterAction.Blocked)
                {
                    Log(DnsOutcome.Blocked, $"alias of {target} ({d.Reason})");
                    return Fit(BlockedAnswer(q, group.BlockModeOverride ?? _settings.BlockMode), q, tcp);
                }
            }
        }

        _cache.Put(key, answer, DateTimeOffset.Now);
        Log(DnsOutcome.Forwarded, decision.Action == FilterAction.Allowed ? decision.Reason : null);
        return Fit(answer, q, tcp);
    }

    private static byte[] BlockedAnswer(DnsQuery q, BlockMode mode) =>
        mode == BlockMode.NxDomain ? DnsWire.BuildError(q, DnsRcode.NxDomain) : DnsWire.BuildNullAnswer(q, BlockedTtl);

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
