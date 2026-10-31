using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows.Mobile;

/// <summary>
/// High-performance local LAN HTTP &amp; HTTPS CONNECT Smart Proxy Hub (Port 8888) with WPAD PAC support.
/// When a phone or Smart TV configures this proxy (Manual: PC_IP:8888 or Auto-Config: http://PC_IP:8888/wpad.dat),
/// 100% of HTTP/HTTPS domain requests are routed through Spectra's blocklist engine and logged per-device,
/// completely eliminating IPv6 DNS bypass, Chrome DoH bypass, and Android Private DNS (DoT) bypass without needing SSL certificates.
/// </summary>
public sealed class SpectraProxyServer : IDisposable
{
    private readonly int _port;
    private readonly ClientAccessPolicy _accessPolicy = new(restrictToLocal: true);
    private readonly ConcurrentDictionary<string, DateTime> _recentAllowedLogGate = new(StringComparer.OrdinalIgnoreCase);
    private TcpListener? _listenerV4;
    private TcpListener? _listenerV6;
    private CancellationTokenSource? _cts;
    private long _totalRequests;
    private long _blockedRequests;

    public int Port => _port;
    public bool IsRunning { get; private set; }
    public long TotalRequests => Interlocked.Read(ref _totalRequests);
    public long BlockedRequests => Interlocked.Read(ref _blockedRequests);

    /// <summary>
    /// Evaluates whether a domain is blocked or allowed for the given client IP.
    /// </summary>
    public Func<IPAddress, string, FilterDecision>? DecideDomain { get; set; }

    /// <summary>
    /// Returns the host PC's active LAN IPv4 address for WPAD generation.
    /// </summary>
    public Func<string>? GetServerLanIp { get; set; }

    /// <summary>
    /// Fired whenever a proxy request or blocked ad domain is processed from a LAN device.
    /// </summary>
    public event Action<DnsLogEntry>? ProxyActivityLogged;

    public SpectraProxyServer(int port = 8888)
    {
        _port = port;
    }

    public void Start()
    {
        if (IsRunning) return;

        try
        {
            _cts = new CancellationTokenSource();
            _listenerV4 = new TcpListener(IPAddress.Any, _port);
            _listenerV4.Start();
            _ = Task.Run(() => AcceptLoopAsync(_listenerV4, _cts.Token));

            if (Socket.OSSupportsIPv6)
            {
                try
                {
                    _listenerV6 = new TcpListener(IPAddress.IPv6Any, _port);
                    _listenerV6.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
                    _listenerV6.Start();
                    _ = Task.Run(() => AcceptLoopAsync(_listenerV6, _cts.Token));
                }
                catch
                {
                    try { _listenerV6?.Stop(); } catch { }
                    _listenerV6 = null;
                }
            }

            IsRunning = true;
        }
        catch
        {
            Stop();
            throw;
        }
    }

    public void Stop()
    {
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _listenerV4?.Stop(); } catch { }
        try { _listenerV6?.Stop(); } catch { }
        _listenerV4 = null;
        _listenerV6 = null;
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                var remoteEp = client.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEp == null) return;

                var clientAddr = remoteEp.Address.IsIPv4MappedToIPv6 ? remoteEp.Address.MapToIPv4() : remoteEp.Address;
                if (clientAddr.AddressFamily == AddressFamily.InterNetworkV6 && clientAddr.ScopeId != 0)
                    clientAddr = new IPAddress(clientAddr.GetAddressBytes());

                if (!_accessPolicy.IsAllowed(clientAddr))
                    return;

                string clientIpStr = DnsClientMatch.NormalizeIp(clientAddr.ToString());
                var stream = client.GetStream();

                // Read HTTP request header block (up to \r\n\r\n)
                var headerBytes = await ReadHeaderBytesAsync(stream, ct).ConfigureAwait(false);
                if (headerBytes.Count == 0) return;

                string headerText = Encoding.ASCII.GetString(headerBytes.Array!, 0, headerBytes.Count);
                var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
                if (lines.Length == 0 || string.IsNullOrWhiteSpace(lines[0])) return;

                var reqParts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                if (reqParts.Length < 2) return;

                string method = reqParts[0].ToUpperInvariant();
                string rawTarget = reqParts[1];
                string httpVer = reqParts.Length > 2 ? reqParts[2] : "HTTP/1.1";

                // 1. Direct WPAD / PAC auto-config request (http://PC_IP:8888/wpad.dat or /proxy.pac)
                if (method == "GET" && (rawTarget.Equals("/wpad.dat", StringComparison.OrdinalIgnoreCase) ||
                                        rawTarget.Equals("/proxy.pac", StringComparison.OrdinalIgnoreCase) ||
                                        rawTarget.EndsWith("/wpad.dat", StringComparison.OrdinalIgnoreCase)))
                {
                    string lanIp = GetServerLanIp?.Invoke() ?? "192.168.178.203";
                    string pac = $$"""
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "10.*")) {
        return "DIRECT";
    }
    return "PROXY {{lanIp}}:{{_port}}; DIRECT";
}
""";
                    byte[] body = Encoding.UTF8.GetBytes(pac);
                    string respHdr = $"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n";
                    byte[] hdrBuf = Encoding.ASCII.GetBytes(respHdr);
                    await stream.WriteAsync(hdrBuf, ct).ConfigureAwait(false);
                    await stream.WriteAsync(body, ct).ConfigureAwait(false);
                    return;
                }

                // 2. HTTPS CONNECT Tunnel (e.g. CONNECT www.youtube.com:443 HTTP/1.1)
                if (method == "CONNECT")
                {
                    var sw = Stopwatch.StartNew();
                    ParseHostPort(rawTarget, 443, out string host, out int port);
                    if (string.IsNullOrWhiteSpace(host)) return;

                    Interlocked.Increment(ref _totalRequests);
                    string normDomain = DomainFilter.Normalize(host);

                    var decision = DecideDomain?.Invoke(clientAddr, normDomain)
                                   ?? new FilterDecision(FilterAction.None, "");

                    if (decision.Action == FilterAction.Blocked)
                    {
                        Interlocked.Increment(ref _blockedRequests);
                        LogProxyQuery(clientIpStr, normDomain, "HTTPS", DnsOutcome.Blocked, $"proxy sinkholed ({decision.Reason})", (int)sw.ElapsedMilliseconds, forceLog: true);

                        byte[] forbidden = Encoding.ASCII.GetBytes($"{httpVer} 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        await stream.WriteAsync(forbidden, ct).ConfigureAwait(false);
                        return;
                    }

                    using var remoteTcp = new TcpClient();
                    remoteTcp.NoDelay = true;
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    connectCts.CancelAfter(TimeSpan.FromSeconds(8));

                    IPAddress? connectedIp = null;
                    try
                    {
                        await remoteTcp.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
                        connectedIp = (remoteTcp.Client.RemoteEndPoint as IPEndPoint)?.Address;
                    }
                    catch (Exception ex)
                    {
                        LogProxyQuery(clientIpStr, normDomain, "HTTPS", DnsOutcome.Failed, $"connect error: {ex.Message}", (int)sw.ElapsedMilliseconds, forceLog: false);
                        byte[] badGw = Encoding.ASCII.GetBytes($"{httpVer} 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        try { await stream.WriteAsync(badGw, ct).ConfigureAwait(false); } catch { }
                        return;
                    }

                    LogProxyQuery(clientIpStr, normDomain, "HTTPS", DnsOutcome.Forwarded,
                        connectedIp != null ? $"{connectedIp}:{port} (Proxy Tunnel)" : $"Port {port} (Proxy Tunnel)",
                        (int)sw.ElapsedMilliseconds, forceLog: false);

                    byte[] established = Encoding.ASCII.GetBytes($"{httpVer} 200 Connection Established\r\n\r\n");
                    await stream.WriteAsync(established, ct).ConfigureAwait(false);

                    var remoteStream = remoteTcp.GetStream();
                    var t1 = stream.CopyToAsync(remoteStream, 16384, ct);
                    var t2 = remoteStream.CopyToAsync(stream, 16384, ct);
                    await Task.WhenAny(t1, t2).ConfigureAwait(false);
                    return;
                }

                // 3. Plain HTTP Proxy Request (e.g. GET http://example.com/index.html HTTP/1.1)
                {
                    var sw = Stopwatch.StartNew();
                    string host = "";
                    int port = 80;
                    string relativePath = rawTarget;

                    if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var absUri) && (absUri.Scheme == "http" || absUri.Scheme == "https"))
                    {
                        host = absUri.Host;
                        port = absUri.Port > 0 ? absUri.Port : 80;
                        relativePath = string.IsNullOrEmpty(absUri.PathAndQuery) ? "/" : absUri.PathAndQuery;
                    }
                    else
                    {
                        for (int i = 1; i < lines.Length; i++)
                        {
                            if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                            {
                                ParseHostPort(lines[i][5..].Trim(), 80, out host, out port);
                                break;
                            }
                        }
                    }

                    if (string.IsNullOrWhiteSpace(host)) return;

                    Interlocked.Increment(ref _totalRequests);
                    string normDomain = DomainFilter.Normalize(host);

                    var decision = DecideDomain?.Invoke(clientAddr, normDomain)
                                   ?? new FilterDecision(FilterAction.None, "");

                    if (decision.Action == FilterAction.Blocked)
                    {
                        Interlocked.Increment(ref _blockedRequests);
                        LogProxyQuery(clientIpStr, normDomain, "HTTP", DnsOutcome.Blocked, $"proxy sinkholed ({decision.Reason})", (int)sw.ElapsedMilliseconds, forceLog: true);

                        byte[] forbidden = Encoding.ASCII.GetBytes($"{httpVer} 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\nBlocked by Spectra Shield.");
                        await stream.WriteAsync(forbidden, ct).ConfigureAwait(false);
                        return;
                    }

                    using var remoteTcp = new TcpClient();
                    remoteTcp.NoDelay = true;
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    connectCts.CancelAfter(TimeSpan.FromSeconds(8));

                    await remoteTcp.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
                    var connectedIp = (remoteTcp.Client.RemoteEndPoint as IPEndPoint)?.Address;

                    LogProxyQuery(clientIpStr, normDomain, "HTTP", DnsOutcome.Forwarded,
                        connectedIp != null ? $"{connectedIp}:{port} (HTTP Proxy)" : $"Port {port} (HTTP Proxy)",
                        (int)sw.ElapsedMilliseconds, forceLog: false);

                    var remoteStream = remoteTcp.GetStream();

                    // Rebuild request with relative path and Connection: close
                    var sb = new StringBuilder();
                    sb.Append($"{method} {relativePath} {httpVer}\r\n");
                    for (int i = 1; i < lines.Length; i++)
                    {
                        string line = lines[i];
                        if (string.IsNullOrEmpty(line)) continue;
                        if (line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase)) continue;
                        sb.Append(line).Append("\r\n");
                    }
                    sb.Append("\r\n");

                    byte[] rebuiltHdr = Encoding.ASCII.GetBytes(sb.ToString());
                    await remoteStream.WriteAsync(rebuiltHdr, ct).ConfigureAwait(false);

                    var t1 = remoteStream.CopyToAsync(stream, 16384, ct);
                    var t2 = stream.CopyToAsync(remoteStream, 16384, ct);
                    await Task.WhenAny(t1, t2).ConfigureAwait(false);
                }
            }
            catch
            {
                // Client or upstream closed connection
            }
        }
    }

    private void LogProxyQuery(string clientIp, string domain, string type, DnsOutcome outcome, string detail, int ms, bool forceLog)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;

        if (!forceLog)
        {
            string gateKey = $"{clientIp}|{domain}";
            var now = DateTime.UtcNow;
            if (_recentAllowedLogGate.TryGetValue(gateKey, out var lastTime) && (now - lastTime).TotalSeconds < 2.5)
            {
                return; // Deduplicate parallel socket connections to the exact same domain within 2.5s
            }
            _recentAllowedLogGate[gateKey] = now;

            if (_recentAllowedLogGate.Count > 2000)
            {
                _recentAllowedLogGate.Clear();
            }
        }

        var entry = new DnsLogEntry(DateTimeOffset.Now, clientIp, domain, type, outcome, detail, ms);
        ProxyActivityLogged?.Invoke(entry);
    }

    private static async Task<ArraySegment<byte>> ReadHeaderBytesAsync(NetworkStream stream, CancellationToken ct)
    {
        byte[] buf = new byte[8192];
        int total = 0;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

        while (total < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(total, 1), timeoutCts.Token).ConfigureAwait(false);
            if (n <= 0) break;
            total += n;

            if (total >= 4 &&
                buf[total - 4] == '\r' &&
                buf[total - 3] == '\n' &&
                buf[total - 2] == '\r' &&
                buf[total - 1] == '\n')
            {
                return new ArraySegment<byte>(buf, 0, total);
            }
        }

        return new ArraySegment<byte>(buf, 0, total);
    }

    private static void ParseHostPort(string input, int defaultPort, out string host, out int port)
    {
        host = "";
        port = defaultPort;
        if (string.IsNullOrWhiteSpace(input)) return;

        string s = input.Trim();
        if (s.StartsWith('['))
        {
            int closeBracket = s.IndexOf(']');
            if (closeBracket > 0)
            {
                host = s[1..closeBracket];
                if (closeBracket + 2 < s.Length && s[closeBracket + 1] == ':' && int.TryParse(s[(closeBracket + 2)..], out int p6))
                {
                    port = p6;
                }
                return;
            }
        }

        int colon = s.LastIndexOf(':');
        if (colon > 0 && colon < s.Length - 1 && int.TryParse(s[(colon + 1)..], out int p))
        {
            host = s[..colon];
            port = p;
        }
        else
        {
            host = s;
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
