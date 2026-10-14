using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Upstream DNS resolver over DNS-over-TLS (RFC 7858) on port 853.
/// Uses 2-byte length-prefixed framing over SslStream with TLS 1.2 / 1.3.
/// </summary>
public sealed class DotUpstreamResolver : IUpstreamResolver, IDisposable
{
    private static readonly Dictionary<string, IReadOnlyList<IPAddress>> KnownBootstrapIps = new(StringComparer.OrdinalIgnoreCase)
    {
        ["dns.quad9.net"] = new[] { IPAddress.Parse("9.9.9.9"), IPAddress.Parse("149.112.112.112") },
        ["cloudflare-dns.com"] = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") },
        ["one.one.one.one"] = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") },
        ["dns.google"] = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4") },
        ["dns.adguard-dns.com"] = new[] { IPAddress.Parse("94.140.14.14"), IPAddress.Parse("94.140.15.15") }
    };

    private readonly string _host;
    private readonly int _port;
    private readonly TimeSpan _timeout;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private TcpClient? _tcp;
    private SslStream? _ssl;
    private DateTimeOffset _lastUsed = DateTimeOffset.MinValue;
    private bool _disposed;

    public string Host => _host;
    public int Port => _port;

    public DotUpstreamResolver(string host, int port = 853, TimeSpan? timeout = null)
    {
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Host cannot be empty", nameof(host));
        _host = host.Trim();
        _port = port is > 0 and <= 65535 ? port : 853;
        _timeout = timeout ?? TimeSpan.FromSeconds(3);
    }

    public async Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(_timeout);

        await _connectionLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
        try
        {
            // Attempt to send over current connection; if failed or idle > 30s, reconnect once
            bool idleExpired = (DateTimeOffset.UtcNow - _lastUsed) > TimeSpan.FromSeconds(30);
            if (_ssl is null || idleExpired)
            {
                await ReconnectAsync(linkedCts.Token).ConfigureAwait(false);
            }

            try
            {
                return await SendAndReceiveAsync(_ssl!, query, linkedCts.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Connection may have been severed by remote; reconnect and retry once
                await ReconnectAsync(linkedCts.Token).ConfigureAwait(false);
                return await SendAndReceiveAsync(_ssl!, query, linkedCts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            CloseCurrentConnection();
            return null;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private async Task<byte[]?> SendAndReceiveAsync(SslStream ssl, byte[] query, CancellationToken ct)
    {
        var framed = new byte[query.Length + 2];
        framed[0] = (byte)(query.Length >> 8);
        framed[1] = (byte)query.Length;
        Buffer.BlockCopy(query, 0, framed, 2, query.Length);

        await ssl.WriteAsync(framed, ct).ConfigureAwait(false);
        await ssl.FlushAsync(ct).ConfigureAwait(false);

        var lenBuf = new byte[2];
        await ssl.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
        int len = (lenBuf[0] << 8) | lenBuf[1];
        if (len < 12) return null;

        var answer = new byte[len];
        await ssl.ReadExactlyAsync(answer, ct).ConfigureAwait(false);

        _lastUsed = DateTimeOffset.UtcNow;
        if (answer[0] == query[0] && answer[1] == query[1]) return answer;

        var adjusted = (byte[])answer.Clone();
        adjusted[0] = query[0];
        adjusted[1] = query[1];
        return adjusted;
    }

    private async Task ReconnectAsync(CancellationToken ct)
    {
        CloseCurrentConnection();

        IReadOnlyList<IPAddress> targets;
        if (IPAddress.TryParse(_host, out var parsedIp))
        {
            targets = new[] { parsedIp };
        }
        else if (KnownBootstrapIps.TryGetValue(_host, out var ips))
        {
            targets = ips;
        }
        else
        {
            targets = await Dns.GetHostAddressesAsync(_host, ct).ConfigureAwait(false);
        }

        SocketException? lastEx = null;
        TcpClient? connectedClient = null;

        foreach (var ip in targets)
        {
            var tcp = new TcpClient(ip.AddressFamily)
            {
                NoDelay = true,
                ReceiveTimeout = (int)_timeout.TotalMilliseconds,
                SendTimeout = (int)_timeout.TotalMilliseconds
            };
            try
            {
                await tcp.ConnectAsync(new IPEndPoint(ip, _port), ct).ConfigureAwait(false);
                connectedClient = tcp;
                break;
            }
            catch (SocketException ex)
            {
                tcp.Dispose();
                lastEx = ex;
            }
        }

        if (connectedClient is null)
        {
            throw lastEx ?? new SocketException((int)SocketError.HostNotFound);
        }

        var ssl = new SslStream(connectedClient.GetStream(), leaveInnerStreamOpen: false);
        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = _host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        };

        await ssl.AuthenticateAsClientAsync(authOptions, ct).ConfigureAwait(false);

        _tcp = connectedClient;
        _ssl = ssl;
        _lastUsed = DateTimeOffset.UtcNow;
    }

    private void CloseCurrentConnection()
    {
        try { _ssl?.Dispose(); } catch { }
        try { _tcp?.Dispose(); } catch { }
        _ssl = null;
        _tcp = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CloseCurrentConnection();
        _connectionLock.Dispose();
    }
}
