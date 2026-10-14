using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Upstream DNS resolver over DNS-over-HTTPS (RFC 8484) using HTTP/2 POST.
/// Supports bootstrap IP URLs (e.g. https://9.9.9.9/dns-query, https://1.1.1.1/dns-query)
/// as well as domain names with built-in bootstrap address resolution.
/// </summary>
public sealed class DohUpstreamResolver : IUpstreamResolver, IDisposable
{
    private static readonly MediaTypeHeaderValue DnsMediaType = new("application/dns-message");
    private static readonly MediaTypeWithQualityHeaderValue DnsMediaTypeAccept = new("application/dns-message");

    // Well-known bootstrap mappings for popular DoH providers
    private static readonly Dictionary<string, IReadOnlyList<IPAddress>> KnownBootstrapIps = new(StringComparer.OrdinalIgnoreCase)
    {
        ["dns.quad9.net"] = new[] { IPAddress.Parse("9.9.9.9"), IPAddress.Parse("149.112.112.112") },
        ["cloudflare-dns.com"] = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") },
        ["one.one.one.one"] = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") },
        ["dns.google"] = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4") },
        ["dns.adguard-dns.com"] = new[] { IPAddress.Parse("94.140.14.14"), IPAddress.Parse("94.140.15.15") }
    };

    private readonly Uri _endpoint;
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly TimeSpan _timeout;

    public Uri Endpoint => _endpoint;

    public DohUpstreamResolver(Uri endpoint, TimeSpan? timeout = null, HttpMessageHandler? handler = null)
    {
        _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        _timeout = timeout ?? TimeSpan.FromSeconds(3);

        if (handler is not null)
        {
            _http = new HttpClient(handler, disposeHandler: false) { Timeout = _timeout };
            _ownsClient = true;
        }
        else
        {
            var socketsHandler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(15),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
                EnableMultipleHttp2Connections = true,
                ConnectTimeout = TimeSpan.FromSeconds(2.5),
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                }
            };

            // If the host is not an IP address, configure custom connect callback using bootstrap IPs if known
            if (!IPAddress.TryParse(endpoint.Host, out _) && KnownBootstrapIps.TryGetValue(endpoint.Host, out var ips))
            {
                socketsHandler.ConnectCallback = async (context, ct) =>
                {
                    var port = context.DnsEndPoint.Port;
                    SocketException? lastEx = null;
                    foreach (var ip in ips)
                    {
                        var socket = new System.Net.Sockets.Socket(ip.AddressFamily, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp)
                        {
                            NoDelay = true
                        };
                        try
                        {
                            await socket.ConnectAsync(new IPEndPoint(ip, port), ct).ConfigureAwait(false);
                            return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
                        }
                        catch (SocketException ex)
                        {
                            socket.Dispose();
                            lastEx = ex;
                        }
                    }
                    throw lastEx ?? new SocketException((int)SocketError.HostNotFound);
                };
            }

            _http = new HttpClient(socketsHandler, disposeHandler: true)
            {
                Timeout = _timeout,
                DefaultRequestVersion = HttpVersion.Version20,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower
            };
            _ownsClient = true;
        }
    }

    public async Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, _endpoint);
            req.Version = HttpVersion.Version20;
            req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            req.Headers.Accept.Clear();
            req.Headers.Accept.Add(DnsMediaTypeAccept);

            using var content = new ByteArrayContent(query);
            content.Headers.ContentType = DnsMediaType;
            req.Content = content;

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linkedCts.CancelAfter(_timeout);

            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, linkedCts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return null;

            byte[] answer = await resp.Content.ReadAsByteArrayAsync(linkedCts.Token).ConfigureAwait(false);
            if (answer.Length >= 12 && answer[0] == query[0] && answer[1] == query[1])
                return answer;

            // Some DoH servers normalize the transaction ID to 0 in wire messages. If so, copy the query's ID.
            if (answer.Length >= 12)
            {
                var adjusted = (byte[])answer.Clone();
                adjusted[0] = query[0];
                adjusted[1] = query[1];
                return adjusted;
            }

            return null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _http.Dispose();
        }
    }
}
