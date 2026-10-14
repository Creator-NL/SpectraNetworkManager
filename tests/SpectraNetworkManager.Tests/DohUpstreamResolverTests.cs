using System.Net;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Tests;

public sealed class DohUpstreamResolverTests
{
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public byte[]? LastRequestBody { get; private set; }
        public HttpResponseMessage ResponseToReturn { get; set; } = new(HttpStatusCode.OK);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content is not null)
            {
                LastRequestBody = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            }
            return ResponseToReturn;
        }
    }

    [Fact]
    public async Task DohResolver_SendsRfc8484PostRequest()
    {
        var mock = new MockHttpHandler();
        var uri = new Uri("https://1.1.1.1/dns-query");
        using var resolver = new DohUpstreamResolver(uri, handler: mock);

        byte[] query = DnsWire.BuildQuery("example.com", DnsType.A, 0x1234);
        byte[] expectedAnswer = DnsWire.BuildResponse(
            DnsQuery.TryParse(query, out var q, out _) ? q! : null!,
            DnsRcode.NoError,
            new[] { (DnsType.A, new byte[] { 93, 184, 216, 34 }) }
        );

        mock.ResponseToReturn = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(expectedAnswer)
            {
                Headers = { { "Content-Type", "application/dns-message" } }
            }
        };

        var result = await resolver.ResolveAsync(query, useTcp: false, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(expectedAnswer, result);
        Assert.NotNull(mock.LastRequest);
        Assert.Equal(HttpMethod.Post, mock.LastRequest.Method);
        Assert.Equal(uri, mock.LastRequest.RequestUri);
        Assert.Equal("application/dns-message", mock.LastRequest.Headers.Accept.ToString());
        Assert.Equal("application/dns-message", mock.LastRequest.Content?.Headers.ContentType?.MediaType);
        Assert.Equal(query, mock.LastRequestBody);
    }

    [Fact]
    public async Task DohResolver_ReturnsNullOnHttpError()
    {
        var mock = new MockHttpHandler
        {
            ResponseToReturn = new HttpResponseMessage(HttpStatusCode.BadGateway)
        };
        using var resolver = new DohUpstreamResolver(new Uri("https://9.9.9.9/dns-query"), handler: mock);

        byte[] query = DnsWire.BuildQuery("example.com", DnsType.A, 0x1234);
        var result = await resolver.ResolveAsync(query, useTcp: false, CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public void UpstreamEndpoint_ParsesDiverseFormats()
    {
        Assert.True(UpstreamEndpoint.TryParse("https://1.1.1.1/dns-query", out var doh1));
        Assert.Equal(UpstreamKind.DoH, doh1.Kind);
        Assert.Equal(new Uri("https://1.1.1.1/dns-query"), doh1.DohUri);

        Assert.True(UpstreamEndpoint.TryParse("tls://9.9.9.9:853", out var dot1));
        Assert.Equal(UpstreamKind.DoT, dot1.Kind);
        Assert.Equal("9.9.9.9", dot1.DotHost);
        Assert.Equal(853, dot1.DotPort);

        Assert.True(UpstreamEndpoint.TryParse("dot://dns.quad9.net", out var dot2));
        Assert.Equal(UpstreamKind.DoT, dot2.Kind);
        Assert.Equal("dns.quad9.net", dot2.DotHost);
        Assert.Equal(853, dot2.DotPort);

        Assert.True(UpstreamEndpoint.TryParse("9.9.9.9", out var std1));
        Assert.Equal(UpstreamKind.Standard, std1.Kind);
        Assert.Equal(IPAddress.Parse("9.9.9.9"), std1.StandardEndpoint!.Address);
        Assert.Equal(53, std1.StandardEndpoint.Port);

        Assert.True(UpstreamEndpoint.TryParse("1.1.1.1:5353", out var std2));
        Assert.Equal(UpstreamKind.Standard, std2.Kind);
        Assert.Equal(5353, std2.StandardEndpoint!.Port);
    }
}
