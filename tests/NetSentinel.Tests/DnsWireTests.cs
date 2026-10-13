using System.Net;
using NetSentinel.Sinkhole;

namespace NetSentinel.Tests;

public class DnsWireTests
{
    [Fact]
    public void BuildQuery_And_TryParse_RoundTrips()
    {
        byte[] raw = DnsWire.BuildQuery("example.com", DnsType.A, 0x1234, recursionDesired: true);
        Assert.True(DnsQuery.TryParse(raw, out var query, out var err), err);
        Assert.NotNull(query);

        Assert.Equal(0x1234, query.Id);
        Assert.True(query.RecursionDesired);
        Assert.Equal(0, query.Opcode);
        Assert.Equal("example.com", query.Question.Name);
        Assert.Equal(DnsType.A, query.Question.Type);
        Assert.Equal(DnsQuestion.ClassIn, query.Question.Class);
    }

    [Fact]
    public void BuildNullAnswer_IPv4_Returns0000()
    {
        byte[] rawQuery = DnsWire.BuildQuery("doubleclick.net", DnsType.A, 0x4321);
        Assert.True(DnsQuery.TryParse(rawQuery, out var q, out _));

        byte[] resp = DnsWire.BuildNullAnswer(q!, ttl: 60);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp));
        Assert.False(DnsWire.IsTruncated(resp));

        var addrs = DnsWire.AddressAnswers(resp);
        Assert.Single(addrs);
        Assert.Equal(IPAddress.Any, addrs[0]); // 0.0.0.0
    }

    [Fact]
    public void BuildNullAnswer_IPv6_ReturnsColonColon()
    {
        byte[] rawQuery = DnsWire.BuildQuery("doubleclick.net", DnsType.AAAA, 0x5555);
        Assert.True(DnsQuery.TryParse(rawQuery, out var q, out _));

        byte[] resp = DnsWire.BuildNullAnswer(q!, ttl: 60);
        Assert.Equal(DnsRcode.NoError, DnsWire.ResponseRcode(resp));

        var addrs = DnsWire.AddressAnswers(resp);
        Assert.Single(addrs);
        Assert.Equal(IPAddress.IPv6Any, addrs[0]); // ::
    }

    [Fact]
    public void BuildError_SetsRcodeCorrectly()
    {
        byte[] rawQuery = DnsWire.BuildQuery("notfound.test", DnsType.A, 0x9999);
        Assert.True(DnsQuery.TryParse(rawQuery, out var q, out _));

        byte[] resp = DnsWire.BuildError(q!, DnsRcode.NxDomain);
        Assert.Equal(DnsRcode.NxDomain, DnsWire.ResponseRcode(resp));
    }

    [Fact]
    public void Truncate_SetsTCBit_AndKeepsHeaderAndQuestion()
    {
        byte[] rawQuery = DnsWire.BuildQuery("huge.example.com", DnsType.TXT, 0x1111);
        Assert.True(DnsQuery.TryParse(rawQuery, out var q, out _));

        byte[] fullResp = DnsWire.BuildResponse(q!, DnsRcode.NoError, new[]
        {
            (DnsType.TXT, new byte[300]),
            (DnsType.TXT, new byte[300]),
        });

        byte[] truncated = DnsWire.Truncate(fullResp, q!);
        Assert.True(DnsWire.IsTruncated(truncated));
        Assert.Equal(q!.QuestionEnd, truncated.Length);
    }

    [Fact]
    public void BuildFormatError_ExtractsIdWhenHeaderAvailable()
    {
        byte[] badPacket = new byte[] { 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
        byte[]? errResp = DnsWire.BuildFormatError(badPacket);

        Assert.NotNull(errResp);
        Assert.Equal(0x12, errResp[0]);
        Assert.Equal(0x34, errResp[1]);
        Assert.Equal(DnsRcode.FormErr, DnsWire.ResponseRcode(errResp));
    }

    [Fact]
    public void MinTtl_And_Rewrite_LowerTtlsAndChangeId()
    {
        byte[] rawQuery = DnsWire.BuildQuery("test.com", DnsType.A, 0x1000);
        Assert.True(DnsQuery.TryParse(rawQuery, out var q, out _));

        byte[] resp = DnsWire.BuildResponse(q!, DnsRcode.NoError, new[]
        {
            (DnsType.A, new byte[] { 1, 2, 3, 4 })
        }, ttl: 3600);

        Assert.Equal(3600u, DnsWire.MinTtl(resp));

        byte[] rewritten = DnsWire.Rewrite(resp, 0x2000, 300);
        Assert.Equal(0x20, rewritten[0]);
        Assert.Equal(0x00, rewritten[1]);
        Assert.Equal(300u, DnsWire.MinTtl(rewritten));
    }
}
