using System.Buffers.Binary;
using System.Text;
using NetSentinel.Sinkhole;
using Xunit;

namespace NetSentinel.Tests;

public class Rfc8482Tests
{
    [Fact]
    public void BuildRfc8482Hinfo_ReturnsMinimalHinfoResponse()
    {
        byte[] raw = DnsWire.BuildQuery("example.com", DnsType.ANY, 0x1234);
        Assert.True(DnsQuery.TryParse(raw, out var q, out _));
        Assert.NotNull(q);

        byte[] response = DnsWire.BuildRfc8482Hinfo(q);

        // Transaction ID preserved
        ushort id = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(0));
        Assert.Equal(0x1234, id);

        // Flags: QR=1 (response), AA=0, TC=0, RD preserved, RA=1, RCODE=0
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
        Assert.NotEqual(0, flags & 0x8000);
        Assert.Equal(DnsRcode.NoError, flags & 0x000F);

        // QDCOUNT=1, ANCOUNT=1
        ushort qd = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4));
        ushort an = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6));
        Assert.Equal(1, qd);
        Assert.Equal(1, an);

        // Skip to Answer section: question is name + 4 bytes
        int pos = q.QuestionEnd;

        // Pointer to question name: 0xC00C
        Assert.Equal(0xC0, response[pos]);
        Assert.Equal(0x0C, response[pos + 1]);

        // TYPE = HINFO (13)
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(pos + 2));
        Assert.Equal(DnsType.HINFO, type);

        // CLASS = IN (1)
        ushort cls = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(pos + 4));
        Assert.Equal(DnsQuestion.ClassIn, cls);

        // RDLENGTH = 9 bytes: [length: 7, "RFC8482", length: 0]
        ushort rdlen = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(pos + 10));
        Assert.Equal(9, rdlen);

        int rdataPos = pos + 12;
        int cpuLen = response[rdataPos];
        Assert.Equal(7, cpuLen);
        string cpuStr = Encoding.ASCII.GetString(response, rdataPos + 1, 7);
        Assert.Equal("RFC8482", cpuStr);

        int osLen = response[rdataPos + 8];
        Assert.Equal(0, osLen);
    }
}
