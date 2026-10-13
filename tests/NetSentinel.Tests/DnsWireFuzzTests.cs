using NetSentinel.Sinkhole;

namespace NetSentinel.Tests;

public class DnsWireFuzzTests
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void FuzzDnsWire_NeverThrowsOrHangs()
    {
        var rnd = new Random(1337);
        byte[] buffer = new byte[1024];

        for (int i = 0; i < 50000; i++)
        {
            int len = rnd.Next(0, 600);
            rnd.NextBytes(buffer.AsSpan(0, len));
            byte[] packet = buffer[..len];

            // 1. Parsing
            bool ok = DnsQuery.TryParse(packet, out var q, out var error);
            if (ok && q is not null)
            {
                Assert.NotNull(q.Question);
                Assert.NotEmpty(q.Question.Name);

                // Check builders with parsed query
                _ = DnsWire.BuildNullAnswer(q);
                _ = DnsWire.BuildError(q, DnsRcode.NxDomain);
            }
            else
            {
                Assert.NotEmpty(error);
                _ = DnsWire.BuildFormatError(packet);
            }

            // 2. Inspection helpers
            _ = DnsWire.ResponseRcode(packet);
            _ = DnsWire.IsTruncated(packet);
            _ = DnsWire.MinTtl(packet);
            _ = DnsWire.CnameTargets(packet);
            _ = DnsWire.AddressAnswers(packet);
        }
    }

    [Fact]
    public void CompressionLoop_DetectedAndDoesNotHang()
    {
        // Construct a packet where a compression pointer points to itself
        // Header (12 bytes) + 1 question
        byte[] loop = new byte[]
        {
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (RD)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0xC0, 0x0C, // Name pointer pointing right to byte 12 (itself!)
            0x00, 0x01, // Type A
            0x00, 0x01  // Class IN
        };

        bool ok = DnsQuery.TryParse(loop, out var q, out var error);
        Assert.False(ok);
        Assert.Null(q);
        Assert.Equal("bad name", error);
    }
}
