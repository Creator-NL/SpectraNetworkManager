using System.Buffers.Binary;
using System.Net;
using System.Text;
using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public sealed class ProtocolDissectorsTests
{
    [Fact]
    public void Dissect_Ipv4TcpSynPacket_DecodesAccurately()
    {
        // Construct standard 40-byte IPv4 + TCP packet (20 byte IPv4, 20 byte TCP SYN)
        byte[] raw = new byte[40];

        // IPv4 Header
        raw[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        raw[1] = 0x00; // DSCP / ECN
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2, 2), 40); // Total length
        raw[8] = 64;   // TTL
        raw[9] = 6;    // Protocol 6 (TCP)
        // Src IP: 192.168.1.50
        raw[12] = 192; raw[13] = 168; raw[14] = 1; raw[15] = 50;
        // Dst IP: 142.250.179.206 (Google)
        raw[16] = 142; raw[17] = 250; raw[18] = 179; raw[19] = 206;

        // TCP Header (starts at offset 20)
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20, 2), 54321); // Src Port
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22, 2), 443);   // Dst Port
        BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(24, 4), 1000);  // Seq
        BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(28, 4), 0);     // Ack
        raw[32] = 0x50; // Data offset 5 (20 bytes)
        raw[33] = 0x02; // Flags: SYN (0x02)

        var pkt = ProtocolDissectors.Dissect(raw, 1, DateTimeOffset.UtcNow, isInbound: false);

        Assert.Equal(PacketProtocol.Tcp, pkt.Protocol);
        Assert.Equal(IPAddress.Parse("192.168.1.50"), pkt.SourceAddress);
        Assert.Equal(54321, pkt.SourcePort);
        Assert.Equal(IPAddress.Parse("142.250.179.206"), pkt.DestinationAddress);
        Assert.Equal(443, pkt.DestinationPort);
        Assert.Equal(40, pkt.TotalLength);
        Assert.Contains("SYN", pkt.TcpFlags);
    }

    [Fact]
    public void Dissect_DnsUdpQuery_DecodesHostnameAndType()
    {
        // 20 byte IPv4 + 8 byte UDP + DNS payload
        byte[] dnsWire = CreateSampleDnsQuery("api.github.com", 1); // QType A
        int totalLen = 20 + 8 + dnsWire.Length;
        byte[] raw = new byte[totalLen];

        // IPv4
        raw[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2, 2), (ushort)totalLen);
        raw[9] = 17; // UDP
        raw[12] = 192; raw[13] = 168; raw[14] = 1; raw[15] = 10;
        raw[16] = 192; raw[17] = 168; raw[18] = 1; raw[19] = 1;

        // UDP
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20, 2), 61234);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22, 2), 53); // DNS port
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(24, 2), (ushort)(8 + dnsWire.Length));

        // DNS
        dnsWire.CopyTo(raw, 28);

        var pkt = ProtocolDissectors.Dissect(raw, 2, DateTimeOffset.UtcNow, isInbound: false);

        Assert.Equal(PacketProtocol.Dns, pkt.Protocol);
        Assert.Equal("api.github.com", pkt.HostOrSni);
        Assert.Contains("DNS Query: api.github.com", pkt.Info);
    }

    [Fact]
    public void Dissect_TlsClientHello_ExtractsServerNameIndication()
    {
        // Create sample TLS ClientHello with SNI extension for "www.youtube.com"
        byte[] tlsPayload = CreateSampleTlsClientHello("www.youtube.com");
        int totalLen = 20 + 20 + tlsPayload.Length;
        byte[] raw = new byte[totalLen];

        // IPv4
        raw[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2, 2), (ushort)totalLen);
        raw[9] = 6; // TCP
        raw[12] = 192; raw[13] = 168; raw[14] = 1; raw[15] = 100;
        raw[16] = 142; raw[17] = 250; raw[18] = 180; raw[19] = 206;

        // TCP
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20, 2), 55555);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22, 2), 443);
        raw[32] = 0x50; // Data offset 20
        raw[33] = 0x18; // PSH, ACK

        tlsPayload.CopyTo(raw, 40);

        var pkt = ProtocolDissectors.Dissect(raw, 3, DateTimeOffset.UtcNow, isInbound: false);

        Assert.Equal(PacketProtocol.Tls, pkt.Protocol);
        Assert.Equal("www.youtube.com", pkt.HostOrSni);
        Assert.Contains("SNI: www.youtube.com", pkt.Info);
    }

    [Fact]
    public void Dissect_HttpRequest_ExtractsMethodAndHost()
    {
        string httpText = "GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: SpectraTest\r\n\r\n";
        byte[] httpBytes = Encoding.ASCII.GetBytes(httpText);
        int totalLen = 20 + 20 + httpBytes.Length;
        byte[] raw = new byte[totalLen];

        raw[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2, 2), (ushort)totalLen);
        raw[9] = 6; // TCP
        raw[12] = 192; raw[13] = 168; raw[14] = 1; raw[15] = 100;
        raw[16] = 93; raw[17] = 184; raw[18] = 216; raw[19] = 34;

        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(20, 2), 52100);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(22, 2), 80);
        raw[32] = 0x50;
        raw[33] = 0x18; // PSH, ACK

        httpBytes.CopyTo(raw, 40);

        var pkt = ProtocolDissectors.Dissect(raw, 4, DateTimeOffset.UtcNow, isInbound: false);

        Assert.Equal(PacketProtocol.Http, pkt.Protocol);
        Assert.Equal("example.org", pkt.HostOrSni);
        Assert.Contains("HTTP GET http://example.org/index.html", pkt.Info);
    }

    [Fact]
    public async Task PcapngWriter_WritesStandardBlocksAndCanBeVerified()
    {
        string tempPcap = Path.Combine(Path.GetTempPath(), $"pcapng-test-{Guid.NewGuid():N}.pcapng");
        try
        {
            var p1 = new CapturedPacket
            {
                Id = 1,
                Timestamp = DateTimeOffset.UtcNow,
                Protocol = PacketProtocol.Tcp,
                SourceAddress = IPAddress.Parse("192.168.1.10"),
                SourcePort = 50000,
                DestinationAddress = IPAddress.Parse("1.1.1.1"),
                DestinationPort = 53,
                TotalLength = 40,
                RawData = new byte[40]
            };

            await PcapngWriter.WriteAsync(tempPcap, new[] { p1 });

            Assert.True(File.Exists(tempPcap));
            byte[] bytes = await File.ReadAllBytesAsync(tempPcap);

            // Verify Section Header Block magic (0x0A0D0D0A)
            uint shb = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
            Assert.Equal(0x0A0D0D0Au, shb);

            // Verify Byte Order Magic (0x1A2B3C4D)
            uint bom = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8, 4));
            Assert.Equal(0x1A2B3C4Du, bom);
        }
        finally
        {
            try { if (File.Exists(tempPcap)) File.Delete(tempPcap); } catch { }
        }
    }

    [Fact]
    public void PacketRingBuffer_RespectsCapacityAndFilters()
    {
        var buffer = new PacketRingBuffer(capacity: 50);

        for (int i = 1; i <= 80; i++)
        {
            buffer.Add(new CapturedPacket
            {
                Id = i,
                Timestamp = DateTimeOffset.UtcNow,
                Protocol = (i % 2 == 0) ? PacketProtocol.Tls : PacketProtocol.Dns,
                ProtocolDisplay = (i % 2 == 0) ? "TLS" : "DNS",
                HostOrSni = (i % 2 == 0) ? "youtube.com" : "github.com",
                TotalLength = 100
            });
        }

        Assert.Equal(50, buffer.Count);
        Assert.Equal(80, buffer.TotalPackets);

        // Filter TLS only
        var tlsOnly = buffer.GetSnapshot(new PacketFilterOptions(Protocol: "TLS"));
        Assert.All(tlsOnly, p => Assert.Equal(PacketProtocol.Tls, p.Protocol));

        // Filter Search Text
        var searchYoutube = buffer.GetSnapshot(new PacketFilterOptions(SearchText: "youtube"));
        Assert.All(searchYoutube, p => Assert.Equal("youtube.com", p.HostOrSni));
    }

    private static byte[] CreateSampleDnsQuery(string domain, ushort qtype)
    {
        var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write((ushort)0x1234); // TxId
        w.Write((ushort)0x0100); // Standard query
        w.Write(BinaryPrimitives.ReverseEndianness((ushort)1)); // QDCount = 1
        w.Write((ushort)0);      // ANCount
        w.Write((ushort)0);      // NSCount
        w.Write((ushort)0);      // ARCount

        foreach (var label in domain.Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            w.Write((byte)bytes.Length);
            w.Write(bytes);
        }
        w.Write((byte)0); // Null terminator

        w.Write(BinaryPrimitives.ReverseEndianness(qtype)); // QType
        w.Write(BinaryPrimitives.ReverseEndianness((ushort)1)); // QClass IN

        return ms.ToArray();
    }

    private static byte[] CreateSampleTlsClientHello(string sniHostname)
    {
        byte[] sniBytes = Encoding.ASCII.GetBytes(sniHostname);
        var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // TLS Record Header: 0x16 (Handshake), Version 0x0303, Length (calculate at end)
        w.Write((byte)0x16);
        w.Write((byte)0x03);
        w.Write((byte)0x03);
        w.Write((ushort)0); // Placeholder for record length

        // Handshake Message Header: 0x01 (ClientHello), Length (3 bytes placeholder)
        w.Write((byte)0x01);
        w.Write((byte)0x00);
        w.Write((ushort)0); // Placeholder for handshake length

        // Client Version: 0x0303
        w.Write((byte)0x03);
        w.Write((byte)0x03);

        // Random: 32 bytes
        w.Write(new byte[32]);

        // Session ID: 0 length
        w.Write((byte)0x00);

        // Cipher Suites: 2 bytes length + 1 cipher (0x1301)
        w.Write(BinaryPrimitives.ReverseEndianness((ushort)2));
        w.Write((ushort)0x0113);

        // Compression: 1 byte length + 0x00
        w.Write((byte)0x01);
        w.Write((byte)0x00);

        // Extensions
        ushort sniExtLen = (ushort)(5 + sniBytes.Length);
        ushort extensionsTotalLen = (ushort)(4 + sniExtLen);

        w.Write(BinaryPrimitives.ReverseEndianness(extensionsTotalLen));

        // Extension: server_name (0x0000)
        w.Write((ushort)0x0000);
        w.Write(BinaryPrimitives.ReverseEndianness(sniExtLen));

        // ServerNameListLength (2 bytes) + ServerNameType (1 byte = 0) + HostNameLength (2 bytes)
        ushort listLen = (ushort)(3 + sniBytes.Length);
        w.Write(BinaryPrimitives.ReverseEndianness(listLen));
        w.Write((byte)0x00); // host_name
        w.Write(BinaryPrimitives.ReverseEndianness((ushort)sniBytes.Length));
        w.Write(sniBytes);

        byte[] result = ms.ToArray();

        // Fill in Handshake length (result.Length - 9)
        int hsLen = result.Length - 9;
        result[7] = (byte)(hsLen >> 8);
        result[8] = (byte)(hsLen & 0xFF);

        // Fill in Record length (result.Length - 5)
        int recLen = result.Length - 5;
        result[3] = (byte)(recLen >> 8);
        result[4] = (byte)(recLen & 0xFF);

        return result;
    }
}
