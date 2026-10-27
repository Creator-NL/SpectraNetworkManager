using System.Buffers.Binary;

namespace SpectraNetworkManager.Core;

/// <summary>
/// Writes standard PCAP-Next Generation (.pcapng) binary files compatible with Wireshark, TShark,
/// and Network Monitor without requiring any third-party drivers or external dependencies.
/// </summary>
public static class PcapngWriter
{
    private const uint BlockTypeSectionHeader = 0x0A0D0D0A;
    private const uint BlockTypeInterfaceDescription = 0x00000001;
    private const uint BlockTypeEnhancedPacket = 0x00000006;
    private const uint ByteOrderMagic = 0x1A2B3C4D;
    private const ushort LinkTypeEthernet = 1;

    // Unix epoch start for PCAPNG timestamps
    private static readonly DateTimeOffset UnixEpoch = new(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static async Task WriteAsync(string filePath, IEnumerable<CapturedPacket> packets, CancellationToken ct = default)
    {
        string? dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        await using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read, 65536, useAsync: true);
        await using var writer = new BinaryWriter(stream);

        // 1. Write Section Header Block (SHB)
        WriteSectionHeaderBlock(writer);

        // 2. Write Interface Description Block (IDB)
        WriteInterfaceDescriptionBlock(writer);

        // 3. Write Enhanced Packet Blocks (EPB) for each packet
        foreach (var packet in packets)
        {
            if (ct.IsCancellationRequested) break;
            WriteEnhancedPacketBlock(writer, packet);
        }

        await stream.FlushAsync(ct);
    }

    private static void WriteSectionHeaderBlock(BinaryWriter writer)
    {
        const uint shbTotalLength = 28;

        writer.Write(BlockTypeSectionHeader);        // 4 bytes: Block Type
        writer.Write(shbTotalLength);                // 4 bytes: Total Length
        writer.Write(ByteOrderMagic);                // 4 bytes: Byte-Order Magic
        writer.Write((ushort)1);                     // 2 bytes: Major Version
        writer.Write((ushort)0);                     // 2 bytes: Minor Version
        writer.Write((long)-1);                      // 8 bytes: Section Length (-1 = unspecified)
        writer.Write(shbTotalLength);                // 4 bytes: Total Length (repeated)
    }

    private static void WriteInterfaceDescriptionBlock(BinaryWriter writer)
    {
        const uint idbTotalLength = 20;

        writer.Write(BlockTypeInterfaceDescription); // 4 bytes: Block Type
        writer.Write(idbTotalLength);                // 4 bytes: Total Length
        writer.Write(LinkTypeEthernet);              // 2 bytes: LinkType (1 = Ethernet)
        writer.Write((ushort)0);                     // 2 bytes: Reserved
        writer.Write((uint)65535);                   // 4 bytes: SnapLen
        writer.Write(idbTotalLength);                // 4 bytes: Total Length (repeated)
    }

    private static void WriteEnhancedPacketBlock(BinaryWriter writer, CapturedPacket packet)
    {
        // Synthesize Ethernet II frame header (14 bytes) so Wireshark parses it seamlessly
        byte[] payload = packet.RawData;
        bool isIpv6 = payload.Length > 0 && (payload[0] >> 4) == 6;
        ushort etherType = isIpv6 ? (ushort)0x86DD : (ushort)0x0800;

        int frameLen = 14 + payload.Length;
        int padLen = (4 - (frameLen % 4)) % 4;
        uint epbTotalLen = (uint)(32 + frameLen + padLen);

        // Calculate microsecond timestamp from Unix Epoch
        var diff = packet.Timestamp - UnixEpoch;
        ulong micros = (ulong)Math.Max(0, diff.Ticks / 10);
        uint tsHigh = (uint)(micros >> 32);
        uint tsLow = (uint)(micros & 0xFFFFFFFF);

        writer.Write(BlockTypeEnhancedPacket);        // 4 bytes: Block Type
        writer.Write(epbTotalLen);                   // 4 bytes: Total Length
        writer.Write((uint)0);                       // 4 bytes: Interface ID = 0
        writer.Write(tsHigh);                        // 4 bytes: Timestamp High
        writer.Write(tsLow);                         // 4 bytes: Timestamp Low
        writer.Write((uint)frameLen);                // 4 bytes: Captured Length
        writer.Write((uint)frameLen);                // 4 bytes: Original Length

        // Ethernet frame: Dst MAC (6 bytes), Src MAC (6 bytes), EtherType (2 bytes)
        writer.Write((byte)0x00);
        writer.Write((byte)0x50);
        writer.Write((byte)0x56);
        writer.Write((byte)0xC0);
        writer.Write((byte)0x00);
        writer.Write((byte)0x01);

        writer.Write((byte)0x00);
        writer.Write((byte)0x50);
        writer.Write((byte)0x56);
        writer.Write((byte)0xC0);
        writer.Write((byte)0x00);
        writer.Write((byte)0x02);

        // Big-endian EtherType
        writer.Write((byte)(etherType >> 8));
        writer.Write((byte)(etherType & 0xFF));

        // IP packet data
        if (payload.Length > 0)
        {
            writer.Write(payload);
        }

        // 32-bit alignment padding
        for (int i = 0; i < padLen; i++)
        {
            writer.Write((byte)0x00);
        }

        writer.Write(epbTotalLen);                   // 4 bytes: Total Length (repeated)
    }
}
