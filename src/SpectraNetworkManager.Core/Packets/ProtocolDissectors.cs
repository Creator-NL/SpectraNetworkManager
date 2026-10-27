using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace SpectraNetworkManager.Core;

public static class ProtocolDissectors
{
    public static CapturedPacket Dissect(ReadOnlySpan<byte> buffer, long packetId, DateTimeOffset timestamp, bool isInbound = false)
    {
        if (buffer.Length < 20)
        {
            return new CapturedPacket
            {
                Id = packetId,
                Timestamp = timestamp,
                Protocol = PacketProtocol.Other,
                ProtocolDisplay = "FRAGMENT",
                TotalLength = buffer.Length,
                IsInbound = isInbound,
                Info = $"Runt / fragment packet ({buffer.Length} bytes)",
                RawData = buffer.ToArray()
            };
        }

        byte version = (byte)(buffer[0] >> 4);
        if (version == 4)
        {
            return DissectIPv4(buffer, packetId, timestamp, isInbound);
        }
        else if (version == 6 && buffer.Length >= 40)
        {
            return DissectIPv6(buffer, packetId, timestamp, isInbound);
        }

        return new CapturedPacket
        {
            Id = packetId,
            Timestamp = timestamp,
            Protocol = PacketProtocol.Other,
            ProtocolDisplay = $"IP-v{version}",
            TotalLength = buffer.Length,
            IsInbound = isInbound,
            Info = $"Non-IPv4/IPv6 IP packet (v{version}, {buffer.Length} bytes)",
            RawData = buffer.Slice(0, Math.Min(buffer.Length, 256)).ToArray()
        };
    }

    private static CapturedPacket DissectIPv4(ReadOnlySpan<byte> buffer, long packetId, DateTimeOffset timestamp, bool isInbound)
    {
        int ihl = (buffer[0] & 0x0F) * 4;
        if (ihl < 20 || buffer.Length < ihl)
        {
            return new CapturedPacket
            {
                Id = packetId,
                Timestamp = timestamp,
                Protocol = PacketProtocol.Other,
                ProtocolDisplay = "IPv4-CORRUPT",
                TotalLength = buffer.Length,
                IsInbound = isInbound,
                Info = "Corrupted IPv4 header length",
                RawData = buffer.Slice(0, Math.Min(buffer.Length, 64)).ToArray()
            };
        }

        int totalLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
        if (totalLen == 0 || totalLen > buffer.Length) totalLen = buffer.Length;

        byte protocol = buffer[9];
        var srcIp = new IPAddress(buffer.Slice(12, 4));
        var dstIp = new IPAddress(buffer.Slice(16, 4));

        var l4Span = buffer.Slice(ihl, Math.Max(0, totalLen - ihl));

        if (protocol == 6 && l4Span.Length >= 20) // TCP
        {
            return DissectTcp(l4Span, srcIp, dstIp, packetId, timestamp, totalLen, isInbound, buffer);
        }
        else if (protocol == 17 && l4Span.Length >= 8) // UDP
        {
            return DissectUdp(l4Span, srcIp, dstIp, packetId, timestamp, totalLen, isInbound, buffer);
        }
        else if (protocol == 1) // ICMP
        {
            string icmpType = l4Span.Length > 0 ? (l4Span[0] switch
            {
                0 => "Echo Reply",
                3 => "Destination Unreachable",
                8 => "Echo Request (Ping)",
                11 => "Time Exceeded (TTL)",
                _ => $"Type {l4Span[0]}"
            }) : "ICMP";

            return new CapturedPacket
            {
                Id = packetId,
                Timestamp = timestamp,
                Protocol = PacketProtocol.Icmp,
                ProtocolDisplay = "ICMP",
                SourceAddress = srcIp,
                DestinationAddress = dstIp,
                TotalLength = totalLen,
                PayloadLength = l4Span.Length,
                IsInbound = isInbound,
                Info = $"ICMP {icmpType} ({srcIp} -> {dstIp})",
                RawData = buffer.Slice(0, Math.Min(buffer.Length, 256)).ToArray()
            };
        }

        return new CapturedPacket
        {
            Id = packetId,
            Timestamp = timestamp,
            Protocol = PacketProtocol.Other,
            ProtocolDisplay = $"PROTO-{protocol}",
            SourceAddress = srcIp,
            DestinationAddress = dstIp,
            TotalLength = totalLen,
            PayloadLength = l4Span.Length,
            IsInbound = isInbound,
            Info = $"IP Protocol {protocol} ({srcIp} -> {dstIp})",
            RawData = buffer.Slice(0, Math.Min(buffer.Length, 256)).ToArray()
        };
    }

    private static CapturedPacket DissectIPv6(ReadOnlySpan<byte> buffer, long packetId, DateTimeOffset timestamp, bool isInbound)
    {
        int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(4, 2));
        byte nextHeader = buffer[6];
        var srcIp = new IPAddress(buffer.Slice(8, 16));
        var dstIp = new IPAddress(buffer.Slice(24, 16));
        int totalLen = 40 + payloadLen;

        var l4Span = buffer.Slice(40, Math.Min(payloadLen, buffer.Length - 40));

        if (nextHeader == 6 && l4Span.Length >= 20) // TCP
        {
            return DissectTcp(l4Span, srcIp, dstIp, packetId, timestamp, totalLen, isInbound, buffer);
        }
        else if (nextHeader == 17 && l4Span.Length >= 8) // UDP
        {
            return DissectUdp(l4Span, srcIp, dstIp, packetId, timestamp, totalLen, isInbound, buffer);
        }

        return new CapturedPacket
        {
            Id = packetId,
            Timestamp = timestamp,
            Protocol = PacketProtocol.Other,
            ProtocolDisplay = nextHeader == 58 ? "ICMPv6" : $"IPv6-{nextHeader}",
            SourceAddress = srcIp,
            DestinationAddress = dstIp,
            TotalLength = totalLen,
            PayloadLength = l4Span.Length,
            IsInbound = isInbound,
            Info = $"IPv6 NextHeader={nextHeader} ({srcIp} -> {dstIp})",
            RawData = buffer.Slice(0, Math.Min(buffer.Length, 256)).ToArray()
        };
    }

    private static CapturedPacket DissectTcp(
        ReadOnlySpan<byte> tcpSpan, IPAddress srcIp, IPAddress dstIp,
        long packetId, DateTimeOffset timestamp, int totalLen, bool isInbound, ReadOnlySpan<byte> fullBuffer)
    {
        int srcPort = BinaryPrimitives.ReadUInt16BigEndian(tcpSpan.Slice(0, 2));
        int dstPort = BinaryPrimitives.ReadUInt16BigEndian(tcpSpan.Slice(2, 2));
        uint seq = BinaryPrimitives.ReadUInt32BigEndian(tcpSpan.Slice(4, 4));
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(tcpSpan.Slice(8, 4));

        int dataOffset = (tcpSpan[12] >> 4) * 4;
        if (dataOffset < 20 || dataOffset > tcpSpan.Length) dataOffset = 20;

        byte flags = tcpSpan[13];
        var flagParts = new List<string>(4);
        if ((flags & 0x02) != 0) flagParts.Add("SYN");
        if ((flags & 0x10) != 0) flagParts.Add("ACK");
        if ((flags & 0x08) != 0) flagParts.Add("PSH");
        if ((flags & 0x01) != 0) flagParts.Add("FIN");
        if ((flags & 0x04) != 0) flagParts.Add("RST");
        if ((flags & 0x20) != 0) flagParts.Add("URG");
        string flagsDisplay = flagParts.Count > 0 ? $"[{string.Join(", ", flagParts)}]" : "[]";

        var appPayload = tcpSpan.Slice(dataOffset);
        int payloadLen = appPayload.Length;

        // Try higher-layer dissectors (TLS, HTTP, DNS)
        if (payloadLen > 0)
        {
            // 1. TLS ClientHello SNI
            if (TryDissectTlsClientHello(appPayload, out string? sni))
            {
                return new CapturedPacket
                {
                    Id = packetId,
                    Timestamp = timestamp,
                    Protocol = PacketProtocol.Tls,
                    ProtocolDisplay = "TLS",
                    SourceAddress = srcIp,
                    SourcePort = srcPort,
                    DestinationAddress = dstIp,
                    DestinationPort = dstPort,
                    TotalLength = totalLen,
                    PayloadLength = payloadLen,
                    IsInbound = isInbound,
                    TcpFlags = flagsDisplay,
                    HostOrSni = sni,
                    Info = $"TLS ClientHello (SNI: {sni})",
                    RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
                };
            }

            // 2. HTTP Request / Response
            if (TryDissectHttp(appPayload, out string httpMethod, out string httpHost, out string httpUri))
            {
                string info = !string.IsNullOrEmpty(httpHost) 
                    ? $"HTTP {httpMethod} http://{httpHost}{httpUri}" 
                    : $"HTTP {httpMethod} {httpUri}";

                return new CapturedPacket
                {
                    Id = packetId,
                    Timestamp = timestamp,
                    Protocol = PacketProtocol.Http,
                    ProtocolDisplay = "HTTP",
                    SourceAddress = srcIp,
                    SourcePort = srcPort,
                    DestinationAddress = dstIp,
                    DestinationPort = dstPort,
                    TotalLength = totalLen,
                    PayloadLength = payloadLen,
                    IsInbound = isInbound,
                    TcpFlags = flagsDisplay,
                    HostOrSni = httpHost,
                    Info = info,
                    RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
                };
            }

            // 3. DNS over TCP (Port 53 or 853)
            if ((srcPort == 53 || dstPort == 53) && appPayload.Length >= 14)
            {
                // DNS over TCP prefixes query with 2-byte length
                var dnsSpan = appPayload.Slice(2);
                if (TryDissectDns(dnsSpan, out string dnsQuery, out bool isDnsResp, out int qtype))
                {
                    string info = isDnsResp 
                        ? $"DNS (TCP) Response: {dnsQuery}" 
                        : $"DNS (TCP) Query: {dnsQuery} ({FormatQType(qtype)})";

                    return new CapturedPacket
                    {
                        Id = packetId,
                        Timestamp = timestamp,
                        Protocol = PacketProtocol.Dns,
                        ProtocolDisplay = "DNS-TCP",
                        SourceAddress = srcIp,
                        SourcePort = srcPort,
                        DestinationAddress = dstIp,
                        DestinationPort = dstPort,
                        TotalLength = totalLen,
                        PayloadLength = payloadLen,
                        IsInbound = isInbound,
                        TcpFlags = flagsDisplay,
                        HostOrSni = dnsQuery,
                        Info = info,
                        RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
                    };
                }
            }
        }

        // Generic TCP Packet
        string defaultInfo = $"TCP {srcPort} -> {dstPort} {flagsDisplay} Seq={seq} Ack={ack} Len={payloadLen}";
        return new CapturedPacket
        {
            Id = packetId,
            Timestamp = timestamp,
            Protocol = PacketProtocol.Tcp,
            ProtocolDisplay = "TCP",
            SourceAddress = srcIp,
            SourcePort = srcPort,
            DestinationAddress = dstIp,
            DestinationPort = dstPort,
            TotalLength = totalLen,
            PayloadLength = payloadLen,
            IsInbound = isInbound,
            TcpFlags = flagsDisplay,
            Info = defaultInfo,
            RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
        };
    }

    private static CapturedPacket DissectUdp(
        ReadOnlySpan<byte> udpSpan, IPAddress srcIp, IPAddress dstIp,
        long packetId, DateTimeOffset timestamp, int totalLen, bool isInbound, ReadOnlySpan<byte> fullBuffer)
    {
        int srcPort = BinaryPrimitives.ReadUInt16BigEndian(udpSpan.Slice(0, 2));
        int dstPort = BinaryPrimitives.ReadUInt16BigEndian(udpSpan.Slice(2, 2));
        int udpLen = BinaryPrimitives.ReadUInt16BigEndian(udpSpan.Slice(4, 2));
        int payloadLen = Math.Max(0, udpSpan.Length - 8);
        var appPayload = udpSpan.Slice(8);

        // 1. DNS (Port 53 or 5353 mDNS)
        if (srcPort is 53 or 5353 or 5355 || dstPort is 53 or 5353 or 5355)
        {
            if (TryDissectDns(appPayload, out string dnsQuery, out bool isDnsResp, out int qtype))
            {
                string label = (srcPort == 5353 || dstPort == 5353) ? "mDNS" : "DNS";
                string info = isDnsResp 
                    ? $"{label} Response: {dnsQuery}" 
                    : $"{label} Query: {dnsQuery} ({FormatQType(qtype)})";

                return new CapturedPacket
                {
                    Id = packetId,
                    Timestamp = timestamp,
                    Protocol = PacketProtocol.Dns,
                    ProtocolDisplay = label,
                    SourceAddress = srcIp,
                    SourcePort = srcPort,
                    DestinationAddress = dstIp,
                    DestinationPort = dstPort,
                    TotalLength = totalLen,
                    PayloadLength = payloadLen,
                    IsInbound = isInbound,
                    HostOrSni = dnsQuery,
                    Info = info,
                    RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
                };
            }
        }

        // Generic UDP Packet
        string defaultInfo = $"UDP {srcPort} -> {dstPort} Len={payloadLen}";
        return new CapturedPacket
        {
            Id = packetId,
            Timestamp = timestamp,
            Protocol = PacketProtocol.Udp,
            ProtocolDisplay = "UDP",
            SourceAddress = srcIp,
            SourcePort = srcPort,
            DestinationAddress = dstIp,
            DestinationPort = dstPort,
            TotalLength = totalLen,
            PayloadLength = payloadLen,
            IsInbound = isInbound,
            Info = defaultInfo,
            RawData = fullBuffer.Slice(0, Math.Min(fullBuffer.Length, 256)).ToArray()
        };
    }

    /// <summary>
    /// Dissects TLS ClientHello records (ContentType=0x16, HandshakeType=0x01)
    /// and extracts the Server Name Indication (SNI) extension value.
    /// </summary>
    public static bool TryDissectTlsClientHello(ReadOnlySpan<byte> span, out string? sni)
    {
        sni = null;
        if (span.Length < 43) return false;

        // TLS Record Header: ContentType 0x16 (Handshake), Version 0x0301/0x0303
        if (span[0] != 0x16 || span[1] != 0x03) return false;

        int recordLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(3, 2));
        if (recordLen < 38) return false;

        // Handshake Message Header: Type 0x01 (Client Hello)
        if (span[5] != 0x01) return false;

        // Skip Handshake Header (4 bytes) + Version (2 bytes) + Random (32 bytes)
        int pos = 5 + 4 + 2 + 32;
        if (pos >= span.Length) return false;

        // Session ID
        byte sessionIdLen = span[pos++];
        pos += sessionIdLen;
        if (pos + 2 > span.Length) return false;

        // Cipher Suites
        int cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
        pos += 2 + cipherSuitesLen;
        if (pos + 1 > span.Length) return false;

        // Compression Methods
        byte compLen = span[pos++];
        pos += compLen;
        if (pos + 2 > span.Length) return false;

        // Extensions Length
        int extensionsLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
        pos += 2;
        int extEnd = Math.Min(span.Length, pos + extensionsLen);

        // Iterate Extensions
        while (pos + 4 <= extEnd)
        {
            ushort extType = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
            ushort extLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos + 2, 2));
            pos += 4;

            if (pos + extLen > extEnd) break;

            if (extType == 0x0000) // server_name (SNI)
            {
                var sniSpan = span.Slice(pos, extLen);
                if (sniSpan.Length >= 5)
                {
                    // ServerNameListLength (2 bytes) + ServerNameType (1 byte, 0 = host_name) + HostNameLength (2 bytes)
                    byte nameType = sniSpan[2];
                    if (nameType == 0) // host_name
                    {
                        ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(sniSpan.Slice(3, 2));
                        if (5 + nameLen <= sniSpan.Length)
                        {
                            sni = Encoding.ASCII.GetString(sniSpan.Slice(5, nameLen));
                            return true;
                        }
                    }
                }
            }

            pos += extLen;
        }

        return false;
    }

    /// <summary>
    /// Dissects standard DNS query/response packets and extracts the queried hostname.
    /// </summary>
    public static bool TryDissectDns(ReadOnlySpan<byte> span, out string queryName, out bool isResponse, out int qtype)
    {
        queryName = "";
        isResponse = false;
        qtype = 1;

        if (span.Length < 12) return false;

        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(2, 2));
        isResponse = (flags & 0x8000) != 0;
        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(4, 2));
        if (qdCount == 0) return false;

        int pos = 12;
        var nameBuilder = new StringBuilder();

        while (pos < span.Length)
        {
            byte len = span[pos++];
            if (len == 0) break; // End of domain
            if ((len & 0xC0) == 0xC0)
            {
                // DNS Pointer compression in question name: skip 1 extra byte
                pos++;
                break;
            }

            if (pos + len > span.Length) return false;

            if (nameBuilder.Length > 0) nameBuilder.Append('.');
            nameBuilder.Append(Encoding.ASCII.GetString(span.Slice(pos, len)));
            pos += len;
        }

        if (nameBuilder.Length == 0) return false;
        queryName = nameBuilder.ToString();

        if (pos + 2 <= span.Length)
        {
            qtype = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
        }

        return true;
    }

    /// <summary>
    /// Dissects plaintext HTTP request or response lines and extracts method and Host header.
    /// </summary>
    public static bool TryDissectHttp(ReadOnlySpan<byte> span, out string method, out string host, out string uri)
    {
        method = "";
        host = "";
        uri = "";

        if (span.Length < 10) return false;

        string headerText = Encoding.ASCII.GetString(span.Slice(0, Math.Min(span.Length, 1024)));

        string[] lines = headerText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return false;

        string firstLine = lines[0].Trim();
        string[] parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length >= 2 && (parts[0] is "GET" or "POST" or "HEAD" or "PUT" or "DELETE" or "OPTIONS" or "CONNECT" or "PATCH"))
        {
            method = parts[0];
            uri = parts[1];

            foreach (var line in lines)
            {
                if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                {
                    host = line.Substring(5).Trim();
                    break;
                }
            }

            return true;
        }
        else if (firstLine.StartsWith("HTTP/1.", StringComparison.OrdinalIgnoreCase))
        {
            method = "RESP";
            uri = firstLine;
            return true;
        }

        return false;
    }

    private static string FormatQType(int qtype) => qtype switch
    {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        65 => "HTTPS",
        12 => "PTR",
        255 => "ANY",
        _ => $"Type-{qtype}"
    };
}
