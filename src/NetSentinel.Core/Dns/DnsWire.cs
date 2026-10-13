using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetSentinel.Sinkhole;

public static class DnsType
{
    public const ushort A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, HINFO = 13, MX = 15, TXT = 16, AAAA = 28, SRV = 33, OPT = 41, HTTPS = 65, ANY = 255;
}

public static class DnsRcode
{
    public const int NoError = 0, FormErr = 1, ServFail = 2, NxDomain = 3, NotImp = 4, Refused = 5;
}

/// <summary>The single question of a DNS query (queries with several questions are not supported).</summary>
public sealed record DnsQuestion(string Name, ushort Type, ushort Class)
{
    public const ushort ClassIn = 1;
}

/// <summary>A parsed DNS query. All parsing treats the input as untrusted: it never throws and never loops forever.</summary>
public sealed class DnsQuery
{
    public required byte[] Raw { get; init; }
    public ushort Id { get; init; }
    public ushort Flags { get; init; }
    public int Opcode => (Flags >> 11) & 0xF;
    public bool RecursionDesired => (Flags & 0x0100) != 0;
    public required DnsQuestion Question { get; init; }

    /// <summary>Offset just after the question section.</summary>
    public int QuestionEnd { get; init; }

    /// <summary>UDP payload size the client accepts (EDNS), or 512.</summary>
    public int MaxUdpPayload { get; init; } = 512;

    public static bool TryParse(byte[] data, out DnsQuery? query, out string error)
    {
        query = null;
        error = "";

        if (data.Length < 12) { error = "too short"; return false; }

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(0));
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(2));
        int qd = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4));
        int an = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(6));
        int ns = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(8));
        int ar = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(10));

        if ((flags & 0x8000) != 0) { error = "not a query"; return false; }
        if (qd != 1) { error = "exactly one question is supported"; return false; }

        int pos = 12;
        if (!DnsWire.TryReadName(data, ref pos, out string name)) { error = "bad name"; return false; }
        if (pos + 4 > data.Length) { error = "truncated question"; return false; }

        ushort type = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos));
        ushort cls = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos + 2));
        int questionEnd = pos + 4;

        // EDNS: look for an OPT record in the additional section to learn the client's UDP size.
        int payload = 512;
        int p = questionEnd;
        bool ok = true;
        for (int i = 0; i < an + ns && ok; i++) ok = DnsWire.TrySkipRecord(data, ref p, out _, out _, out _, out _);
        for (int i = 0; i < ar && ok; i++)
        {
            ok = DnsWire.TrySkipRecord(data, ref p, out ushort rtype, out ushort rclass, out _, out _);
            if (ok && rtype == DnsType.OPT) payload = Math.Max(512, (int)rclass);
        }

        query = new DnsQuery
        {
            Raw = data,
            Id = id,
            Flags = flags,
            Question = new DnsQuestion(name, type, cls),
            QuestionEnd = questionEnd,
            MaxUdpPayload = Math.Min(payload, 4096),
        };
        return true;
    }
}

/// <summary>Low-level DNS message helpers (RFC 1035): names, records, building answers, TTL handling.</summary>
public static class DnsWire
{
    private const int MaxJumps = 64;

    /// <summary>Reads a (possibly compressed) domain name. Returns it lowercase, without a trailing dot; "" is the root.</summary>
    public static bool TryReadName(byte[] data, ref int offset, out string name)
    {
        name = "";
        var sb = new StringBuilder();
        int pos = offset;
        int end = -1;
        int jumps = 0;
        int total = 0;

        while (true)
        {
            if (pos >= data.Length) return false;
            byte b = data[pos];

            if (b == 0)
            {
                pos++;
                break;
            }

            if ((b & 0xC0) == 0xC0)                       // compression pointer
            {
                if (pos + 1 >= data.Length) return false;
                int target = ((b & 0x3F) << 8) | data[pos + 1];
                if (end < 0) end = pos + 2;
                if (++jumps > MaxJumps || target >= data.Length) return false;
                pos = target;
                continue;
            }

            if ((b & 0xC0) != 0) return false;            // reserved label types

            int len = b;
            pos++;
            if (pos + len > data.Length) return false;
            total += len + 1;
            if (total > 255) return false;

            if (sb.Length > 0) sb.Append('.');
            for (int i = 0; i < len; i++)
            {
                char c = (char)data[pos + i];
                sb.Append(c is >= 'A' and <= 'Z' ? (char)(c + 32) : c);
            }
            pos += len;
        }

        offset = end >= 0 ? end : pos;
        name = sb.ToString();
        return true;
    }

    /// <summary>Skips over a name without decoding it.</summary>
    public static bool TrySkipName(byte[] data, ref int offset)
    {
        int pos = offset;
        int guard = 0;
        while (true)
        {
            if (pos >= data.Length || ++guard > 300) return false;
            byte b = data[pos];
            if (b == 0) { offset = pos + 1; return true; }
            if ((b & 0xC0) == 0xC0) { if (pos + 1 >= data.Length) return false; offset = pos + 2; return true; }
            if ((b & 0xC0) != 0) return false;
            pos += 1 + b;
        }
    }

    /// <summary>Skips one resource record; reports its type, class, the offset of its TTL field and of its RDATA.</summary>
    public static bool TrySkipRecord(byte[] data, ref int offset, out ushort type, out ushort cls, out int ttlOffset, out int rdataOffset)
    {
        type = 0; cls = 0; ttlOffset = 0; rdataOffset = 0;
        int pos = offset;
        if (!TrySkipName(data, ref pos)) return false;
        if (pos + 10 > data.Length) return false;

        type = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos));
        cls = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos + 2));
        ttlOffset = pos + 4;
        int rdlen = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos + 8));
        rdataOffset = pos + 10;
        if (rdataOffset + rdlen > data.Length) return false;

        offset = rdataOffset + rdlen;
        return true;
    }

    // ---- building responses ----------------------------------------------------------------

    public static byte[] BuildResponse(DnsQuery q, int rcode, IReadOnlyList<(ushort Type, byte[] Data)>? answers = null, uint ttl = 30)
    {
        answers ??= Array.Empty<(ushort, byte[])>();
        int questionLen = q.QuestionEnd - 12;
        int size = 12 + questionLen + answers.Sum(a => 12 + a.Data.Length);
        var r = new byte[size];

        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(0), q.Id);
        ushort flags = (ushort)(0x8000 | (q.Opcode << 11) | (q.Flags & 0x0100) | 0x0080 | (rcode & 0xF));
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(6), (ushort)answers.Count);
        Buffer.BlockCopy(q.Raw, 12, r, 12, questionLen);

        int pos = 12 + questionLen;
        foreach (var (type, data) in answers)
        {
            r[pos] = 0xC0; r[pos + 1] = 0x0C;                                        // name: pointer to the question
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(pos + 2), type);
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(pos + 4), DnsQuestion.ClassIn);
            BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(pos + 6), ttl);
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(pos + 10), (ushort)data.Length);
            Buffer.BlockCopy(data, 0, r, pos + 12, data.Length);
            pos += 12 + data.Length;
        }
        return r;
    }

    /// <summary>"Blocked" answer: A -> 0.0.0.0, AAAA -> ::, anything else -> empty NOERROR (no data).</summary>
    public static byte[] BuildNullAnswer(DnsQuery q, uint ttl = 30) => q.Question.Type switch
    {
        DnsType.A => BuildResponse(q, DnsRcode.NoError, new[] { (DnsType.A, new byte[4]) }, ttl),
        DnsType.AAAA => BuildResponse(q, DnsRcode.NoError, new[] { (DnsType.AAAA, new byte[16]) }, ttl),
        _ => BuildResponse(q, DnsRcode.NoError),
    };

    /// <summary>RFC 8482 minimal answer for ANY queries: returns an HINFO record with CPU "RFC8482" and empty OS.</summary>
    public static byte[] BuildRfc8482Hinfo(DnsQuery q, uint ttl = 300) =>
        BuildResponse(q, DnsRcode.NoError, new[] { (DnsType.HINFO, new byte[] { 7, 0x52, 0x46, 0x43, 0x38, 0x34, 0x38, 0x32, 0 }) }, ttl);

    public static byte[] BuildError(DnsQuery q, int rcode) => BuildResponse(q, rcode);

    /// <summary>An error response when the query itself could not be parsed but its ID is readable.</summary>
    public static byte[]? BuildFormatError(byte[] rawQuery)
    {
        if (rawQuery.Length < 12) return null;
        var r = new byte[12];
        r[0] = rawQuery[0]; r[1] = rawQuery[1];
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2), (ushort)(0x8000 | 0x0080 | DnsRcode.FormErr));
        return r;
    }

    /// <summary>Header + question only, with the TC bit: tells the client to retry over TCP.</summary>
    public static byte[] Truncate(byte[] response, DnsQuery q)
    {
        int len = q.QuestionEnd;
        var r = new byte[len];
        Buffer.BlockCopy(response, 0, r, 0, Math.Min(len, response.Length));
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) | 0x0200));
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(4), 1);
        for (int i = 6; i < 12; i++) r[i] = 0;
        return r;
    }

    // ---- inspecting responses --------------------------------------------------------------

    public static int ResponseRcode(byte[] response) => response.Length >= 4 ? response[3] & 0x0F : DnsRcode.ServFail;

    public static bool IsTruncated(byte[] response) => response.Length >= 3 && (response[2] & 0x02) != 0;

    /// <summary>Calls <paramref name="visit"/> for every resource record after the question (type, ttl offset, rdata offset, rdata length).</summary>
    private static bool ForEachRecord(byte[] r, Action<ushort, int, int, int> visit)
    {
        if (r.Length < 12) return false;
        int qd = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(4));
        int total = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(6)) + BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(8)) + BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(10));

        int pos = 12;
        for (int i = 0; i < qd; i++)
        {
            if (!TrySkipName(r, ref pos) || pos + 4 > r.Length) return false;
            pos += 4;
        }

        for (int i = 0; i < total; i++)
        {
            int start = pos;
            if (!TrySkipRecord(r, ref pos, out ushort type, out _, out int ttlOffset, out int rdataOffset)) return false;
            visit(type, ttlOffset, rdataOffset, pos - rdataOffset);
            _ = start;
        }
        return true;
    }

    /// <summary>The smallest TTL among the records of a response, or null if it has none.</summary>
    public static uint? MinTtl(byte[] response)
    {
        uint? min = null;
        ForEachRecord(response, (type, ttlOffset, _, _) =>
        {
            if (type == DnsType.OPT) return;
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(ttlOffset));
            min = min is null ? ttl : Math.Min(min.Value, ttl);
        });
        return min;
    }

    /// <summary>A copy of the response with the transaction id replaced and every TTL lowered to at most <paramref name="maxTtl"/>.</summary>
    public static byte[] Rewrite(byte[] response, ushort id, uint maxTtl)
    {
        var copy = (byte[])response.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(0), id);
        ForEachRecord(copy, (type, ttlOffset, _, _) =>
        {
            if (type == DnsType.OPT) return;
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(copy.AsSpan(ttlOffset));
            if (ttl > maxTtl) BinaryPrimitives.WriteUInt32BigEndian(copy.AsSpan(ttlOffset), maxTtl);
        });
        return copy;
    }

    /// <summary>The target names of CNAME records in a response (used to catch trackers hiding behind harmless names).</summary>
    public static IReadOnlyList<string> CnameTargets(byte[] response)
    {
        var targets = new List<string>();
        ForEachRecord(response, (type, _, rdataOffset, _) =>
        {
            if (type != DnsType.CNAME) return;
            int pos = rdataOffset;
            if (TryReadName(response, ref pos, out string target)) targets.Add(target);
        });
        return targets;
    }

    /// <summary>The IPv4/IPv6 addresses in the A and AAAA records of a response (used by the "Test my DNS server" button).</summary>
    public static IReadOnlyList<IPAddress> AddressAnswers(byte[] response)
    {
        var list = new List<IPAddress>();
        ForEachRecord(response, (type, _, rdataOffset, rdlen) =>
        {
            if ((type == DnsType.A && rdlen == 4) || (type == DnsType.AAAA && rdlen == 16))
                list.Add(new IPAddress(response.AsSpan(rdataOffset, rdlen)));
        });
        return list;
    }

    // ---- building queries (used by the upstream resolver tests and the "test a domain" button) ------

    public static byte[] BuildQuery(string name, ushort type, ushort id, bool recursionDesired = true)
    {
        var ms = new List<byte>();
        ms.Add((byte)(id >> 8)); ms.Add((byte)id);
        ms.Add((byte)(recursionDesired ? 0x01 : 0x00)); ms.Add(0);
        ms.AddRange(new byte[] { 0, 1, 0, 0, 0, 0, 0, 0 });
        foreach (var label in name.Trim('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            byte[] b = Encoding.ASCII.GetBytes(label);
            ms.Add((byte)b.Length);
            ms.AddRange(b);
        }
        ms.Add(0);
        ms.Add((byte)(type >> 8)); ms.Add((byte)type);
        ms.Add(0); ms.Add(1);
        return ms.ToArray();
    }
}
