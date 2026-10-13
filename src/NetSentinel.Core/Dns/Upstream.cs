using System.Net;
using System.Net.Sockets;

namespace NetSentinel.Sinkhole;

public interface IUpstreamResolver
{
    /// <summary>Sends the raw query to the upstream DNS servers and returns the raw answer, or null if none of them answered.</summary>
    Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct);
}

/// <summary>Forwards queries to ordinary DNS servers over UDP (and TCP when the answer is too big or the client used TCP). Tries the servers in order.</summary>
public sealed class NetworkUpstreamResolver : IUpstreamResolver
{
    private readonly IReadOnlyList<IPEndPoint> _servers;
    private readonly TimeSpan _timeout;

    public NetworkUpstreamResolver(IReadOnlyList<IPEndPoint> servers, TimeSpan? timeout = null)
    {
        _servers = servers;
        _timeout = timeout ?? TimeSpan.FromSeconds(2.5);
    }

    public async Task<byte[]?> ResolveAsync(byte[] query, bool useTcp, CancellationToken ct)
    {
        foreach (var server in _servers)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                byte[]? answer = useTcp ? await TcpAsync(server, query, ct) : await UdpAsync(server, query, ct);

                // A truncated UDP answer means "ask again over TCP".
                if (!useTcp && answer is not null && DnsWire.IsTruncated(answer))
                    answer = await TcpAsync(server, query, ct) ?? answer;

                if (answer is not null) return answer;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // timeout or network error: try the next server
            }
        }
        return null;
    }

    private async Task<byte[]?> UdpAsync(IPEndPoint server, byte[] query, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server);                                        // a connected socket only accepts answers from that server
        await udp.SendAsync(query, ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);

        while (true)
        {
            var result = await udp.ReceiveAsync(cts.Token);
            byte[] answer = result.Buffer;
            if (answer.Length >= 12 && answer[0] == query[0] && answer[1] == query[1]) return answer;   // ignore answers with a wrong id
        }
    }

    private async Task<byte[]?> TcpAsync(IPEndPoint server, byte[] query, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout + _timeout);

        using var tcp = new TcpClient(server.AddressFamily);
        await tcp.ConnectAsync(server, cts.Token);
        var stream = tcp.GetStream();

        var framed = new byte[query.Length + 2];
        framed[0] = (byte)(query.Length >> 8);
        framed[1] = (byte)query.Length;
        Buffer.BlockCopy(query, 0, framed, 2, query.Length);
        await stream.WriteAsync(framed, cts.Token);

        var lenBuf = new byte[2];
        await stream.ReadExactlyAsync(lenBuf, cts.Token);
        int len = (lenBuf[0] << 8) | lenBuf[1];
        if (len < 12) return null;

        var answer = new byte[len];
        await stream.ReadExactlyAsync(answer, cts.Token);
        return answer[0] == query[0] && answer[1] == query[1] ? answer : null;
    }
}
