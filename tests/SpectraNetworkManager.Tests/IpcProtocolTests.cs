using System.Threading.Channels;
using SpectraNetworkManager.Core.Ipc;
using Xunit;

namespace SpectraNetworkManager.Tests;

public class IpcProtocolTests
{
    [Fact]
    public async Task FrameCodec_RoundTrips_SmallMessage()
    {
        using var stream = new MemoryStream();
        var original = IpcMessage.CreateRequest("TestPing", new { Greeting = "Hello World" });

        await IpcFrameCodec.WriteMessageAsync(stream, original);
        stream.Position = 0;

        var decoded = await IpcFrameCodec.ReadMessageAsync(stream);

        Assert.NotNull(decoded);
        Assert.Equal(original.Id, decoded.Id);
        Assert.Equal("Request", decoded.Type);
        Assert.Equal("TestPing", decoded.Action);
        Assert.Contains("Hello World", decoded.PayloadJson ?? "");
    }

    [Fact]
    public async Task FrameCodec_Handles_EmptyPayload()
    {
        using var stream = new MemoryStream();
        var original = IpcMessage.CreateRequest("EmptyAction");

        await IpcFrameCodec.WriteMessageAsync(stream, original);
        stream.Position = 0;

        var decoded = await IpcFrameCodec.ReadMessageAsync(stream);

        Assert.NotNull(decoded);
        Assert.Equal("EmptyAction", decoded.Action);
        Assert.Null(decoded.PayloadJson);
    }

    [Fact]
    public async Task ClientServer_RequestResponse_MatchesCorrelationId()
    {
        var (clientStream, serverStream) = CreateConnectedStreamPair();

        await using var server = new IpcServer();
        server.RequestHandler = req =>
        {
            if (req.Action == "Echo")
            {
                return Task.FromResult(IpcMessage.CreateResponse(req, new { Echo = req.PayloadJson }));
            }
            return Task.FromResult(IpcMessage.CreateErrorResponse(req, "Unknown action"));
        };
        server.AttachClientStream(serverStream);

        await using var client = new IpcClient();
        client.AttachStream(clientStream);

        var response = await client.SendRequestAsync("Echo", "Testing123", TimeSpan.FromSeconds(3));

        Assert.NotNull(response);
        Assert.True(response.Success);
        Assert.Equal("Echo", response.Action);
        Assert.Contains("Testing123", response.PayloadJson ?? "");
    }

    [Fact]
    public async Task ClientServer_ServerBroadcastsEvent_ClientReceives()
    {
        var (clientStream, serverStream) = CreateConnectedStreamPair();

        await using var server = new IpcServer();
        server.AttachClientStream(serverStream);

        await using var client = new IpcClient();
        client.AttachStream(clientStream);

        var eventReceivedTcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.EventReceived += msg =>
        {
            if (msg.Action == "TestAlert")
            {
                eventReceivedTcs.TrySetResult(msg);
            }
        };

        await server.BroadcastEventAsync("TestAlert", new { Level = "Warning", Code = 42 });

        var received = await eventReceivedTcs.Task.WaitAsync(TimeSpan.FromSeconds(3));

        Assert.NotNull(received);
        Assert.Equal("Event", received.Type);
        Assert.Equal("TestAlert", received.Action);
        Assert.Contains("Warning", received.PayloadJson ?? "");
    }

    [Fact]
    public async Task Client_TimesOut_WhenServerDoesNotRespond()
    {
        var (clientStream, serverStream) = CreateConnectedStreamPair();

        await using var server = new IpcServer();
        // Server handler deliberately hangs or delays
        server.RequestHandler = async _ =>
        {
            await Task.Delay(5000);
            return new IpcMessage();
        };
        server.AttachClientStream(serverStream);

        await using var client = new IpcClient();
        client.AttachStream(clientStream);

        await Assert.ThrowsAsync<TimeoutException>(async () =>
        {
            await client.SendRequestAsync("SlowAction", null, TimeSpan.FromMilliseconds(100));
        });
    }

    [Fact]
    public async Task Server_ReturnsError_WhenHandlerThrows()
    {
        var (clientStream, serverStream) = CreateConnectedStreamPair();

        await using var server = new IpcServer();
        server.RequestHandler = _ => throw new InvalidOperationException("Simulated failure in handler");
        server.AttachClientStream(serverStream);

        await using var client = new IpcClient();
        client.AttachStream(clientStream);

        var response = await client.SendRequestAsync("CrashingAction", null, TimeSpan.FromSeconds(3));

        Assert.False(response.Success);
        Assert.Contains("Simulated failure", response.Error ?? "");
    }

    [Fact]
    public void TerminateConnectionsRequest_SerializesAndDeserializes()
    {
        var req = new TerminateConnectionsRequest(Pid: 1234, ProgramPath: @"C:\Test\App.exe", LocalEndPoint: "127.0.0.1:80", RemoteEndPoint: "127.0.0.1:443");
        var msg = IpcMessage.CreateRequest(IpcConstants.Actions.TerminateConnections, req);

        var restored = msg.DeserializePayload<TerminateConnectionsRequest>();
        Assert.NotNull(restored);
        Assert.Equal(1234, restored.Pid);
        Assert.Equal(@"C:\Test\App.exe", restored.ProgramPath);
        Assert.Equal("127.0.0.1:80", restored.LocalEndPoint);
        Assert.Equal("127.0.0.1:443", restored.RemoteEndPoint);
    }

    [Fact]
    public void TerminateProcessRequest_SerializesAndDeserializes()
    {
        var req = new TerminateProcessRequest(5678);
        var msg = IpcMessage.CreateRequest(IpcConstants.Actions.TerminateProcess, req);

        var restored = msg.DeserializePayload<TerminateProcessRequest>();
        Assert.NotNull(restored);
        Assert.Equal(5678, restored.Pid);
    }

    private static (Stream ClientSide, Stream ServerSide) CreateConnectedStreamPair()
    {
        var clientToServer = new SimplexPipeStream();
        var serverToClient = new SimplexPipeStream();

        var clientStream = new DuplexPipeStream(serverToClient, clientToServer);
        var serverStream = new DuplexPipeStream(clientToServer, serverToClient);

        return (clientStream, serverStream);
    }

    private sealed class SimplexPipeStream : Stream
    {
        private readonly Channel<byte[]> _channel = Channel.CreateUnbounded<byte[]>();
        private byte[]? _currentChunk;
        private int _currentOffset;
        private bool _completed;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() { }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_completed) throw new InvalidOperationException("Stream closed.");
            byte[] copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            await _channel.Writer.WriteAsync(copy, cancellationToken).ConfigureAwait(false);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_completed) throw new InvalidOperationException("Stream closed.");
            byte[] copy = buffer.ToArray();
            await _channel.Writer.WriteAsync(copy, cancellationToken).ConfigureAwait(false);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (_currentChunk == null || _currentOffset >= _currentChunk.Length)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0; // EOF
                }

                if (_channel.Reader.TryRead(out var chunk))
                {
                    _currentChunk = chunk;
                    _currentOffset = 0;
                }
            }

            int available = _currentChunk.Length - _currentOffset;
            int toCopy = Math.Min(available, count);
            Buffer.BlockCopy(_currentChunk, _currentOffset, buffer, offset, toCopy);
            _currentOffset += toCopy;
            return toCopy;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_currentChunk == null || _currentOffset >= _currentChunk.Length)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0; // EOF
                }

                if (_channel.Reader.TryRead(out var chunk))
                {
                    _currentChunk = chunk;
                    _currentOffset = 0;
                }
            }

            int available = _currentChunk.Length - _currentOffset;
            int toCopy = Math.Min(available, buffer.Length);
            _currentChunk.AsSpan(_currentOffset, toCopy).CopyTo(buffer.Span);
            _currentOffset += toCopy;
            return toCopy;
        }

        public void Complete()
        {
            _completed = true;
            _channel.Writer.TryComplete();
        }

        protected override void Dispose(bool disposing)
        {
            Complete();
            base.Dispose(disposing);
        }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class DuplexPipeStream : Stream
    {
        private readonly SimplexPipeStream _reader;
        private readonly SimplexPipeStream _writer;

        public DuplexPipeStream(SimplexPipeStream reader, SimplexPipeStream writer)
        {
            _reader = reader;
            _writer = writer;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() => _writer.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _writer.FlushAsync(cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _reader.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _reader.ReadAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _writer.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            _writer.WriteAsync(buffer, cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => _reader.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => _writer.Write(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _reader.Dispose();
                _writer.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
