using System.Collections.Concurrent;
using System.IO.Pipes;

namespace SpectraNetworkManager.Core.Ipc;

/// <summary>
/// Server for hosting the SpectraNetworkManager IPC channel over named pipes.
/// Manages multi-client connections, request routing, and broadcast event dispatching.
/// </summary>
public sealed class IpcServer : IAsyncDisposable, IDisposable
{
    private readonly string _pipeName;
    private readonly Func<string, NamedPipeServerStream>? _pipeFactory;
    private readonly ConcurrentDictionary<string, ClientSession> _sessions = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _cts = new();
    private Task? _listenerTask;
    private bool _disposed;

    /// <summary>
    /// Router for processing incoming requests from clients.
    /// </summary>
    public Func<IpcMessage, Task<IpcMessage>>? RequestHandler { get; set; }

    /// <summary>
    /// Event fired when a client connects.
    /// </summary>
    public event Action<string>? ClientConnected;

    /// <summary>
    /// Event fired when a client disconnects.
    /// </summary>
    public event Action<string>? ClientDisconnected;

    public int ConnectedClientCount => _sessions.Count;

    public IpcServer(string pipeName = IpcConstants.PipeName, Func<string, NamedPipeServerStream>? pipeFactory = null)
    {
        _pipeName = pipeName;
        _pipeFactory = pipeFactory;
    }

    /// <summary>
    /// Starts the background listener loop.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_listenerTask != null) return;

        _listenerTask = Task.Run(ListenLoopAsync);
    }

    /// <summary>
    /// Manually attaches an arbitrary bidirectional stream (e.g. for testing).
    /// </summary>
    public string AttachClientStream(Stream stream)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(stream);

        var sessionId = Guid.NewGuid().ToString("N");
        var session = new ClientSession(sessionId, stream, this);
        _sessions[sessionId] = session;
        session.Start();
        ClientConnected?.Invoke(sessionId);
        return sessionId;
    }

    /// <summary>
    /// Broadcasts an event message to all currently connected clients.
    /// </summary>
    public async Task BroadcastEventAsync(string eventName, object? payload = null, CancellationToken ct = default)
    {
        if (_disposed || _sessions.IsEmpty) return;

        var message = IpcMessage.CreateEvent(eventName, payload);
        var tasks = new List<Task>(_sessions.Count);

        foreach (var session in _sessions.Values)
        {
            tasks.Add(session.SendMessageAsync(message, ct));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task ListenLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? serverPipe = null;
            try
            {
                serverPipe = _pipeFactory != null
                    ? _pipeFactory(_pipeName)
                    : new NamedPipeServerStream(
                        _pipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                await serverPipe.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);

                var sessionId = Guid.NewGuid().ToString("N");
                var session = new ClientSession(sessionId, serverPipe, this);
                _sessions[sessionId] = session;
                session.Start();
                ClientConnected?.Invoke(sessionId);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                serverPipe?.Dispose();
                break;
            }
            catch (Exception)
            {
                serverPipe?.Dispose();
                if (!_cts.IsCancellationRequested)
                {
                    await Task.Delay(100, _cts.Token).ConfigureAwait(false);
                }
            }
        }
    }

    internal void RemoveSession(string sessionId)
    {
        if (_sessions.TryRemove(sessionId, out var session))
        {
            ClientDisconnected?.Invoke(sessionId);
            session.Dispose();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();

        foreach (var session in _sessions.Values)
        {
            session.Dispose();
        }
        _sessions.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();

        if (_listenerTask != null)
        {
            try { await _listenerTask.ConfigureAwait(false); } catch { }
        }

        foreach (var session in _sessions.Values)
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
        _sessions.Clear();
        _cts.Dispose();
    }

    private sealed class ClientSession : IAsyncDisposable, IDisposable
    {
        private readonly string _sessionId;
        private readonly Stream _stream;
        private readonly IpcServer _server;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly CancellationTokenSource _cts = new();
        private Task? _readTask;
        private bool _disposed;

        public ClientSession(string sessionId, Stream stream, IpcServer server)
        {
            _sessionId = sessionId;
            _stream = stream;
            _server = server;
        }

        public void Start()
        {
            _readTask = Task.Run(ReadLoopAsync);
        }

        public async Task SendMessageAsync(IpcMessage message, CancellationToken ct = default)
        {
            if (_disposed) return;

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            try
            {
                await _writeLock.WaitAsync(linked.Token).ConfigureAwait(false);
                try
                {
                    await IpcFrameCodec.WriteMessageAsync(_stream, message, linked.Token).ConfigureAwait(false);
                }
                finally
                {
                    _writeLock.Release();
                }
            }
            catch (Exception)
            {
                _server.RemoveSession(_sessionId);
            }
        }

        private async Task ReadLoopAsync()
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var request = await IpcFrameCodec.ReadMessageAsync(_stream, _cts.Token).ConfigureAwait(false);
                    if (request == null) break;

                    if (string.Equals(request.Type, "Request", StringComparison.OrdinalIgnoreCase))
                    {
                        IpcMessage response;
                        if (_server.RequestHandler != null)
                        {
                            try
                            {
                                response = await _server.RequestHandler(request).ConfigureAwait(false);
                            }
                            catch (Exception ex)
                            {
                                response = IpcMessage.CreateErrorResponse(request, ex.Message);
                            }
                        }
                        else
                        {
                            response = IpcMessage.CreateErrorResponse(request, "No request handler registered on server.");
                        }

                        await SendMessageAsync(response, _cts.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception)
            {
                // Disconnected
            }
            finally
            {
                _server.RemoveSession(_sessionId);
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Cancel();
            _cts.Dispose();
            _writeLock.Dispose();
            _stream.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Cancel();
            await _stream.DisposeAsync().ConfigureAwait(false);
            if (_readTask != null)
            {
                try { await _readTask.ConfigureAwait(false); } catch { }
            }
            _cts.Dispose();
            _writeLock.Dispose();
        }
    }
}
