using System.Collections.Concurrent;
using System.IO.Pipes;

namespace NetSentinel.Core.Ipc;

/// <summary>
/// Client for communicating with NetSentinel.Engine over named pipes or raw streams.
/// Supports asynchronous request-response correlation and real-time event streaming.
/// </summary>
public sealed class IpcClient : IAsyncDisposable, IDisposable
{
    private readonly string _pipeName;
    private Stream? _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<IpcMessage>> _pendingRequests = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _cts = new();
    private Task? _readLoopTask;
    private bool _disposed;

    public event Action<IpcMessage>? EventReceived;
    public event Action? Disconnected;

    public bool IsConnected => _stream != null && !_disposed;

    public IpcClient(string pipeName = IpcConstants.PipeName)
    {
        _pipeName = pipeName;
    }

    /// <summary>
    /// Connects to the NetSentinel engine named pipe.
    /// </summary>
    public async Task ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(timeout);

        await pipe.ConnectAsync(linkedCts.Token).ConfigureAwait(false);
        AttachStream(pipe);
    }

    /// <summary>
    /// Attaches an arbitrary bidirectional stream (e.g. for testing with memory/pipe streams).
    /// </summary>
    public void AttachStream(Stream stream)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(stream);

        _stream = stream;
        _readLoopTask = Task.Run(ReadLoopAsync);
    }

    /// <summary>
    /// Sends a request and awaits the engine's response.
    /// </summary>
    public async Task<IpcMessage> SendRequestAsync(string action, object? payload = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_stream == null) throw new InvalidOperationException("IPC client is not connected.");

        var request = IpcMessage.CreateRequest(action, payload);
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[request.Id] = tcs;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
        if (timeout.HasValue)
        {
            linkedCts.CancelAfter(timeout.Value);
        }

        try
        {
            await _writeLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            try
            {
                await IpcFrameCodec.WriteMessageAsync(_stream, request, linkedCts.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }

            using var reg = linkedCts.Token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            throw new TimeoutException($"IPC request '{action}' timed out waiting for response from Engine.");
        }
        finally
        {
            _pendingRequests.TryRemove(request.Id, out _);
        }
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested && _stream != null)
            {
                var message = await IpcFrameCodec.ReadMessageAsync(_stream, _cts.Token).ConfigureAwait(false);
                if (message == null) break; // End of stream

                if (string.Equals(message.Type, "Response", StringComparison.OrdinalIgnoreCase))
                {
                    if (_pendingRequests.TryRemove(message.Id, out var tcs))
                    {
                        tcs.TrySetResult(message);
                    }
                }
                else if (string.Equals(message.Type, "Event", StringComparison.OrdinalIgnoreCase))
                {
                    EventReceived?.Invoke(message);
                }
            }
        }
        catch (Exception)
        {
            // Stream disconnected or read error
        }
        finally
        {
            foreach (var kvp in _pendingRequests)
            {
                kvp.Value.TrySetException(new IOException("IPC connection closed unexpectedly."));
            }
            _pendingRequests.Clear();
            Disconnected?.Invoke();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
        _writeLock.Dispose();
        _stream?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        if (_stream != null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        if (_readLoopTask != null)
        {
            try { await _readLoopTask.ConfigureAwait(false); } catch { }
        }
        _cts.Dispose();
        _writeLock.Dispose();
    }
}
