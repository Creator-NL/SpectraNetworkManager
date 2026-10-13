using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Threading.Channels;
using NetSentinel.Core;

namespace NetSentinel.Platform.Windows;

/// <summary>
/// Verifies programs' digital signatures natively using Win32 WinVerifyTrust and CryptCATAdmin* APIs,
/// supporting both embedded signatures and security catalogs (used by Windows system binaries).
/// Checks run asynchronously on background threads; results are cached in memory and on disk.
/// </summary>
[SupportedOSPlatform("windows5.1.2600")]
public sealed class AuthenticodeVerifier : ISignatureVerifier, IDisposable
{
    private static readonly TimeSpan BatchWindow = TimeSpan.FromMilliseconds(50);

    private readonly SignatureCache _cache;
    private readonly ConcurrentDictionary<string, SignatureInfo> _known = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    private readonly CancellationTokenSource _cts = new();

    public AuthenticodeVerifier(SignatureCache cache)
    {
        _cache = cache;
        _ = Task.Run(() => WorkerAsync(_cts.Token));
    }

    public event Action<string, SignatureInfo>? Verified;

    public SignatureInfo? TryGet(string path)
    {
        if (_known.TryGetValue(path, out var known)) return known;
        if (_queued.ContainsKey(path)) return null;

        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                var gone = new SignatureInfo(SignatureStatus.Unknown, null, false, "file not found");
                _known[path] = gone;
                return gone;
            }

            var cached = _cache.TryGet(path, file.Length, file.LastWriteTimeUtc.Ticks, DateTimeOffset.Now);
            if (cached is not null)
            {
                _known[path] = cached;
                return cached;
            }
        }
        catch (Exception)
        {
            // Could not inspect the file (permissions): let the worker report "unknown".
        }

        if (_queued.TryAdd(path, 0)) _queue.Writer.TryWrite(path);
        return null;
    }

    private async Task WorkerAsync(CancellationToken ct)
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                await Task.Delay(BatchWindow, ct).ConfigureAwait(false);

                var batch = new List<string>();
                while (batch.Count < 50 && _queue.Reader.TryRead(out var path)) batch.Add(path);
                if (batch.Count > 0)
                {
                    await Task.Run(() => VerifyBatch(batch), ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }

    private void VerifyBatch(List<string> batch)
    {
        foreach (var path in batch)
        {
            SignatureInfo info;
            try
            {
                info = NativeAuthenticodeVerifier.VerifyFile(path);
            }
            catch (Exception ex)
            {
                info = new SignatureInfo(SignatureStatus.Unknown, null, false, ex.Message);
            }

            _known[path] = info;
            _queued.TryRemove(path, out _);

            try
            {
                var file = new FileInfo(path);
                if (file.Exists) _cache.Put(path, file.Length, file.LastWriteTimeUtc.Ticks, DateTimeOffset.Now, info);
            }
            catch (Exception) { /* not cacheable, fine */ }

            Verified?.Invoke(path, info);
        }

        _cache.Save();
    }

    public void Dispose() => _cts.Cancel();
}
