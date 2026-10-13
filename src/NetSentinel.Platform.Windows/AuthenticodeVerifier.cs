using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Channels;
using NetSentinel.Core;

namespace NetSentinel.Platform.Windows;

/// <summary>
/// Verifies programs' digital signatures with Windows' own Authenticode check (Get-AuthenticodeSignature), which understands
/// both signatures embedded in the file and the catalog signatures used by most Windows system files.
/// Checks run in the background in small batches; results are remembered between runs.
///
/// Notes: certificate revocation is not queried (no network calls). Paths are sent to PowerShell base64-encoded on stdin,
/// so odd characters in a path can never be interpreted as commands. A later phase replaces this with a native WinVerifyTrust call.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeVerifier : ISignatureVerifier, IDisposable
{
    private const string Script = @"
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$lines=@([Console]::In.ReadToEnd() -split '\r?\n' | Where-Object { $_ })
$out=@()
for($i=0;$i -lt $lines.Count;$i++){
  $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($lines[$i]))
  $s=Get-AuthenticodeSignature -LiteralPath $p
  $subj=''; if($s -and $s.SignerCertificate){$subj=$s.SignerCertificate.Subject}
  $os=$false; if($s -and $s.IsOSBinary){$os=$true}
  $out+=[pscustomobject]@{I=$i;Status=[string]$s.Status;Subject=$subj;IsOs=$os}
}
ConvertTo-Json -InputObject $out -Compress
";

    private static readonly TimeSpan BatchWindow = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(90);

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
            // Could not even look at the file (permissions): let the check below report "unknown".
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
                await Task.Delay(BatchWindow, ct).ConfigureAwait(false);   // let a burst of new programs collect into one batch

                var batch = new List<string>();
                while (batch.Count < 25 && _queue.Reader.TryRead(out var path)) batch.Add(path);
                if (batch.Count > 0) await VerifyBatchAsync(batch, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }

    private async Task VerifyBatchAsync(List<string> batch, CancellationToken ct)
    {
        IReadOnlyDictionary<string, SignatureInfo> results;
        try
        {
            results = await RunPowerShellAsync(batch, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            results = new Dictionary<string, SignatureInfo>();
            foreach (var p in batch) _known[p] = new SignatureInfo(SignatureStatus.Unknown, null, false, ex.Message);
        }

        foreach (var path in batch)
        {
            var info = results.TryGetValue(path, out var r) ? r : new SignatureInfo(SignatureStatus.Unknown, null, false, "no result");
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

    private static async Task<IReadOnlyDictionary<string, SignatureInfo>> RunPowerShellAsync(List<string> paths, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(Script)));

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        foreach (var p in paths)
            await proc.StandardInput.WriteLineAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(p))).ConfigureAwait(false);
        proc.StandardInput.Close();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProcessTimeout);
        try
        {
            await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch (Exception) { }
            throw;
        }

        string stdout = await stdoutTask.ConfigureAwait(false);
        if (proc.ExitCode != 0 && string.IsNullOrWhiteSpace(stdout))
            throw new InvalidOperationException("PowerShell failed: " + (await stderrTask.ConfigureAwait(false)).Trim());

        return AuthenticodeParser.Parse(stdout, paths);
    }

    public void Dispose() => _cts.Cancel();
}
