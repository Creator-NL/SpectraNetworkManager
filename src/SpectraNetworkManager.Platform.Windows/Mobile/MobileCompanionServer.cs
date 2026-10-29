using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows.Mobile;

public sealed record CompanionClientInfo(
    string Ip,
    string UserAgent,
    DateTime PairedUtc,
    DateTime LastContactUtc,
    long RequestCount,
    bool IsAuthenticated
);

/// <summary>
/// Lightweight, hardened TCP HTTP server for the GSM Mobile Companion Dashboard.
/// Uses standard WinSock sockets (TcpListener) instead of kernel HTTP.SYS, ensuring
/// zero dependency on HTTP.SYS urlacl registrations and immunity to HTTP 503 errors.
/// Provides real-time network and TV defense metrics to mobile browsers with one-time pairing.
/// </summary>
public sealed class MobileCompanionServer : IDisposable
{
    private static readonly JsonSerializerOptions CamelCaseOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly ConcurrentDictionary<string, DateTime> _validSessions = new();
    private readonly ConcurrentDictionary<string, DateTime> _pendingPairingTokens = new();
    private readonly ConcurrentDictionary<string, CompanionClientInfo> _connectedClients = new(StringComparer.OrdinalIgnoreCase);
    private TcpListener? _tcpListener;
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;
    private bool _isRunning;
    private long _remoteRequestCount;

    public int Port { get; }
    public bool IsRunning => _isRunning && _tcpListener != null;
    public string RequirePin { get; set; } = "";
    public bool AllowMobileRuleChanges { get; set; }

    // Callbacks to Spectra services
    public Func<(bool IsDnsRunning, long TotalQueries, long BlockedQueries, double BlockRate, int ActiveClients)>? GetMetrics { get; set; }
    public Func<IReadOnlyList<object>>? GetRecentQueries { get; set; }
    public Func<IReadOnlyList<object>>? GetDevices { get; set; }
    public Action<int>? PauseDnsAction { get; set; }
    public Action? ResumeDnsAction { get; set; }
    public Action<string, bool>? ToggleGroupBlockingAction { get; set; }

    public MobileCompanionServer(int port = 8765)
    {
        Port = port;
    }

    /// <summary>
    /// Generates a cryptographic 6-character one-time pairing token valid for 60 seconds.
    /// </summary>
    public string GeneratePairingToken()
    {
        // Prune expired tokens
        var now = DateTime.UtcNow;
        foreach (var kvp in _pendingPairingTokens)
        {
            if (kvp.Value < now) _pendingPairingTokens.TryRemove(kvp.Key, out _);
        }

        string token = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
        _pendingPairingTokens[token] = now.AddSeconds(60);
        return token;
    }

    /// <summary>"all interfaces" when reachable from the LAN, "this PC only" when the wildcard bind was refused.</summary>
    public string BindScope { get; private set; } = "not started";

    /// <summary>Why the server could not listen on the LAN (empty when everything is fine).</summary>
    public string LastBindError { get; private set; } = "";

    /// <summary>UTC time of the most recent request from any device other than this PC (null = none yet).</summary>
    public DateTime? LastRemoteContactUtc { get; private set; }

    /// <summary>IP address of the most recent request from a device other than this PC.</summary>
    public string LastRemoteContactIp { get; private set; } = "";

    /// <summary>Number of requests received from other devices since the server started.</summary>
    public long RemoteRequestCount => Interlocked.Read(ref _remoteRequestCount);

    /// <summary>Fires when a remote LAN device connects to the companion server.</summary>
    public event Action<string, string>? RemoteContactReceived;

    /// <summary>Gets live connection details for a specific LAN client IP (null if no companion contact).</summary>
    public CompanionClientInfo? GetClientInfo(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        return _connectedClients.TryGetValue(ip.Trim(), out var info) ? info : null;
    }

    /// <summary>Gets all active or paired companion clients.</summary>
    public IReadOnlyList<CompanionClientInfo> GetAllClients() => _connectedClients.Values.ToList();

    public void Start()
    {
        if (_isRunning) return;

        LastBindError = "";
        try
        {
            _cts = new CancellationTokenSource();
            _tcpListener = new TcpListener(IPAddress.Any, Port);
            _tcpListener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _tcpListener.Start();
            _isRunning = true;
            BindScope = "all interfaces";
            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
        }
        catch (Exception ex)
        {
            LastBindError = ex.Message;
            _isRunning = false;
            try { _tcpListener?.Stop(); } catch { }
        }
    }

    public void Stop()
    {
        _isRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _tcpListener?.Stop(); } catch { }
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _isRunning && _tcpListener != null)
        {
            try
            {
                var client = await _tcpListener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleTcpClientAsync(client, ct), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) when (ct.IsCancellationRequested) { break; }
            catch { }
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            using (var stream = client.GetStream())
            {
                client.ReceiveTimeout = 8000;
                client.SendTimeout = 8000;

                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
                string? requestLine = await reader.ReadLineAsync(ct);
                if (string.IsNullOrWhiteSpace(requestLine)) return;

                var parts = requestLine.Split(' ', 3);
                if (parts.Length < 2) return;

                string method = parts[0].ToUpperInvariant();
                string rawUrl = parts[1];

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? headerLine;
                while (!string.IsNullOrEmpty(headerLine = await reader.ReadLineAsync(ct)))
                {
                    int colon = headerLine.IndexOf(':');
                    if (colon > 0)
                    {
                        headers[headerLine[..colon].Trim()] = headerLine[(colon + 1)..].Trim();
                    }
                }

                string path = rawUrl;
                string queryString = "";
                int qIdx = rawUrl.IndexOf('?');
                if (qIdx >= 0)
                {
                    path = rawUrl[..qIdx];
                    queryString = rawUrl[(qIdx + 1)..];
                }

                string body = "";
                if (headers.TryGetValue("Content-Length", out var clStr) && int.TryParse(clStr, out int contentLength) && contentLength > 0 && contentLength < 1_000_000)
                {
                    char[] buf = new char[contentLength];
                    int totalRead = 0;
                    while (totalRead < contentLength)
                    {
                        int n = await reader.ReadAsync(buf, totalRead, contentLength - totalRead);
                        if (n <= 0) break;
                        totalRead += n;
                    }
                    body = new string(buf, 0, totalRead);
                }

                string userAgent = headers.TryGetValue("User-Agent", out var ua) ? ua : "Unknown";

                var remote = (client.Client.RemoteEndPoint as IPEndPoint)?.Address;
                string? remoteIpStr = remote?.ToString();
                if (remote is not null && !IPAddress.IsLoopback(remote))
                {
                    LastRemoteContactUtc = DateTime.UtcNow;
                    LastRemoteContactIp = remoteIpStr!;
                    Interlocked.Increment(ref _remoteRequestCount);
                    RemoteContactReceived?.Invoke(LastRemoteContactIp, path);
                }

                if (method == "OPTIONS")
                {
                    await SendResponseAsync(stream, 200, "OK", "text/plain", Array.Empty<byte>());
                    return;
                }

                if (path == "/api/ping")
                {
                    var pingObj = new
                    {
                        ok = true,
                        app = "SpectraNetworkManager",
                        server = Environment.MachineName,
                        clientIp = remote?.ToString() ?? "unknown",
                        timeUtc = DateTime.UtcNow
                    };
                    await SendJsonAsync(stream, 200, pingObj);
                    return;
                }

                string? pairQuery = GetQueryParam(queryString, "token");
                string? newSessionCookie = null;
                if (!string.IsNullOrEmpty(pairQuery) && _pendingPairingTokens.TryGetValue(pairQuery, out var expires) && expires > DateTime.UtcNow)
                {
                    _pendingPairingTokens.TryRemove(pairQuery, out _);
                    string sessionToken = Guid.NewGuid().ToString("N");
                    _validSessions[sessionToken] = DateTime.UtcNow.AddHours(24);
                    newSessionCookie = $"SpectraSession={sessionToken}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax";
                }

                bool isAuthenticated = false;
                if (headers.TryGetValue("Cookie", out var cookieHdr))
                {
                    string? sessionCookie = GetCookieValue(cookieHdr, "SpectraSession");
                    if (!string.IsNullOrEmpty(sessionCookie) && _validSessions.TryGetValue(sessionCookie, out var exp) && exp > DateTime.UtcNow)
                    {
                        isAuthenticated = true;
                    }
                }
                if (newSessionCookie != null)
                {
                    isAuthenticated = true;
                }

                if (remote is not null && !IPAddress.IsLoopback(remote) && !string.IsNullOrEmpty(remoteIpStr))
                {
                    _connectedClients.AddOrUpdate(
                        remoteIpStr,
                        ip => new CompanionClientInfo(ip, userAgent, DateTime.UtcNow, DateTime.UtcNow, 1, isAuthenticated),
                        (ip, old) => new CompanionClientInfo(
                            ip,
                            !string.IsNullOrEmpty(userAgent) && userAgent != "Unknown" ? userAgent : old.UserAgent,
                            old.IsAuthenticated ? old.PairedUtc : (isAuthenticated ? DateTime.UtcNow : old.PairedUtc),
                            DateTime.UtcNow,
                            old.RequestCount + 1,
                            old.IsAuthenticated || isAuthenticated
                        )
                    );
                }

                if (path == "/")
                {
                    string html = GetMobileDashboardHtml(isAuthenticated);
                    await SendHtmlAsync(stream, 200, html, newSessionCookie);
                    return;
                }

                if (path == "/api/status")
                {
                    if (!isAuthenticated)
                    {
                        await SendJsonAsync(stream, 401, new { error = "Unauthorized. Please scan QR pairing code." });
                        return;
                    }

                    var metrics = GetMetrics?.Invoke() ?? (false, 0, 0, 0.0, 0);
                    var devices = GetDevices?.Invoke() ?? Array.Empty<object>();

                    await SendJsonAsync(stream, 200, new
                    {
                        serverName = Environment.MachineName,
                        dnsActive = metrics.IsDnsRunning,
                        totalQueries = metrics.TotalQueries,
                        blockedQueries = metrics.BlockedQueries,
                        blockPercentage = Math.Round(metrics.BlockRate, 1),
                        activeClients = metrics.ActiveClients,
                        devices = devices,
                        allowWrite = AllowMobileRuleChanges
                    });
                    return;
                }

                if (path == "/api/logs")
                {
                    if (!isAuthenticated)
                    {
                        await SendJsonAsync(stream, 401, new { error = "Unauthorized." });
                        return;
                    }

                    var logs = GetRecentQueries?.Invoke() ?? Array.Empty<object>();
                    await SendJsonAsync(stream, 200, logs);
                    return;
                }

                if (path == "/api/pause" && method == "POST")
                {
                    if (!isAuthenticated || !AllowMobileRuleChanges)
                    {
                        await SendJsonAsync(stream, 403, new { error = "Mobile rule modification disabled on host PC." });
                        return;
                    }

                    int minutes = 15;
                    try
                    {
                        using var doc = JsonDocument.Parse(body);
                        if (doc.RootElement.TryGetProperty("minutes", out var mProp))
                            minutes = mProp.GetInt32();
                    }
                    catch { }

                    PauseDnsAction?.Invoke(minutes);
                    await SendJsonAsync(stream, 200, new { success = true, pausedMinutes = minutes });
                    return;
                }

                if (path == "/api/resume" && method == "POST")
                {
                    if (!isAuthenticated || !AllowMobileRuleChanges)
                    {
                        await SendJsonAsync(stream, 403, new { error = "Mobile rule modification disabled on host PC." });
                        return;
                    }

                    ResumeDnsAction?.Invoke();
                    await SendJsonAsync(stream, 200, new { success = true });
                    return;
                }

                await SendResponseAsync(stream, 404, "Not Found", "text/plain", Encoding.UTF8.GetBytes("Not Found"));
            }
        }
        catch
        {
            // Transient network disconnects or aborts are ignored
        }
    }

    private static async Task SendResponseAsync(
        NetworkStream stream,
        int statusCode,
        string statusText,
        string contentType,
        byte[] body,
        string? setCookie = null)
    {
        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {statusCode} {statusText}\r\n");
        sb.Append($"Content-Type: {contentType}\r\n");
        sb.Append($"Content-Length: {body.Length}\r\n");
        sb.Append("Connection: close\r\n");
        sb.Append("X-Content-Type-Options: nosniff\r\n");
        sb.Append("X-Frame-Options: DENY\r\n");
        sb.Append("Cache-Control: no-store, no-cache, must-revalidate\r\n");
        sb.Append("Access-Control-Allow-Origin: *\r\n");
        sb.Append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        sb.Append("Access-Control-Allow-Headers: *\r\n");
        if (!string.IsNullOrEmpty(setCookie))
        {
            sb.Append($"Set-Cookie: {setCookie}\r\n");
        }
        sb.Append("\r\n");

        byte[] headerBytes = Encoding.UTF8.GetBytes(sb.ToString());
        await stream.WriteAsync(headerBytes);
        if (body.Length > 0)
        {
            await stream.WriteAsync(body);
        }
        await stream.FlushAsync();
    }

    private static Task SendJsonAsync(NetworkStream stream, int statusCode, object data)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(data, CamelCaseOpts);
        string statusText = statusCode switch
        {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "OK"
        };
        return SendResponseAsync(stream, statusCode, statusText, "application/json; charset=utf-8", bytes);
    }

    private static Task SendHtmlAsync(NetworkStream stream, int statusCode, string html, string? setCookie)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(html);
        return SendResponseAsync(stream, statusCode, "OK", "text/html; charset=utf-8", bytes, setCookie);
    }

    private static string? GetQueryParam(string queryString, string key)
    {
        if (string.IsNullOrEmpty(queryString)) return null;
        var pairs = queryString.Split('&');
        foreach (var pair in pairs)
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && string.Equals(Uri.UnescapeDataString(kv[0]), key, StringComparison.OrdinalIgnoreCase))
            {
                return Uri.UnescapeDataString(kv[1]);
            }
        }
        return null;
    }

    private static string? GetCookieValue(string cookieHeader, string name)
    {
        var cookies = cookieHeader.Split(';');
        foreach (var c in cookies)
        {
            var kv = c.Trim().Split('=', 2);
            if (kv.Length == 2 && string.Equals(kv[0], name, StringComparison.OrdinalIgnoreCase))
            {
                return kv[1];
            }
        }
        return null;
    }

    private static string GetMobileDashboardHtml(bool isAuthenticated)
    {
        return $$"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
  <title>Spectra Mobile Companion</title>
  <style>
    :root {
      --bg: #0B0E14;
      --card: #151B26;
      --cyan: #00E5FF;
      --magenta: #FF2BD6;
      --amber: #FFB000;
      --text: #DCE3F0;
      --muted: #7E8BA3;
      --line: #222C3D;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 16px; min-height: 100vh; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--line); padding-bottom: 12px; margin-bottom: 16px; }
    .title { font-size: 1.15rem; font-weight: 700; color: var(--cyan); letter-spacing: 0.5px; }
    .badge { font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 600; text-transform: uppercase; }
    .badge-on { background: rgba(0,229,255,0.15); color: var(--cyan); border: 1px solid var(--cyan); }
    .badge-off { background: rgba(255,43,214,0.15); color: var(--magenta); border: 1px solid var(--magenta); }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 16px; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
    .metric-val { font-size: 1.6rem; font-weight: 800; color: var(--text); margin-top: 4px; }
    .metric-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; font-weight: 600; }
    .section-title { font-size: 0.9rem; font-weight: 700; color: var(--muted); margin-bottom: 8px; text-transform: uppercase; }
    .btn { display: block; width: 100%; padding: 12px; border-radius: 6px; border: none; font-size: 0.95rem; font-weight: 600; cursor: pointer; text-align: center; margin-bottom: 8px; transition: opacity 0.2s; }
    .btn-pause { background: #FF2BD6; color: #fff; }
    .btn-resume { background: #00E5FF; color: #000; }
    .query-item { padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 0.85rem; display: flex; justify-content: space-between; }
    .query-domain { font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 70%; }
    .blocked { color: var(--magenta); }
    .allowed { color: var(--cyan); }
    .auth-banner { background: rgba(255,176,0,0.1); border: 1px solid var(--amber); color: var(--amber); padding: 16px; border-radius: 8px; text-align: center; }
  </style>
</head>
<body>
  <header>
    <div>
      <div class="title">SPECTRA COMPANION</div>
      <div style="font-size: 0.8rem; color: var(--muted);">Mobile Defense Hub</div>
    </div>
    <div id="statusBadge" class="badge badge-on">ONLINE</div>
  </header>

  {{(isAuthenticated ? """
  <div class="grid">
    <div class="card">
      <div class="metric-lbl">Total Queries</div>
      <div class="metric-val" id="totalQueries">0</div>
    </div>
    <div class="card">
      <div class="metric-lbl">Blocked (ACR / Ads)</div>
      <div class="metric-val blocked" id="blockedQueries">0</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 16px;">
    <div class="section-title">Quick Defense Control</div>
    <button class="btn btn-pause" onclick="pauseSinkhole(15)">⏸ Pause Blocking (15 Mins)</button>
    <button class="btn btn-resume" onclick="resumeSinkhole()">▶ Resume Protection</button>
  </div>

  <div class="card">
    <div class="section-title">Recent Activity</div>
    <div id="logList" style="max-height: 250px; overflow-y: auto;">
      <div style="color: var(--muted); font-size: 0.85rem; padding: 8px;">Loading live stream...</div>
    </div>
  </div>

  <script>
    async function refresh() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('totalQueries').innerText = data.totalQueries.toLocaleString();
        document.getElementById('blockedQueries').innerText = data.blockedQueries.toLocaleString() + ' (' + data.blockPercentage + '%)';
        const badge = document.getElementById('statusBadge');
        if (data.dnsActive) {
          badge.className = 'badge badge-on';
          badge.innerText = 'SHIELD ON';
        } else {
          badge.className = 'badge badge-off';
          badge.innerText = 'PAUSED';
        }
      } catch (e) {}

      try {
        const logRes = await fetch('/api/logs');
        const logs = await logRes.json();
        const list = document.getElementById('logList');
        if (logs.length > 0) {
          list.innerHTML = logs.slice(0, 15).map(l => `
            <div class="query-item">
              <span class="query-domain">${l.domain || l.Domain || 'Unknown'}</span>
              <span class="${(l.isBlocked || l.IsBlocked) ? 'blocked' : 'allowed'}">${(l.isBlocked || l.IsBlocked) ? '🚫 Block' : '🛡️ OK'}</span>
            </div>
          `).join('');
        } else {
          list.innerHTML = '<div style="color: var(--muted); font-size: 0.85rem; padding: 8px;">No DNS activity yet. On your phone set the Wi-Fi DNS to this PC and leave DNS 2 empty.</div>';
        }
      } catch (e) {}
    }

    async function pauseSinkhole(mins) {
      if (!confirm('Pause DNS Sinkhole filtering for ' + mins + ' minutes?')) return;
      await fetch('/api/pause', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ minutes: mins }) });
      refresh();
    }

    async function resumeSinkhole() {
      await fetch('/api/resume', { method: 'POST' });
      refresh();
    }

    setInterval(refresh, 2500);
    refresh();
  </script>
  """ : """
  <div class="auth-banner">
    <div style="font-weight: 700; font-size: 1.1rem; margin-bottom: 8px;">🔐 Unpaired Device</div>
    <div style="font-size: 0.85rem; line-height: 1.4;">
      To securely connect your phone to SpectraNetworkManager:
      <br/><br/>
      1. Open <b>TV & Mobile Protection</b> in Spectra on your PC.<br/>
      2. Click <b>📱 Launch Mobile Companion & Show QR</b>.<br/>
      3. Scan the QR code with your phone camera to pair instantly!
    </div>
  </div>
  """)}}
</body>
</html>
""";
    }

    public void Dispose()
    {
        Stop();
    }
}
