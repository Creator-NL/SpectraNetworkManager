using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows.Mobile;

/// <summary>
/// Lightweight, hardened HTTP server for the GSM Mobile Companion Dashboard.
/// Provides real-time network and TV defense metrics to mobile browsers with one-time pairing.
/// </summary>
public sealed class MobileCompanionServer : IDisposable
{
    private static readonly JsonSerializerOptions CamelCaseOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly HttpListener _listener = new();
    private readonly ConcurrentDictionary<string, DateTime> _validSessions = new();
    private readonly ConcurrentDictionary<string, DateTime> _pendingPairingTokens = new();
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;

    public int Port { get; }
    public bool IsRunning => _listener.IsListening;
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

    private long _remoteRequestCount;

    public void Start()
    {
        if (_listener.IsListening) return;

        LastBindError = "";
        try
        {
            _listener.Prefixes.Clear();
            _listener.Prefixes.Add($"http://*:{Port}/");
            _listener.Start();
            BindScope = "all interfaces";
        }
        catch (HttpListenerException ex)
        {
            LastBindError = ex.Message;

            // If wildcard http://*:8765 requires admin URL reservation, fall back to localhost/local prefix
            _listener.Prefixes.Clear();
            _listener.Prefixes.Add($"http://+:{Port}/");
            try
            {
                _listener.Start();
                BindScope = "all interfaces";
                LastBindError = "";
            }
            catch (HttpListenerException ex2)
            {
                LastBindError = ex2.Message;
                _listener.Prefixes.Clear();
                _listener.Prefixes.Add($"http://localhost:{Port}/");
                _listener.Start();
                BindScope = "this PC only";
            }
        }

        _cts = new CancellationTokenSource();
        _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        try
        {
            _cts?.Cancel();
            if (_listener.IsListening) _listener.Stop();
        }
        catch { }
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener.IsListening)
        {
            try
            {
                var context = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context));
            }
            catch (HttpListenerException) when (ct.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) { break; }
            catch { }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        try
        {
            var req = ctx.Request;
            var res = ctx.Response;

            // Security headers
            res.Headers.Add("X-Content-Type-Options", "nosniff");
            res.Headers.Add("X-Frame-Options", "DENY");
            res.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate");

            string path = req.Url?.AbsolutePath ?? "/";

            // Remember contact from other devices (phones/TVs) so the PC can show whether they reach us at all.
            var remote = req.RemoteEndPoint?.Address;
            if (remote is not null && !IPAddress.IsLoopback(remote))
            {
                LastRemoteContactUtc = DateTime.UtcNow;
                LastRemoteContactIp = remote.ToString();
                Interlocked.Increment(ref _remoteRequestCount);
                RemoteContactReceived?.Invoke(LastRemoteContactIp, path);
            }

            // Unauthenticated connectivity check: "can my phone reach this PC at all?"
            if (path == "/api/ping")
            {
                await WriteJsonAsync(res, new { ok = true, app = "SpectraNetworkManager", server = Environment.MachineName });
                return;
            }

            // Check pairing query token
            string? pairQuery = req.QueryString["token"];
            if (!string.IsNullOrEmpty(pairQuery) && _pendingPairingTokens.TryGetValue(pairQuery, out var expires) && expires > DateTime.UtcNow)
            {
                _pendingPairingTokens.TryRemove(pairQuery, out _);
                string sessionToken = Guid.NewGuid().ToString("N");
                _validSessions[sessionToken] = DateTime.UtcNow.AddHours(24);
                res.Cookies.Add(new Cookie("SpectraSession", sessionToken)
                {
                    Path = "/",
                    HttpOnly = true,
                    Expires = DateTime.Now.AddHours(24)
                });
            }

            // Authenticate session
            bool isAuthenticated = false;
            var cookie = req.Cookies["SpectraSession"];
            if (cookie != null && _validSessions.TryGetValue(cookie.Value, out var exp) && exp > DateTime.UtcNow)
            {
                isAuthenticated = true;
            }

            if (path == "/")
            {
                await ServeSinglePageAppAsync(res, isAuthenticated);
                return;
            }

            if (path == "/api/status")
            {
                if (!isAuthenticated)
                {
                    res.StatusCode = 401;
                    await WriteJsonAsync(res, new { error = "Unauthorized. Please scan QR pairing code." });
                    return;
                }

                var metrics = GetMetrics?.Invoke() ?? (false, 0, 0, 0.0, 0);
                var devices = GetDevices?.Invoke() ?? Array.Empty<object>();

                await WriteJsonAsync(res, new
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
                    res.StatusCode = 401;
                    await WriteJsonAsync(res, new { error = "Unauthorized." });
                    return;
                }

                var logs = GetRecentQueries?.Invoke() ?? Array.Empty<object>();
                await WriteJsonAsync(res, logs);
                return;
            }

            if (path == "/api/pause" && req.HttpMethod == "POST")
            {
                if (!isAuthenticated || !AllowMobileRuleChanges)
                {
                    res.StatusCode = 403;
                    await WriteJsonAsync(res, new { error = "Mobile rule modification disabled on host PC." });
                    return;
                }

                using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
                string body = await reader.ReadToEndAsync();
                int minutes = 15;
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("minutes", out var mProp))
                        minutes = mProp.GetInt32();
                }
                catch { }

                PauseDnsAction?.Invoke(minutes);
                await WriteJsonAsync(res, new { success = true, pausedMinutes = minutes });
                return;
            }

            if (path == "/api/resume" && req.HttpMethod == "POST")
            {
                if (!isAuthenticated || !AllowMobileRuleChanges)
                {
                    res.StatusCode = 403;
                    await WriteJsonAsync(res, new { error = "Mobile rule modification disabled on host PC." });
                    return;
                }

                ResumeDnsAction?.Invoke();
                await WriteJsonAsync(res, new { success = true });
                return;
            }

            res.StatusCode = 404;
            res.Close();
        }
        catch
        {
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    private static async Task WriteJsonAsync(HttpListenerResponse res, object data)
    {
        res.ContentType = "application/json; charset=utf-8";
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(data, CamelCaseOpts);
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.Close();
    }

    private static async Task ServeSinglePageAppAsync(HttpListenerResponse res, bool isAuthenticated)
    {
        res.ContentType = "text/html; charset=utf-8";
        string html = GetMobileDashboardHtml(isAuthenticated);
        byte[] bytes = Encoding.UTF8.GetBytes(html);
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.Close();
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
        ((IDisposable)_listener).Dispose();
    }
}
