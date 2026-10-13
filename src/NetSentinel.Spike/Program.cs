using System.Net;
using NetSentinel.Core;
using NetSentinel.Platform.Windows;

// Phase 0 spike: prove we can see every connection and which program owns it.
//   NetSentinel.Spike            -> print one snapshot (established connections + listeners)
//   NetSentinel.Spike --all      -> include TIME_WAIT/closing noise too
//   NetSentinel.Spike --watch    -> stream connections as they open and close (Ctrl+C to stop)
//   NetSentinel.Spike --dns      -> run the DNS sinkhole without the window (options: --port N, --listen IP, --upstream IP[:port], --block domain[,domain...], --update,
//                                   --settings file; by default a temp file is used, so the window's own DNS settings are never changed)
//   NetSentinel.Spike --blocks   -> show what Windows Firewall blocked (needs Administrator + audit policy, see below)
//   NetSentinel.Spike --blocks --packets   -> also include individual dropped packets (very noisy)

if (args.Contains("--dns", StringComparer.OrdinalIgnoreCase)) return await RunDnsAsync(args);

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This spike reads the Windows IP Helper tables, so it only runs on Windows.");
    return 1;
}

bool showAll = args.Contains("--all", StringComparer.OrdinalIgnoreCase);
bool watch = args.Contains("--watch", StringComparer.OrdinalIgnoreCase);
bool blocks = args.Contains("--blocks", StringComparer.OrdinalIgnoreCase);
bool packets = args.Contains("--packets", StringComparer.OrdinalIgnoreCase);

if (blocks) return await ShowBlocksAsync(packets);

var source = new IpHelperConnectionSource();
var resolver = new ProcessResolver();

bool Interesting(ConnectionInfo c) =>
    showAll || c.Protocol == Protocol.Udp
            || c.State is ConnectionState.Established or ConnectionState.Listen
                       or ConnectionState.SynSent or ConnectionState.SynReceived;

static string Endpoint(IPEndPoint? ep) => ep is null || ep.Port == 0 && ep.Address.Equals(IPAddress.Any) ? "*" : $"{ep.Address}:{ep.Port}";

void PrintRow(string prefix, ConnectionInfo c)
{
    var proc = resolver.Resolve(c.ProcessId);
    Console.WriteLine($"{prefix,-2} {c.Protocol.ToString().ToUpperInvariant(),-4} {Endpoint(c.Local),-28} {Endpoint(c.Remote),-28} {c.State,-12} {c.ProcessId,6}  {proc.Name}");
}

void Header() =>
    Console.WriteLine($"{"",-2} {"PROTO",-4} {"LOCAL",-28} {"REMOTE",-28} {"STATE",-12} {"PID",6}  PROGRAM");

try
{
    var snapshot = source.GetConnections();
    resolver.Prune(snapshot.Select(c => c.ProcessId).ToHashSet());

    if (!watch)
    {
        Header();
        foreach (var c in snapshot.Where(Interesting).OrderBy(c => c.Protocol).ThenBy(c => c.ProcessId))
            PrintRow("", c);
        Console.WriteLine($"\n{snapshot.Count(Interesting)} entries shown ({snapshot.Count} total).");
        return 0;
    }

    var tracker = new ConnectionTracker();
    tracker.Update(snapshot); // prime: don't report everything that already existed
    Console.WriteLine("Watching for connection changes. Press Ctrl+C to stop.\n");
    Header();

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    while (!cts.IsCancellationRequested)
    {
        await Task.Delay(TimeSpan.FromSeconds(1), cts.Token).ConfigureAwait(false);
        snapshot = source.GetConnections();
        resolver.Prune(snapshot.Select(c => c.ProcessId).ToHashSet());

        var diff = tracker.Update(snapshot);
        foreach (var c in diff.Opened.Where(Interesting)) PrintRow("+", c);
        foreach (var c in diff.Closed.Where(Interesting)) PrintRow("-", c);
    }
    return 0;
}
catch (OperationCanceledException)
{
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed: {ex.Message}");
    return 2;
}


static async Task<int> ShowBlocksAsync(bool includePackets)
{
    var log = new FirewallBlockLog();
    try
    {
        var recent = log.ReadRecent(TimeSpan.FromMinutes(30), 200, includePackets).Reverse().ToList();
        Console.WriteLine($"Blocked in the last 30 minutes: {recent.Count}");
        if (recent.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("Nothing found. If auditing is off, enable it ONCE from an elevated prompt:");
            Console.WriteLine("  auditpol /set /subcategory:\"{0CCE9226-69AE-11D9-BED3-505054503030}\" /failure:enable");
            Console.WriteLine("  auditpol /set /subcategory:\"{0CCE9225-69AE-11D9-BED3-505054503030}\" /failure:enable");
        }

        Console.WriteLine();
        foreach (var e in recent) PrintBlock(e);

        long last = recent.Count > 0 ? recent.Max(e => e.RecordId) : 0;
        Console.WriteLine("\nFollowing new blocks. Press Ctrl+C to stop.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        while (!cts.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cts.Token).ConfigureAwait(false);
            foreach (var e in log.ReadAfter(last, 200, includePackets))
            {
                PrintBlock(e);
                last = Math.Max(last, e.RecordId);
            }
        }
        return 0;
    }
    catch (OperationCanceledException) { return 0; }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed: {ex.Message}");
        return 2;
    }
}

static void PrintBlock(BlockEvent e)
{
    string dir = e.Inbound ? "IN " : "OUT";
    string app = string.IsNullOrEmpty(e.Application) ? "(unknown)" : e.Application;
    Console.WriteLine($"{e.Time:HH:mm:ss} {dir} {e.ProtocolName,-6} {e.SourceAddress}:{e.SourcePort} -> {e.DestinationAddress}:{e.DestinationPort}  pid {e.ProcessId}  {app}");
}


static async Task<int> RunDnsAsync(string[] args)
{
    string? Option(string name)
    {
        int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    // Never touch the window's settings (%LocalAppData%\NetSentinel\dns-settings.json): the console uses its own file.
    // The downloaded block lists are shared, they are only a cache.
    string settingsFile = Option("--settings") ?? Path.Combine(Path.GetTempPath(), "NetSentinel-spike-dns-settings.json");
    using var dns = new NetSentinel.Sinkhole.DnsService(settingsFile, NetSentinel.Sinkhole.BlocklistManager.DefaultFolder);
    var settings = dns.Settings;
    if (Option("--port") is string port && int.TryParse(port, out int p)) settings.Port = p;
    if (Option("--listen") is string listen) settings.ListenAddress = listen;
    if (Option("--upstream") is string upstream) settings.Upstreams = new List<string> { upstream };
    if (Option("--block") is string block)
        foreach (var d in block.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (!settings.CustomBlock.Contains(d, StringComparer.OrdinalIgnoreCase)) settings.CustomBlock.Add(d);
    Console.WriteLine($"Console settings file: {settingsFile}");

    try
    {
        await dns.ApplySettingsAsync(settings);

        if (args.Contains("--update", StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine("Updating block lists...");
            foreach (var r in await dns.UpdateListsAsync())
                Console.WriteLine($"  {(r.Ok ? "OK    " : "FAILED")} {r.Name}: {r.Message}");
        }

        dns.Queried += e => Console.WriteLine(
            $"{e.Time:HH:mm:ss} {e.Client,-15} {e.Type,-5} {e.Domain,-40} {e.Outcome,-9} {e.Milliseconds,4} ms  {e.Detail}");

        await dns.StartAsync();
        Console.WriteLine($"DNS sinkhole running on {dns.LocalEndPoint}, {dns.BlockedDomainCount:N0} blocked domains, upstream {string.Join(", ", settings.Upstreams)}.");
        Console.WriteLine("Press Ctrl+C to stop.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        await Task.Delay(Timeout.Infinite, cts.Token).ConfigureAwait(false);
        return 0;
    }
    catch (OperationCanceledException)
    {
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("Failed: " + ex.Message);
        return 2;
    }
}
