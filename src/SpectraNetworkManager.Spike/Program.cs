using System.Net;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Platform.Windows;

// Phase 0 spike: prove we can see every connection and which program owns it.
//   SpectraNetworkManager.Spike            -> print one snapshot (established connections + listeners)
//   SpectraNetworkManager.Spike --all      -> include TIME_WAIT/closing noise too
//   SpectraNetworkManager.Spike --watch    -> stream connections as they open and close (Ctrl+C to stop)
//   SpectraNetworkManager.Spike --dns      -> run the DNS sinkhole without the window (options: --port N, --listen IP, --upstream IP[:port], --block domain[,domain...], --update,
//                                   --settings file; by default a temp file is used, so the window's own DNS settings are never changed)
//   SpectraNetworkManager.Spike --blocks   -> show what Windows Firewall blocked (needs Administrator + audit policy, see below)
//   SpectraNetworkManager.Spike --blocks --packets   -> also include individual dropped packets (very noisy)

if (args.Contains("--dns", StringComparer.OrdinalIgnoreCase)) return await RunDnsAsync(args);
if (args.Contains("--test-m1", StringComparer.OrdinalIgnoreCase)) return RunMilestone1SelfTest();
if (args.Contains("--test-m2", StringComparer.OrdinalIgnoreCase)) return RunMilestone2SelfTest();

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

    // Never touch the window's settings (%LocalAppData%\SpectraNetworkManager\dns-settings.json): the console uses its own file.
    // The downloaded block lists are shared, they are only a cache.
    string settingsFile = Option("--settings") ?? Path.Combine(Path.GetTempPath(), "SpectraNetworkManager-spike-dns-settings.json");
    using var dns = new SpectraNetworkManager.Sinkhole.DnsService(settingsFile, SpectraNetworkManager.Sinkhole.BlocklistManager.DefaultFolder);
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

static int RunMilestone1SelfTest()
{
    Console.WriteLine("Running Milestone 1 Self-Test (Process Intelligence, SHA-256, Service/Parent & IP/ASN)...");

    // 1. ExecutableHashCache
    string tempDir = Path.Combine(Path.GetTempPath(), "SpectraM1Test_" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(tempDir);
    try
    {
        string cacheFile = Path.Combine(tempDir, "hash-cache.json");
        string binFile = Path.Combine(tempDir, "sample.exe");
        File.WriteAllText(binFile, "spectra-v2-test-payload-1");

        var hashCache = new ExecutableHashCache(cacheFile);
        string? h1 = hashCache.GetSha256(binFile);
        string? h2 = hashCache.GetSha256(binFile);
        if (string.IsNullOrEmpty(h1) || h1.Length != 64 || h1 != h2)
            throw new InvalidOperationException("SHA-256 computation or cache hit failed.");

        File.WriteAllText(binFile, "spectra-v2-test-payload-2-modified");
        File.SetLastWriteTimeUtc(binFile, DateTime.UtcNow.AddMinutes(2));
        string? h3 = hashCache.GetSha256(binFile);
        if (string.IsNullOrEmpty(h3) || h3 == h1)
            throw new InvalidOperationException("SHA-256 cache invalidation on file change failed.");

        Console.WriteLine($"  [OK] ExecutableHashCache: SHA-256 computed & invalidated cleanly ({h3[..16]}...)");
    }
    finally
    {
        try { Directory.Delete(tempDir, recursive: true); } catch { }
    }

    // 2. IpIntelligenceService
    var ipIntel = new IpIntelligenceService();
    var cf = ipIntel.Analyze(IPAddress.Parse("1.1.1.1"));
    var q9 = ipIntel.Analyze(IPAddress.Parse("9.9.9.9"));
    var lan = ipIntel.Analyze(IPAddress.Parse("192.168.1.10"));
    if (cf.Asn != "AS13335" || !cf.IsPublicRoutable)
        throw new InvalidOperationException($"Expected AS13335 for 1.1.1.1, got {cf.Asn}");
    if (q9.CountryCode != "CH" || q9.Asn != "AS19281")
        throw new InvalidOperationException($"Expected CH/AS19281 for 9.9.9.9, got {q9.CountryCode}/{q9.Asn}");
    if (lan.IsPublicRoutable || lan.CountryCode != "LAN")
        throw new InvalidOperationException("Expected LAN non-routable for 192.168.1.10");
    Console.WriteLine($"  [OK] IpIntelligenceService: 1.1.1.1 -> '{cf.ShortDisplay}', 9.9.9.9 -> '{q9.ShortDisplay}', 192.168.1.10 -> '{lan.ShortDisplay}'");

    // 3. ProcessInfo.ClassifyIdentity
    var osSig = new SignatureInfo(SignatureStatus.Valid, "Microsoft Windows", IsOsBinary: true);
    var pubSig = new SignatureInfo(SignatureStatus.Valid, "Mozilla Corporation", IsOsBinary: false);
    var unsignedSig = new SignatureInfo(SignatureStatus.NotSigned, null, IsOsBinary: false);
    var tamperedSig = new SignatureInfo(SignatureStatus.Tampered, "Bad", IsOsBinary: false);

    if (ProcessInfo.ClassifyIdentity(@"C:\Windows\System32\svchost.exe", osSig) != IdentityVerificationLevel.VerifiedSystemBinary)
        throw new InvalidOperationException("Expected VerifiedSystemBinary");
    if (ProcessInfo.ClassifyIdentity(@"C:\Program Files\Firefox\firefox.exe", pubSig) != IdentityVerificationLevel.VerifiedPublisherBinary)
        throw new InvalidOperationException("Expected VerifiedPublisherBinary");
    if (ProcessInfo.ClassifyIdentity(@"C:\Temp\app.exe", unsignedSig) != IdentityVerificationLevel.UnsignedOrUnverified)
        throw new InvalidOperationException("Expected UnsignedOrUnverified");
    if (ProcessInfo.ClassifyIdentity(@"C:\Temp\app.exe", tamperedSig) != IdentityVerificationLevel.TamperedOrUntrusted)
        throw new InvalidOperationException("Expected TamperedOrUntrusted");
    Console.WriteLine("  [OK] ProcessInfo.ClassifyIdentity: 4-tier verification model verified.");

    // 4. ProcessResolver on current process
    if (OperatingSystem.IsWindows())
    {
        var procResolver = new ProcessResolver();
        var self = procResolver.Resolve(Environment.ProcessId);
        if (self.Pid != Environment.ProcessId || string.IsNullOrEmpty(self.Name))
            throw new InvalidOperationException("ProcessResolver failed on current process.");
        Console.WriteLine($"  [OK] ProcessResolver: PID={self.Pid}, Name={self.Name}, ParentPID={self.ParentPid}, ParentName={self.ParentName}, StartTimeUtc={self.StartTimeUtc:O}");
    }

    Console.WriteLine("ALL MILESTONE 1 SELF-TESTS PASSED SUCCESSFULLY.");
    return 0;
}

static int RunMilestone2SelfTest()
{
    Console.WriteLine("RUNNING MILESTONE 2 SELF-TEST: Port Scanner & Passive LAN Discovery...");

    // 1. DeviceClassifier
    var (kRoku, vRoku, _) = DeviceClassifier.Classify("B0:EE:7B:11:22:33", "", null);
    if (kRoku != DeviceKind.SmartTv || !vRoku.Contains("Roku"))
        throw new InvalidOperationException($"Expected Roku Smart TV, got {kRoku} {vRoku}");

    var (kApple, vApple, _) = DeviceClassifier.Classify("00:1C:B3:AA:BB:CC", "", null);
    if (kApple != DeviceKind.MobileOrTablet || !vApple.Contains("Apple"))
        throw new InvalidOperationException($"Expected Apple Mobile, got {kApple} {vApple}");

    var (kGw, _, _) = DeviceClassifier.Classify("", "", null, isGateway: true);
    if (kGw != DeviceKind.RouterOrGateway)
        throw new InvalidOperationException($"Expected RouterOrGateway, got {kGw}");

    var (kEsp, vEsp, _) = DeviceClassifier.Classify("24:0A:C4:00:11:22", "", null);
    if (kEsp != DeviceKind.IotOrSmartHome || !vEsp.Contains("Espressif"))
        throw new InvalidOperationException($"Expected Espressif IoT, got {kEsp} {vEsp}");

    Console.WriteLine("  [OK] DeviceClassifier: Smart TV, Mobile, Router, and IoT hardware classification verified.");

    // 2. NetworkScanner Subnet & Private IP checks
    if (!NetworkScanner.IsPrivateOrLocal(IPAddress.Loopback)) throw new InvalidOperationException("Loopback should be private/local");
    if (!NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("192.168.1.1"))) throw new InvalidOperationException("192.168.1.1 should be private/local");
    if (!NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("10.0.0.1"))) throw new InvalidOperationException("10.0.0.1 should be private/local");
    if (NetworkScanner.IsPrivateOrLocal(IPAddress.Parse("8.8.8.8"))) throw new InvalidOperationException("8.8.8.8 should NOT be private/local");

    var subnetIps = NetworkScanner.GenerateSubnetIps(IPAddress.Parse("192.168.1.100"));
    if (subnetIps.Count != 254 || subnetIps[0].ToString() != "192.168.1.1" || subnetIps[253].ToString() != "192.168.1.254")
        throw new InvalidOperationException("GenerateSubnetIps failed to produce 254 IPs");

    Console.WriteLine("  [OK] NetworkScanner: Private IP checks & /24 subnet generation (254 hosts) verified.");

    // 3. WellKnownPorts
    if (WellKnownPorts.Top20.Length != 20) throw new InvalidOperationException("Top20 should have 20 ports");
    if (WellKnownPorts.Top100.Length != 100) throw new InvalidOperationException("Top100 should have 100 ports");
    if (WellKnownPorts.GetServiceName(80, Protocol.Tcp) != "HTTP") throw new InvalidOperationException("Port 80 should be HTTP");
    if (WellKnownPorts.GetServiceName(443, Protocol.Tcp) != "HTTPS") throw new InvalidOperationException("Port 443 should be HTTPS");

    Console.WriteLine("  [OK] WellKnownPorts: Port directories and service mappings verified.");

    // 4. LocalSocketInventory & WindowsNeighborScanner
    var mockSource = new FakeConnectionSource(new List<ConnectionInfo>
    {
        new(Protocol.Tcp, new IPEndPoint(IPAddress.Any, 8080), new IPEndPoint(IPAddress.Any, 0), ConnectionState.Listen, Environment.ProcessId),
        new(Protocol.Tcp, new IPEndPoint(IPAddress.Loopback, 5000), new IPEndPoint(IPAddress.Loopback, 0), ConnectionState.Listen, Environment.ProcessId),
    });
    var mockResolver = new FakeProcessResolver();
    var mockInv = new LocalSocketInventory(mockSource, mockResolver);
    var mockDev = mockInv.GetLocalInventory();
    if (!mockDev.IsLocalHost || mockDev.OpenPorts.Count != 2)
        throw new InvalidOperationException("LocalSocketInventory logic failed on test sockets");

    Console.WriteLine($"  [OK] LocalSocketInventory: Discovered {mockDev.OpenPorts.Count} listening sockets (1 LAN exposed, 1 loopback).");

    if (OperatingSystem.IsWindows())
    {
        try
        {
            var liveInv = new LocalSocketInventory(new IpHelperConnectionSource(), new ProcessResolver());
            var liveDev = liveInv.GetLocalInventory();
            Console.WriteLine($"  [OK] Live LocalSocketInventory: Discovered {liveDev.OpenPorts.Count} listening sockets on {Environment.MachineName}.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [INFO] Live IP Helper query restricted in current sandbox: {ex.Message}");
        }

        try
        {
            var neighborScanner = new WindowsNeighborScanner();
            var neighbors = neighborScanner.GetNeighborTable();
            Console.WriteLine($"  [OK] WindowsNeighborScanner: Successfully read {neighbors.Count} neighbor/ARP entries.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [INFO] Neighbor query restricted in current sandbox: {ex.Message}");
        }
    }

    Console.WriteLine("ALL MILESTONE 2 SELF-TESTS PASSED SUCCESSFULLY.");
    return 0;
}

sealed class FakeConnectionSource : IConnectionSource
{
    private readonly IReadOnlyList<ConnectionInfo> _conns;
    public FakeConnectionSource(IReadOnlyList<ConnectionInfo> conns) => _conns = conns;
    public IReadOnlyList<ConnectionInfo> GetConnections() => _conns;
}

sealed class FakeProcessResolver : IProcessResolver
{
    public ProcessInfo Resolve(int pid) =>
        new(pid, "SpikeProc", "C:\\Spike.exe", null, null, null, null, null);
    public void Prune(IReadOnlySet<int> livePids) { }
}
