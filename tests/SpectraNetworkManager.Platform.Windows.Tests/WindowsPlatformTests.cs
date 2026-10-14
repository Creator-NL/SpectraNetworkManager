using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Principal;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Platform.Windows;

namespace SpectraNetworkManager.Platform.Windows.Tests;

[SupportedOSPlatform("windows")]
public class WindowsPlatformTests
{
    [Fact]
    public void ProcessResolver_ResolvesCurrentProcess()
    {
        var resolver = new ProcessResolver();
        int currentPid = Environment.ProcessId;

        var info = resolver.Resolve(currentPid);
        Assert.Equal(currentPid, info.Pid);
        Assert.NotNull(info.Name);
        Assert.NotEmpty(info.Name);
        Assert.NotNull(info.Path);
        Assert.True(File.Exists(info.Path));
    }

    [Fact]
    public void ProcessResolver_ResolvesSystemAndPid0()
    {
        var resolver = new ProcessResolver();

        var pid0 = resolver.Resolve(0);
        Assert.Equal(0, pid0.Pid);
        Assert.Contains("none", pid0.Name, StringComparison.OrdinalIgnoreCase);

        var pid4 = resolver.Resolve(4);
        Assert.Equal(4, pid4.Pid);
        Assert.Equal("System", pid4.Name);
    }

    [Fact]
    public void IpHelperConnectionSource_FindsOwnListeningSocket()
    {
        // Open a local TCP listener on dynamic port
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var source = new IpHelperConnectionSource();
            var connections = source.GetConnections();

            int currentPid = Environment.ProcessId;
            var match = connections.FirstOrDefault(c =>
                c.Protocol == Protocol.Tcp &&
                c.Local?.Port == port &&
                c.ProcessId == currentPid);

            Assert.NotNull(match);
            Assert.Equal(ConnectionState.Listen, match.State);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void DevicePathConverter_ConvertsOrPreservesPath()
    {
        var converter = new DevicePathConverter();
        string testPath = @"C:\Windows\System32\notepad.exe";
        string converted = converter.ToDosPath(testPath);
        Assert.Equal(testPath, converted);
    }

    [Fact]
    [Trait("Category", "FirewallAdmin")]
    public void FirewallEnforcer_AddAndRemoveRule_OnlyOnElevatedCI()
    {
        bool isCi = string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);
        bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        if (!isCi || !isAdmin)
        {
            // Skip on local development machines to follow the safety contract (never touch firewall unprompted).
            return;
        }

        var enforcer = new WindowsFirewallEnforcer();
        string testApp = Process.GetCurrentProcess().MainModule?.FileName ?? @"C:\Windows\System32\notepad.exe";
        var plan = RulePlanner.Plan(RuleDirection.Outbound, TrafficScope.All);

        try
        {
            enforcer.Block(testApp, plan, "CI test rule");
            var counts = enforcer.CountByProgram();
            Assert.True(counts.ContainsKey(testApp));
            Assert.True(counts[testApp] > 0);
        }
        finally
        {
            enforcer.Unblock(testApp);
        }
    }

    [Fact]
    public void TcpConnectionTerminator_SafeWithInvalidInputs()
    {
        var terminator = new TcpConnectionTerminator();
        Assert.Equal(0, terminator.TerminateConnectionsForPid(-1));
        Assert.Equal(0, terminator.TerminateConnectionsForPid(0));
        Assert.Equal(0, terminator.TerminateConnectionsForPid(999999999));
        Assert.Equal(0, terminator.TerminateConnectionsForProgram(""));
        Assert.Equal(0, terminator.TerminateConnectionsForProgram("NonExistentFakeProgram_XYZ123.exe"));

        var ep1 = new IPEndPoint(IPAddress.IPv6Loopback, 12345);
        var ep2 = new IPEndPoint(IPAddress.IPv6Loopback, 54321);
        Assert.False(terminator.TerminateConnection(ep1, ep2));
    }

    [Fact]
    public void TcpConnectionTerminator_KillProcess_SafeWithInvalidPid()
    {
        Assert.False(TcpConnectionTerminator.KillProcess(-1));
        Assert.False(TcpConnectionTerminator.KillProcess(0));
        Assert.False(TcpConnectionTerminator.KillProcess(999999999));
    }
}
