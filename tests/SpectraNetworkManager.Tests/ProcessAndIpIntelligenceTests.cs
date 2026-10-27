using System.Net;
using System.Text;
using SpectraNetworkManager.Core;
using Xunit;

namespace SpectraNetworkManager.Tests;

public sealed class ProcessAndIpIntelligenceTests
{
    [Fact]
    public void ExecutableHashCache_ComputesAndCachesSha256_AndInvalidatesOnChange()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "SpectraHashTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string cachePath = Path.Combine(tempDir, "hash-cache.json");
            string sampleExe = Path.Combine(tempDir, "sample.exe");
            File.WriteAllBytes(sampleExe, Encoding.UTF8.GetBytes("spectra-test-binary-v1"));

            var cache = new ExecutableHashCache(cachePath);
            string? hash1 = cache.GetSha256(sampleExe);
            Assert.NotNull(hash1);
            Assert.Equal(64, hash1!.Length);

            // Second lookup hits cache and matches
            string? hash2 = cache.GetSha256(sampleExe);
            Assert.Equal(hash1, hash2);

            // Modify file content & timestamp -> hash must update
            File.WriteAllBytes(sampleExe, Encoding.UTF8.GetBytes("spectra-test-binary-v2-modified-length"));
            File.SetLastWriteTimeUtc(sampleExe, DateTime.UtcNow.AddMinutes(1));

            string? hash3 = cache.GetSha256(sampleExe);
            Assert.NotNull(hash3);
            Assert.NotEqual(hash1, hash3);

            string vtUrl = ExecutableHashCache.GetVirusTotalUrl(hash3!);
            Assert.Equal($"https://www.virustotal.com/gui/file/{hash3}", vtUrl);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void IpIntelligenceService_ClassifiesLanLoopbackAndKnownAsns()
    {
        var svc = new IpIntelligenceService();

        var loopback = svc.Analyze(IPAddress.Loopback);
        Assert.Equal("LOCAL", loopback.CountryCode);
        Assert.False(loopback.IsPublicRoutable);

        var lan = svc.Analyze(IPAddress.Parse("192.168.1.50"));
        Assert.Equal("LAN", lan.CountryCode);
        Assert.False(lan.IsPublicRoutable);

        var cgnat = svc.Analyze(IPAddress.Parse("100.100.10.5"));
        Assert.Equal("VPN", cgnat.CountryCode);
        Assert.False(cgnat.IsPublicRoutable);

        var cf = svc.Analyze(IPAddress.Parse("1.1.1.1"));
        Assert.Equal("AS13335", cf.Asn);
        Assert.Contains("Cloudflare", cf.Organization);
        Assert.True(cf.IsPublicRoutable);

        var quad9 = svc.Analyze(IPAddress.Parse("9.9.9.9"));
        Assert.Equal("CH", quad9.CountryCode);
        Assert.Equal("AS19281", quad9.Asn);
        Assert.True(quad9.IsPublicRoutable);

        var google = svc.Analyze(IPAddress.Parse("8.8.8.8"));
        Assert.Equal("AS15169", google.Asn);
        Assert.True(google.IsPublicRoutable);

        Assert.Equal("https://www.abuseipdb.com/check/1.1.1.1", IpIntelligenceService.GetAbuseIpDbUrl(IPAddress.Parse("1.1.1.1")));
        Assert.Equal("https://www.shodan.io/host/8.8.8.8", IpIntelligenceService.GetShodanUrl(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void ProcessInfo_ClassifyIdentity_SeparatesMicrosoftSystemTrustedUnsignedAndTampered()
    {
        string sysPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe");
        string userPath = @"C:\Users\Test\AppData\Local\Temp\svchost.exe";

        var validMicrosoftOsSig = new SignatureInfo(SignatureStatus.Valid, "Microsoft Windows", IsOsBinary: true);
        var validMicrosoftNonOsSig = new SignatureInfo(SignatureStatus.Valid, "Microsoft Corporation", IsOsBinary: false);
        var validThirdPartySig = new SignatureInfo(SignatureStatus.Valid, "Mozilla Corporation", IsOsBinary: false);
        var unsignedSig = new SignatureInfo(SignatureStatus.NotSigned, null, IsOsBinary: false);
        var tamperedSig = new SignatureInfo(SignatureStatus.Tampered, "Bad Actor", IsOsBinary: false);

        // Signed Microsoft OS binary -> VerifiedSystemBinary
        Assert.Equal(IdentityVerificationLevel.VerifiedSystemBinary, ProcessInfo.ClassifyIdentity(sysPath, validMicrosoftOsSig));

        // Signed non-OS publisher -> VerifiedPublisherBinary
        Assert.Equal(IdentityVerificationLevel.VerifiedPublisherBinary, ProcessInfo.ClassifyIdentity(userPath, validMicrosoftNonOsSig));
        Assert.Equal(IdentityVerificationLevel.VerifiedPublisherBinary, ProcessInfo.ClassifyIdentity(userPath, validThirdPartySig));

        // Unsigned -> UnsignedOrUnverified
        Assert.Equal(IdentityVerificationLevel.UnsignedOrUnverified, ProcessInfo.ClassifyIdentity(userPath, unsignedSig));

        // Tampered -> TamperedOrUntrusted
        Assert.Equal(IdentityVerificationLevel.TamperedOrUntrusted, ProcessInfo.ClassifyIdentity(userPath, tamperedSig));
    }
}
