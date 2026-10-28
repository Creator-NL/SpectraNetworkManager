namespace SpectraNetworkManager.Core.Audit;

public sealed record AuditInput(
    bool IsAdmin,
    bool DnsRunning,
    string DnsListenAddress,
    int DnsPort,
    bool BlockBrowserDoh,
    bool SystemDnsSwitched,
    bool LanFirewallOpen,
    bool AnyPublicNetwork,
    bool StrictActive,
    int PendingAskProgramsCount,
    int QuarantinedCount,
    long StoredHistoryBytes);

public static class SystemAuditService
{
    public static SystemAuditReport RunAudit(AuditInput input)
    {
        var findings = new List<AuditFinding>();

        // 1. DNS Sinkhole Server
        if (input.DnsRunning)
        {
            findings.Add(new AuditFinding(
                "dns-running",
                AuditSeverity.Good,
                "DNS Sinkhole",
                "DNS Server Active",
                $"Spectra DNS sinkhole is actively running on {input.DnsListenAddress}:{input.DnsPort}.",
                "No action needed."));
        }
        else
        {
            findings.Add(new AuditFinding(
                "dns-running",
                AuditSeverity.Critical,
                "DNS Sinkhole",
                "DNS Server Stopped",
                "The DNS sinkhole is stopped. No domain queries are being filtered or blocked.",
                "Start the DNS Sinkhole server to enable ad, tracker, and malware protection.",
                FixActionLabel: "Start DNS",
                CanAutoFix: true));
        }

        // 2. System DNS Switch
        if (input.SystemDnsSwitched)
        {
            findings.Add(new AuditFinding(
                "system-dns",
                AuditSeverity.Good,
                "System DNS",
                "Windows DNS Routed to Spectra",
                "Windows network adapters are configured to use Spectra as their primary DNS server.",
                "All PC DNS traffic is protected."));
        }
        else
        {
            findings.Add(new AuditFinding(
                "system-dns",
                AuditSeverity.Warning,
                "System DNS",
                "Windows DNS Points Elsewhere",
                "Windows is currently using external DNS servers. Local PC queries bypass Spectra unless redirected.",
                "Click 'Switch System DNS' on the DNS tab to route all Windows traffic through Spectra.",
                FixActionLabel: "Switch DNS",
                TargetTab: "Dns"));
        }

        // 3. DoH Browser Bypass
        if (input.BlockBrowserDoh)
        {
            findings.Add(new AuditFinding(
                "doh-block",
                AuditSeverity.Good,
                "DNS Hardening",
                "DoH Browser Bypass Blocked",
                "Browser DNS-over-HTTPS fallback is disabled, ensuring Chrome, Edge and Firefox cannot evade filters.",
                "Protected against DNS-over-HTTPS evasion."));
        }
        else
        {
            findings.Add(new AuditFinding(
                "doh-block",
                AuditSeverity.Warning,
                "DNS Hardening",
                "DoH Bypass Not Blocked",
                "Browsers (Chrome, Firefox, Edge) can quietly switch to DNS-over-HTTPS and bypass Spectra.",
                "Enable 'Block Browser DNS-over-HTTPS (DoH)' in DNS settings.",
                FixActionLabel: "Block DoH",
                CanAutoFix: true));
        }

        // 4. LAN Protection & Firewall
        if (input.DnsListenAddress == "0.0.0.0")
        {
            if (input.LanFirewallOpen)
            {
                findings.Add(new AuditFinding(
                    "lan-protection",
                    AuditSeverity.Good,
                    "TV & Mobile",
                    "LAN Protection Active",
                    "Spectra is listening on 0.0.0.0 and Windows Firewall permits inbound local subnet traffic.",
                    "Smart TVs and phones can resolve DNS through this PC."));
            }
            else
            {
                findings.Add(new AuditFinding(
                    "lan-protection",
                    AuditSeverity.Critical,
                    "TV & Mobile",
                    "Firewall Blocking LAN Devices",
                    "Spectra is configured for LAN listening (0.0.0.0), but inbound Windows Firewall rules are missing.",
                    "Open Windows Firewall inbound DNS rules to allow LAN devices to connect.",
                    FixActionLabel: "Fix Firewall",
                    CanAutoFix: true));
            }
        }
        else
        {
            findings.Add(new AuditFinding(
                "lan-protection",
                AuditSeverity.Info,
                "TV & Mobile",
                "LAN Protection Restricted (Localhost Only)",
                "Spectra is listening on 127.0.0.1. Other devices (Smart TVs, phones) cannot connect.",
                "If you want to protect TVs and mobile devices, click 'Enable LAN Protection' on the TV & Mobile tab.",
                FixActionLabel: "Go to TV & Mobile",
                TargetTab: "TvMobile"));
        }

        // 5. Network Profile
        if (input.AnyPublicNetwork)
        {
            findings.Add(new AuditFinding(
                "network-profile",
                AuditSeverity.Warning,
                "Network Security",
                "Network Profile is 'Public'",
                "Windows classifies your active network as Public. Windows Firewall may restrict local device discovery and ports.",
                "Change the network profile to 'Private' in Windows Settings or via the TV & Mobile tab.",
                FixActionLabel: "Set to Private",
                TargetTab: "TvMobile"));
        }
        else
        {
            findings.Add(new AuditFinding(
                "network-profile",
                AuditSeverity.Good,
                "Network Security",
                "Private Network Profile",
                "Active network connection is classified as Private or Domain.",
                "Local device communication is permitted."));
        }

        // 6. Strict Mode
        if (input.StrictActive)
        {
            findings.Add(new AuditFinding(
                "strict-mode",
                AuditSeverity.Good,
                "Zero Trust",
                "Strict Mode Active",
                "Outbound zero-trust firewall policy is enforcing strict per-application authorization.",
                "Zero-trust protection active."));
        }
        else
        {
            findings.Add(new AuditFinding(
                "strict-mode",
                AuditSeverity.Info,
                "Firewall Mode",
                "Interactive Mode Active",
                "Normal operating mode is active. Unknown outbound connections trigger interactive prompts.",
                "For high-security zero-trust lockdown, enable Strict Mode.",
                FixActionLabel: "Review Strict Mode",
                TargetTab: "Strict"));
        }

        // 7. Pending Programs
        if (input.PendingAskProgramsCount > 0)
        {
            findings.Add(new AuditFinding(
                "pending-programs",
                AuditSeverity.Warning,
                "Program Control",
                $"{input.PendingAskProgramsCount} Programs Pending Decision",
                $"{input.PendingAskProgramsCount} newly detected programs are awaiting your Allow or Block decision.",
                "Review the pending programs list to approve trusted software or block threats.",
                FixActionLabel: "Review Programs",
                TargetTab: "Programs"));
        }

        // 8. Quarantine Vault
        if (input.QuarantinedCount > 0)
        {
            findings.Add(new AuditFinding(
                "quarantine-vault",
                AuditSeverity.Info,
                "Quarantine",
                $"{input.QuarantinedCount} Quarantined Files Held",
                $"{input.QuarantinedCount} executable files are safely isolated in the Quarantine Vault.",
                "Inspect quarantined items or delete them permanently if confirmed malicious.",
                FixActionLabel: "Open Vault",
                TargetTab: "Quarantine"));
        }

        // 9. Stored Data Size
        if (input.StoredHistoryBytes > 50 * 1024 * 1024)
        {
            string mb = (input.StoredHistoryBytes / (1024.0 * 1024)).ToString("F1");
            findings.Add(new AuditFinding(
                "history-size",
                AuditSeverity.Warning,
                "Maintenance",
                $"History Databases Large ({mb} MB)",
                $"Network traffic and DNS history databases have grown to {mb} MB.",
                "Use 'Clean Stored Data' to reclaim disk space and purge old logs.",
                FixActionLabel: "Clean Data",
                CanAutoFix: true));
        }

        // 10. Administrator Privileges
        if (input.IsAdmin)
        {
            findings.Add(new AuditFinding(
                "admin-elevation",
                AuditSeverity.Good,
                "Privileges",
                "Administrator Mode Active",
                "Spectra has full administrative rights to manage Windows Firewall, WFP drivers, and network profiles.",
                "All protection features available."));
        }
        else
        {
            findings.Add(new AuditFinding(
                "admin-elevation",
                AuditSeverity.Warning,
                "Privileges",
                "Standard User Mode",
                "Running without Administrator rights. Firewall rules and driver-level packet inspection cannot be updated.",
                "Restart Spectra as Administrator to enable full firewall enforcement.",
                FixActionLabel: "Restart as Admin",
                CanAutoFix: true));
        }

        int good = findings.Count(f => f.Severity == AuditSeverity.Good);
        int warn = findings.Count(f => f.Severity == AuditSeverity.Warning);
        int crit = findings.Count(f => f.Severity == AuditSeverity.Critical);

        return new SystemAuditReport(DateTime.UtcNow, findings.Count, good, warn, crit, findings);
    }
}
