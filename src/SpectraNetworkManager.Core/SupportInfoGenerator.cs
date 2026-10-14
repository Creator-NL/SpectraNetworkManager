using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SpectraNetworkManager.Core;

public sealed record SupportInfoOptions(
    bool RedactUserPaths = true,
    bool RedactDomains = false);

/// <summary>
/// Generates a structured markdown support and diagnostic bundle for troubleshooting,
/// with automatic privacy redaction of personal user profile paths and optional domain masking.
/// </summary>
public static class SupportInfoGenerator
{
    private static readonly Regex UserPathRegex = new(
        @"([A-Za-z]:\\Users\\)([^\\]+)(\\)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex DomainRegex = new(
        @"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        RegexOptions.Compiled);

    public static string Generate(
        string? engineStatusSummary = null,
        int ruleCount = 0,
        int blocklistCount = 0,
        IReadOnlyList<LogEntry>? recentLogs = null,
        SupportInfoOptions? options = null)
    {
        options ??= new SupportInfoOptions();
        var sb = new StringBuilder();

        sb.AppendLine("# SpectraNetworkManager Support Diagnostic Info");
        sb.AppendLine($"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();

        // System & Environment
        sb.AppendLine("## System & Environment");
        sb.AppendLine($"- OS: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
        sb.AppendLine($"- .NET Runtime: {RuntimeInformation.FrameworkDescription}");
        sb.AppendLine($"- Elevated (Admin): {IsAdministrator()}");
        sb.AppendLine($"- 64-Bit OS / Process: {Environment.Is64BitOperatingSystem} / {Environment.Is64BitProcess}");
        sb.AppendLine($"- Processor Count: {Environment.ProcessorCount}");
        sb.AppendLine();

        // SpectraNetworkManager Engine & Storage
        sb.AppendLine("## Storage & Engine");
        string baseDir = options.RedactUserPaths ? RedactPaths(EngineStoragePaths.BaseDirectory) : EngineStoragePaths.BaseDirectory;
        sb.AppendLine($"- Storage Base Directory: `{baseDir}`");
        sb.AppendLine($"- Engine Status: {engineStatusSummary ?? "Standalone / UI process"}");
        sb.AppendLine($"- Active Rule Count: {ruleCount}");
        sb.AppendLine($"- Blocklist Domains Loaded: {blocklistCount.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)}");
        sb.AppendLine();

        // Recent Diagnostics & Log Tail
        sb.AppendLine("## Recent Diagnostics");
        var logs = recentLogs ?? RotatingFileLogger.Instance.GetRecentEntries(40);
        if (logs.Count == 0)
        {
            sb.AppendLine("_No recent log entries recorded._");
        }
        else
        {
            sb.AppendLine("```text");
            foreach (var log in logs)
            {
                string msg = log.Message;
                if (options.RedactUserPaths) msg = RedactPaths(msg);
                if (options.RedactDomains) msg = RedactDomainNames(msg);

                sb.AppendLine($"[{log.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{log.Level.ToString().ToUpperInvariant().PadRight(5)}] {msg}");
                if (!string.IsNullOrEmpty(log.Exception))
                {
                    string exMsg = log.Exception;
                    if (options.RedactUserPaths) exMsg = RedactPaths(exMsg);
                    sb.AppendLine($"  {exMsg}");
                }
            }
            sb.AppendLine("```");
        }

        return sb.ToString();
    }

    public static string RedactPaths(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return UserPathRegex.Replace(text, "${1}<redacted>${3}");
    }

    public static string RedactDomainNames(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return DomainRegex.Replace(text, "[domain redacted]");
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
