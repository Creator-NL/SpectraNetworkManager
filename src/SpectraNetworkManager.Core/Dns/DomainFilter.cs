using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace SpectraNetworkManager.Sinkhole;

public enum FilterAction { None, Blocked, Allowed }

public sealed record FilterDecision(FilterAction Action, string? Reason)
{
    public static FilterDecision NoMatch { get; } = new(FilterAction.None, null);
}

/// <summary>
/// Decides whether a domain is blocked. A listed domain also blocks all of its subdomains (blocking "ads.example.com"
/// blocks "x.ads.example.com" too). Your allow list always wins over the block lists.
/// </summary>
public sealed class DomainFilter
{
    private readonly HashSet<string> _block;
    private readonly HashSet<string> _allow;
    private readonly List<(Regex Regex, string Pattern)> _blockRegex;
    private readonly List<(Regex Regex, string Pattern)> _allowRegex;

    internal DomainFilter(HashSet<string> block, HashSet<string> allow, List<(Regex, string)> blockRegex, List<(Regex, string)> allowRegex)
    {
        _block = block;
        _allow = allow;
        _blockRegex = blockRegex;
        _allowRegex = allowRegex;
    }

    public static DomainFilter Empty { get; } = new(new(), new(), new(), new());

    public int BlockedDomainCount => _block.Count;
    public int AllowedDomainCount => _allow.Count;
    public int RegexCount => _blockRegex.Count + _allowRegex.Count;

    public FilterDecision Decide(string domain)
    {
        domain = Normalize(domain);
        if (domain.Length == 0) return FilterDecision.NoMatch;

        string? allowed = FindSuffix(_allow, domain) ?? FindRegex(_allowRegex, domain);
        if (allowed is not null) return new FilterDecision(FilterAction.Allowed, "allow list: " + allowed);

        string? blocked = FindSuffix(_block, domain) ?? FindRegex(_blockRegex, domain);
        if (blocked is not null) return new FilterDecision(FilterAction.Blocked, blocked);

        return FilterDecision.NoMatch;
    }

    // "a.b.example.com" is tested as itself, then "b.example.com", then "example.com". The bare TLD is never tested.
    private static string? FindSuffix(HashSet<string> set, string domain)
    {
        if (set.Count == 0) return null;
        int start = 0;
        while (true)
        {
            string candidate = start == 0 ? domain : domain[start..];
            if (candidate.IndexOf('.') < 0) return null;
            if (set.Contains(candidate)) return candidate;

            int dot = domain.IndexOf('.', start);
            if (dot < 0) return null;
            start = dot + 1;
        }
    }

    private static string? FindRegex(List<(Regex Regex, string Pattern)> list, string domain)
    {
        foreach (var (regex, pattern) in list)
        {
            try
            {
                if (regex.IsMatch(domain)) return "regex " + pattern;
            }
            catch (RegexMatchTimeoutException)
            {
                // a pattern that takes too long counts as "no match"
            }
        }
        return null;
    }

    public static string Normalize(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();

    public static string WildcardToRegex(string pattern)
    {
        string p = pattern.Trim().ToLowerInvariant();
        string escaped = Regex.Escape(p);
        return "^" + escaped.Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
    }

    public static bool MatchesCustomRule(string rule, string domain)
    {
        rule = rule.Trim();
        if (rule.Length == 0 || rule.StartsWith('#')) return false;

        domain = Normalize(domain);

        if (rule.Length > 2 && rule.StartsWith('/') && rule.EndsWith('/'))
        {
            try
            {
                return Regex.IsMatch(domain, rule[1..^1], RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            }
            catch
            {
                return false;
            }
        }

        if (rule.Contains('*') || rule.Contains('?'))
        {
            if (rule.StartsWith("*.", StringComparison.Ordinal) && !rule[2..].Contains('*') && !rule[2..].Contains('?'))
            {
                string baseDomain = Normalize(rule[2..]);
                return domain.Equals(baseDomain, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + baseDomain, StringComparison.OrdinalIgnoreCase);
            }

            try
            {
                string rx = WildcardToRegex(rule);
                return Regex.IsMatch(domain, rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            }
            catch
            {
                return false;
            }
        }

        string ruleNorm = Normalize(rule);
        return domain.Equals(ruleNorm, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + ruleNorm, StringComparison.OrdinalIgnoreCase);
    }

    public static readonly HashSet<string> IgnoredHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
        "127.0.0.1", "::1", "::"
    };

    public static bool TryNormalizeDomain(string input, out string domain)
    {
        domain = "";
        string d = input.Trim();
        if (d.StartsWith("*.", StringComparison.Ordinal)) d = d[2..];
        d = d.TrimStart('.').TrimEnd('.').ToLowerInvariant();

        if (d.Length is 0 or > 253 || IgnoredHosts.Contains(d)) return false;
        if (IPAddress.TryParse(d, out _)) return false;

        var labels = d.Split('.');
        if (labels.Length < 2) return false;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63) return false;
            foreach (char ch in label)
                if (!(ch is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')) return false;
        }

        if (labels[^1].All(char.IsDigit)) return false;
        domain = d;
        return true;
    }

    public static bool IsValidCustomRule(string rule, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(rule)) return false;
        string r = rule.Trim().TrimEnd('.').ToLowerInvariant();

        if (r.Length is 0 or > 253) return false;
        if (IgnoredHosts.Contains(r) || IPAddress.TryParse(r, out _)) return false;

        if (r.Length > 2 && r.StartsWith('/') && r.EndsWith('/'))
        {
            try
            {
                _ = new Regex(r[1..^1]);
                normalized = r;
                return true;
            }
            catch { return false; }
        }

        if (r.Contains('*') || r.Contains('?'))
        {
            foreach (char c in r)
            {
                if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.' or '*' or '?'))
                    return false;
            }
            if (!r.Contains('.')) return false;
            normalized = r;
            return true;
        }

        if (TryNormalizeDomain(r, out string d))
        {
            normalized = d;
            return true;
        }

        return false;
    }

    public static List<string> ExtractRulesFromLines(IEnumerable<string> lines)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == '!' || line[0] == ';' || line[0] == '[')
                continue;

            if (line.StartsWith("//", StringComparison.Ordinal))
                continue;

            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();

            int slashes = line.IndexOf("//", StringComparison.Ordinal);
            if (slashes >= 0) line = line[..slashes].Trim();

            if (line.Length == 0) continue;

            // Strip Adblock prefix if present
            if (line.StartsWith("@@||", StringComparison.Ordinal)) line = line[4..];
            else if (line.StartsWith("||", StringComparison.Ordinal)) line = line[2..];

            int caret = line.IndexOf('^');
            if (caret >= 0) line = line[..caret].Trim();

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;

            IEnumerable<string> candidates = parts.Length > 1 && IPAddress.TryParse(parts[0], out _)
                ? parts.Skip(1)
                : parts;

            foreach (var c in candidates)
            {
                string token = c.Trim().TrimEnd('.');
                if (token.StartsWith("||", StringComparison.Ordinal)) token = token[2..];
                int cCaret = token.IndexOf('^');
                if (cCaret >= 0) token = token[..cCaret];

                if (IsValidCustomRule(token, out string rule) && seen.Add(rule))
                {
                    result.Add(rule);
                }
            }
        }

        return result;
    }

    /// <summary>Creates a new filter combining this filter with additional custom block and allow rules.</summary>
    public DomainFilter WithOverrides(IEnumerable<string> customBlock, IEnumerable<string> customAllow)
    {
        var block = new HashSet<string>(_block, StringComparer.Ordinal);
        var allow = new HashSet<string>(_allow, StringComparer.Ordinal);
        var blockRegex = new List<(Regex, string)>(_blockRegex);
        var allowRegex = new List<(Regex, string)>(_allowRegex);

        var builder = new DomainFilterBuilder();
        foreach (var rule in customBlock) builder.AddCustom(rule, allow: false);
        foreach (var rule in customAllow) builder.AddCustom(rule, allow: true);
        var extra = builder.Build();

        foreach (var b in extra._block) block.Add(b);
        foreach (var a in extra._allow) allow.Add(a);
        blockRegex.AddRange(extra._blockRegex);
        allowRegex.AddRange(extra._allowRegex);

        return new DomainFilter(block, allow, blockRegex, allowRegex);
    }
}

public sealed record ListParseStats(int Blocked, int Allowed, int Skipped);

/// <summary>Collects entries from block lists (hosts files, plain domain lists, Adblock-style rules) and your own rules.</summary>
public sealed class DomainFilterBuilder
{
    private static readonly HashSet<string> Ignored = DomainFilter.IgnoredHosts;

    private readonly HashSet<string> _block = new(StringComparer.Ordinal);
    private readonly HashSet<string> _allow = new(StringComparer.Ordinal);
    private readonly List<(Regex, string)> _blockRegex = new();
    private readonly List<(Regex, string)> _allowRegex = new();

    public List<string> Warnings { get; } = new();

    public DomainFilter Build() => new(_block, _allow, _blockRegex, _allowRegex);

    public bool AddBlock(string domain) => TryNormalizeDomain(domain, out string d) && _block.Add(d);
    public bool AddAllow(string domain) => TryNormalizeDomain(domain, out string d) && _allow.Add(d);

    public bool AddRegex(string pattern, bool allow)
    {
        try
        {
            var rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            (allow ? _allowRegex : _blockRegex).Add((rx, pattern));
            return true;
        }
        catch (ArgumentException ex)
        {
            Warnings.Add($"Ignored invalid regular expression '{pattern}': {ex.Message}");
            return false;
        }
    }

    /// <summary>A custom rule typed by the user: "example.com", "*.example.com", "*pattern.com" or "/regex/".</summary>
    public void AddCustom(string rule, bool allow)
    {
        rule = rule.Trim();
        if (rule.Length == 0 || rule.StartsWith('#')) return;

        if (rule.Length > 2 && rule.StartsWith('/') && rule.EndsWith('/'))
        {
            AddRegex(rule[1..^1], allow);
            return;
        }

        if (rule.Contains('*') || rule.Contains('?'))
        {
            if (rule.StartsWith("*.", StringComparison.Ordinal) && !rule[2..].Contains('*') && !rule[2..].Contains('?'))
            {
                string baseDomain = rule[2..].TrimStart('.');
                if (TryNormalizeDomain(baseDomain, out string bd))
                {
                    if (allow) AddAllow(bd); else AddBlock(bd);
                    return;
                }
            }

            string rx = DomainFilter.WildcardToRegex(rule);
            AddRegex(rx, allow);
            return;
        }

        bool ok = allow ? AddAllow(rule) || _allow.Contains(Clean(rule)) : AddBlock(rule) || _block.Contains(Clean(rule));
        if (!ok) Warnings.Add($"Ignored invalid domain '{rule}'.");
    }

    private static string Clean(string d) => d.Trim().TrimStart('*').TrimStart('.').TrimEnd('.').ToLowerInvariant();

    /// <summary>Reads a whole downloaded list. Recognises hosts files ("0.0.0.0 ads.example.com"), plain domain lists and Adblock rules ("||ads.example.com^").</summary>
    public ListParseStats AddListText(string text)
    {
        int blocked = 0, allowed = 0, skipped = 0;

        foreach (var rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == '!' || line[0] == '[') continue;

            // Adblock exception: @@||example.com^  -> allow
            if (line.StartsWith("@@||", StringComparison.Ordinal))
            {
                if (TryAdblockDomain(line[4..], out string a) && _allow.Add(a)) allowed++; else skipped++;
                continue;
            }

            // Adblock block rule: ||example.com^
            if (line.StartsWith("||", StringComparison.Ordinal))
            {
                if (TryAdblockDomain(line[2..], out string b)) { if (_block.Add(b)) blocked++; } else skipped++;
                continue;
            }

            if (line.Contains("##") || line.Contains("#@#") || line.Contains("#?#") || line[0] == '|' || line[0] == '/' || line[0] == '@')
            {
                skipped++;                                          // cosmetic or path rules cannot be done with DNS
                continue;
            }

            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();
            if (line.Length == 0) continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            IEnumerable<string> candidates = parts.Length > 1 && IPAddress.TryParse(parts[0], out _) ? parts.Skip(1) : parts.Length == 1 ? parts : Array.Empty<string>();

            bool any = false;
            foreach (var c in candidates)
            {
                if (Ignored.Contains(c)) continue;
                any = true;
                if (TryNormalizeDomain(c, out string d)) { if (_block.Add(d)) blocked++; } else skipped++;
            }
            if (!any && parts.Length > 1 && !IPAddress.TryParse(parts[0], out _)) skipped++;
        }

        return new ListParseStats(blocked, allowed, skipped);
    }

    // "example.com^", "example.com^$third-party", "example.com/path" (the last one is rejected)
    private static bool TryAdblockDomain(string rest, out string domain)
    {
        domain = "";
        int end = rest.IndexOfAny(new[] { '^', '$', '/', '|', '*' });
        if (end >= 0)
        {
            char c = rest[end];
            if (c is '/' or '*') return false;                      // path or wildcard inside the name: not expressible in DNS
            rest = rest[..end];
        }
        return TryNormalizeDomain(rest, out domain);
    }

    private static bool TryNormalizeDomain(string input, out string domain) => DomainFilter.TryNormalizeDomain(input, out domain);
}
