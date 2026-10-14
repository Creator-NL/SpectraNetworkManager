using System.Globalization;

namespace SpectraNetworkManager.Core;

/// <summary>A set of TCP/UDP ports such as "80,443,8000-8100". Valid ports are 1-65535.</summary>
public sealed class PortSet
{
    private const int Min = 1, Max = 65535;
    private readonly List<(int Start, int End)> _ranges;

    private PortSet(List<(int, int)> merged) => _ranges = merged;

    public static PortSet Empty { get; } = new(new List<(int, int)>());

    public bool IsEmpty => _ranges.Count == 0;

    public static bool TryParse(string? text, out PortSet set, out string error)
    {
        set = Empty;
        error = "";
        if (string.IsNullOrWhiteSpace(text)) return true;

        var ranges = new List<(int, int)>();
        foreach (var raw in text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = raw.Split('-', StringSplitOptions.TrimEntries);
            if (parts.Length > 2 || !TryPort(parts[0], out int start) || (parts.Length == 2 && !TryPort(parts[1], out _)))
            {
                error = $"'{raw}' is not a valid port or port range (use numbers 1-65535, like 443 or 8000-8100).";
                return false;
            }

            int end = parts.Length == 2 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : start;
            if (end < start)
            {
                error = $"'{raw}': the first port of a range must not be bigger than the last.";
                return false;
            }
            ranges.Add((start, end));
        }

        set = new PortSet(Merge(ranges));
        return true;
    }

    private static bool TryPort(string s, out int port) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port >= Min && port <= Max;

    private static List<(int, int)> Merge(List<(int Start, int End)> ranges)
    {
        var sorted = ranges.OrderBy(r => r.Start).ToList();
        var merged = new List<(int, int)>();
        foreach (var (s, e) in sorted)
        {
            if (merged.Count > 0 && s <= merged[^1].Item2 + 1)
                merged[^1] = (merged[^1].Item1, Math.Max(merged[^1].Item2, e));
            else
                merged.Add((s, e));
        }
        return merged;
    }

    /// <summary>All ports from 1 to 65535 that are NOT in this set.</summary>
    public PortSet Complement()
    {
        var result = new List<(int, int)>();
        int next = Min;
        foreach (var (s, e) in _ranges)
        {
            if (s > next) result.Add((next, s - 1));
            next = e + 1;
        }
        if (next <= Max) result.Add((next, Max));
        return new PortSet(result);
    }

    public bool Contains(int port) => _ranges.Any(r => port >= r.Start && port <= r.End);

    /// <summary>Normalised text that Windows Firewall accepts, e.g. "80,443,8000-8100".</summary>
    public override string ToString() =>
        string.Join(",", _ranges.Select(r => r.Start == r.End ? r.Start.ToString(CultureInfo.InvariantCulture) : $"{r.Start}-{r.End}"));
}
