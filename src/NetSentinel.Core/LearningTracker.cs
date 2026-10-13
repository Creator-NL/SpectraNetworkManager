namespace NetSentinel.Core;

public sealed record LearningUpdate(int? BaselineCount, IReadOnlyList<ProgramSummary> NewPrograms);

/// <summary>
/// Learning mode: notices programs that reach the internet but have no decision yet.
/// The first update only sets a baseline (what was already running when NetSentinel started);
/// after that, each program that newly shows up is reported once.
/// </summary>
public sealed class LearningTracker
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private bool _baselined;

    public LearningUpdate Update(IEnumerable<ProgramSummary> summaries, Func<string, bool> hasRule)
    {
        var candidates = summaries
            .Where(s => s.InternetPeers > 0 && !string.IsNullOrEmpty(s.Path) && !hasRule(s.Path!))
            .ToList();

        if (!_baselined)
        {
            _baselined = true;
            foreach (var c in candidates) _seen.Add(c.Path!);
            return new LearningUpdate(candidates.Count, Array.Empty<ProgramSummary>());
        }

        var fresh = candidates.Where(c => _seen.Add(c.Path!)).ToList();
        return new LearningUpdate(null, fresh);
    }
}
