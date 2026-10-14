using System.Net;

namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// Manages conditional DNS forwarding rules (e.g. routing *.home, *.lan, 168.192.in-addr.arpa
/// to a local router or domain controller).
/// </summary>
public sealed class ConditionalForwarder : IDisposable
{
    private sealed class ActiveRule : IDisposable
    {
        public string Suffix { get; }
        public IUpstreamResolver Resolver { get; }

        public ActiveRule(string suffix, IUpstreamResolver resolver)
        {
            Suffix = suffix.TrimStart('*', '.').ToLowerInvariant();
            Resolver = resolver;
        }

        public bool Matches(string domain)
        {
            domain = domain.Trim('.').ToLowerInvariant();
            return domain == Suffix || domain.EndsWith("." + Suffix, StringComparison.OrdinalIgnoreCase);
        }

        public void Dispose()
        {
            (Resolver as IDisposable)?.Dispose();
        }
    }

    private readonly List<ActiveRule> _rules = new();

    public ConditionalForwarder(IEnumerable<ConditionalForwardingRule> rules, TimeSpan? timeout = null)
    {
        foreach (var r in rules)
        {
            if (!r.Enabled || string.IsNullOrWhiteSpace(r.DomainSuffix) || string.IsNullOrWhiteSpace(r.TargetServer))
                continue;

            if (UpstreamEndpoint.TryParse(r.TargetServer, out var ep))
            {
                var resolver = ep.CreateResolver(timeout ?? TimeSpan.FromSeconds(2));
                _rules.Add(new ActiveRule(r.DomainSuffix, resolver));
            }
        }
    }

    public ConditionalForwarder(IEnumerable<(string Suffix, IUpstreamResolver Resolver)> customRules)
    {
        foreach (var (suffix, resolver) in customRules)
        {
            _rules.Add(new ActiveRule(suffix, resolver));
        }
    }

    public async Task<byte[]?> TryForwardAsync(string domain, byte[] rawQuery, bool useTcp, CancellationToken ct)
    {
        foreach (var rule in _rules)
        {
            if (rule.Matches(domain))
            {
                try
                {
                    return await rule.Resolver.ResolveAsync(rawQuery, useTcp, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    return null;
                }
            }
        }
        return null;
    }

    public void Dispose()
    {
        foreach (var rule in _rules)
        {
            rule.Dispose();
        }
        _rules.Clear();
    }
}
