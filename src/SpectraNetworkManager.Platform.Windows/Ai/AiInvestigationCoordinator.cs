using System.Runtime.Versioning;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ai;
using SpectraNetworkManager.Sinkhole;

namespace SpectraNetworkManager.Platform.Windows.Ai;

[SupportedOSPlatform("windows5.1.2600")]
public sealed class AiInvestigationCoordinator
{
    private readonly ProcessResolver _resolver;
    private readonly ExecutableHashCache _hashCache;
    private readonly OllamaClient _ollama;
    private readonly AiInvestigationDatabase _db;

    public AiInvestigationCoordinator(
        ProcessResolver resolver,
        ExecutableHashCache hashCache,
        AiInvestigationDatabase db,
        OllamaClient? ollama = null)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _hashCache = hashCache ?? throw new ArgumentNullException(nameof(hashCache));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _ollama = ollama ?? new OllamaClient();
    }

    public OllamaClient Ollama => _ollama;
    public AiInvestigationDatabase Database => _db;

    public async Task<InvestigationReport> InvestigatePidAsync(
        int pid,
        string language = "English",
        string? modelOverride = null,
        IReadOnlyList<StartupEntry>? startupEntries = null,
        IReadOnlyList<DiscoveredPort>? localSockets = null,
        IReadOnlyList<ConnectionHistoryRecord>? recentConnections = null,
        CancellationToken ct = default)
    {
        var evidence = ProcessEvidenceCollector.CollectForPid(
            pid, _resolver, _hashCache, startupEntries, localSockets, recentConnections);

        return await ProcessEvidenceInvestigationAsync(evidence, language, modelOverride, ct).ConfigureAwait(false);
    }

    public async Task<InvestigationReport> InvestigatePathAsync(
        string path,
        string language = "English",
        string? modelOverride = null,
        IReadOnlyList<StartupEntry>? startupEntries = null,
        IReadOnlyList<DiscoveredPort>? localSockets = null,
        IReadOnlyList<ConnectionHistoryRecord>? recentConnections = null,
        CancellationToken ct = default)
    {
        var evidence = ProcessEvidenceCollector.CollectForPath(
            path, _hashCache, startupEntries, localSockets, recentConnections);

        return await ProcessEvidenceInvestigationAsync(evidence, language, modelOverride, ct).ConfigureAwait(false);
    }

    public async Task<InvestigationReport> InvestigateDomainAsync(
        string domain,
        string clientIp,
        string queryType,
        string result,
        string? detail,
        bool isBlocked,
        string language = "English",
        string? modelOverride = null,
        CancellationToken ct = default)
    {
        string cleanDomain = DomainFilter.Normalize(domain).TrimEnd('.');
        if (string.IsNullOrWhiteSpace(cleanDomain))
        {
            cleanDomain = domain.Trim();
        }

        var analysis = DomainIntelligence.Analyze(cleanDomain, isBlocked, isFailed: false);

        int riskScore = analysis.Category switch
        {
            DomainCategory.AdvertisingTracker => 72,
            DomainCategory.TelemetryAnalytics => 58,
            DomainCategory.SocialTracker => 54,
            DomainCategory.CdnInfrastructure => 22,
            DomainCategory.StreamingMedia => 18,
            DomainCategory.SystemCore => 10,
            DomainCategory.SearchEngine => 12,
            _ => 35
        };

        ThreatVerdict verdict = analysis.Category switch
        {
            DomainCategory.AdvertisingTracker => ThreatVerdict.Suspicious,
            DomainCategory.TelemetryAnalytics => ThreatVerdict.LowRisk,
            DomainCategory.SocialTracker => ThreatVerdict.LowRisk,
            DomainCategory.CdnInfrastructure or DomainCategory.StreamingMedia or DomainCategory.SystemCore or DomainCategory.SearchEngine => ThreatVerdict.Safe,
            _ => ThreatVerdict.LowRisk
        };

        RecommendedAction recommendation = analysis.Advice switch
        {
            BlockAdvice.SafeToBlock => RecommendedAction.BlockFirewall,
            BlockAdvice.EssentialKeepAllowed => RecommendedAction.Allow,
            _ => RecommendedAction.Monitor
        };

        var findings = new List<string>
        {
            $"Target Domain: {cleanDomain} (Root Domain: {analysis.RootDomain})",
            $"Category: {analysis.CategoryName} — Service/Organization: {analysis.ServiceName}",
            $"Requesting Device / Client IP: {clientIp} (Query Type: {queryType}, Current Status: {result})",
            $"Blocking Advice: {analysis.AdviceTitle} — {analysis.AdviceDetail}",
            $"Service Intelligence: {analysis.Description}"
        };

        if (!string.IsNullOrWhiteSpace(detail))
        {
            findings.Add($"Resolution / Proxy Details: {detail}");
        }

        var capabilities = new List<string>
        {
            analysis.CategoryName,
            $"Root: {analysis.RootDomain}",
            isBlocked ? "Sinkhole Blocked" : "Active Resolution"
        };

        string execSummary = $"{cleanDomain} ({analysis.ServiceName}) is categorized as {analysis.CategoryName}. {analysis.Description} {analysis.AdviceTitle}: {analysis.AdviceDetail}";
        string modelName = "Deterministic Domain Intelligence";
        bool aiGenerated = false;

        try
        {
            if (await _ollama.IsAvailableAsync(ct).ConfigureAwait(false))
            {
                string sysPrompt = language.StartsWith("Neder", StringComparison.OrdinalIgnoreCase)
                    ? "Je bent Spectra AI, een cybersecurity en netwerk-DNS analist. Geef een beknopte samenvatting (3-4 zinnen) over dit domein, of het advertenties/tracking bevat, en of blokkeren veilig is."
                    : "You are Spectra AI, a cybersecurity and network DNS analyst. Provide a concise 3-4 sentence executive assessment of this domain, whether it serves ads/telemetry/tracking, and whether blocking it in the DNS sinkhole is safe or could break app functionality.";
                string usrPrompt = $"Domain: {cleanDomain}\nRoot Domain: {analysis.RootDomain}\nDetected Category: {analysis.CategoryName}\nService: {analysis.ServiceName}\nClient Device: {clientIp}\nQuery Type: {queryType}\nDetails: {detail}\nOffline Assessment: {analysis.Description} ({analysis.AdviceDetail})";

                string? llmReply = await _ollama.GenerateChatCompletionAsync(sysPrompt, usrPrompt, modelOverride, ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(llmReply))
                {
                    execSummary = llmReply.Trim();
                    modelName = $"Ollama ({modelOverride ?? _ollama.DefaultModel}) + Domain Intel";
                    aiGenerated = true;
                }
            }
        }
        catch { }

        var evidence = new VerifiedProcessEvidence
        {
            Pid = 0,
            ProcessName = $"🌐 {cleanDomain}",
            ExecutablePath = cleanDomain,
            CompanyName = analysis.ServiceName,
            FileDescription = $"{analysis.CategoryName} ({analysis.RootDomain})",
            Publisher = analysis.ServiceName,
            SignatureStatus = analysis.Category is DomainCategory.SystemCore or DomainCategory.CdnInfrastructure or DomainCategory.SearchEngine
                ? SignatureStatus.Valid
                : SignatureStatus.Unknown,
            VerificationLevel = analysis.Category is DomainCategory.AdvertisingTracker
                ? IdentityVerificationLevel.UnsignedOrUnverified
                : IdentityVerificationLevel.VerifiedPublisherBinary,
            RecentDnsQueries = new[] { $"{cleanDomain} ({queryType} -> {result})" },
            ActiveConnections = string.IsNullOrWhiteSpace(detail) ? Array.Empty<string>() : new[] { $"{clientIp} -> {detail}" },
            DeterministicConfidenceScore = 100 - riskScore
        };

        var report = new InvestigationReport
        {
            TargetType = "Domain",
            TargetIdentifier = cleanDomain,
            Pid = null,
            ProcessName = $"🌐 {cleanDomain}",
            VerificationLevel = evidence.VerificationLevel,
            Verdict = verdict,
            RiskScore = riskScore,
            ExecutiveSummary = execSummary,
            KeyFindings = findings,
            IdentifiedCapabilities = capabilities,
            Uncertainties = Array.Empty<string>(),
            Recommendation = recommendation,
            IsAiGenerated = aiGenerated,
            ModelUsed = modelName,
            Evidence = evidence
        };

        try
        {
            await _db.SaveInvestigationAsync(report).ConfigureAwait(false);
        }
        catch { }

        return report;
    }

    private async Task<InvestigationReport> ProcessEvidenceInvestigationAsync(
        VerifiedProcessEvidence evidence,
        string language,
        string? modelOverride,
        CancellationToken ct)
    {
        InvestigationReport report;

        bool ollamaReady = await _ollama.IsAvailableAsync(ct).ConfigureAwait(false);
        if (ollamaReady)
        {
            string systemPrompt = PromptSanitizer.BuildSystemPrompt(language);
            string userPrompt = PromptSanitizer.BuildInvestigationUserPrompt(evidence, language);

            string? llmResponse = await _ollama.GenerateChatCompletionAsync(
                systemPrompt, userPrompt, modelOverride, ct).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(llmResponse))
            {
                string modelName = $"Ollama ({modelOverride ?? _ollama.DefaultModel})";
                report = InvestigationValidator.ValidateAndNormalize(llmResponse, evidence, modelName, language);
            }
            else
            {
                report = DeterministicAnalysisEngine.Analyze(evidence, language, isFallback: true);
            }
        }
        else
        {
            report = DeterministicAnalysisEngine.Analyze(evidence, language, isFallback: false);
        }

        // Persist to history database
        try
        {
            await _db.SaveInvestigationAsync(report).ConfigureAwait(false);
        }
        catch { }

        return report;
    }
}
