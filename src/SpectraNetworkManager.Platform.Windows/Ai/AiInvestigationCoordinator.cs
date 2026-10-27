using System.Runtime.Versioning;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Core.Ai;

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
