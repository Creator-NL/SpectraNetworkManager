using System.Globalization;

namespace SpectraNetworkManager.Core.Localization;

public static class LocalizationManager
{
    private static string _currentLanguage = "Auto";

    public static event Action? LanguageChanged;

    public static string CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            if (_currentLanguage != value)
            {
                _currentLanguage = value ?? "Auto";
                LanguageChanged?.Invoke();
            }
        }
    }

    public static bool IsDutch
    {
        get
        {
            if (_currentLanguage.Equals("Nederlands", StringComparison.OrdinalIgnoreCase) ||
                _currentLanguage.Equals("nl", StringComparison.OrdinalIgnoreCase))
                return true;

            if (_currentLanguage.Equals("Auto", StringComparison.OrdinalIgnoreCase))
            {
                string culture = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLowerInvariant();
                return culture == "nl";
            }

            return false;
        }
    }

    public static string T(string key, string? defaultText = null)
    {
        bool dutch = IsDutch;
        if (dutch && DutchStrings.TryGetValue(key, out var nlVal))
            return nlVal;

        if (EnglishStrings.TryGetValue(key, out var enVal))
            return enVal;

        return defaultText ?? key;
    }

    private static readonly Dictionary<string, string> EnglishStrings = new(StringComparer.OrdinalIgnoreCase)
    {
        // Navigation Tabs
        ["TabConnections"] = "Connections",
        ["TabPrograms"] = "Programs",
        ["TabStartup"] = "Startup",
        ["TabTraffic"] = "Traffic",
        ["TabScanner"] = "Port Scanner",
        ["TabPackets"] = "Packets",
        ["TabTvMobile"] = "TV & Mobile",
        ["TabBrowserGuard"] = "Browser Guard",
        ["TabAi"] = "Spectra AI",
        ["TabRules"] = "Rules",
        ["TabQuarantine"] = "Quarantine",
        ["TabStrictMode"] = "Strict mode",
        ["TabDns"] = "DNS",
        ["TabBlocks"] = "Firewall blocks",

        // Toolbar toggles & Settings
        ["SettingsButton"] = "Settings",
        ["SettingsTitle"] = "⚙️ SETTINGS & PREFERENCES",
        ["SettingsLanguage"] = "Interface Language / Taal",
        ["AskModeCheck"] = "Ask about new programs",
        ["AlwaysAdminCheck"] = "Always run as admin",
        ["AlwaysOnTopCheck"] = "Always on top",
        ["AlertSoundsCheck"] = "Alert sounds",

        // AI Investigation
        ["AiTitle"] = "Spectra AI Threat Intelligence & Investigation",
        ["AiSelectProcess"] = "Target Process:",
        ["AiBrowseExe"] = "Browse .exe...",
        ["AiRunInvestigation"] = "✨ Investigate with Spectra AI",
        ["AiRunning"] = "Investigating process...",
        ["AiAutoInvestigate"] = "Auto-investigate new unverified programs",
        ["AiOllamaOnline"] = "🟢 Ollama Local LLM Connected",
        ["AiOllamaOffline"] = "⚪ Deterministic Offline Engine (Ollama Offline)",
        ["AiTestOllama"] = "Test LLM",
        ["AiRiskScore"] = "THREAT RISK SCORE",
        ["AiExecutiveSummary"] = "Executive Summary",
        ["AiKeyFindings"] = "Deterministic Telemetry Findings",
        ["AiCapabilities"] = "Identified Capabilities",
        ["AiUncertainties"] = "Uncertainties & Blind Spots",
        ["AiHistory"] = "Investigation History",
        ["AiClearHistory"] = "Clear History",
        ["AiActionAllow"] = "🛡️ Allow Program",
        ["AiActionBlock"] = "🚫 Block Outbound",
        ["AiActionQuarantine"] = "⚠️ 5-Stage Quarantine",
        ["AiCopyJson"] = "📋 Copy JSON Report",
        ["AiVirusTotal"] = "🌐 Search VirusTotal",

        // Verification Badges
        ["BadgeVerifiedSystem"] = "🛡️ Verified System Binary",
        ["BadgeVerifiedPublisher"] = "✔ Verified Publisher",
        ["BadgeUnverified"] = "⚠️ Unverified (Unsigned)",
        ["BadgeTampered"] = "🚨 Tampered / Invalid Signature",
        ["BadgeSuspiciousLocation"] = "⛔ Suspicious Location",
        ["BadgeEphemeral"] = "❓ Ephemeral / Exited",

        // Context Menu
        ["MenuInvestigateAi"] = "✨ Investigate with Spectra AI",
        ["MenuQuarantine"] = "🛡️ 5-Stage Quarantine Program...",
        ["MenuCheckVirusTotal"] = "🛡️ Check File Hash on VirusTotal",
        ["MenuCheckAbuseIpDb"] = "🚨 Check Remote IP on AbuseIPDB",

        // Quarantine Vault
        ["QuarantineShowRestored"] = "Show Restored History",
        ["QuarantineRestore"] = "🔄 Restore Program (Un-Quarantine)",
        ["QuarantineBrowse"] = "🛡️ Quarantine New File...",
        ["QuarantineRemoveVault"] = "🗑️ Remove from Vault",
        ["QuarantinePanicRestore"] = "PANIC: Restore All Quarantined",

        // TV & Mobile
        ["TvMobileTitle"] = "Smart TV & GSM Mobile Defense Hub",
        ["PairGsm"] = "📱 Pair GSM Device",

        // Language Options
        ["LangAuto"] = "🌐 Auto (System)",
        ["LangEnglish"] = "🇬🇧 English",
        ["LangDutch"] = "🇳🇱 Nederlands"
    };

    private static readonly Dictionary<string, string> DutchStrings = new(StringComparer.OrdinalIgnoreCase)
    {
        // Navigation Tabs
        ["TabConnections"] = "Verbindingen",
        ["TabPrograms"] = "Programma's",
        ["TabStartup"] = "Opstarten",
        ["TabTraffic"] = "Netwerkverkeer",
        ["TabScanner"] = "Poortscanner",
        ["TabPackets"] = "Pakketinspectie",
        ["TabTvMobile"] = "TV & Mobiel",
        ["TabBrowserGuard"] = "Browser Guard",
        ["TabAi"] = "Spectra AI",
        ["TabRules"] = "Regels",
        ["TabQuarantine"] = "Quarantaine",
        ["TabStrictMode"] = "Strikte modus",
        ["TabDns"] = "DNS Sinkhole",
        ["TabBlocks"] = "Firewall Blokkeerlijst",

        // Toolbar toggles & Settings
        ["SettingsButton"] = "Instellingen",
        ["SettingsTitle"] = "⚙️ INSTELLINGEN & VOORKEUREN",
        ["SettingsLanguage"] = "Interfacetaal / Language",
        ["AskModeCheck"] = "Vragen over nieuwe programma's",
        ["AlwaysAdminCheck"] = "Altijd als administrator starten",
        ["AlwaysOnTopCheck"] = "Venster altijd op voorgrond",
        ["AlertSoundsCheck"] = "Geluidssignalen",

        // AI Investigation
        ["AiTitle"] = "Spectra AI Dreigingsanalyse & Procesverificatie",
        ["AiSelectProcess"] = "Doelproces:",
        ["AiBrowseExe"] = "Blader .exe...",
        ["AiRunInvestigation"] = "✨ Analyseer met Spectra AI",
        ["AiRunning"] = "Proces wordt geanalyseerd...",
        ["AiAutoInvestigate"] = "Nieuwe niet-geverifieerde programma's automatisch analyseren",
        ["AiOllamaOnline"] = "🟢 Ollama Lokaal AI-model Verbonden",
        ["AiOllamaOffline"] = "⚪ Deterministische Offline Engine (Ollama Offline)",
        ["AiTestOllama"] = "Test AI",
        ["AiRiskScore"] = "DREIGINGSRISICO SCORE",
        ["AiExecutiveSummary"] = "Directie Samenvatting",
        ["AiKeyFindings"] = "Deterministische Telemetrie Bevindingen",
        ["AiCapabilities"] = "Vastgestelde Mogelijkheden",
        ["AiUncertainties"] = "Onzekerheden & Beperkingen",
        ["AiHistory"] = "Onderzoeksgeschiedenis",
        ["AiClearHistory"] = "Geschiedenis Wissen",
        ["AiActionAllow"] = "🛡️ Programma Toestaan",
        ["AiActionBlock"] = "🚫 Uitgaand Blokkeren",
        ["AiActionQuarantine"] = "⚠️ 5-Staps Quarantaine",
        ["AiCopyJson"] = "📋 Kopieer JSON Rapport",
        ["AiVirusTotal"] = "🌐 Zoek op VirusTotal",

        // Verification Badges
        ["BadgeVerifiedSystem"] = "🛡️ Geverifieerd Systeembestand",
        ["BadgeVerifiedPublisher"] = "✔ Geverifieerde Uitgever",
        ["BadgeUnverified"] = "⚠️ Niet Geverifieerd (Zonder handtekening)",
        ["BadgeTampered"] = "🚨 Handtekening Gemanipuleerd / Ongeldig",
        ["BadgeSuspiciousLocation"] = "⛔ Verdachte Uitvoerlocatie",
        ["BadgeEphemeral"] = "❓ Kortstondig / Afgesloten",

        // Context Menu
        ["MenuInvestigateAi"] = "✨ Analyseer met Spectra AI",
        ["MenuQuarantine"] = "🛡️ 5-Staps Quarantaine Programma...",
        ["MenuCheckVirusTotal"] = "🛡️ Controleer File Hash op VirusTotal",
        ["MenuCheckAbuseIpDb"] = "🚨 Controleer IP op AbuseIPDB",

        // Quarantine Vault
        ["QuarantineShowRestored"] = "Herstelde Geschiedenis Tonen",
        ["QuarantineRestore"] = "🔄 Programma Herstellen (Uit Quarantaine)",
        ["QuarantineBrowse"] = "🛡️ Nieuw Bestand In Quarantaine...",
        ["QuarantineRemoveVault"] = "🗑️ Verwijderen uit Kluis",
        ["QuarantinePanicRestore"] = "PANIEK: Herstel Alle Quarantaine",

        // TV & Mobile
        ["TvMobileTitle"] = "Smart TV & GSM Mobiele Beveiligingshub",
        ["PairGsm"] = "📱 Koppel GSM Apparaat",

        // Language Options
        ["LangAuto"] = "🌐 Auto (Systeemtaal)",
        ["LangEnglish"] = "🇬🇧 Engels",
        ["LangDutch"] = "🇳🇱 Nederlands"
    };
}
