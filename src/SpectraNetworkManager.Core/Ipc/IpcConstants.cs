namespace SpectraNetworkManager.Core.Ipc;

public static class IpcConstants
{
    public const string PipeName = "SpectraNetworkManager.Engine.Pipe";

    public static class Actions
    {
        public const string Ping = "Ping";
        public const string GetEngineStatus = "GetEngineStatus";
        public const string GetSnapshot = "GetSnapshot";
        public const string GetRules = "GetRules";
        public const string AddRule = "AddRule";
        public const string RemoveRule = "RemoveRule";
        public const string ClearRules = "ClearRules";

        // Strict mode controls
        public const string SetStrictMode = "SetStrictMode";
        public const string ConfirmStrictMode = "ConfirmStrictMode";
        public const string CancelStrictMode = "CancelStrictMode";
        public const string Panic = "Panic";

        // DNS sinkhole controls
        public const string StartDns = "StartDns";
        public const string StopDns = "StopDns";
        public const string GetDnsSettings = "GetDnsSettings";
        public const string ApplyDnsSettings = "ApplyDnsSettings";
        public const string PauseDnsBlocking = "PauseDnsBlocking";
        public const string ResumeDnsBlocking = "ResumeDnsBlocking";
        public const string UpdateBlocklists = "UpdateBlocklists";
        public const string QueryDnsHistory = "QueryDnsHistory";
        public const string ExportDnsCsv = "ExportDnsCsv";

        // System DNS switch
        public const string GetDnsSwitchAdapters = "GetDnsSwitchAdapters";
        public const string ApplyDnsSwitch = "ApplyDnsSwitch";
        public const string ConfirmDnsSwitch = "ConfirmDnsSwitch";
        public const string RestoreDnsSwitch = "RestoreDnsSwitch";

        // Traffic & Bandwidth
        public const string GetTopTalkers = "GetTopTalkers";
        public const string GetConnectionHistory = "GetConnectionHistory";
    }

    public static class Events
    {
        public const string MonitorTick = "MonitorTick";
        public const string BlockDetected = "BlockDetected";
        public const string DnsQuery = "DnsQuery";
        public const string StrictModeChanged = "StrictModeChanged";
        public const string StrictModeTick = "StrictModeTick";
        public const string DnsSwitchChanged = "DnsSwitchChanged";
        public const string BandwidthUpdate = "BandwidthUpdate";
    }
}
