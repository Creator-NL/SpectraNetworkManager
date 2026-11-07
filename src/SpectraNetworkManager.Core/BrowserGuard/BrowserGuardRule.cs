using System;
using System.Collections.Generic;

namespace SpectraNetworkManager.Core.BrowserGuard;

public enum GuardAction
{
    Block = 0,
    Allow = 1
}

public sealed class BrowserGuardRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Title { get; set; } = "";
    public string Pattern { get; set; } = "";
    public string Description { get; set; } = "";
    public GuardAction Action { get; set; } = GuardAction.Block;
    public string ResourceType { get; set; } = "all";
    public bool Enabled { get; set; } = true;
    public bool IsBuiltIn { get; set; }
}

public sealed class ElementPickerBlockRequest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Url { get; set; } = "";
    public string Pattern { get; set; } = "";
    public string Title { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public sealed class BrowserGuardConfig
{
    public bool ExtensionEnabled { get; set; } = true;
    public bool BlockYouTubeAds { get; set; } = true;
    public bool BlockYouTubeAnnotations { get; set; } = true;
    public bool BlockYouTubeShorts { get; set; }
    public bool BlockYouTubeVideoStreams { get; set; }
    public bool BlockSocialVideoFeeds { get; set; }
    public bool ShowInPagePlaceholder { get; set; } = true;
    public bool AutoApproveElementPickerBlocks { get; set; }
    public List<BrowserGuardRule> CustomRules { get; set; } = new();
    public List<ElementPickerBlockRequest> PendingBlockRequests { get; set; } = new();
}
