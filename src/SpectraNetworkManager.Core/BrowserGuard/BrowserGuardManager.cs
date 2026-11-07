using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace SpectraNetworkManager.Core.BrowserGuard;

/// <summary>
/// Manages browser URL, media, and video blocking policies, and synchronizes them with
/// the Spectra Browser Guard Manifest V3 browser extension via Native Messaging IPC.
/// </summary>
public sealed class BrowserGuardManager
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private readonly string _configFilePath;
    private readonly object _lock = new();

    public BrowserGuardConfig Config { get; private set; } = new();

    public event Action? RulesChanged;
    public event Action<ElementPickerBlockRequest>? ElementPickerRequestReceived;

    public BrowserGuardManager(string? configPath = null)
    {
        _configFilePath = configPath ?? EngineStoragePaths.BrowserGuardRulesPath;
        Load();
    }

    public void Load()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(_configFilePath))
                {
                    string json = File.ReadAllText(_configFilePath);
                    var cfg = JsonSerializer.Deserialize<BrowserGuardConfig>(json);
                    if (cfg != null)
                    {
                        Config = cfg;
                        EnsureBuiltInRules();
                        Config.BlockYouTubeShorts = Config.BlockYouTubeShorts && Config.CustomRules.Any(r => r.Id.Equals("yt-shorts", StringComparison.OrdinalIgnoreCase) && r.Enabled);
                        Config.BlockYouTubeVideoStreams = Config.BlockYouTubeVideoStreams && Config.CustomRules.Any(r => r.Id.Equals("yt-video-stream", StringComparison.OrdinalIgnoreCase) && r.Enabled);
                        Config.BlockSocialVideoFeeds = Config.BlockSocialVideoFeeds && Config.CustomRules.Any(r => r.Id.Equals("tiktok-feed", StringComparison.OrdinalIgnoreCase) && r.Enabled);
                        return;
                    }
                }
            }
            catch
            {
                // Fall back to default
            }

            Config = new BrowserGuardConfig();
            EnsureBuiltInRules();
            Save();
        }
    }

    public void Save()
    {
        lock (_lock)
        {
            try
            {
                string dir = Path.GetDirectoryName(_configFilePath)!;
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                string json = JsonSerializer.Serialize(Config, JsonOpts);
                File.WriteAllText(_configFilePath, json);
            }
            catch
            {
                // Best effort
            }
        }

        RulesChanged?.Invoke();
    }

    public void EnsureBuiltInRules()
    {
        var builtIns = GetDefaultBuiltInRules();
        foreach (var bi in builtIns)
        {
            if (Config.CustomRules.All(r => r.Id != bi.Id))
            {
                Config.CustomRules.Insert(0, bi);
            }
        }
    }

    public static List<BrowserGuardRule> GetDefaultBuiltInRules()
    {
        return new List<BrowserGuardRule>
        {
            new()
            {
                Id = "yt-shorts",
                Title = "Block YouTube Shorts",
                Pattern = "*://*.youtube.com/shorts/*",
                Description = "Blocks YouTube Shorts feeds and short-form video reels.",
                Action = GuardAction.Block,
                ResourceType = "main_frame",
                Enabled = false,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-video-stream",
                Title = "Block Video Delivery Streams (googlevideo)",
                Pattern = "*://*.googlevideo.com/videoplayback*",
                Description = "Blocks raw YouTube video stream segments (stops video playback completely).",
                Action = GuardAction.Block,
                ResourceType = "media",
                Enabled = false,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-ads",
                Title = "Block YouTube Ad Delivery Beacons",
                Pattern = "*://*.youtube.com/api/stats/ads*",
                Description = "Blocks in-player YouTube ad statistics and telemetry pings.",
                Action = GuardAction.Block,
                ResourceType = "xmlhttprequest",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-pagead",
                Title = "Block YouTube PageAd & Pre-Roll Requests",
                Pattern = "*://*.youtube.com/pagead/*",
                Description = "Blocks YouTube pre-roll, banner, and masthead ad payloads.",
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-midroll",
                Title = "Block YouTube Mid-Roll Ad Fetchers",
                Pattern = "*://*.youtube.com/get_midroll_*",
                Description = "Blocks YouTube mid-roll ad break scheduling and injection.",
                Action = GuardAction.Block,
                ResourceType = "xmlhttprequest",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-ptracking",
                Title = "Block YouTube Ad Playback Tracking",
                Pattern = "*://*.youtube.com/ptracking*",
                Description = "Blocks YouTube ad impression and ptracking telemetry.",
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-doubleclick",
                Title = "Block Google DoubleClick Video Ad Server",
                Pattern = "*://*.doubleclick.net/*",
                Description = "Blocks DoubleClick pre-roll and embedded YouTube video ad serving.",
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-googlesyndication",
                Title = "Block Google Syndication Companion Ads",
                Pattern = "*://*.googlesyndication.com/*",
                Description = "Blocks YouTube sidebar companion ads and overlay banners.",
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "yt-googleadservices",
                Title = "Block Google AdServices Scripts",
                Pattern = "*://*.googleadservices.com/*",
                Description = "Blocks Google AdServices conversion and video ad scripts.",
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = true
            },
            new()
            {
                Id = "tiktok-feed",
                Title = "Block TikTok Video Feeds",
                Pattern = "*://*.tiktokcdn.com/*video*",
                Description = "Blocks short-form video playback delivery on TikTok web.",
                Action = GuardAction.Block,
                ResourceType = "media",
                Enabled = false,
                IsBuiltIn = true
            },
            new()
            {
                Id = "ig-reels",
                Title = "Block Instagram Reels",
                Pattern = "*://*.instagram.com/reels/*",
                Description = "Blocks Instagram Reels video page navigation.",
                Action = GuardAction.Block,
                ResourceType = "main_frame",
                Enabled = false,
                IsBuiltIn = true
            }
        };
    }

    private static readonly System.Text.RegularExpressions.Regex YouTubeVideoRegex = new(
        @"(?:v=|\/embed\/|\/shorts\/|youtu\.be\/|\/v\/)([a-zA-Z0-9_-]{11})",
        System.Text.RegularExpressions.RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    public static bool TryExtractYouTubeVideoId(string input, out string videoId)
    {
        videoId = "";
        if (string.IsNullOrWhiteSpace(input)) return false;
        var m = YouTubeVideoRegex.Match(input);
        if (m.Success)
        {
            videoId = m.Groups[1].Value;
            return true;
        }
        return false;
    }

    public static string NormalizePattern(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return "";
        string p = pattern.Trim();
        if (TryExtractYouTubeVideoId(p, out string videoId))
        {
            return $"*://*.youtube.com/watch*v={videoId}*";
        }
        if (!p.Contains("://", StringComparison.Ordinal) && !p.StartsWith('*') && !p.StartsWith("||", StringComparison.Ordinal))
        {
            if (p.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                p = string.Concat("*://*.", p.AsSpan(4), p.EndsWith('*') ? "" : "/*");
            else
                p = string.Concat("*://*.", p, p.EndsWith('*') ? "" : "/*");
        }
        return p;
    }

    public static string ToDnrUrlFilter(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return "*";
        string p = pattern.Trim();
        if (p.StartsWith("*://*.", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(6));
        }
        if (p.StartsWith("*://", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(4));
        }
        if (p.StartsWith("https://www.", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(12));
        }
        if (p.StartsWith("http://www.", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(11));
        }
        if (p.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(8));
        }
        if (p.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return string.Concat("||", p.AsSpan(7));
        }
        return p;
    }

    public void AddRule(string title, string pattern, string description, GuardAction action = GuardAction.Block, string resourceType = "all")
    {
        lock (_lock)
        {
            string cleanPattern = NormalizePattern(pattern);
            string finalTitle = title?.Trim() ?? "";

            if (TryExtractYouTubeVideoId(pattern, out string videoId))
            {
                if (string.IsNullOrWhiteSpace(finalTitle) || finalTitle.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    finalTitle = $"Block YouTube Video: {videoId}";
                }
                if (string.IsNullOrWhiteSpace(description) || description.Contains(pattern))
                {
                    description = $"Blocks playback and navigation for YouTube video ID {videoId}.";
                }
            }
            else if (string.IsNullOrWhiteSpace(finalTitle))
            {
                finalTitle = cleanPattern;
            }

            var rule = new BrowserGuardRule
            {
                Title = finalTitle,
                Pattern = cleanPattern,
                Description = string.IsNullOrWhiteSpace(description) ? $"Custom rule for {cleanPattern}" : description.Trim(),
                Action = action,
                ResourceType = resourceType,
                Enabled = true,
                IsBuiltIn = false
            };
            Config.CustomRules.Add(rule);
            Save();
        }
    }

    public bool RemoveRule(string id)
    {
        lock (_lock)
        {
            var r = Config.CustomRules.FirstOrDefault(x => x.Id == id);
            if (r == null || r.IsBuiltIn) return false;
            Config.CustomRules.Remove(r);
            Save();
            return true;
        }
    }

    public bool ToggleRule(string id, bool enabled)
    {
        lock (_lock)
        {
            var r = Config.CustomRules.FirstOrDefault(x => x.Id == id);
            if (r == null) return false;
            r.Enabled = enabled;
            if (id.Equals("yt-shorts", StringComparison.OrdinalIgnoreCase))
            {
                Config.BlockYouTubeShorts = enabled;
            }
            else if (id.Equals("yt-video-stream", StringComparison.OrdinalIgnoreCase))
            {
                Config.BlockYouTubeVideoStreams = enabled;
            }
            else if (id.Equals("tiktok-feed", StringComparison.OrdinalIgnoreCase))
            {
                Config.BlockSocialVideoFeeds = enabled;
            }
            Save();
            return true;
        }
    }

    public void ToggleYouTubeAdRules(bool enabled)
    {
        lock (_lock)
        {
            Config.BlockYouTubeAds = enabled;
            var ytAdIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "yt-ads", "yt-pagead", "yt-midroll", "yt-ptracking",
                "yt-doubleclick", "yt-googlesyndication", "yt-googleadservices"
            };
            foreach (var r in Config.CustomRules.Where(x => ytAdIds.Contains(x.Id)))
            {
                r.Enabled = enabled;
            }
            Save();
        }
    }

    public bool HandleElementPickerRequest(string url, string title, string domain, out string ruleId)
    {
        lock (_lock)
        {
            ruleId = "";
            if (string.IsNullOrWhiteSpace(url)) return false;

            string pattern = NormalizePattern(url);
            string finalTitle = title?.Trim() ?? "";
            string desc;

            if (TryExtractYouTubeVideoId(url, out string videoId))
            {
                if (string.IsNullOrWhiteSpace(finalTitle) || finalTitle.Equals(url, StringComparison.OrdinalIgnoreCase))
                {
                    finalTitle = $"Block YouTube Video: {videoId}";
                }
                desc = $"Selected via Browser Guard Element Picker on {DateTime.Now:g}. Blocks YouTube video {videoId}.";
            }
            else
            {
                if (string.IsNullOrWhiteSpace(finalTitle))
                    finalTitle = !string.IsNullOrWhiteSpace(domain) ? $"Block Element on {domain}" : $"Block {pattern}";
                desc = $"Selected via Browser Guard Element Picker on {DateTime.Now:g}. Intercepts {pattern}.";
            }

            if (Config.AutoApproveElementPickerBlocks)
            {
                var rule = new BrowserGuardRule
                {
                    Id = "picker-" + Guid.NewGuid().ToString("N")[..8],
                    Title = finalTitle,
                    Pattern = pattern,
                    Description = desc,
                    Action = GuardAction.Block,
                    ResourceType = "all",
                    Enabled = true,
                    IsBuiltIn = false
                };
                Config.CustomRules.Add(rule);
                ruleId = rule.Id;
                Save();
                return true;
            }
            else
            {
                var pending = new ElementPickerBlockRequest
                {
                    Id = "req-" + Guid.NewGuid().ToString("N")[..8],
                    Url = url,
                    Pattern = pattern,
                    Title = finalTitle,
                    Domain = domain,
                    Description = desc,
                    Timestamp = DateTime.UtcNow
                };
                Config.PendingBlockRequests.Insert(0, pending);
                Save();
                ElementPickerRequestReceived?.Invoke(pending);
                return false;
            }
        }
    }

    public void ApprovePendingRequest(string id)
    {
        lock (_lock)
        {
            var req = Config.PendingBlockRequests.FirstOrDefault(x => x.Id == id);
            if (req == null) return;
            Config.PendingBlockRequests.Remove(req);

            var rule = new BrowserGuardRule
            {
                Id = "picker-" + Guid.NewGuid().ToString("N")[..8],
                Title = req.Title,
                Pattern = req.Pattern,
                Description = req.Description,
                Action = GuardAction.Block,
                ResourceType = "all",
                Enabled = true,
                IsBuiltIn = false
            };
            Config.CustomRules.Add(rule);
            Save();
        }
    }

    public void DismissPendingRequest(string id)
    {
        lock (_lock)
        {
            Config.PendingBlockRequests.RemoveAll(x => x.Id == id);
            Save();
        }
    }

    public void ApproveAllPendingRequests()
    {
        lock (_lock)
        {
            foreach (var req in Config.PendingBlockRequests)
            {
                var rule = new BrowserGuardRule
                {
                    Id = "picker-" + Guid.NewGuid().ToString("N")[..8],
                    Title = req.Title,
                    Pattern = req.Pattern,
                    Description = req.Description,
                    Action = GuardAction.Block,
                    ResourceType = "all",
                    Enabled = true,
                    IsBuiltIn = false
                };
                Config.CustomRules.Add(rule);
            }
            Config.PendingBlockRequests.Clear();
            Save();
        }
    }

    public void DismissAllPendingRequests()
    {
        lock (_lock)
        {
            Config.PendingBlockRequests.Clear();
            Save();
        }
    }

    /// <summary>
    /// Compiles active rules into Manifest V3 declarativeNetRequest dynamic rule JSON objects.
    /// Compatible with Chrome, Edge, and Firefox (v113+).
    /// </summary>
    public string ExportMv3DynamicRulesJson()
    {
        lock (_lock)
        {
            var rulesList = new List<object>();
            int ruleId = 1;

            if (Config.ExtensionEnabled)
            {
                foreach (var rule in Config.CustomRules.Where(r => r.Enabled))
                {
                    var resourceTypes = GetMv3ResourceTypes(rule.ResourceType);
                    var ruleObj = new Dictionary<string, object>
                    {
                        ["id"] = ruleId++,
                        ["priority"] = 1,
                        ["action"] = new Dictionary<string, string>
                        {
                            ["type"] = rule.Action == GuardAction.Block ? "block" : "allow"
                        },
                        ["condition"] = new Dictionary<string, object>
                        {
                            ["urlFilter"] = ToDnrUrlFilter(rule.Pattern),
                            ["resourceTypes"] = resourceTypes
                        }
                    };
                    rulesList.Add(ruleObj);
                }
            }

            return JsonSerializer.Serialize(rulesList, JsonOpts);
        }
    }

    private static string[] GetMv3ResourceTypes(string resourceType)
    {
        return (resourceType?.ToLowerInvariant()) switch
        {
            "media" => new[] { "media" },
            "sub_frame" => new[] { "sub_frame" },
            "xmlhttprequest" => new[] { "xmlhttprequest" },
            "script" => new[] { "script" },
            "main_frame" => new[] { "main_frame" },
            _ => new[] { "main_frame", "sub_frame", "media", "xmlhttprequest", "image", "script", "stylesheet", "font", "ping", "websocket", "other" }
        };
    }
}
