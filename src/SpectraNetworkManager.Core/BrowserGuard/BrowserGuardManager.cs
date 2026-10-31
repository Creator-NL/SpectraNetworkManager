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
                Enabled = true,
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

    public void AddRule(string title, string pattern, string description, GuardAction action = GuardAction.Block, string resourceType = "all")
    {
        lock (_lock)
        {
            var rule = new BrowserGuardRule
            {
                Title = string.IsNullOrWhiteSpace(title) ? pattern : title.Trim(),
                Pattern = pattern.Trim(),
                Description = description.Trim(),
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
                            ["urlFilter"] = rule.Pattern,
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
            _ => new[] { "main_frame", "sub_frame", "media", "xmlhttprequest", "image", "script" }
        };
    }
}
