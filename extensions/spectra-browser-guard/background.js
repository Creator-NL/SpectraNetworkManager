// Spectra Browser Guard & YouTube AdShield - Manifest V3 Background Script
// Cross-browser: Works in Google Chrome, Microsoft Edge, Brave, and Mozilla Firefox.
// Synchronizes declarativeNetRequest rules and custom URL block rules with SpectraNetworkManager via Native Messaging.

const HOST_NAME = "com.spectranetworkmanager.browser_host";
const api = typeof browser !== "undefined" ? browser : chrome;

let nativePort = null;
let syncedWithNativeHost = false;

const DEFAULT_STANDALONE_RULES = [
  {
    id: 1,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||youtube.com/api/stats/ads*",
      resourceTypes: ["xmlhttprequest", "ping", "other"]
    }
  },
  {
    id: 2,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||youtube.com/pagead/*",
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  },
  {
    id: 3,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||youtube.com/get_midroll_*",
      resourceTypes: ["xmlhttprequest", "other"]
    }
  },
  {
    id: 4,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||youtube.com/ptracking*",
      resourceTypes: ["xmlhttprequest", "image", "ping", "other"]
    }
  },
  {
    id: 5,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||doubleclick.net/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "media", "other"]
    }
  },
  {
    id: 6,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||googlesyndication.com/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  },
  {
    id: 7,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "||googleadservices.com/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  }
];

async function ensureDefaultSettingsAndRules() {
  try {
    const stored = await api.storage.local.get([
      "spectraInitialized",
      "blockYouTubeAds",
      "blockYouTubeAnnotations",
      "blockYouTubeShorts",
      "showPlaceholder",
      "customRules"
    ]);

    if (!stored.spectraInitialized) {
      await api.storage.local.set({
        spectraInitialized: true,
        blockYouTubeAds: stored.blockYouTubeAds !== undefined ? stored.blockYouTubeAds : true,
        blockYouTubeAnnotations: stored.blockYouTubeAnnotations !== undefined ? stored.blockYouTubeAnnotations : true,
        blockYouTubeShorts: stored.blockYouTubeShorts !== undefined ? stored.blockYouTubeShorts : false,
        showPlaceholder: stored.showPlaceholder !== undefined ? stored.showPlaceholder : true,
        customRules: stored.customRules || []
      });
    }

    if (!syncedWithNativeHost && api.declarativeNetRequest) {
      try {
        const existing = await api.declarativeNetRequest.getDynamicRules();
        if (existing.length === 0) {
          await api.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [],
            addRules: DEFAULT_STANDALONE_RULES
          });
        }
      } catch (dnrErr) {
        console.warn("[Spectra Browser Guard] Standalone DNR init note:", dnrErr);
      }
    }
  } catch (err) {
    console.warn("[Spectra Browser Guard] Initialization fallback notice:", err);
  }
}

function connectNativeHost() {
  try {
    if (!api.runtime || !api.runtime.connectNative) {
      console.warn("[Spectra Browser Guard] Native messaging API unavailable in this context.");
      return;
    }

    nativePort = api.runtime.connectNative(HOST_NAME);

    nativePort.onMessage.addListener((msg) => {
      if (msg && msg.type === "rules_update") {
        syncedWithNativeHost = true;
        applyDynamicRules(msg);
      } else if (msg && msg.type === "element_picked_ack" && msg.autoApproved) {
        nativePort.postMessage({ type: "get_rules" });
      }
    });

    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
    });

    nativePort.postMessage({ type: "get_rules" });
  } catch (e) {
    console.warn("[Spectra Browser Guard] Running in standalone mode (Native Host not connected):", e);
  }
}

async function applyDynamicRules(payload) {
  try {
    let addRules = [];
    if (payload.enabled && payload.rulesJson) {
      try {
        const parsed = JSON.parse(payload.rulesJson);
        if (Array.isArray(parsed)) {
          addRules = parsed;
        }
      } catch (err) {
        console.error("[Spectra Browser Guard] Invalid rulesJson:", err);
      }
    }

    if (api.declarativeNetRequest) {
      try {
        const existingRules = await api.declarativeNetRequest.getDynamicRules();
        const removeIds = existingRules.map(r => r.id);

        await api.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: addRules
        });
      } catch (dnrErr) {
        console.warn("[Spectra Browser Guard] declarativeNetRequest update note:", dnrErr);
      }
    }

    const customRulesList = Array.isArray(payload.customRules) ? payload.customRules : [];

    await api.storage.local.set({
      spectraInitialized: true,
      showPlaceholder: payload.placeholder !== false,
      blockYouTubeAds: payload.blockYouTubeAds !== false,
      blockYouTubeAnnotations: payload.blockYouTubeAnnotations !== false,
      blockYouTubeShorts: payload.blockYouTubeShorts === true,
      autoApprovePicker: payload.autoApprovePicker === true,
      activeRulesCount: addRules.length,
      customRules: customRulesList
    });

    // Notify all open tabs of updated rules so active videos/pages block immediately
    try {
      if (api.tabs && api.tabs.query) {
        const tabs = await api.tabs.query({});
        for (const tab of tabs) {
          if (tab.id) {
            api.tabs.sendMessage(tab.id, {
              type: "spectra_rules_updated",
              customRules: customRulesList,
              blockYouTubeShorts: payload.blockYouTubeShorts === true,
              blockYouTubeAds: payload.blockYouTubeAds !== false
            }).catch(() => {});
          }
        }
      }
    } catch {}
  } catch (err) {
    console.error("[Spectra Browser Guard] Failed to update dynamic rules:", err);
  }
}

api.runtime.onInstalled.addListener(() => {
  ensureDefaultSettingsAndRules();
  connectNativeHost();
});

api.runtime.onStartup.addListener(() => {
  ensureDefaultSettingsAndRules();
  connectNativeHost();
});

// Handle popup inquiries and in-browser rule toggling
if (api.runtime && api.runtime.onMessage) {
  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "get_status") {
      api.storage.local.get([
        "blockYouTubeAds",
        "blockYouTubeAnnotations",
        "blockYouTubeShorts",
        "customRules",
        "adsSkipped"
      ], (stored) => {
        sendResponse({
          connected: syncedWithNativeHost,
          blockYouTubeShorts: stored.blockYouTubeShorts === true,
          blockYouTubeAds: stored.blockYouTubeAds !== false,
          adsSkipped: stored.adsSkipped || 0
        });
      });
      return true; // asynchronous response
    }

    // Content script reports every ad it fast-forwarded / skipped (shown in the popup)
    if (msg && msg.type === "ad_skipped") {
      api.storage.local.get(["adsSkipped"], (st) => {
        api.storage.local.set({ adsSkipped: (st.adsSkipped || 0) + 1 });
      });
      return false;
    }

    if (msg && msg.type === "element_picked") {
      if (nativePort) {
        try {
          nativePort.postMessage({
            type: "element_picked",
            url: msg.url,
            title: msg.title,
            domain: msg.domain,
            videoId: msg.videoId
          });
        } catch (e) {
          console.warn("[Spectra Browser Guard] Native host element picker post error:", e);
        }
      }

      api.storage.local.get(["customRules", "autoApprovePicker"], (res) => {
        const autoApproved = res.autoApprovePicker === true;
        if (autoApproved) {
          const rules = Array.isArray(res.customRules) ? res.customRules : [];
          rules.push({
            id: "picker-" + Date.now(),
            pattern: msg.url,
            title: msg.title || msg.url,
            action: "block",
            resourceType: "all",
            enabled: true
          });
          api.storage.local.set({ customRules: rules });
        }
        sendResponse({ ok: true, autoApproved: autoApproved });
      });
      return true;
    }

    if (msg && msg.type === "toggle_rule") {
      if (msg.id === "yt-shorts") {
        const enabled = Boolean(msg.enabled);
        api.storage.local.set({ blockYouTubeShorts: enabled }).then(() => {
          if (api.tabs && api.tabs.query) {
            api.tabs.query({}).then((tabs) => {
              for (const tab of tabs) {
                if (tab.id) {
                  api.tabs.sendMessage(tab.id, {
                    type: "spectra_rules_updated",
                    blockYouTubeShorts: enabled
                  }).catch(() => {});
                }
              }
            });
          }
        });
        if (nativePort) {
          try {
            nativePort.postMessage({ type: "toggle_rule", id: "yt-shorts", enabled: enabled });
          } catch {}
        }
      }

      if (msg.id === "yt-ads") {
        const enabled = Boolean(msg.enabled);
        api.storage.local.set({ blockYouTubeAds: enabled }).then(() => {
          if (api.tabs && api.tabs.query) {
            api.tabs.query({}).then((tabs) => {
              for (const tab of tabs) {
                if (tab.id) {
                  api.tabs.sendMessage(tab.id, {
                    type: "spectra_rules_updated",
                    blockYouTubeAds: enabled
                  }).catch(() => {});
                }
              }
            });
          }
        });
        if (nativePort) {
          try {
            nativePort.postMessage({ type: "toggle_rule", id: "yt-ads", enabled: enabled });
          } catch {}
        }
      }
    }
  });
}

function requestRulesSync() {
  if (!nativePort) {
    connectNativeHost();
  } else {
    try {
      nativePort.postMessage({ type: "get_rules" });
    } catch {
      nativePort = null;
      connectNativeHost();
    }
  }
}

// Sync immediately when user switches focus to browser or activates a tab
if (api.windows && api.windows.onFocusChanged) {
  api.windows.onFocusChanged.addListener((winId) => {
    if (winId !== (api.windows.WINDOW_ID_NONE || -1)) {
      requestRulesSync();
    }
  });
}

if (api.tabs && api.tabs.onActivated) {
  api.tabs.onActivated.addListener(() => {
    requestRulesSync();
  });
}

// Periodic sync every 2.5 seconds to pick up new rules from SpectraNetworkManager
setInterval(requestRulesSync, 2500);

ensureDefaultSettingsAndRules();
connectNativeHost();
