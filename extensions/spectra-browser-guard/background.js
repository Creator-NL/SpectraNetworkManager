// Spectra Browser Guard & YouTube AdShield - Manifest V3 Service Worker
// Synchronizes declarativeNetRequest rules and YouTube AdShield settings with SpectraNetworkManager via Native Messaging,
// while providing built-in standalone YouTube ad-blocking rules immediately on startup.

const HOST_NAME = "com.spectranetworkmanager.browser_host";
let nativePort = null;
let syncedWithNativeHost = false;

const DEFAULT_STANDALONE_RULES = [
  {
    id: 1,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.youtube.com/api/stats/ads*",
      resourceTypes: ["xmlhttprequest", "ping", "other"]
    }
  },
  {
    id: 2,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.youtube.com/pagead/*",
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  },
  {
    id: 3,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.youtube.com/get_midroll_*",
      resourceTypes: ["xmlhttprequest", "other"]
    }
  },
  {
    id: 4,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.youtube.com/ptracking*",
      resourceTypes: ["xmlhttprequest", "image", "ping", "other"]
    }
  },
  {
    id: 5,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.doubleclick.net/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "media", "other"]
    }
  },
  {
    id: 6,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.googlesyndication.com/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  },
  {
    id: 7,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "*://*.googleadservices.com/*",
      initiatorDomains: ["youtube.com", "www.youtube.com", "m.youtube.com", "youtube-nocookie.com"],
      resourceTypes: ["xmlhttprequest", "script", "image", "sub_frame", "other"]
    }
  }
];

async function ensureDefaultSettingsAndRules() {
  try {
    const stored = await chrome.storage.local.get([
      "spectraInitialized",
      "blockYouTubeAds",
      "blockYouTubeAnnotations",
      "blockYouTubeShorts",
      "showPlaceholder"
    ]);

    if (!stored.spectraInitialized) {
      await chrome.storage.local.set({
        spectraInitialized: true,
        blockYouTubeAds: stored.blockYouTubeAds !== undefined ? stored.blockYouTubeAds : true,
        blockYouTubeAnnotations: stored.blockYouTubeAnnotations !== undefined ? stored.blockYouTubeAnnotations : true,
        blockYouTubeShorts: stored.blockYouTubeShorts !== undefined ? stored.blockYouTubeShorts : false,
        showPlaceholder: stored.showPlaceholder !== undefined ? stored.showPlaceholder : true
      });
    }

    if (!syncedWithNativeHost) {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      if (existing.length === 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: [],
          addRules: DEFAULT_STANDALONE_RULES
        });
      }
    }
  } catch (err) {
    console.warn("[Spectra Browser Guard] Initialization fallback notice:", err);
  }
}

function connectNativeHost() {
  try {
    nativePort = chrome.runtime.connectNative(HOST_NAME);

    nativePort.onMessage.addListener((msg) => {
      if (msg && msg.type === "rules_update") {
        syncedWithNativeHost = true;
        applyDynamicRules(msg);
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
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeIds = existingRules.map(r => r.id);

    let addRules = [];
    if (payload.enabled && payload.rulesJson) {
      try {
        addRules = JSON.parse(payload.rulesJson);
      } catch (err) {
        console.error("[Spectra Browser Guard] Invalid rulesJson:", err);
      }
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules: addRules
    });

    await chrome.storage.local.set({
      spectraInitialized: true,
      showPlaceholder: payload.placeholder !== false,
      blockYouTubeAds: payload.blockYouTubeAds !== false,
      blockYouTubeAnnotations: payload.blockYouTubeAnnotations !== false,
      blockYouTubeShorts: payload.blockYouTubeShorts === true,
      activeRulesCount: addRules.length
    });
  } catch (err) {
    console.error("[Spectra Browser Guard] Failed to update dynamic rules:", err);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  ensureDefaultSettingsAndRules();
  connectNativeHost();
});

chrome.runtime.onStartup.addListener(() => {
  ensureDefaultSettingsAndRules();
  connectNativeHost();
});

// Periodic sync every 30 seconds
setInterval(() => {
  if (!nativePort) {
    connectNativeHost();
  } else {
    try {
      nativePort.postMessage({ type: "get_rules" });
    } catch {
      nativePort = null;
    }
  }
}, 30000);

ensureDefaultSettingsAndRules();
connectNativeHost();
