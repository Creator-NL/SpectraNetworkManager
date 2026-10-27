// Spectra Browser Guard - Manifest V3 Background Service Worker
const HOST_NAME = "com.spectranetworkmanager.browser_host";
let nativePort = null;
let isConnected = false;
let currentRules = [];

function connectToHost() {
  try {
    nativePort = chrome.runtime.connectNative(HOST_NAME);
    
    nativePort.onMessage.addListener((msg) => {
      handleHostMessage(msg);
    });

    nativePort.onDisconnect.addListener(() => {
      isConnected = false;
      const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : "Disconnected";
      console.log("Spectra Host disconnected:", err);
      nativePort = null;
      // Retry connection after 5 seconds
      setTimeout(connectToHost, 5000);
    });

    isConnected = true;
    console.log("Connected to Spectra Browser Guard Host.");
    // Request initial rules
    nativePort.postMessage({ type: "get_rules" });
  } catch (e) {
    isConnected = false;
    nativePort = null;
    setTimeout(connectToHost, 5000);
  }
}

async function handleHostMessage(msg) {
  if (!msg) return;
  
  if (msg.type === "rules_update") {
    try {
      const dynamicRules = JSON.parse(msg.rulesJson || "[]");
      await applyDynamicRules(dynamicRules);
      chrome.storage.local.set({
        isConnected: true,
        rulesCount: dynamicRules.length,
        showPlaceholder: msg.placeholder !== false,
        lastUpdated: Date.now()
      });
    } catch (e) {
      console.error("Failed to parse/apply dynamic rules:", e);
    }
  }
}

async function applyDynamicRules(newRules) {
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules.map(r => r.id);

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeRuleIds,
      addRules: newRules
    });

    currentRules = newRules;
    console.log(`Applied ${newRules.length} dynamic blocking rules.`);
  } catch (err) {
    console.error("Error updating declarativeNetRequest rules:", err);
  }
}

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "get_status") {
    sendResponse({
      connected: isConnected,
      rulesCount: currentRules.length
    });
    return true;
  }
  
  if (message.type === "toggle_rule") {
    if (nativePort && isConnected) {
      nativePort.postMessage(message);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "allow_once") {
    // Temporary allow rule for 10 minutes
    const tempRule = {
      id: 999000 + Math.floor(Math.random() * 999),
      priority: 100,
      action: { type: "allow" },
      condition: {
        urlFilter: message.urlPattern,
        resourceTypes: ["media", "main_frame", "sub_frame"]
      }
    };

    chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [tempRule]
    }).then(() => {
      sendResponse({ allowed: true });
      // Remove after 10 minutes
      setTimeout(() => {
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: [tempRule.id]
        });
      }, 10 * 60 * 1000);
    });
    return true;
  }
});

// Initial startup
connectToHost();
