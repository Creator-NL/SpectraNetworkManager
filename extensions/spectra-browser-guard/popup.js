// Spectra Browser Guard - Popup Script
document.addEventListener("DOMContentLoaded", async () => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const badge = document.getElementById("statusBadge");
  const toggleShorts = document.getElementById("toggleShorts");
  const toggleStreams = document.getElementById("toggleStreams");
  const toggleAds = document.getElementById("toggleAds");
  const btnElementPicker = document.getElementById("btnElementPicker");

  api.runtime.sendMessage({ type: "get_status" }, (res) => {
    if (res) {
      if (badge) {
        badge.className = res.connected ? "badge badge-on" : "badge badge-off";
        badge.innerText = res.connected ? "CONNECTED" : "STANDALONE";
      }
      if (toggleShorts && res.blockYouTubeShorts !== undefined) {
        toggleShorts.checked = res.blockYouTubeShorts;
      }
      if (toggleAds && res.blockYouTubeAds !== undefined) {
        toggleAds.checked = res.blockYouTubeAds;
      }
      const adsCounter = document.getElementById("adsSkippedCount");
      if (adsCounter) {
        adsCounter.textContent = String(res.adsSkipped || 0);
      }
    }
  });

  if (btnElementPicker) {
    btnElementPicker.addEventListener("click", async () => {
      try {
        const queryTabs = api.tabs.query ? api.tabs.query({ active: true, currentWindow: true }) : null;
        if (queryTabs && typeof queryTabs.then === "function") {
          const tabs = await queryTabs;
          if (tabs && tabs[0] && tabs[0].id) {
            api.tabs.sendMessage(tabs[0].id, { type: "start_element_picker" }).catch(() => {});
            window.close();
          }
        } else if (api.tabs && api.tabs.query) {
          api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs[0] && tabs[0].id) {
              api.tabs.sendMessage(tabs[0].id, { type: "start_element_picker" });
              window.close();
            }
          });
        }
      } catch (err) {
        console.warn("Element picker start note:", err);
      }
    });
  }

  if (toggleShorts) {
    toggleShorts.addEventListener("change", () => {
      api.runtime.sendMessage({
        type: "toggle_rule",
        id: "yt-shorts",
        enabled: toggleShorts.checked
      });
    });
  }

  if (toggleStreams) {
    toggleStreams.addEventListener("change", () => {
      api.runtime.sendMessage({
        type: "toggle_rule",
        id: "yt-video-stream",
        enabled: toggleStreams.checked
      });
    });
  }

  if (toggleAds) {
    toggleAds.addEventListener("change", () => {
      api.runtime.sendMessage({
        type: "toggle_rule",
        id: "yt-ads",
        enabled: toggleAds.checked
      });
    });
  }
});
