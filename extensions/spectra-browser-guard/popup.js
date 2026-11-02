// Spectra Browser Guard - Popup Script
document.addEventListener("DOMContentLoaded", async () => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const badge = document.getElementById("statusBadge");
  const toggleShorts = document.getElementById("toggleShorts");
  const toggleStreams = document.getElementById("toggleStreams");
  const toggleAds = document.getElementById("toggleAds");

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
    }
  });

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
