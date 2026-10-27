// Spectra Browser Guard - Popup Script
document.addEventListener("DOMContentLoaded", async () => {
  const badge = document.getElementById("statusBadge");
  const toggleShorts = document.getElementById("toggleShorts");
  const toggleStreams = document.getElementById("toggleStreams");
  const toggleAds = document.getElementById("toggleAds");

  chrome.runtime.sendMessage({ type: "get_status" }, (res) => {
    if (res && res.connected) {
      badge.className = "badge badge-on";
      badge.innerText = "CONNECTED";
    } else {
      badge.className = "badge badge-off";
      badge.innerText = "STANDALONE";
    }
  });

  toggleShorts.addEventListener("change", () => {
    chrome.runtime.sendMessage({
      type: "toggle_rule",
      id: "yt-shorts",
      enabled: toggleShorts.checked
    });
  });

  toggleStreams.addEventListener("change", () => {
    chrome.runtime.sendMessage({
      type: "toggle_rule",
      id: "yt-video-stream",
      enabled: toggleStreams.checked
    });
  });

  toggleAds.addEventListener("change", () => {
    chrome.runtime.sendMessage({
      type: "toggle_rule",
      id: "yt-ads",
      enabled: toggleAds.checked
    });
  });
});
