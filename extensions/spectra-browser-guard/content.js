// Spectra Browser Guard & YouTube AdShield - Content Script
// 1. Eliminates YouTube pre-roll & mid-roll video ads, auto-clicks skip buttons, and strips overlay ads & annotations
//    on both youtube.com and embedded YouTube players across all websites.
// 2. Enforces YouTube Shorts / blocked media cybernetic overlay when configured.

(function () {
  let showPlaceholder = true;
  let blockYouTubeAds = true;
  let blockYouTubeAnnotations = true;
  let blockYouTubeShorts = false;
  let wasMutedBeforeAd = null;
  let userPlaybackRate = 1;

  const isYouTubeHost =
    location.hostname.includes("youtube.com") ||
    location.hostname.includes("youtube-nocookie.com") ||
    location.hostname.includes("youtu.be");

  function syncAttributes() {
    const root = document.documentElement;
    if (!root) return;
    root.setAttribute("data-spectra-yt-ads", blockYouTubeAds ? "on" : "off");
    root.setAttribute("data-spectra-yt-annotations", blockYouTubeAnnotations ? "on" : "off");
  }

  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(
      ["showPlaceholder", "blockYouTubeAds", "blockYouTubeAnnotations", "blockYouTubeShorts"],
      (res) => {
        if (res.showPlaceholder !== undefined) showPlaceholder = res.showPlaceholder;
        if (res.blockYouTubeAds !== undefined) blockYouTubeAds = res.blockYouTubeAds;
        if (res.blockYouTubeAnnotations !== undefined) blockYouTubeAnnotations = res.blockYouTubeAnnotations;
        if (res.blockYouTubeShorts !== undefined) blockYouTubeShorts = res.blockYouTubeShorts;
        syncAttributes();
      }
    );

    chrome.storage.onChanged.addListener((changes) => {
      if (changes.showPlaceholder) showPlaceholder = changes.showPlaceholder.newValue;
      if (changes.blockYouTubeAds) blockYouTubeAds = changes.blockYouTubeAds.newValue;
      if (changes.blockYouTubeAnnotations) blockYouTubeAnnotations = changes.blockYouTubeAnnotations.newValue;
      if (changes.blockYouTubeShorts) blockYouTubeShorts = changes.blockYouTubeShorts.newValue;
      syncAttributes();
    });
  }

  syncAttributes();

  // ---- YouTube Pre-Roll / Mid-Roll Ad Skipper & Cosmetic Cleaner ----
  const SKIP_BUTTON_SELECTORS = [
    ".ytp-ad-skip-button",
    ".ytp-ad-skip-button-modern",
    ".ytp-skip-ad-button",
    ".ytp-ad-skip-button-slot button",
    ".ytp-ad-skip-button-container button",
    ".ytp-ad-overlay-close-button",
    "button.ytp-ad-skip-button-modern",
    "button[id^='skip-button']"
  ];

  function neutralizeYouTubeAds() {
    if (!isYouTubeHost || !blockYouTubeAds) return;

    // 1. Click any visible skip or overlay close buttons immediately
    for (const sel of SKIP_BUTTON_SELECTORS) {
      const btns = document.querySelectorAll(sel);
      for (const btn of btns) {
        if (btn && typeof btn.click === "function") {
          try {
            btn.click();
          } catch {}
        }
      }
    }

    // 2. Detect active pre-roll / mid-roll ad stream inside the HTML5 player
    const player = document.querySelector("#movie_player, .html5-video-player");
    if (!player) return;

    const isAdShowing =
      player.classList.contains("ad-showing") ||
      player.classList.contains("ad-interrupting") ||
      document.querySelector(".ad-showing, .ad-interrupting, .ytp-ad-player-overlay, .ytp-ad-player-overlay-layout") !== null;

    const video = player.querySelector("video.html5-main-video") || player.querySelector("video");
    if (!video) return;

    if (isAdShowing) {
      if (wasMutedBeforeAd === null) {
        wasMutedBeforeAd = video.muted;
        if (!video.paused && video.playbackRate > 0 && video.playbackRate <= 2) {
          userPlaybackRate = video.playbackRate;
        }
      }

      // Mute ad audio immediately
      video.muted = true;

      // Fast-forward to the end of the ad stream
      if (Number.isFinite(video.duration) && video.duration > 0.5) {
        try {
          if (video.currentTime < video.duration - 0.1) {
            video.currentTime = video.duration;
          }
        } catch {}
      }

      try {
        video.playbackRate = 16;
      } catch {}

      // Re-attempt skip button click after seeking to end
      for (const sel of SKIP_BUTTON_SELECTORS) {
        const btn = player.querySelector(sel);
        if (btn && typeof btn.click === "function") {
          try {
            btn.click();
          } catch {}
        }
      }
    } else if (wasMutedBeforeAd !== null) {
      // Ad finished: restore user's original mute state and playback speed
      video.muted = wasMutedBeforeAd;
      if (video.playbackRate > 2) {
        video.playbackRate = userPlaybackRate || 1;
      }
      wasMutedBeforeAd = null;
    }
  }

  // ---- Blocked Media & Shorts Overlay ----
  function createBlockedPlaceholder(targetEl, reasonText) {
    if (!showPlaceholder || !targetEl || targetEl.dataset.spectraGuarded === "true") return;
    targetEl.dataset.spectraGuarded = "true";

    const overlay = document.createElement("div");
    overlay.className = "spectra-media-blocked-overlay";

    const icon = document.createElement("div");
    icon.className = "spectra-overlay-icon";
    icon.textContent = "🛡️";

    const title = document.createElement("div");
    title.className = "spectra-overlay-title";
    title.textContent = "MEDIA STREAM BLOCKED BY SPECTRA GUARD";

    const desc = document.createElement("div");
    desc.className = "spectra-overlay-desc";
    desc.textContent = reasonText || "This video or short-form feed matches an active Spectra Browser Guard policy.";

    const btn = document.createElement("button");
    btn.className = "spectra-allow-once-btn";
    btn.textContent = "▶ Allow Once";
    btn.addEventListener("click", () => {
      overlay.remove();
      targetEl.style.display = "";
    });

    overlay.appendChild(icon);
    overlay.appendChild(title);
    overlay.appendChild(desc);
    overlay.appendChild(btn);

    if (targetEl.parentNode) {
      targetEl.style.display = "none";
      targetEl.parentNode.insertBefore(overlay, targetEl);
    }
  }

  function inspectMediaElements() {
    if (blockYouTubeShorts && window.location.href.includes("/shorts/")) {
      const shortsContainer = document.querySelector("ytd-shorts, #shorts-container");
      if (shortsContainer) {
        createBlockedPlaceholder(shortsContainer, "YouTube Shorts feeds are blocked by your Spectra Browser Guard settings.");
      }
    }
  }

  function runGuardTick() {
    syncAttributes();
    neutralizeYouTubeAds();
    inspectMediaElements();
  }

  // Observe DOM mutations as early as documentElement is available
  const startObserver = () => {
    const target = document.documentElement || document.body;
    if (!target) {
      requestAnimationFrame(startObserver);
      return;
    }
    const observer = new MutationObserver(() => {
      neutralizeYouTubeAds();
      inspectMediaElements();
    });
    observer.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  };

  startObserver();
  setInterval(runGuardTick, 250);
})();
