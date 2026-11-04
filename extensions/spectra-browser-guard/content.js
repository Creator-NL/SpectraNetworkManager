// Spectra Browser Guard & YouTube AdShield - Content Script
// 1. YouTube in-page pre-roll & mid-roll video ad skipper, annotation stripper, and cosmetic ad removal.
// 2. Custom URL & YouTube video page blocker: enforces user block rules live during SPA navigation and page loads.
// 3. YouTube Shorts suppressor and cybernetic blocked media overlay.

(function () {
  const api = typeof browser !== "undefined" ? browser : chrome;

  let showPlaceholder = true;
  let blockYouTubeAds = true;
  let blockYouTubeAnnotations = true;
  let blockYouTubeShorts = false;
  let activeCustomRules = [];
  let wasMutedBeforeAd = null;
  let userPlaybackRate = 1;
  let lastCheckedUrl = "";
  let currentBlockedRule = null;

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

  // --- Settings & Custom Rules Synchronization ---
  if (typeof api !== "undefined" && api.storage && api.storage.local) {
    api.storage.local.get(
      ["showPlaceholder", "blockYouTubeAds", "blockYouTubeAnnotations", "blockYouTubeShorts", "customRules"],
      (res) => {
        if (res.showPlaceholder !== undefined) showPlaceholder = res.showPlaceholder;
        if (res.blockYouTubeAds !== undefined) blockYouTubeAds = res.blockYouTubeAds;
        if (res.blockYouTubeAnnotations !== undefined) blockYouTubeAnnotations = res.blockYouTubeAnnotations;
        if (res.blockYouTubeShorts !== undefined) blockYouTubeShorts = res.blockYouTubeShorts;
        if (Array.isArray(res.customRules)) activeCustomRules = res.customRules;
        syncAttributes();
        checkPageBlockRules(true);
        inspectShortsElements();
      }
    );

    api.storage.onChanged.addListener((changes) => {
      const relevant = ["showPlaceholder", "blockYouTubeAds", "blockYouTubeAnnotations", "blockYouTubeShorts", "customRules"];
      if (!relevant.some((k) => changes[k])) return;
      if (changes.showPlaceholder) showPlaceholder = changes.showPlaceholder.newValue;
      if (changes.blockYouTubeAds) blockYouTubeAds = changes.blockYouTubeAds.newValue;
      if (changes.blockYouTubeAnnotations) blockYouTubeAnnotations = changes.blockYouTubeAnnotations.newValue;
      if (changes.blockYouTubeShorts) blockYouTubeShorts = changes.blockYouTubeShorts.newValue;
      if (changes.customRules) {
        activeCustomRules = Array.isArray(changes.customRules.newValue) ? changes.customRules.newValue : [];
      }
      syncAttributes();
      checkPageBlockRules(true);
      inspectShortsElements();
    });
  }

  if (typeof api !== "undefined" && api.runtime && api.runtime.onMessage) {
    api.runtime.onMessage.addListener((msg) => {
      if (msg && msg.type === "start_element_picker") {
        startElementPicker();
      }

      if (msg && msg.type === "spectra_rules_updated") {
        if (Array.isArray(msg.customRules)) activeCustomRules = msg.customRules;
        if (msg.blockYouTubeShorts !== undefined) blockYouTubeShorts = msg.blockYouTubeShorts;
        if (msg.blockYouTubeAds !== undefined) blockYouTubeAds = msg.blockYouTubeAds;
        syncAttributes();
        checkPageBlockRules(true);
        inspectShortsElements();
      }
    });
  }

  syncAttributes();

  // --- YouTube Video ID Extraction Helper ---
  function extractYouTubeVideoId(urlStr) {
    if (!urlStr) return null;
    try {
      const u = new URL(urlStr, location.origin);
      if (u.hostname.includes("youtube.com") || u.hostname.includes("youtube-nocookie.com")) {
        const v = u.searchParams.get("v");
        if (v && v.length >= 8) return v;

        const mShorts = u.pathname.match(/\/shorts\/([a-zA-Z0-9_-]{8,})/);
        if (mShorts) return mShorts[1];

        const mEmbed = u.pathname.match(/\/embed\/([a-zA-Z0-9_-]{8,})/);
        if (mEmbed) return mEmbed[1];

        const mV = u.pathname.match(/\/v\/([a-zA-Z0-9_-]{8,})/);
        if (mV) return mV[1];
      } else if (u.hostname === "youtu.be") {
        const m = u.pathname.match(/^\/([a-zA-Z0-9_-]{8,})/);
        if (m) return m[1];
      }
    } catch {}
    return null;
  }

  // --- Rule Matcher Helper ---
  function patternMatchesUrl(pattern, targetUrl) {
    if (!pattern || !targetUrl) return false;
    const cleanPattern = pattern.trim().toLowerCase();
    const cleanUrl = targetUrl.toLowerCase();

    if (cleanUrl.includes(cleanPattern)) return true;

    // Check if pattern is a bare YouTube Video ID (11 chars)
    if (/^[a-zA-Z0-9_-]{11}$/.test(cleanPattern)) {
      const vid = extractYouTubeVideoId(targetUrl);
      if (vid && vid === cleanPattern) return true;
    }

    try {
      const rxStr = "^" + cleanPattern
        .replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&")
        .replace(/\*/g, ".*") + "$";
      const rx = new RegExp(rxStr);
      if (rx.test(cleanUrl)) return true;
    } catch {}

    return false;
  }

  function findMatchingBlockRule(currentUrl) {
    if (!Array.isArray(activeCustomRules) || activeCustomRules.length === 0) return null;

    const currentVid = extractYouTubeVideoId(currentUrl);

    for (const rule of activeCustomRules) {
      if (rule.action === "allow" || rule.enabled === false) continue;

      if (rule.videoId && currentVid && rule.videoId === currentVid) {
        return rule;
      }

      if (rule.url && patternMatchesUrl(rule.url, currentUrl)) {
        return rule;
      }

      if (rule.domain) {
        try {
          const u = new URL(currentUrl);
          if (u.hostname.toLowerCase() === rule.domain.toLowerCase() || u.hostname.toLowerCase().endsWith("." + rule.domain.toLowerCase())) {
            return rule;
          }
        } catch {}
      }
    }
    return null;
  }

  // --- Active Enforcement & Video Halting ---
  function checkPageBlockRules(force = false) {
    const currentUrl = window.location.href;
    if (!force && currentUrl === lastCheckedUrl) return;
    lastCheckedUrl = currentUrl;

    const matchedRule = findMatchingBlockRule(currentUrl);
    if (matchedRule) {
      currentBlockedRule = matchedRule;
      haltActiveVideo();

      if (isYouTubeHost && (currentUrl.includes("/watch") || currentUrl.includes("/embed/"))) {
        blockYouTubeVideoPlayer(matchedRule);
      } else {
        blockEntireWebPage(matchedRule);
      }
    } else {
      currentBlockedRule = null;
      removeBlockOverlayIfExists();
    }
  }

  function haltActiveVideo() {
    const videos = document.querySelectorAll("video");
    for (const v of videos) {
      try {
        v.pause();
        v.currentTime = 0;
        v.playbackRate = 0;
        v.muted = true;
      } catch {}
    }
  }

  function blockYouTubeVideoPlayer(matchedRule) {
    const player = document.querySelector("#movie_player, .html5-video-player");
    if (!player) return;

    haltActiveVideo();

    let overlay = document.getElementById("spectra-player-block-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "spectra-player-block-overlay";
      overlay.className = "spectra-media-blocked-overlay";
      overlay.style.position = "absolute";
      overlay.style.inset = "0";
      overlay.style.zIndex = "2147483647";
      overlay.style.background = "linear-gradient(135deg, rgba(13, 17, 23, 0.96) 0%, rgba(21, 28, 40, 0.98) 100%)";

      const iconEl = document.createElement("div");
      iconEl.className = "spectra-overlay-icon";
      iconEl.textContent = "🛡️";

      const titleEl = document.createElement("div");
      titleEl.className = "spectra-overlay-title";
      titleEl.textContent = "ACCESS RESTRICTED BY SPECTRA NETWORK MANAGER";

      const descEl = document.createElement("div");
      descEl.className = "spectra-overlay-desc";
      const ruleLabel = matchedRule.title || matchedRule.name || matchedRule.url || matchedRule.videoId || "Spectra Security Policy";
      descEl.textContent = `This content is blocked by Spectra Browser Guard (${ruleLabel}).`;

      const allowBtn = document.createElement("button");
      allowBtn.className = "spectra-allow-once-btn";
      allowBtn.textContent = "Allow Once for this Session";
      allowBtn.onclick = () => {
        matchedRule.action = "allow";
        overlay.remove();
        const v = player.querySelector("video");
        if (v) {
          v.playbackRate = 1;
          v.play().catch(() => {});
        }
      };

      overlay.appendChild(iconEl);
      overlay.appendChild(titleEl);
      overlay.appendChild(descEl);
      overlay.appendChild(allowBtn);

      player.appendChild(overlay);
    }
  }

  function blockEntireWebPage(matchedRule) {
    if (document.getElementById("spectra-page-block-overlay")) return;

    haltActiveVideo();

    const overlay = document.createElement("div");
    overlay.id = "spectra-page-block-overlay";
    overlay.className = "spectra-media-blocked-overlay";
    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100vw";
    overlay.style.height = "100vh";
    overlay.style.zIndex = "2147483647";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.background = "#0D1117";

    const iconEl = document.createElement("div");
    iconEl.className = "spectra-overlay-icon";
    iconEl.textContent = "🛡️";

    const titleEl = document.createElement("div");
    titleEl.className = "spectra-overlay-title";
    titleEl.textContent = "WEBSITE BLOCKED BY SPECTRA BROWSER GUARD";

    const descEl = document.createElement("div");
    descEl.className = "spectra-overlay-desc";
    const ruleLabel = matchedRule.title || matchedRule.name || matchedRule.url || matchedRule.domain || "Spectra Security Policy";
    descEl.textContent = `Access to this website is restricted (${ruleLabel}).`;

    const backBtn = document.createElement("button");
    backBtn.className = "spectra-allow-once-btn";
    backBtn.textContent = "Go Back";
    backBtn.onclick = () => {
      window.history.back();
    };

    overlay.appendChild(iconEl);
    overlay.appendChild(titleEl);
    overlay.appendChild(descEl);
    overlay.appendChild(backBtn);

    const target = document.body || document.documentElement;
    if (target) target.appendChild(overlay);
  }

  function removeBlockOverlayIfExists() {
    const playerOverlay = document.getElementById("spectra-player-block-overlay");
    if (playerOverlay && typeof playerOverlay.remove === "function") playerOverlay.remove();
    const pageOverlay = document.getElementById("spectra-page-block-overlay");
    if (pageOverlay && typeof pageOverlay.remove === "function") pageOverlay.remove();
  }

  // Listen to YouTube SPA navigation events & browser history
  let lastNavTime = Date.now();
  let pendingAutoplay = true;

  function onWatchNavigation() {
    lastNavTime = Date.now();
    pendingAutoplay = true;
    checkPageBlockRules(true);
    inspectShortsElements();
  }

  window.addEventListener("yt-navigate-start", onWatchNavigation);
  window.addEventListener("yt-navigate-finish", onWatchNavigation);
  window.addEventListener("yt-page-data-updated", onWatchNavigation);
  window.addEventListener("popstate", onWatchNavigation);
  window.addEventListener("hashchange", onWatchNavigation);

  window.addEventListener("focus", () => {
    const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
    if (pendingAutoplay && isWatch && (Date.now() - lastNavTime < 10000)) {
      const v = document.querySelector("video");
      if (v && v.paused && !v.ended && !currentBlockedRule && !shouldBlockShorts()) {
        v.play().catch(() => {});
      }
    }
  });

  // Hook pushState / replaceState for dynamic client-side URL updates
  const origPush = history.pushState;
  history.pushState = function () {
    origPush.apply(this, arguments);
    setTimeout(() => {
      onWatchNavigation();
    }, 20);
  };
  const origReplace = history.replaceState;
  history.replaceState = function () {
    origReplace.apply(this, arguments);
    setTimeout(() => {
      onWatchNavigation();
    }, 20);
  };

  // ---- Main-World Script Injection for Native YouTube Player API Access ----
  function injectMainWorldAdSkipper() {
    if (!isYouTubeHost) return;
    const scriptId = "spectra-yt-main-world-shield";
    if (document.getElementById(scriptId)) return;

    const script = document.createElement("script");
    script.id = scriptId;
    script.textContent = `
      (function() {
        const SKIP_SELECTORS = [
          ".ytp-ad-skip-button",
          ".ytp-ad-skip-button-modern",
          ".ytp-skip-ad-button",
          ".ytp-ad-skip-button-slot button",
          ".ytp-ad-skip-button-container button",
          "button.ytp-ad-skip-button-modern",
          "button.ytp-skip-ad-button",
          "button[id^='skip-button']",
          "button[class*='skip-button']",
          "button[class*='skip-ad']",
          "button[aria-label*='Skip']",
          "button[aria-label*='skip']",
          "button[aria-label*='Overslaan']",
          "button[aria-label*='overslaan']",
          ".ytp-ad-overlay-close-button",
          ".ytp-ad-preview-container button",
          ".video-ads .ytp-ad-skip-button-slot button",
          ".ytp-ad-action-interstitial button"
        ];

        let adJustFinished = false;
        let navTime = Date.now();
        let pendingAutoplay = true;

        function markNav() {
          navTime = Date.now();
          pendingAutoplay = true;
          adJustFinished = false;
        }

        document.addEventListener("yt-navigate-start", markNav);
        document.addEventListener("yt-navigate-finish", markNav);
        window.addEventListener("popstate", markNav);

        function isPlayerAd(player) {
          if (!player) return false;
          if (player.classList.contains("ad-showing") || player.classList.contains("ad-interrupting")) return true;
          if (typeof player.getAdState === "function") {
            try {
              const s = player.getAdState();
              if (s === 1 || s === 2) return true;
            } catch(e) {}
          }
          if (player.querySelector && player.querySelector(".ytp-ad-text, .ytp-ad-badge, [class*='ytp-ad-badge'], .ytp-ad-player-overlay, .ytp-ad-player-overlay-layout")) {
            return true;
          }
          return false;
        }

        function handlePlayer() {
          const player = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
          if (!player) return;

          const video = player.querySelector("video");
          const isShorts = location.pathname.includes("/shorts/");
          if (isShorts) return;
          if (video && (!Number.isFinite(video.duration) || video.duration === Infinity)) return;

          const adActive = isPlayerAd(player);

          if (adActive) {
            adJustFinished = true;

            // 1. YouTube internal player API - skip and cancel ad
            try {
              if (typeof player.skipAd === "function") player.skipAd();
            } catch(e) {}
            try {
              if (typeof player.cancelPlayback === "function") player.cancelPlayback();
            } catch(e) {}

            // 2. Dispatch trusted-like click on skip buttons
            for (const sel of SKIP_SELECTORS) {
              const btns = player.querySelectorAll ? player.querySelectorAll(sel) : [];
              for (const b of btns) {
                try {
                  b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                  b.click();
                } catch(e) {}
              }
            }

            // 3. Fast forward ad video ONLY while ad is showing
            if (video && isPlayerAd(player)) {
              if (Number.isFinite(video.duration) && video.duration > 0.1) {
                try { video.currentTime = video.duration; } catch(e) {}
              }
              try { video.playbackRate = 16; } catch(e) {}
              if (video.paused && !video.ended) {
                try { video.play().catch(function() {}); } catch(e) {}
              }
            }
            return;
          }

          // NO ad is showing right now
          if (adJustFinished) {
            // Ad was just cancelled or skipped! Resume main video playback immediately!
            try {
              if (typeof player.playVideo === "function") {
                player.playVideo();
              }
            } catch(e) {}
            if (video && video.paused && !video.ended) {
              try { video.play().catch(function() {}); } catch(e) {}
            }
            if (video && !video.paused && video.currentTime > 0.1) {
              adJustFinished = false;
              pendingAutoplay = false;
            }
            return;
          }

          // Once video is actively playing past 0.3s, reset autoplay request
          if (video && !video.paused && video.currentTime > 0.3) {
            pendingAutoplay = false;
            return;
          }

          // Auto-start if we navigated to a watch page within 4 seconds and the video is paused/unstarted
          const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
          const timeSinceNav = Date.now() - navTime;
          if (pendingAutoplay && timeSinceNav < 4000 && isWatch && video && video.paused && !video.ended) {
            try {
              if (typeof player.playVideo === "function") {
                const state = typeof player.getPlayerState === "function" ? player.getPlayerState() : -1;
                // -1: unstarted, 2: paused, 5: cued
                if (state === -1 || state === 2 || state === 5) {
                  player.playVideo();
                }
              }
            } catch(e) {}
            try {
              video.play().catch(function() {});
            } catch(e) {}
          }
        }

        setInterval(handlePlayer, 100);
        document.addEventListener("yt-navigate-finish", handlePlayer);
      })();
    `;
    (document.head || document.documentElement).appendChild(script);
  }

  // ---- YouTube Pre-Roll / Mid-Roll Ad Skipper & Cosmetic Cleaner ----
  const SKIP_BUTTON_SELECTORS = [
    ".ytp-ad-skip-button",
    ".ytp-ad-skip-button-modern",
    ".ytp-skip-ad-button",
    "button.ytp-ad-skip-button-modern",
    "button.ytp-skip-ad-button",
    ".ytp-ad-skip-button-slot button",
    ".ytp-ad-skip-button-container button",
    ".ytp-ad-overlay-close-button",
    "button[id^='skip-button']",
    "button[class*='skip-button']",
    "button[class*='skip-ad']",
    "button[aria-label*='Skip']",
    "button[aria-label*='skip']",
    "button[aria-label*='Overslaan']",
    "button[aria-label*='overslaan']",
    ".ytp-ad-preview-container button",
    ".video-ads .ytp-ad-skip-button-slot button",
    ".ytp-ad-action-interstitial button"
  ];

  function isAdSkipPage() {
    const p = location.pathname;
    return !p.includes("/shorts/") && (p.startsWith("/watch") || p.startsWith("/embed") || p.startsWith("/live"));
  }

  function setAdActiveAttr(on) {
    const root = document.documentElement;
    if (!root) return;
    if (on) {
      if (root.getAttribute("data-spectra-ad-active") !== "1") root.setAttribute("data-spectra-ad-active", "1");
    } else if (root.hasAttribute("data-spectra-ad-active")) {
      root.removeAttribute("data-spectra-ad-active");
    }
  }

  function isPlayerAd(player) {
    if (!player) return false;
    if (player.classList.contains("ad-showing") || player.classList.contains("ad-interrupting")) return true;
    if (typeof player.getAdState === "function") {
      try {
        const s = player.getAdState();
        if (s === 1 || s === 2) return true;
      } catch(e) {}
    }
    if (player.wrappedJSObject && typeof player.wrappedJSObject.getAdState === "function") {
      try {
        const s = player.wrappedJSObject.getAdState();
        if (s === 1 || s === 2) return true;
      } catch(e) {}
    }
    if (player.querySelector && player.querySelector(".ytp-ad-text, .ytp-ad-badge, [class*='ytp-ad-badge'], .ytp-ad-player-overlay, .ytp-ad-player-overlay-layout")) {
      return true;
    }
    return false;
  }

  function hookVideoEvents(video) {
    if (!video || video.dataset.spectraHooked === "true") return;
    video.dataset.spectraHooked = "true";
    video.addEventListener("timeupdate", () => {
      if (blockYouTubeAds) neutralizeYouTubeAds();
    });
    video.addEventListener("playing", () => {
      if (blockYouTubeAds) neutralizeYouTubeAds();
    });
  }

  let adSessionActive = false;
  let adSessionStartedAt = 0;

  function reportAdSkipped() {
    try {
      const p = api.runtime.sendMessage({ type: "ad_skipped" });
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch {}
  }

  function neutralizeYouTubeAds() {
    if (!isYouTubeHost || !blockYouTubeAds) return;
    if (!isAdSkipPage()) {
      setAdActiveAttr(false);
      adSessionActive = false;
      return;
    }

    const player = document.querySelector("#movie_player, .html5-video-player");
    if (!player) {
      setAdActiveAttr(false);
      return;
    }

    const video = player.querySelector("video.html5-main-video") || player.querySelector("video");
    if (video) hookVideoEvents(video);

    if (video && (!Number.isFinite(video.duration) || video.duration === Infinity)) {
      setAdActiveAttr(false);
      return;
    }

    if (!isPlayerAd(player)) {
      if (adSessionActive) {
        adSessionActive = false;
      }
      setAdActiveAttr(false);

      // Normal video playing! Restore original playback rate and mute state if needed
      if (wasMutedBeforeAd !== null) {
        if (video) {
          video.muted = wasMutedBeforeAd;
          if (video.playbackRate > 2) {
            video.playbackRate = userPlaybackRate || 1;
          }
          if (video.paused && !video.ended && !currentBlockedRule && !shouldBlockShorts()) {
            video.play().catch(() => {});
          }
        }
        wasMutedBeforeAd = null;
      } else if (video && video.muted) {
        video.muted = false;
      }

      if (video) {
        if (video.playbackRate > 2) {
          video.playbackRate = userPlaybackRate || 1;
        } else if (!video.paused && video.playbackRate > 0 && video.playbackRate <= 2) {
          userPlaybackRate = video.playbackRate;
        }
      }

      // Check if video is paused right after navigation
      const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
      if (pendingAutoplay && isWatch && (Date.now() - lastNavTime < 4000)) {
        if (video && video.paused && !video.ended && !currentBlockedRule && !shouldBlockShorts()) {
          video.play().catch(() => {});
        }
      }

      if (video && !video.paused && video.currentTime > 0.3) {
        pendingAutoplay = false;
      }
      return;
    }

    // ---------------- AD IS SHOWING ----------------
    const now = Date.now();
    if (!adSessionActive) {
      adSessionActive = true;
      adSessionStartedAt = now;
      reportAdSkipped();
    }
    setAdActiveAttr(true);

    // 1. YouTube internal player API - skip and cancel ad
    try {
      if (player && player.wrappedJSObject && typeof player.wrappedJSObject.skipAd === "function") {
        player.wrappedJSObject.skipAd();
      }
    } catch(e) {}
    try {
      if (player && player.wrappedJSObject && typeof player.wrappedJSObject.cancelPlayback === "function") {
        player.wrappedJSObject.cancelPlayback();
      }
    } catch(e) {}

    // 2. Click skip / overlay close buttons immediately
    for (const sel of SKIP_BUTTON_SELECTORS) {
      const btns = player.querySelectorAll ? player.querySelectorAll(sel) : [];
      for (const btn of btns) {
        try {
          btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
          btn.click();
        } catch {}
      }
    }

    // 3. Fast-forward AD video only
    if (video) {
      if (wasMutedBeforeAd === null) {
        wasMutedBeforeAd = video.muted;
        if (!video.paused && video.playbackRate > 0 && video.playbackRate <= 2) {
          userPlaybackRate = video.playbackRate;
        }
      }

      video.muted = true;

      const d = video.duration;
      if (Number.isFinite(d) && d > 0.1) {
        try {
          video.currentTime = Math.max(0, d - 0.05);
        } catch {}
      }
      try { video.playbackRate = 16; } catch {}
      if (video.paused && !video.ended) {
        try { video.play().catch(() => {}); } catch {}
      }

      for (const sel of SKIP_BUTTON_SELECTORS) {
        const btn = player.querySelector ? player.querySelector(sel) : null;
        if (btn) {
          try {
            btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
            btn.click();
          } catch {}
        }
      }
    }
  }

  // ---- Blocked Shorts Overlay ----
  function shouldBlockShorts() {
    if (!isYouTubeHost || !window.location.href.includes("/shorts/")) return false;

    // 1. If custom rules are loaded from SpectraNetworkManager:
    if (activeCustomRules && activeCustomRules.length > 0) {
      const hasShortsRule = activeCustomRules.some(r => r.id === "yt-shorts" && r.enabled !== false && r.action !== "allow");
      return Boolean(blockYouTubeShorts && hasShortsRule);
    }

    // 2. Standalone fallback (before sync or if running without host)
    return Boolean(blockYouTubeShorts);
  }

  function inspectShortsElements() {
    const isShortsPage = isYouTubeHost && window.location.href.includes("/shorts/");
    const shortsContainers = document.querySelectorAll("ytd-shorts, #shorts-container, ytd-reel-video-renderer");

    if (shouldBlockShorts()) {
      for (const container of shortsContainers) {
        if (container.dataset.spectraGuarded !== "true") {
          container.dataset.spectraGuarded = "true";
          container.style.display = "none";
        }
      }
      haltActiveVideo();
      let overlay = document.getElementById("spectra-shorts-blocked-overlay");
      if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "spectra-shorts-blocked-overlay";
        overlay.className = "spectra-media-blocked-overlay spectra-shorts-overlay";
        const iconEl = document.createElement("div");
        iconEl.className = "spectra-overlay-icon";
        iconEl.textContent = "🛡️";

        const titleEl = document.createElement("div");
        titleEl.className = "spectra-overlay-title";
        titleEl.textContent = "SHORTS FEED BLOCKED BY SPECTRA GUARD";

        const descEl = document.createElement("div");
        descEl.className = "spectra-overlay-desc";
        descEl.textContent = "YouTube Shorts feeds are blocked by your Spectra Browser Guard settings.";

        overlay.appendChild(iconEl);
        overlay.appendChild(titleEl);
        overlay.appendChild(descEl);
        const firstContainer = document.querySelector("ytd-shorts, #shorts-container");
        if (firstContainer && firstContainer.parentNode) {
          firstContainer.parentNode.insertBefore(overlay, firstContainer);
        } else if (document.body) {
          document.body.appendChild(overlay);
        }
      }
    } else {
      // Shorts blocking is DISABLED or not on a shorts page: clean up overlay completely!
      const overlay = document.getElementById("spectra-shorts-blocked-overlay");
      if (overlay) overlay.remove();

      const genericOverlays = document.querySelectorAll(".spectra-media-blocked-overlay.spectra-shorts-overlay, #spectra-shorts-blocked-overlay");
      for (const o of genericOverlays) o.remove();

      for (const container of shortsContainers) {
        container.dataset.spectraGuarded = "false";
        if (container.style.display === "none") {
          container.style.display = "";
        }
      }
    }
  }

  // Feed & In-Page Sponsored Ad Purger
  function purgeFeedAds() {
    if (!blockYouTubeAds) return;
    try {
      const selectors = [
        "#masthead-ad",
        "ytd-ad-slot-renderer",
        "ytd-in-feed-ad-layout-renderer",
        "ytd-banner-promo-renderer",
        "ytd-statement-banner-renderer",
        "ytd-promoted-sparkles-web-renderer",
        "ytd-promoted-sparkles-text-search-renderer",
        "ytd-promoted-video-renderer",
        "ytd-compact-promoted-video-renderer",
        "ytd-video-masthead-ad-v3-renderer",
        "ytd-primetime-promo-renderer",
        ".badge-shape-wiz--ad",
        "[class*='badge-shape-wiz--ad']",
        ".badge-style-type-ad"
      ];
      const elements = document.querySelectorAll(selectors.join(", "));
      for (let i = 0; i < elements.length; i++) {
        const el = elements[i];
        if (el.closest("#movie_player, .html5-video-player")) continue;
        const container = el.closest("ytd-rich-item-renderer, ytd-rich-section-renderer, ytd-video-renderer, ytd-compact-video-renderer, ytd-ad-slot-renderer") || el;
        if (container && container.style.display !== "none") {
          container.style.display = "none";
        }
      }
    } catch {}
  }

  function runGuardTick() {
    syncAttributes();
    checkPageBlockRules(false);
    neutralizeYouTubeAds();
    purgeFeedAds();
    inspectShortsElements();
  }

  const startObserver = () => {
    const target = document.documentElement || document.body;
    if (!target) {
      requestAnimationFrame(startObserver);
      return;
    }
    injectMainWorldAdSkipper();
    const observer = new MutationObserver(() => {
      checkPageBlockRules(false);
      neutralizeYouTubeAds();
      purgeFeedAds();
      inspectShortsElements();
    });
    observer.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  };

  // --- Element Picker Mode (Interactive Visual Rule Creator) ---
  let isPickerActive = false;
  let hoveredTarget = null;
  let pickerHud = null;
  let prevOutline = "";
  let prevCursor = "";

  function showPickerToast(message) {
    const existing = document.getElementById("spectra-picker-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "spectra-picker-toast";
    toast.style.cssText = "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#151C28;border:1px solid #00E5FF;color:#E6EDF3;padding:10px 22px;border-radius:6px;font:13px 'Segoe UI',sans-serif;font-weight:600;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.7);pointer-events:none;";
    toast.textContent = message;
    document.documentElement.appendChild(toast);
    setTimeout(() => {
      toast.style.transition = "opacity 0.4s ease";
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 400);
    }, 3200);
  }

  function startElementPicker() {
    if (isPickerActive) return;
    isPickerActive = true;

    pickerHud = document.createElement("div");
    pickerHud.id = "spectra-picker-hud";
    pickerHud.style.cssText = "position:fixed;top:16px;left:50%;transform:translateX(-50%);background:rgba(13,17,23,0.95);border:1px solid #FF2BD6;color:#FFF;padding:10px 20px;border-radius:8px;font:13px 'Segoe UI',sans-serif;z-index:2147483647;display:flex;align-items:center;gap:14px;box-shadow:0 8px 30px rgba(255,43,214,0.35);backdrop-filter:blur(6px);pointer-events:auto;";

    const textWrap = document.createElement("div");
    textWrap.innerHTML = "<strong style='color:#00E5FF;'>🛡️ Spectra Element Picker Active:</strong> Click any video or card to block it.";
    const sub = document.createElement("div");
    sub.style.cssText = "font-size:11px;color:#8B949E;margin-top:2px;";
    sub.textContent = "Hover over content to highlight. Press ESC to cancel.";
    textWrap.appendChild(sub);

    const cancelBtn = document.createElement("button");
    cancelBtn.style.cssText = "background:rgba(255,43,214,0.15)!important;border:1px solid #FF2BD6!important;color:#FF2BD6!important;padding:6px 14px!important;border-radius:4px!important;font-weight:700!important;font-size:11px!important;cursor:pointer!important;transition:all 0.15s ease!important;";
    cancelBtn.textContent = "✕ Cancel (ESC)";
    cancelBtn.addEventListener("click", stopElementPicker);

    pickerHud.appendChild(textWrap);
    pickerHud.appendChild(cancelBtn);
    document.documentElement.appendChild(pickerHud);

    document.addEventListener("mousemove", onPickerMouseMove, true);
    document.addEventListener("click", onPickerClick, true);
    document.addEventListener("keydown", onPickerKeyDown, true);
  }

  function stopElementPicker() {
    if (!isPickerActive) return;
    isPickerActive = false;
    if (pickerHud) {
      pickerHud.remove();
      pickerHud = null;
    }
    if (hoveredTarget) {
      hoveredTarget.style.outline = prevOutline;
      hoveredTarget.style.cursor = prevCursor;
      hoveredTarget = null;
    }
    document.removeEventListener("mousemove", onPickerMouseMove, true);
    document.removeEventListener("click", onPickerClick, true);
    document.removeEventListener("keydown", onPickerKeyDown, true);
  }

  function onPickerKeyDown(e) {
    if (e.key === "Escape") {
      stopElementPicker();
    }
  }

  function onPickerMouseMove(e) {
    if (!isPickerActive) return;
    const target = document.elementFromPoint(e.clientX, e.clientY);
    if (!target || target.closest("#spectra-picker-hud") || target.closest("#spectra-picker-toast")) return;

    if (hoveredTarget !== target) {
      if (hoveredTarget) {
        hoveredTarget.style.outline = prevOutline;
        hoveredTarget.style.cursor = prevCursor;
      }
      hoveredTarget = target;
      prevOutline = target.style.outline;
      prevCursor = target.style.cursor;
      target.style.outline = "3px dashed #FF2BD6";
      target.style.cursor = "crosshair";
    }
  }

  function onPickerClick(e) {
    if (!isPickerActive) return;
    const target = e.target;
    if (!target || target.closest("#spectra-picker-hud")) return;

    e.preventDefault();
    e.stopPropagation();

    let pickedUrl = "";
    let pickedTitle = "";
    let pickedVideoId = null;

    // 1. YouTube video card detection
    const ytCard = target.closest("ytd-rich-item-renderer, ytd-video-renderer, ytd-compact-video-renderer, ytd-grid-video-renderer");
    if (ytCard) {
      const link = ytCard.querySelector("a#thumbnail, a#video-title-link, a[href*='/watch?v=']");
      if (link && link.href) {
        pickedUrl = link.href;
        pickedVideoId = extractYouTubeVideoId(pickedUrl);
      }
      const titleEl = ytCard.querySelector("#video-title, #title");
      if (titleEl) pickedTitle = titleEl.textContent.trim();
    }

    // 2. Direct link or video element
    if (!pickedUrl) {
      const link = target.closest("a[href]");
      if (link && link.href) {
        pickedUrl = link.href;
        pickedVideoId = extractYouTubeVideoId(pickedUrl);
        pickedTitle = link.textContent.trim() || link.title;
      }
    }

    // 3. Iframe / embedded video
    if (!pickedUrl) {
      const iframe = target.closest("iframe[src]");
      if (iframe && iframe.src) {
        pickedUrl = iframe.src;
        pickedVideoId = extractYouTubeVideoId(pickedUrl);
      }
    }

    // 4. YouTube player on watch page
    if (!pickedUrl && isYouTubeHost && location.pathname.includes("/watch")) {
      pickedUrl = location.href;
      pickedVideoId = extractYouTubeVideoId(pickedUrl);
      pickedTitle = document.title;
    }

    // 5. Fallback
    if (!pickedUrl) {
      pickedUrl = location.href;
      pickedTitle = (target.tagName.toLowerCase()) + (target.id ? '#' + target.id : '');
    }

    const elementToAnimate = ytCard || target;
    stopElementPicker();

    // Visual disintegration
    elementToAnimate.style.transition = "all 0.4s ease";
    elementToAnimate.style.opacity = "0.2";
    elementToAnimate.style.filter = "grayscale(100%)";

    showPickerToast("🎯 Sending to SpectraNetworkManager: " + (pickedTitle || pickedUrl));

    if (typeof api !== "undefined" && api.runtime && api.runtime.sendMessage) {
      api.runtime.sendMessage({
        type: "element_picked",
        url: pickedUrl,
        title: pickedTitle,
        videoId: pickedVideoId,
        domain: location.hostname
      }, (res) => {
        if (res && res.autoApproved) {
          elementToAnimate.style.display = "none";
          showPickerToast("🛡️ Auto-Approved & Blocked: " + (pickedTitle || pickedUrl));
        } else {
          showPickerToast("⏳ Sent to SpectraNetworkManager Confirmation Queue");
        }
      });
    }
  }

  startObserver();
  injectMainWorldAdSkipper();
  setInterval(runGuardTick, 100);
})();
