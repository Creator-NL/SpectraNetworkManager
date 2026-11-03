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

    const vMatch = urlStr.match(/[?&]v=([a-zA-Z0-9_-]{8,})/);
    if (vMatch) return vMatch[1];
    return null;
  }

  // --- Pattern Matching Logic ---
  function patternMatchesUrl(pattern, targetUrl) {
    if (!pattern || !targetUrl) return false;
    const p = pattern.trim();
    const u = targetUrl.trim();

    // 1. Literal or clean substring match
    const cleanPattern = p.replace(/^\*:\/\/\*\./, "").replace(/^\*:\/\//, "").replace(/\*$/, "");
    if (cleanPattern.length > 3 && u.includes(cleanPattern)) {
      return true;
    }

    // 2. Wildcard to Regex conversion
    try {
      let regexStr = p
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*");

      if (!regexStr.startsWith(".*")) regexStr = ".*" + regexStr;
      if (!regexStr.endsWith(".*")) regexStr = regexStr + ".*";

      const rx = new RegExp("^" + regexStr + "$", "i");
      if (rx.test(u)) return true;
    } catch {}

    return false;
  }

  function findMatchingBlockRule(currentUrl) {
    if (!activeCustomRules || activeCustomRules.length === 0) return null;

    const currentVid = isYouTubeHost ? extractYouTubeVideoId(currentUrl) : null;

    for (const rule of activeCustomRules) {
      if (!rule || rule.action === "allow") continue;

      // Shorts overlay is handled exclusively by inspectShortsElements; skip here
      if (rule.id === "yt-shorts" || rule.id === "yt-video-stream") continue;

      // Check YouTube Video ID match
      if (isYouTubeHost && currentVid) {
        const ruleVid = extractYouTubeVideoId(rule.pattern);
        if (ruleVid && ruleVid === currentVid) {
          return rule;
        }
        if (rule.pattern && rule.pattern.includes(currentVid)) {
          return rule;
        }
      }

      // Check URL pattern match
      if (patternMatchesUrl(rule.pattern, currentUrl)) {
        return rule;
      }
    }

    return null;
  }

  // --- Enforce Blocking on Matched Rule ---
  function checkPageBlockRules(force = false) {
    const currentUrl = window.location.href;
    if (!force && currentUrl === lastCheckedUrl && currentBlockedRule) {
      haltActiveVideo();
      return;
    }
    lastCheckedUrl = currentUrl;

    const matchedRule = findMatchingBlockRule(currentUrl);

    if (matchedRule) {
      currentBlockedRule = matchedRule;
      if (isYouTubeHost) {
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
        if (!v.paused) v.pause();
        v.muted = true;
        v.currentTime = 0;
      } catch {}
    }
  }

  function blockYouTubeVideoPlayer(matchedRule) {
    haltActiveVideo();

    const player = document.querySelector("#movie_player, .html5-video-player, #player-container, ytd-watch-flexy #player");
    if (!player) return;

    let overlay = document.getElementById("spectra-yt-blocked-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "spectra-yt-blocked-overlay";
      overlay.className = "spectra-media-blocked-overlay spectra-custom-block";

      const icon = document.createElement("div");
      icon.className = "spectra-overlay-icon";
      icon.textContent = "🚫";

      const title = document.createElement("div");
      title.className = "spectra-overlay-title";
      title.style.color = "#FF2BD6";
      title.style.fontSize = "17px";
      title.textContent = "YOUTUBE VIDEO BLOCKED BY SPECTRA GUARD";

      const desc = document.createElement("div");
      desc.className = "spectra-overlay-desc";
      desc.innerHTML = `
        <div style="font-weight:600; color:#E6EDF3; margin-bottom:4px;">${matchedRule.title || "Custom Blocked Video"}</div>
        <code style="display:inline-block; background:#1C1936; border:1px solid #FF2BD6; color:#00E5FF; padding:3px 8px; border-radius:4px; font-size:11px; word-break:break-all;">${matchedRule.pattern}</code>
        <div style="margin-top:10px; font-size:11px; color:#8B949E;">This video matches an active block rule in SpectraNetworkManager Browser Guard.</div>
      `;

      overlay.appendChild(icon);
      overlay.appendChild(title);
      overlay.appendChild(desc);

      if (player.parentNode) {
        player.style.position = "relative";
        player.appendChild(overlay);
      }
    }
  }

  function blockEntireWebPage(matchedRule) {
    if (document.getElementById("spectra-full-page-block")) return;
    try { window.stop(); } catch {}

    const html = `
      <head>
        <meta charset="utf-8">
        <title>Blocked by Spectra Browser Guard</title>
        <style>
          body { background: #0B0F19; color: #E6EDF3; font-family: 'Segoe UI', system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .card { background: #121826; border: 2px solid #FF2BD6; border-radius: 10px; padding: 36px; max-width: 580px; text-align: center; box-shadow: 0 10px 40px rgba(255, 43, 214, 0.3); }
          .icon { font-size: 48px; margin-bottom: 14px; }
          h1 { color: #FF2BD6; font-size: 20px; margin: 0 0 12px; font-weight: 700; letter-spacing: 0.5px; }
          p { color: #8B949E; font-size: 13px; line-height: 1.5; margin: 8px 0; }
          .pattern { display: inline-block; background: #1C1936; border: 1px solid #FF2BD6; color: #00E5FF; padding: 6px 12px; border-radius: 6px; font-family: Consolas, monospace; font-size: 12px; margin: 14px 0; word-break: break-all; }
          .brand { margin-top: 24px; font-size: 11px; color: #00E5FF; font-weight: 600; letter-spacing: 1px; }
        </style>
      </head>
      <body id="spectra-full-page-block">
        <div class="card">
          <div class="icon">🚫</div>
          <h1>WEBPAGE BLOCKED BY SPECTRA BROWSER GUARD</h1>
          <p>Access to this page has been blocked by your Spectra Browser Guard security policy.</p>
          <div class="pattern">${matchedRule.pattern}</div>
          <p>To access this content, remove or uncheck the matching rule in SpectraNetworkManager ➔ Browser Guard.</p>
          <div class="brand">SPECTRA NETWORKMANAGER // BROWSER DEFENSE SYSTEM</div>
        </div>
      </body>
    `;
    document.documentElement.innerHTML = html;
  }

  function removeBlockOverlayIfExists() {
    const overlay = document.getElementById("spectra-yt-blocked-overlay");
    if (overlay) overlay.remove();
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

  window.addEventListener("yt-navigate-finish", onWatchNavigation);
  window.addEventListener("yt-page-data-updated", onWatchNavigation);
  window.addEventListener("popstate", onWatchNavigation);
  window.addEventListener("hashchange", onWatchNavigation);

  window.addEventListener("focus", () => {
    const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
    if (pendingAutoplay && isWatch && (Date.now() - lastNavTime < 10000)) {
      const v = document.querySelector("video");
      if (v && v.paused && !currentBlockedRule && !shouldBlockShorts()) {
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
          "button[aria-label*='Skip']",
          "button[aria-label*='overslaan']",
          ".ytp-ad-overlay-close-button"
        ];

        let adJustFinished = false;
        let navTime = Date.now();
        let pendingAutoplay = true;

        function markNav() {
          navTime = Date.now();
          pendingAutoplay = true;
          adJustFinished = false;
        }

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
          return false;
        }

        function handlePlayer() {
          const player = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
          if (!player) return;

          const adActive = isPlayerAd(player);

          if (adActive) {
            adJustFinished = true;

            // 1. YouTube internal player API - skip ad cleanly
            try {
              if (typeof player.skipAd === "function") player.skipAd();
            } catch(e) {}

            // 2. Dispatch trusted-like click on skip buttons
            for (const sel of SKIP_SELECTORS) {
              const btns = player.querySelectorAll(sel);
              for (const b of btns) {
                try {
                  b.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
                  b.click();
                } catch(e) {}
              }
            }

            // 3. Fast forward ad video ONLY while ad is showing
            const video = player.querySelector("video");
            if (video && isPlayerAd(player)) {
              video.muted = true;
              if (video.duration && !isNaN(video.duration) && isFinite(video.duration) && video.duration > 0.1) {
                video.currentTime = video.duration - 0.05;
              }
              try { video.playbackRate = 16; } catch(e) {}
            }
            return;
          }

          // NO ad is showing right now
          const video = player.querySelector("video");

          // Once video is actively playing past 0.3s, reset autoplay request
          if (video && !video.paused && video.currentTime > 0.3) {
            adJustFinished = false;
            pendingAutoplay = false;
            return;
          }

          // Auto-start if an ad was just finished, OR we navigated to a watch page within 4 seconds and the video is paused/unstarted
          const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
          const timeSinceNav = Date.now() - navTime;
          const shouldStart = (adJustFinished || (pendingAutoplay && timeSinceNav < 4000)) && isWatch;

          if (shouldStart && video && video.paused) {
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
    ".ytp-ad-skip-button-slot button",
    ".ytp-ad-skip-button-container button",
    ".ytp-ad-overlay-close-button",
    "button.ytp-ad-skip-button-modern",
    "button[id^='skip-button']",
    "button[aria-label*='Skip']",
    "button[aria-label*='overslaan']",
    ".ytp-ad-preview-container"
  ];

  function isPlayerAd(player) {
    if (!player) return false;
    if (player.classList.contains("ad-showing") || player.classList.contains("ad-interrupting")) return true;
    if (typeof player.getAdState === "function") {
      try {
        const s = player.getAdState();
        if (s === 1 || s === 2) return true;
      } catch(e) {}
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

  function neutralizeYouTubeAds() {
    if (!isYouTubeHost || !blockYouTubeAds) return;

    const player = document.querySelector("#movie_player, .html5-video-player");
    if (!player) return;

    const video = player.querySelector("video.html5-main-video") || player.querySelector("video");
    if (video) hookVideoEvents(video);

    if (!isPlayerAd(player)) {
      // Normal video playing! Restore original playback rate and mute state if needed
      if (wasMutedBeforeAd !== null) {
        if (video) {
          video.muted = wasMutedBeforeAd;
          if (video.playbackRate > 2) {
            video.playbackRate = userPlaybackRate || 1;
          }
          if (video.paused && !currentBlockedRule && !shouldBlockShorts()) {
            video.play().catch(() => {});
          }
        }
        wasMutedBeforeAd = null;
      }

      // Check if video is paused right after navigation
      const isWatch = location.pathname.includes("/watch") || location.pathname.includes("/shorts/");
      if (pendingAutoplay && isWatch && (Date.now() - lastNavTime < 4000)) {
        if (video && video.paused && !currentBlockedRule && !shouldBlockShorts()) {
          video.play().catch(() => {});
        }
      }

      if (video && !video.paused && video.currentTime > 0.3) {
        pendingAutoplay = false;
      }
      return;
    }

    // AD is showing!
    // 1. Click skip / overlay close buttons immediately
    for (const sel of SKIP_BUTTON_SELECTORS) {
      const btns = player.querySelectorAll(sel);
      for (const btn of btns) {
        try {
          btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
          btn.click();
        } catch {}
      }
    }

    // 2. Fast-forward AD video only
    if (video) {
      if (wasMutedBeforeAd === null) {
        wasMutedBeforeAd = video.muted;
        if (!video.paused && video.playbackRate > 0 && video.playbackRate <= 2) {
          userPlaybackRate = video.playbackRate;
        }
      }

      video.muted = true;

      if (Number.isFinite(video.duration) && video.duration > 0.1) {
        try {
          video.currentTime = video.duration - 0.05;
        } catch {}
      }
      try { video.playbackRate = 16; } catch {}

      for (const sel of SKIP_BUTTON_SELECTORS) {
        const btn = player.querySelector(sel);
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
    // When the user disables the Shorts rule, activeCustomRules will NOT contain 'yt-shorts'.
    if (activeCustomRules && activeCustomRules.length > 0) {
      const hasShortsRule = activeCustomRules.some(r => r.id === "yt-shorts" && r.action !== "allow");
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
        overlay.innerHTML = `
          <div class="spectra-overlay-icon">🛡️</div>
          <div class="spectra-overlay-title">SHORTS FEED BLOCKED BY SPECTRA GUARD</div>
          <div class="spectra-overlay-desc">YouTube Shorts feeds are blocked by your Spectra Browser Guard settings.</div>
        `;
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

      // Clean up any other non-custom overlays
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

  function runGuardTick() {
    syncAttributes();
    checkPageBlockRules(false);
    neutralizeYouTubeAds();
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
      inspectShortsElements();
    });
    observer.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  };

  startObserver();
  injectMainWorldAdSkipper();
  setInterval(runGuardTick, 100);
})();
