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
  window.addEventListener("yt-navigate-finish", () => checkPageBlockRules(true));
  window.addEventListener("yt-page-data-updated", () => checkPageBlockRules(true));
  window.addEventListener("popstate", () => checkPageBlockRules(true));
  window.addEventListener("hashchange", () => checkPageBlockRules(true));

  // Hook pushState / replaceState for dynamic client-side URL updates
  const origPush = history.pushState;
  history.pushState = function () {
    origPush.apply(this, arguments);
    setTimeout(() => checkPageBlockRules(true), 20);
  };
  const origReplace = history.replaceState;
  history.replaceState = function () {
    origReplace.apply(this, arguments);
    setTimeout(() => checkPageBlockRules(true), 20);
  };

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

    // 1. Click skip / overlay close buttons
    for (const sel of SKIP_BUTTON_SELECTORS) {
      const btns = document.querySelectorAll(sel);
      for (const btn of btns) {
        if (btn && typeof btn.click === "function") {
          try { btn.click(); } catch {}
        }
      }
    }

    // 2. Detect active pre-roll / mid-roll ad
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

      video.muted = true;

      if (Number.isFinite(video.duration) && video.duration > 0.5) {
        try {
          if (video.currentTime < video.duration - 0.1) {
            video.currentTime = video.duration;
          }
        } catch {}
      }

      try { video.playbackRate = 16; } catch {}

      for (const sel of SKIP_BUTTON_SELECTORS) {
        const btn = player.querySelector(sel);
        if (btn && typeof btn.click === "function") {
          try { btn.click(); } catch {}
        }
      }
    } else if (wasMutedBeforeAd !== null) {
      video.muted = wasMutedBeforeAd;
      if (video.playbackRate > 2) {
        video.playbackRate = userPlaybackRate || 1;
      }
      wasMutedBeforeAd = null;
    }
  }

  // ---- Blocked Shorts Overlay ----
  function inspectShortsElements() {
    if (blockYouTubeShorts && window.location.href.includes("/shorts/")) {
      const shortsContainer = document.querySelector("ytd-shorts, #shorts-container");
      if (shortsContainer && shortsContainer.dataset.spectraGuarded !== "true") {
        shortsContainer.dataset.spectraGuarded = "true";
        haltActiveVideo();
        const overlay = document.createElement("div");
        overlay.className = "spectra-media-blocked-overlay";
        overlay.innerHTML = `
          <div class="spectra-overlay-icon">🛡️</div>
          <div class="spectra-overlay-title">SHORTS FEED BLOCKED BY SPECTRA GUARD</div>
          <div class="spectra-overlay-desc">YouTube Shorts feeds are blocked by your Spectra Browser Guard settings.</div>
        `;
        if (shortsContainer.parentNode) {
          shortsContainer.style.display = "none";
          shortsContainer.parentNode.insertBefore(overlay, shortsContainer);
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
    const observer = new MutationObserver(() => {
      checkPageBlockRules(false);
      neutralizeYouTubeAds();
      inspectShortsElements();
    });
    observer.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  };

  startObserver();
  setInterval(runGuardTick, 250);
})();
