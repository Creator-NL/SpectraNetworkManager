// Spectra Browser Guard - Content Script
(function() {
  // Check if current page is YouTube Shorts and blocked
  if (window.location.href.includes("/shorts/")) {
    injectBlockedOverlay("YouTube Shorts is blocked by Spectra Browser Guard.", window.location.href);
  }

  // Monitor DOM for blocked media elements or YouTube player errors
  const observer = new MutationObserver(() => {
    checkMediaElements();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  function checkMediaElements() {
    // Check for error states on HTML5 video elements (network errors or blocked media)
    const videos = document.querySelectorAll("video");
    videos.forEach(v => {
      if (v.error && v.error.code === MediaError.MEDIA_ERR_NETWORK && !v.dataset.spectraShielded) {
        v.dataset.spectraShielded = "true";
        injectMediaPlaceholder(v);
      }
    });

    // Check YouTube player container
    const ytPlayer = document.getElementById("movie_player") || document.querySelector(".html5-video-player");
    if (ytPlayer && ytPlayer.classList.contains("ytp-error") && !ytPlayer.dataset.spectraShielded) {
      ytPlayer.dataset.spectraShielded = "true";
      injectMediaPlaceholder(ytPlayer);
    }
  }

  function injectMediaPlaceholder(container) {
    const overlay = document.createElement("div");
    overlay.className = "spectra-media-blocked-overlay";
    overlay.innerHTML = `
      <div class="spectra-card">
        <div class="spectra-badge">🛡️ SPECTRA BROWSER GUARD</div>
        <div class="spectra-title">Video Playback Blocked</div>
        <div class="spectra-desc">Video stream delivery was blocked according to your Spectra network rules.</div>
        <button class="spectra-btn" id="spectraAllowBtn">Allow Playback Once</button>
      </div>
    `;

    overlay.querySelector("#spectraAllowBtn").addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "allow_once",
        urlPattern: "*://*.googlevideo.com/videoplayback*"
      }, (res) => {
        if (res && res.allowed) {
          overlay.remove();
          window.location.reload();
        }
      });
    });

    container.parentElement.style.position = "relative";
    container.parentElement.appendChild(overlay);
  }

  function injectBlockedOverlay(message, url) {
    const fullOverlay = document.createElement("div");
    fullOverlay.className = "spectra-full-blocked-overlay";
    fullOverlay.innerHTML = `
      <div class="spectra-card spectra-card-large">
        <div class="spectra-badge">🛡️ SPECTRA BROWSER GUARD</div>
        <div class="spectra-title">Shorts / Video Blocked</div>
        <div class="spectra-desc">${message}</div>
        <div style="margin-top: 16px;">
          <button class="spectra-btn" id="spectraBypassBtn">Allow Once</button>
          <a class="spectra-btn spectra-btn-sec" href="https://www.youtube.com">Back to YouTube Home</a>
        </div>
      </div>
    `;

    fullOverlay.querySelector("#spectraBypassBtn").addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "allow_once",
        urlPattern: "*://*.youtube.com/shorts/*"
      }, (res) => {
        if (res && res.allowed) {
          fullOverlay.remove();
          window.location.reload();
        }
      });
    });

    document.body.appendChild(fullOverlay);
  }
})();
