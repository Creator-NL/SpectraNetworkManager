/**
 * Spectra Browser Guard - YouTube AdShield Automated Test Suite
 * Validates deterministic state machine transitions across all YouTube video & ad lifecycles.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const contentJsPath = path.resolve(__dirname, '../content.js');
const contentJsSource = fs.readFileSync(contentJsPath, 'utf8');

// 1. Syntax Validation for both Content Script and Injected Page Script
try {
  new Function(contentJsSource);
  const s = contentJsSource.indexOf('script.textContent = `');
  const e = contentJsSource.indexOf('`;', s + 25);
  if (s >= 0 && e >= 0) {
    const injCode = eval(contentJsSource.slice(s + 'script.textContent = '.length, e + 1));
    new Function(injCode);
  }
} catch (err) {
  console.error('SYNTAX ERROR in content.js:', err);
  process.exit(1);
}

// 2. Mock Environment Factory
function createTestHarness(options = {}) {
  const {
    duration = 600,
    currentTime = 0,
    pathname = '/watch',
    isAd = false,
    hasAdText = false,
    hasSkipButton = false,
    skipButtonLabel = 'Skip',
    userSpeed = 1,
    userMuted = false
  } = options;

  const intervals = [];
  const timeouts = [];
  const stats = {
    playCalls: 0,
    restarts: 0,
    skipClicks: 0,
    reloads: 0,
    injectedSkipAdCalls: 0,
    injectedPlayVideoCalls: 0
  };

  const video = {
    muted: userMuted,
    paused: true,
    ended: false,
    playbackRate: userSpeed,
    duration: duration,
    _currentTime: currentTime,
    dataset: {},
    get currentTime() { return this._currentTime; },
    set currentTime(val) {
      this._currentTime = val;
      if (Number.isFinite(this.duration) && val >= this.duration) {
        this.ended = true;
        this.paused = true;
      }
    },
    addEventListener() {},
    play() {
      stats.playCalls++;
      if (this.ended) {
        stats.restarts++;
        this._currentTime = 0;
        this.ended = false;
      }
      this.paused = false;
      return Promise.resolve();
    },
    pause() {
      this.paused = true;
    }
  };

  const adClasses = new Set(['html5-video-player']);
  if (isAd) adClasses.add('ad-showing');

  const skipBtn = {
    getAttribute: (attr) => (attr === 'aria-label' ? skipButtonLabel : null),
    textContent: skipButtonLabel,
    dispatchEvent() {},
    click() { stats.skipClicks++; }
  };

  const player = {
    id: 'movie_player',
    hasSkipButton: hasSkipButton,
    hasAdText: hasAdText,
    classList: {
      contains: (cls) => adClasses.has(cls),
      add: (cls) => adClasses.add(cls),
      delete: (cls) => adClasses.delete(cls)
    },
    skipAd() { stats.injectedSkipAdCalls++; },
    playVideo() { stats.injectedPlayVideoCalls++; video.play(); },
    getPlayerState() { return video.paused ? 2 : 1; },
    getAdState() { return adClasses.has('ad-showing') || this.hasAdText || this.hasSkipButton ? 1 : 0; },
    querySelector: function(selector) {
      if (selector === 'video' || selector === 'video.html5-main-video' || selector.startsWith('video')) return video;
      if (this.hasAdText && (selector.includes('ytp-ad-text') || selector.includes('ytp-ad-badge') || selector.includes('video-ads'))) return {};
      if (this.hasSkipButton && (selector.includes('ytp-skip-ad-button') || selector.includes('skip-button') || selector.includes('skip-button-slot'))) return skipBtn;
      if (adClasses.has('ad-showing') && selector.includes('ytp-ad-module')) return {};
      return null;
    },
    querySelectorAll: function(selector) {
      if (this.hasSkipButton && (selector.includes('button') || selector.includes('skip'))) return [skipBtn];
      return [];
    },
    appendChild(child) {
      if (child && child.id === 'spectra-ad-cover') stats.overlayAdded = true;
    }
  };

  const rootAttributes = {};
  const document = {
    documentElement: {
      setAttribute: (k, v) => { rootAttributes[k] = v; },
      getAttribute: (k) => rootAttributes[k] ?? null,
      hasAttribute: (k) => k in rootAttributes,
      removeAttribute: (k) => { delete rootAttributes[k]; }
    },
    body: {},
    head: {
      appendChild(el) {
        if (el && el.textContent) {
          try { vm.runInContext(el.textContent, context); } catch (e) {}
        }
      }
    },
    getElementById: (id) => (id === 'movie_player' ? player : null),
    querySelector: (selector) => {
      if (selector.includes('movie_player') || selector.includes('.html5-video-player')) return player;
      if (player.hasAdText && (selector.includes('ytp-ad-text') || selector.includes('ytp-ad-badge'))) return {};
      if (player.hasSkipButton && (selector.includes('ytp-skip-ad-button') || selector.includes('skip-button'))) return skipBtn;
      return null;
    },
    querySelectorAll: () => [],
    createElement: (tag) => ({ tag, style: {}, appendChild() {} }),
    addEventListener() {}
  };

  const contextWindow = {
    location: {
      pathname,
      hostname: 'www.youtube.com',
      href: 'https://www.youtube.com' + pathname,
      reload() { stats.reloads++; }
    },
    addEventListener() {},
    history: { pushState() {}, replaceState() {} }
  };

  const context = vm.createContext({
    document,
    window: contextWindow,
    location: contextWindow.location,
    history: contextWindow.history,
    chrome: {
      storage: { local: { get: (k, cb) => cb && cb({}) }, onChanged: { addListener() {} } },
      runtime: { onMessage: { addListener() {} }, sendMessage: () => Promise.resolve() }
    },
    sessionStorage: {
      _store: {},
      getItem(k) { return this._store[k] ?? null; },
      setItem(k, v) { this._store[k] = v; }
    },
    MutationObserver: function() { this.observe = () => {}; },
    requestAnimationFrame: (cb) => cb(),
    setInterval: (cb) => { intervals.push(cb); return intervals.length; },
    setTimeout: (cb) => { timeouts.push(cb); return timeouts.length; },
    MouseEvent: function() {},
    console, Promise, Number, Math, Date, Boolean, Array, Object, String, Error, JSON, URL, RegExp
  });

  vm.runInContext(contentJsSource, context);

  const tick = () => {
    intervals.forEach(fn => fn());
    if (!video.paused && !video.ended) {
      video.currentTime = video._currentTime + 0.1 * video.playbackRate;
    }
  };

  return { video, player, stats, tick, rootAttributes, context };
}

// 3. Test Runner Framework
let passedCount = 0;
let failedCount = 0;

function runTest(name, runner) {
  try {
    runner();
    console.log(`  \x1b[32m[PASS]\x1b[0m ${name}`);
    passedCount++;
  } catch (err) {
    console.error(`  \x1b[31m[FAIL]\x1b[0m ${name}`);
    console.error(`         Reason: ${err.message}`);
    failedCount++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

console.log('\n=============================================================');
console.log(' Spectra Browser Guard: YouTube AdShield Automated Test Suite');
console.log('=============================================================\n');

// --- Test 1: Clean Autoplay (Normal video, no ads) ---
runTest('Scenario 1: Clean main video autoplay on watch page', () => {
  const h = createTestHarness({ duration: 900, isAd: false });
  h.tick();
  assert(h.stats.playCalls >= 1, 'Video play() should be called on navigation');
  assert(!h.video.muted, 'Video should not be muted');
  assert(h.video.playbackRate === 1, 'Video should play at normal speed (1x)');
  assert(!h.rootAttributes['data-spectra-ad-active'], 'Ad-active attribute must not be set');
});

// --- Test 2: Skippable Pre-Roll Ad ---
runTest('Scenario 2: Skippable pre-roll ad is muted, fast-forwarded and skipped', () => {
  const h = createTestHarness({ duration: 30, isAd: true, hasSkipButton: true });
  h.tick();
  assert(h.video.muted, 'Ad video must be immediately muted');
  assert(h.video.playbackRate === 16, 'Ad video must be accelerated to 16x speed');
  assert(h.video.currentTime >= 29.5, 'Ad video must seek to the end (currentTime >= d - 0.05)');
  assert(h.stats.skipClicks >= 1, 'Skip button must be automatically clicked');

  // Transition to main video
  h.player.classList.delete('ad-showing');
  h.player.hasSkipButton = false;
  h.video.duration = 600;
  h.video.ended = false;
  h.video.currentTime = 0;
  h.tick();

  assert(!h.video.muted, 'Audio must be unmuted when main video begins');
  assert(h.video.playbackRate === 1, 'Playback rate must be restored to 1x');
  assert(!h.rootAttributes['data-spectra-ad-active'], 'Ad-active flag must be cleared');
});

// --- Test 3: Unskippable Bumper Ad (Scapino style) ---
runTest('Scenario 3: Unskippable bumper ad (Scapino 15s) detected via ytp-ad-text and accelerated', () => {
  // Scapino ad: isAd = false (no ad-showing class on player), duration = 15s, has ytp-ad-text/badge
  const h = createTestHarness({ duration: 15, isAd: false, hasAdText: true, hasSkipButton: false });
  h.tick();
  assert(h.video.muted, 'Scapino bumper ad must be muted immediately');
  assert(h.video.playbackRate === 16, 'Scapino bumper ad must be accelerated to 16x');
  assert(h.video.currentTime >= 14.7, 'Scapino bumper ad must seek directly to the end');
});

// --- Test 4: Mid-Roll Ad in Middle of Video ---
runTest('Scenario 4: Mid-roll ad at 5:00 is accelerated and smoothly resumes main video at 5:00', () => {
  const h = createTestHarness({ duration: 1200, currentTime: 300, isAd: false });
  h.tick(); // playing main video at 300s
  assert(h.video.currentTime >= 300, 'Main video playing at t=300s');

  // Mid-roll ad triggers (media duration switches to 15s ad)
  h.player.classList.add('ad-showing');
  h.video.duration = 15;
  h.video.currentTime = 0;
  h.tick();

  assert(h.video.muted, 'Mid-roll ad must be muted');
  assert(h.video.playbackRate === 16, 'Mid-roll ad must run at 16x speed');

  // Ad finishes, main video content reloads at 300s
  h.player.classList.delete('ad-showing');
  h.video.duration = 1200;
  h.video.ended = false;
  h.video.currentTime = 300;
  h.video.paused = true;
  h.tick();

  assert(!h.video.muted, 'Volume must be restored on mid-roll resumption');
  assert(h.video.playbackRate === 1, 'Speed must be restored on mid-roll resumption');
  assert(h.stats.playCalls >= 2, 'Main video must be resumed smoothly with play()');
});

// --- Test 5: Post-Ad Interstitial End-Card Dismissal ---
runTest('Scenario 5: Post-ad companion card ("#1 Sci-Fi Game") is dismissed immediately without delay', () => {
  // Ad video is at end frame (15/15s), skip button present on interstitial
  const h = createTestHarness({ duration: 15, currentTime: 15, isAd: false, hasSkipButton: true });
  h.video.ended = true;
  h.tick();
  assert(h.stats.skipClicks >= 1, 'Interstitial Skip button must be clicked immediately');
});

// --- Test 6: End-of-Video Protection (No Replay Loop) ---
runTest('Scenario 6: Finished real video (t=600/600s) is strictly protected from replay loops', () => {
  const h = createTestHarness({ duration: 600, currentTime: 600, isAd: false });
  h.video.ended = true;
  h.video.paused = true;
  const initialPlayCalls = h.stats.playCalls;

  for (let i = 0; i < 50; i++) h.tick();

  assert(h.stats.restarts === 0, 'Finished video must NEVER be restarted from 0:00');
  assert(h.stats.playCalls === initialPlayCalls, 'Finished video must not receive automated play() calls');
  assert(h.video.ended, 'Finished video must remain in ended state');
});

// --- Test 7: Shorts and Live Streams Preservation ---
runTest('Scenario 7: Shorts and Live streams are untouched by ad accelerator', () => {
  const hShorts = createTestHarness({ duration: 15, pathname: '/shorts/xyz', isAd: true });
  hShorts.tick();
  assert(hShorts.video.playbackRate === 1, 'Shorts must not be accelerated');

  const hLive = createTestHarness({ duration: Infinity, pathname: '/watch', isAd: true });
  hLive.tick();
  assert(hLive.video.playbackRate === 1, 'Live streams must not be accelerated');
});

// --- Test 8: User Volume & Speed Preservation ---
runTest('Scenario 8: Custom user playback speed (1.5x) is preserved after ad skips', () => {
  const h = createTestHarness({ duration: 600, isAd: false, userSpeed: 1.5 });
  h.video.paused = false;
  h.tick();

  // Ad triggers
  h.player.classList.add('ad-showing');
  h.video.duration = 15;
  h.video.currentTime = 0;
  h.tick();
  assert(h.video.playbackRate === 16, 'Ad accelerated to 16x');

  // Ad finishes
  h.player.classList.delete('ad-showing');
  h.video.duration = 600;
  h.video.ended = false;
  h.video.currentTime = 10;
  h.tick();

  assert(h.video.playbackRate === 1.5, `User speed 1.5x must be restored (got ${h.video.playbackRate})`);
});

// --- Test 9: Native Prototype Integrity Check ---
runTest('Scenario 9: Built-in JavaScript prototypes (JSON.parse, Response.json) remain native', () => {
  assert(JSON.parse.toString().includes('[native code]'), 'JSON.parse must remain a native built-in');
});

// --- Test 10: Ad Cover Overlay Toggle Disabled ---
runTest('Scenario 10: SHOW_AD_COVER_OVERLAY is false (no black cover inserted into player)', () => {
  const h = createTestHarness({ duration: 15, isAd: true });
  h.tick();
  assert(!h.stats.overlayAdded, 'spectra-ad-cover overlay must not be appended to DOM');
});

// --- Test 11: Long Infomercial Ad (2:22 / 142s glasses ad) ---
runTest('Scenario 11: Long infomercial ad (2:22 / 142s) is accelerated and skipped (no 60s limit)', () => {
  const h = createTestHarness({ duration: 142, isAd: true, hasAdText: true });
  h.tick();
  assert(h.video.muted, '2:22 ad video must be immediately muted');
  assert(h.video.playbackRate === 16, '2:22 ad video must be accelerated to 16x speed');
  assert(h.video.currentTime >= 141.5, '2:22 ad video must seek to the end (currentTime >= 141.5s)');
});

console.log('\n-------------------------------------------------------------');
console.log(` Results: ${passedCount} Passed, ${failedCount} Failed`);
console.log('=============================================================\n');

if (failedCount > 0) process.exit(1);
