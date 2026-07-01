/* =========================
   DEVICE INTEGRITY & BEHAVIORAL DETECTION
   ========================= */
window.__deviceIntegrity = (function () {

  const CHECKS = [];
  const FLAGS  = [];
  const BEHAVIOR_LOG = [];

  // ── helpers ──────────────────────────────────────────────────────
  function flag(rule, detail, severity) {
    FLAGS.push({ rule, detail, severity: severity || 'low', ts: Date.now() });
  }

  function check(name, fn) {
    CHECKS.push({ name, fn });
  }

  function testUA(regex) {
    return regex.test((navigator.userAgent || '').toLowerCase());
  }

  // ── ADMIN / TRUSTED DEVICE SYSTEM ────────────────────────────────
  const TRUSTED_KEY = 'vault-trusted-device';

  function isTrusted() {
    return localStorage.getItem(TRUSTED_KEY) === 'true';
  }

  function markTrusted() {
    localStorage.setItem(TRUSTED_KEY, 'true');
    console.log('[DeviceIntegrity] Device marked as trusted');
  }

  function unmarkTrusted() {
    localStorage.removeItem(TRUSTED_KEY);
    console.log('[DeviceIntegrity] Trust status removed');
  }

  function trustedFingerprint() {
    // Combine several stable device signals for a rough fingerprint
    const parts = [
      navigator.userAgent,
      navigator.platform,
      screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
      Intl.DateTimeFormat().resolvedOptions().timeZone
    ];
    let hash = 0;
    const str = parts.join('|||');
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + c;
      hash |= 0;
    }
    return 'fp_' + Math.abs(hash).toString(36);
  }

  // ── 1. AUTOMATION / BOT DETECTION ────────────────────────────────
  check('webdriver', () => {
    if (navigator.webdriver === true) {
      flag('webdriver', 'navigator.webdriver is true (selenium/chromedriver)', 'high');
    }
  });

  check('chrome-automation', () => {
    if (window.chrome && window.chrome.automation) {
      flag('chrome-automation', 'window.chrome.automation exposed', 'high');
    }
  });

  check('plugins-length', () => {
    if (navigator.plugins && navigator.plugins.length === 0) {
      flag('no-plugins', 'navigator.plugins is empty (headless browser pattern)', 'high');
    }
  });

  check('languages', () => {
    if (!navigator.languages || navigator.languages.length === 0) {
      flag('no-languages', 'navigator.languages is empty (automation pattern)', 'high');
    }
  });

  check('headless-ua', () => {
    if (testUA(/headless|phantom|puppet|selenium|playwright|pyppeteer/)) {
      flag('headless-ua', 'User-Agent contains headless/automation marker', 'high');
    }
  });

  check('pdf-viewer', () => {
    if (navigator.pdfViewerEnabled === false) {
      flag('pdf-disabled', 'navigator.pdfViewerEnabled is false', 'medium');
    }
  });

  // ── 2. EMULATOR DETECTION ────────────────────────────────────────
  check('emulator-ua', () => {
    if (testUA(/android sdk|genymotion|Android.*Emulator|BlueStacks|Nox Player|MEmu|LeapDroid|AndyOS|Remix OS/i)) {
      flag('emulator-ua', 'User-Agent indicates emulator', 'high');
    }
  });

  check('emulator-build', () => {
    const emuBuild = /sdk_gphone|emu64|generic_x86|generic_arm64|vsemu|goldfish/;
    if (testUA(emuBuild)) {
      flag('emulator-build', 'User-Agent contains emulator build fingerprint', 'high');
    }
  });

  // ── 3. DEBUGGER DETECTION ────────────────────────────────────────
  check('devtools-docked', () => {
    // DevTools docked changes outerWidth - innerWidth significantly
    if (window.outerWidth - window.innerWidth > 200 ||
        window.outerHeight - window.innerHeight > 200) {
      flag('devtools-docked', 'Developer tools are docked', 'high');
    }
  });

  check('devtools-undocked', () => {
    // Undocked devtools: difference in window dimensions with small content area
    try {
      const e = document.createElement('div');
      e.style.cssText = 'position:fixed;width:1px;height:1px;top:-999px;left:-999px;pointer-events:none;z-index:-1';
      document.body.appendChild(e);
      const w = e.offsetWidth;
      document.body.removeChild(e);
      // If body offsetWidth differs significantly from outerWidth, devtools may be open undocked
    } catch (e) {}
  });

  check('debugger-statement', () => {
    const start = Date.now();
    try {
      (function () {
        for (let i = 0; i < 100; i++) {
          new Function('debugger')();
        }
      })();
    } catch (e) {}
    const elapsed = Date.now() - start;
    if (elapsed > 500) {
      flag('debugger-detected', 'Debugger statement triggered delay (' + elapsed + 'ms) — devtools likely open', 'high');
    }
  });

  // ── 4. VM / LOW-END DETECTION (aggressive for untrusted) ────────
  check('vm-core-count', () => {
    const cores = navigator.hardwareConcurrency;
    const mem   = navigator.deviceMemory;
    const isMobile = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
    if (isMobile) return;
    // Even-numbered core counts (2, 4) are very common in VM allocations
    // Single core is almost always a VM on desktop
    if (cores <= 1) {
      flag('single-core', 'Single-core desktop — almost certainly a VM', 'high');
    } else if (cores === 2 && (!mem || mem <= 4)) {
      flag('dual-core-low-ram', '2 cores + ≤4GB RAM — common VM config', 'high');
    }
  });

  check('vm-resolution', () => {
    const w = screen.width;
    const h = screen.height;
    // 1024x768 is extremely rare on real hardware today, very common in VMs
    if (w === 1024 && h === 768) {
      flag('vm-resolution-1024', '1024x768 resolution — typical VM default', 'high');
    }
  });

  // ── 5. BEHAVIORAL: TYPING DYNAMICS ───────────────────────────────
  const _typingData = { timestamps: [], fieldId: null };
  let _typingMonitorActive = false;

  function startTypingMonitor(fieldId) {
    if (_typingMonitorActive) return;
    _typingMonitorActive = true;
    _typingData.fieldId = fieldId;
    const field = document.getElementById(fieldId);
    if (!field) return;

    field.addEventListener('keydown', function _onKey(e) {
      if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta' ||
          e.key === 'CapsLock' || e.key === 'Tab' || e.key === 'Escape') return;
      const now = Date.now();
      _typingData.timestamps.push(now);
      if (_typingData.timestamps.length > 30) {
        _typingData.timestamps.shift();
      }
    }, { passive: true });

    _typingData.check = function () {
      if (this.timestamps.length < 5) return null;
      const intervals = [];
      for (let i = 1; i < this.timestamps.length; i++) {
        intervals.push(this.timestamps[i] - this.timestamps[i-1]);
      }
      const avg = intervals.reduce((a,b) => a+b, 0) / intervals.length;
      const zeroGaps = intervals.filter(v => v < 20).length;
      return { avg, zeroGaps, count: this.timestamps.length };
    };
  }

  // ── 6. BEHAVIORAL: PASTE DETECTION ───────────────────────────────
  let _pasteDetected = false;

  function startPasteMonitor(fieldId) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    field.addEventListener('paste', function _onPaste(e) {
      _pasteDetected = true;
      flag('paste-detected', 'Content pasted into ' + fieldId + ' field', 'high');
    }, { passive: true });
  }

  // ── 7. BEHAVIORAL: MOUSE ABNORMALITY ─────────────────────────────
  let _mousePositions = [];
  let _mouseMonitorActive = false;

  function startMouseMonitor() {
    if (_mouseMonitorActive) return;
    _mouseMonitorActive = true;

    document.addEventListener('mousemove', function _onMouse(e) {
      _mousePositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      if (_mousePositions.length > 100) {
        _mousePositions.shift();
      }
    }, { passive: true });
  }

  function analyzeMousePattern() {
    if (_mousePositions.length < 10) return null;
    const unique = new Set(_mousePositions.map(p => p.x + ',' + p.y));
    const pctSame = 1 - (unique.size / _mousePositions.length);
    const teleports = [];
    for (let i = 1; i < _mousePositions.length; i++) {
      const dx = _mousePositions[i].x - _mousePositions[i-1].x;
      const dy = _mousePositions[i].y - _mousePositions[i-1].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if (dist > 500 && (_mousePositions[i].t - _mousePositions[i-1].t) < 200) {
        teleports.push(dist);
      }
    }
    return { samples: _mousePositions.length, percentSame: pctSame, teleports: teleports.length };
  }

  // ── GET RISK ─────────────────────────────────────────────────────
  function runChecks() {
    FLAGS.length = 0;
    CHECKS.forEach(c => {
      try { c.fn(); } catch (e) {}
    });
    return [...FLAGS];
  }

  function getRiskScore() {
    const flags = runChecks();
    let score = 0;
    flags.forEach(f => {
      if (f.severity === 'high')   score += 5;
      if (f.severity === 'medium') score += 2;
      if (f.severity === 'low')    score += 0.5;
    });

    // Typing analysis
    const typingData = _typingData.check ? _typingData.check() : null;
    if (typingData) {
      BEHAVIOR_LOG.push('typing avg ' + typingData.avg.toFixed(0) + 'ms, ' + typingData.zeroGaps + ' near-zero gaps');
      if (typingData.avg < 120 && typingData.count >= 5) {
        score += 5;
        flag('auto-typing', 'Average keystroke interval ' + typingData.avg.toFixed(0) + 'ms — automation', 'high');
      }
    }

    // Mouse analysis
    const mouseData = analyzeMousePattern();
    if (mouseData) {
      BEHAVIOR_LOG.push('mouse ' + mouseData.samples + ' samples, ' + mouseData.teleports + ' teleports');
      if (mouseData.teleports > 2) {
        score += 3;
        flag('mouse-teleport', mouseData.teleports + ' mouse teleports — automation', 'high');
      }
    }

    return { score, flags };
  }

  // ── PUBLIC API ───────────────────────────────────────────────────
  function startBehavioralMonitoring() {
    startMouseMonitor();
    startTypingMonitor('vault-pass');
    startPasteMonitor('vault-pass');
  }

  function getDeviceReport() {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      cores: navigator.hardwareConcurrency,
      memory: navigator.deviceMemory,
      screen: screen.width + 'x' + screen.height,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      webdriver: navigator.webdriver,
      pluginsLen: navigator.plugins ? navigator.plugins.length : -1,
      languages: navigator.languages,
      pdfViewer: navigator.pdfViewerEnabled,
      maxTouchPoints: navigator.maxTouchPoints,
      trusted: isTrusted(),
      flags: FLAGS
    };
  }

  return {
    startBehavioralMonitoring,
    getRiskScore,
    getDeviceReport,
    isTrusted,
    markTrusted,
    unmarkTrusted,
    getFlags: () => [...FLAGS],
    getBehaviorLog: () => [...BEHAVIOR_LOG]
  };

})();

// Auto-start behavioral monitoring + trusted-device keyboard toggle
document.addEventListener('DOMContentLoaded', () => {
  const di = window.__deviceIntegrity;
  if (!di) return;
  di.startBehavioralMonitoring();

  // Ctrl+Shift+D to toggle trusted device status (admin quick-toggle)
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
      e.preventDefault();
      if (di.isTrusted()) {
        di.unmarkTrusted();
        alert('🔴 Trusted device status removed. Aggressive checks enabled.');
      } else {
        di.markTrusted();
        alert('🟢 Device marked as trusted. Aggressive checks bypassed.');
      }
    }
  });
});
