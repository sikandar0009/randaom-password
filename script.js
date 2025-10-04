(function () {
  'use strict';

  // DOM helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // Elements
  const lengthRange = $('#lengthRange');
  const lengthNumber = $('#lengthNumber');
  const includeLower = $('#includeLower');
  const includeUpper = $('#includeUpper');
  const includeNumbers = $('#includeNumbers');
  const includeSymbols = $('#includeSymbols');
  const excludeSimilar = $('#excludeSimilar');
  const requireEverySet = $('#requireEverySet');

  const passwordOutput = $('#passwordOutput');
  const toggleVisibilityBtn = $('#toggleVisibility');
  const copyBtn = $('#copyBtn');
  const regenBtn = $('#regenBtn');

  const strengthBar = $('.strength-bar');
  const strengthFill = $('.strength-fill');
  const strengthValue = $('#strengthValue');
  const entropyBits = $('#entropyBits');

  const copyToast = $('#copyToast');
  const validationMessage = $('#validationMessage');

  const themeToggle = $('#themeToggle');

  // Constants
  const STORAGE_KEYS = {
    PREFS: 'pwgen_prefs',
    HISTORY: 'pwgen_history',
    THEME: 'pwgen_theme',
  };

  const MAX_HISTORY = 20;

  const CHARSETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  };

  const SIMILAR = new Set('Il1O0oS5Z2B8G6'.split(''));

  // Utils
  function getSecureRandomInt(maxExclusive) {
    // returns uniform integer in [0, maxExclusive)
    if (maxExclusive <= 0) return 0;
    const cryptoObj = window.crypto || window.msCrypto;
    if (!cryptoObj || !cryptoObj.getRandomValues) {
      // Fallback (less secure) - should not happen in modern browsers
      return Math.floor(Math.random() * maxExclusive);
    }
    const maxUint32 = 0xffffffff;
    const threshold = maxUint32 - (maxUint32 % maxExclusive);
    const buf = new Uint32Array(1);
    let rnd;
    do {
      cryptoObj.getRandomValues(buf);
      rnd = buf[0];
    } while (rnd >= threshold);
    return rnd % maxExclusive;
  }

  function pickRandom(chars) {
    if (chars.length === 0) return '';
    const idx = getSecureRandomInt(chars.length);
    return chars[idx];
  }

  function sanitizeCharset(chars, shouldExcludeSimilar) {
    if (!shouldExcludeSimilar) return chars;
    return chars.split('').filter((c) => !SIMILAR.has(c)).join('');
  }

  function computeEntropyBits(length, poolSize) {
    if (length <= 0 || poolSize <= 1) return 0;
    // entropy = length * log2(poolSize)
    return length * Math.log2(poolSize);
  }

  function rateEntropy(bits) {
    if (bits < 28) return { label: 'Very weak', score: 10 };
    if (bits < 36) return { label: 'Weak', score: 25 };
    if (bits < 60) return { label: 'Fair', score: 45 };
    if (bits < 128) return { label: 'Strong', score: 75 };
    return { label: 'Excellent', score: 95 };
  }

  function getOptions() {
    return {
      length: clamp(parseInt(lengthNumber.value, 10) || 16, parseInt(lengthNumber.min, 10), parseInt(lengthNumber.max, 10)),
      lower: includeLower.checked,
      upper: includeUpper.checked,
      numbers: includeNumbers.checked,
      symbols: includeSymbols.checked,
      excludeSimilar: excludeSimilar.checked,
      requireEverySet: requireEverySet.checked,
    };
  }

  function clamp(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }

  function buildPool(opts) {
    const sets = [];
    if (opts.lower) sets.push(sanitizeCharset(CHARSETS.lower, opts.excludeSimilar));
    if (opts.upper) sets.push(sanitizeCharset(CHARSETS.upper, opts.excludeSimilar));
    if (opts.numbers) sets.push(sanitizeCharset(CHARSETS.numbers, opts.excludeSimilar));
    if (opts.symbols) sets.push(sanitizeCharset(CHARSETS.symbols, opts.excludeSimilar));

    const pool = sets.join('');
    return { pool, sets };
  }

  function validateOptions(opts, sets) {
    const numSets = sets.filter(Boolean).length;
    if (numSets === 0) {
      return 'Select at least one character set.';
    }
    if (opts.requireEverySet && opts.length < numSets) {
      return `Length must be ≥ number of selected sets (${numSets}).`;
    }
    return '';
  }

  function generatePassword(opts) {
    const { pool, sets } = buildPool(opts);
    const err = validateOptions(opts, sets);
    if (err) return { password: '', error: err, poolSize: pool.length };

    let passwordChars = [];

    if (opts.requireEverySet) {
      // Guarantee at least one from each selected set
      for (const set of sets) {
        if (set && set.length > 0) {
          passwordChars.push(pickRandom(set));
        }
      }
    }

    while (passwordChars.length < opts.length) {
      passwordChars.push(pickRandom(pool));
    }

    // Shuffle using Fisher-Yates with secure RNG
    for (let i = passwordChars.length - 1; i > 0; i--) {
      const j = getSecureRandomInt(i + 1);
      [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
    }

    const password = passwordChars.join('');
    return { password, error: '', poolSize: pool.length };
  }

  function setStrengthUI(bits) {
    const rating = rateEntropy(bits);
    const percent = Math.max(0, Math.min(100, Math.round(Math.min(bits, 120) / 120 * 100)));
    strengthFill.style.width = percent + '%';
    strengthBar.setAttribute('aria-valuenow', String(percent));
    strengthValue.textContent = rating.label;
    entropyBits.textContent = `${Math.round(bits)} bits`;
  }

  function savePrefs(opts) {
    try {
      localStorage.setItem(STORAGE_KEYS.PREFS, JSON.stringify(opts));
    } catch (_) {}
  }

  function loadPrefs() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.PREFS);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (_) { return null; }
  }

  function saveHistory(list) {
    try { localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(list)); } catch (_) {}
  }
  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.HISTORY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) { return []; }
  }

  function addToHistory(pw) {
    if (!pw) return;
    const now = new Date().toISOString();
    historyItems.unshift({ password: pw, createdAt: now });
    // Deduplicate identical adjacent entries
    const seen = new Set();
    const deduped = [];
    for (const item of historyItems) {
      if (seen.has(item.password)) continue;
      seen.add(item.password);
      deduped.push(item);
      if (deduped.length >= MAX_HISTORY) break;
    }
    historyItems = deduped;
    saveHistory(historyItems);
    renderHistory();
  }

  function formatTimestamp(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString();
  }

  function renderHistory() {
    const list = $('#historyList');
    list.innerHTML = '';
    if (historyItems.length === 0) {
      const empty = document.createElement('li');
      empty.className = 'history-item';
      empty.textContent = 'No history yet.';
      list.appendChild(empty);
      return;
    }

    for (const [index, item] of historyItems.entries()) {
      const li = document.createElement('li');
      li.className = 'history-item';

      const pw = document.createElement('input');
      pw.className = 'history-pass';
      pw.type = 'password';
      pw.readOnly = true;
      pw.value = item.password;
      pw.setAttribute('aria-label', `Generated password ${index + 1}`);

      const meta = document.createElement('span');
      meta.className = 'history-meta';
      meta.textContent = formatTimestamp(item.createdAt);

      const revealBtn = document.createElement('button');
      revealBtn.className = 'btn btn-ghost';
      revealBtn.type = 'button';
      revealBtn.textContent = 'Show';
      revealBtn.addEventListener('click', () => {
        const isPw = pw.type === 'password';
        pw.type = isPw ? 'text' : 'password';
        revealBtn.textContent = isPw ? 'Hide' : 'Show';
      });

      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn';
      copyBtn.type = 'button';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(item.password);
          showToast('Copied to clipboard');
        } catch (e) { showToast('Copy failed'); }
      });

      const right = document.createElement('div');
      right.style.display = 'flex';
      right.style.gap = '0.5rem';
      right.appendChild(revealBtn);
      right.appendChild(copyBtn);

      li.appendChild(pw);
      li.appendChild(meta);
      li.appendChild(right);

      list.appendChild(li);
    }
  }

  function showToast(message) {
    copyToast.textContent = message;
    copyToast.classList.add('show');
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => copyToast.classList.remove('show'), 1200);
  }

  function syncLengthInputs(fromRange) {
    if (fromRange) {
      lengthNumber.value = lengthRange.value;
    } else {
      lengthRange.value = String(clamp(parseInt(lengthNumber.value, 10) || 16, parseInt(lengthNumber.min, 10), parseInt(lengthNumber.max, 10)));
    }
  }

  function updateAll() {
    const opts = getOptions();
    savePrefs(opts);

    const { password, error, poolSize } = generatePassword(opts);

    if (error) {
      validationMessage.textContent = error;
      regenBtn.disabled = true;
      passwordOutput.value = '';
      setStrengthUI(0);
      return;
    }

    validationMessage.textContent = '';
    regenBtn.disabled = false;

    passwordOutput.value = password;

    const bits = computeEntropyBits(opts.length, poolSize);
    setStrengthUI(bits);

    addToHistory(password);
  }

  function regenerateOnly() {
    const opts = getOptions();
    const { password, error, poolSize } = generatePassword(opts);

    if (error) {
      validationMessage.textContent = error;
      regenBtn.disabled = true;
      passwordOutput.value = '';
      setStrengthUI(0);
      return;
    }

    validationMessage.textContent = '';
    regenBtn.disabled = false;

    passwordOutput.value = password;

    const bits = computeEntropyBits(opts.length, poolSize);
    setStrengthUI(bits);

    addToHistory(password);
  }

  function applyPrefs(prefs) {
    if (!prefs) return;
    lengthRange.value = String(prefs.length ?? 16);
    lengthNumber.value = String(prefs.length ?? 16);
    includeLower.checked = !!prefs.lower;
    includeUpper.checked = !!prefs.upper;
    includeNumbers.checked = !!prefs.numbers;
    includeSymbols.checked = !!prefs.symbols;
    excludeSimilar.checked = !!prefs.excludeSimilar;
    requireEverySet.checked = !!prefs.requireEverySet;
  }

  function initTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.THEME);
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
      const current = saved || (prefersDark.matches ? 'dark' : 'light');
      document.documentElement.setAttribute('data-theme', current);
      themeToggle.setAttribute('aria-pressed', String(current === 'dark'));
      themeToggle.addEventListener('click', () => {
        const now = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', now);
        themeToggle.setAttribute('aria-pressed', String(now === 'dark'));
        try { localStorage.setItem(STORAGE_KEYS.THEME, now); } catch (_) {}
      });
      prefersDark.addEventListener?.('change', (e) => {
        const saved = localStorage.getItem(STORAGE_KEYS.THEME);
        if (saved) return; // respect saved preference
        const now = e.matches ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', now);
        themeToggle.setAttribute('aria-pressed', String(now === 'dark'));
      });
    } catch (_) {}
  }

  function initEvents() {
    // Length sync
    lengthRange.addEventListener('input', () => { syncLengthInputs(true); regenerateOnly(); });
    lengthNumber.addEventListener('input', () => { syncLengthInputs(false); regenerateOnly(); });

    // Options
    [includeLower, includeUpper, includeNumbers, includeSymbols, excludeSimilar, requireEverySet]
      .forEach(el => el.addEventListener('change', updateAll));

    // Buttons
    regenBtn.addEventListener('click', regenerateOnly);

    toggleVisibilityBtn.addEventListener('click', () => {
      const isPassword = passwordOutput.type === 'password';
      passwordOutput.type = isPassword ? 'text' : 'password';
      toggleVisibilityBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      toggleVisibilityBtn.textContent = isPassword ? '🙈' : '👁';
    });

    copyBtn.addEventListener('click', async () => {
      const value = passwordOutput.value;
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        showToast('Copied to clipboard');
      } catch (e) {
        showToast('Copy failed');
      }
    });

    $('#clearHistoryBtn').addEventListener('click', () => {
      historyItems = [];
      saveHistory(historyItems);
      renderHistory();
    });
  }

  // State
  let historyItems = loadHistory();

  // Boot
  initTheme();
  applyPrefs(loadPrefs());
  renderHistory();
  updateAll();
})();
