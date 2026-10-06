// ========== APP VERSION (display label only) ==========
  // Shown in the bottom-right corner badge (see #version-badge in the HTML
  // below) so you can eyeball what build is actually loaded in the browser,
  // even on the lock screen before unlocking. This is just a label baked
  // into this file at deploy time — it does NOT control caching and has no
  // effect on what the Service Worker serves.
  // Bump CACHE_VERSION in sw.js too when you bump this (they live in
  // different files and don't sync automatically) — sw.js has a matching
  // reminder comment pointing back here.
  const APP_VERSION = 'v1.2.9';
  const APP_VERSION_DATE = '2026-10-06';
  document.getElementById('version-badge').textContent = `${APP_VERSION} · ${APP_VERSION_DATE}`;

  // ========== DB SETUP ==========
  const db = new Dexie('BudgetReferenceTablesDB');
  db.version(1).stores({
    fixedExpenses: '++id, category, item, monthlyAmt, freq, note, dueDate',
    insurancePolicies: '++id, year, policyName, amount, note'
  });
  db.version(2).stores({
    fixedExpenses: '++id, category, item, monthlyAmt, freq, note, dueDate',
    insurancePolicies: '++id, year, policyName, amount, note', // kept for migration only, superseded below
    policies: '++id, name, note',
    policyRanges: '++id, policyId, fromYear, toYear, amount, note'
  }).upgrade(async tx => {
    // Migrate old "one row per policy per year" rows into grouped policies + year-range periods.
    const oldRows = await tx.table('insurancePolicies').toArray();
    const byName = {};
    oldRows.forEach(r => {
      const name = r.policyName || '';
      if (!byName[name]) byName[name] = [];
      byName[name].push({ year: r.year || 0, amount: r.amount || 0, note: r.note || '' });
    });
    for (const name of Object.keys(byName)) {
      const rows = byName[name].sort((a,b) => a.year - b.year);
      const policyId = await tx.table('policies').add({ name, note:'' });
      // merge consecutive years with the same amount into a single range
      let i = 0;
      while (i < rows.length) {
        let j = i;
        while (j + 1 < rows.length && rows[j+1].year === rows[j].year + 1 && rows[j+1].amount === rows[i].amount) j++;
        await tx.table('policyRanges').add({
          policyId, fromYear: rows[i].year, toYear: rows[j].year, amount: rows[i].amount, note: rows[i].note || ''
        });
        i = j + 1;
      }
    }
    // The old rows are now fully represented in policies/policyRanges — clear
    // them out instead of leaving them behind. Otherwise this plaintext copy
    // survives indefinitely, including after the user later enables
    // encryption (insurancePolicies is intentionally not part of ENC_TABLES,
    // since nothing should still be writing to it after this migration).
    await tx.table('insurancePolicies').clear();
  });
  db.version(3).stores({
    fixedExpenses: '++id, category, item, monthlyAmt, freq, note, dueDate',
    insurancePolicies: '++id, year, policyName, amount, note',
    policies: '++id, name, note',
    policyRanges: '++id, policyId, fromYear, toYear, amount, note',
    paidMarks: '++id, policyId, year'
  });
  // v4 — adds Income Forecast (what-if income scenarios) and Multi-Year
  // Planner (staged multi-account cashflow projection). Both are fully
  // manual-entry: unlike the Wealth Planner app they're modeled after,
  // this tool has no investment-fund or real-estate modules to pull
  // numbers from, so every figure here is typed in directly.
  db.version(4).stores({
    fixedExpenses: '++id, category, item, monthlyAmt, freq, note, dueDate',
    insurancePolicies: '++id, year, policyName, amount, note',
    policies: '++id, name, note',
    policyRanges: '++id, policyId, fromYear, toYear, amount, note',
    paidMarks: '++id, policyId, year',
    incomeForecasts: '++id, name',
    forecastLines: '++id, forecastId, kind',
    mypPlans: '++id, name',
    mypFunds: '++id, planId',
    mypFundRules: '++id, fundId',
    mypIncomeCategories: '++id, planId',
    mypIncomeRanges: '++id, categoryId',
    mypExpenseCategories: '++id, planId',
    mypExpenseRanges: '++id, categoryId',
    mypBaselines: '++id, planId',
    mypBaselineValues: '++id, baselineId',
    mypActuals: '++id, planId, year',
    mypSavedForecasts: '++id, planId'
  });

  // v5 — encMeta: plain (non-secret) copy of the encryption salt / iteration
  // count / canary, so a localStorage-only wipe cannot orphan encrypted rows.
  db.version(5).stores({ encMeta: 'key' });

  let pendingImportData = null;
  let pendingEncryptedImport = null; // raw {salt, enc} payload from a picked file, awaiting its passcode

  // ========== ENCRYPTION (optional — off by default) ==========
  // Same pattern as the main Wealth Planner app: passphrase is never stored;
  // it derives an in-memory AES-GCM key (PBKDF2, 250,000 iterations). Per
  // table, a small set of structural fields stay plaintext (id, and the
  // policyId foreign key used in a Dexie .where().equals() query) — everything
  // else is bundled into one JSON blob and encrypted under a single `_enc` field.
  let encryptionKey = null; // CryptoKey | null — in-memory only, never persisted
  const ENC_CANARY_PLAINTEXT = 'budgetref-encryption-canary-v1';
  // PBKDF2 iteration count used when NEW encryption is enabled (raised from
  // the original 250,000 to track current OWASP guidance for PBKDF2-SHA256).
  // The count actually used is stored alongside the salt (see
  // 'budgetref-encryption-iterations' below / the `iterations` field on
  // encrypted exports) and passed explicitly into deriveEncryptionKey() on
  // every unlock/disable/import — never re-derived from this constant alone.
  // That's what lets this go up in a later version without locking existing
  // users out: their data stays keyed to whatever count it was *originally*
  // encrypted with. PBKDF2_ITERATIONS_LEGACY_DEFAULT is only the fallback for
  // data encrypted before this constant existed (nothing stored yet).
  const PBKDF2_ITERATIONS = 600000;
  const PBKDF2_ITERATIONS_LEGACY_DEFAULT = 250000;
  const PLAIN_FIELDS = {
    fixedExpenses: ['id'],
    policies: ['id'],
    policyRanges: ['id', 'policyId'],
    // paidMarks intentionally excluded — it holds no sensitive content
    // (just a policyId + year linkage), so it's never encrypted.
    incomeForecasts: ['id'],
    forecastLines: ['id', 'forecastId'],
    mypPlans: ['id'],
    mypFunds: ['id', 'planId'],
    mypFundRules: ['id', 'fundId'],
    mypIncomeCategories: ['id', 'planId'],
    mypIncomeRanges: ['id', 'categoryId'],
    mypExpenseCategories: ['id', 'planId'],
    mypExpenseRanges: ['id', 'categoryId'],
    mypBaselines: ['id', 'planId'],
    mypBaselineValues: ['id', 'baselineId'],
    // both planId and year kept plain: saveActualResult queries by year
    // directly, deletePlan cascades query by planId directly
    mypActuals: ['id', 'planId', 'year'],
    mypSavedForecasts: ['id', 'planId']
  };

  function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach(b => { binary += String.fromCharCode(b); });
    return btoa(binary);
  }
  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function deriveEncryptionKey(passphrase, saltB64, iterations) {
    const salt = saltB64 ? base64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    const iters = iterations || PBKDF2_ITERATIONS; // only used when generating a brand-new salt; every other caller passes the stored count explicitly
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return { key, saltB64: bytesToBase64(salt), iterations: iters };
  }

  // AAD (additional authenticated data) binds a record's ciphertext to its own
  // table + id, so a blob copied onto another row or table fails to decrypt.
  // v:2 blobs carry the binding; older blobs (no v) decrypt without it and are
  // upgraded by normalizeEncryptedRows() at the next unlock.
  function rowAad(table, id) { return 'budgetref:' + table + ':' + id; }
  async function encryptValue(key, plainValue, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const data = enc.encode(JSON.stringify(plainValue));
    const params = { name: 'AES-GCM', iv };
    if (aad) params.additionalData = enc.encode(aad);
    const cipherBuf = await crypto.subtle.encrypt(params, key, data);
    const out = { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(cipherBuf)) };
    if (aad) out.v = 2;
    return out;
  }
  async function decryptValue(key, encShape, aad) {
    const iv = base64ToBytes(encShape.iv);
    const data = base64ToBytes(encShape.data);
    const params = { name: 'AES-GCM', iv };
    if (encShape.v === 2) {
      if (!aad) throw new Error('Record binding missing');
      params.additionalData = new TextEncoder().encode(aad);
    }
    const plainBuf = await crypto.subtle.decrypt(params, key, data);
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  async function encryptRecord(table, obj) {
    if (!encryptionKey) return obj;
    const plainKeys = PLAIN_FIELDS[table] || ['id'];
    const plainPart = {};
    const secretPart = {};
    Object.keys(obj).forEach(k => {
      if (plainKeys.includes(k)) plainPart[k] = obj[k];
      else secretPart[k] = obj[k];
    });
    plainPart._enc = await encryptValue(encryptionKey, secretPart, obj.id != null ? rowAad(table, obj.id) : null);
    return plainPart;
  }
  async function decryptRecord(row, table) {
    if (!row || !row._enc) return row;
    if (!encryptionKey) throw new Error('Data is encrypted but no key is loaded — unlock first.');
    const secretPart = await decryptValue(encryptionKey, row._enc, rowAad(table, row.id));
    const { _enc, ...plainPart } = row;
    return Object.assign({}, plainPart, secretPart);
  }

  async function encGetAll(table) {
    const rows = await db[table].toArray();
    return Promise.all(rows.map((r) => decryptRecord(r, table)));
  }
  async function encGet(table, id) {
    const row = await db[table].get(id);
    return row ? decryptRecord(row, table) : row;
  }
  async function encAdd(table, obj) {
    if (isWriteLocked()) throw new Error(LOCKED_WRITE_ERROR);
    if (!encryptionKey) return db[table].add(obj);
    // The AAD needs the row id, which only exists after the insert: first add a
    // shell holding just the plain linking fields (no secret content), then
    // overwrite it with the encrypted record. A failure removes the shell.
    const shell = {};
    (PLAIN_FIELDS[table] || ['id']).forEach((k) => { if (k !== 'id' && k in obj) shell[k] = obj[k]; });
    const id = await db[table].add(shell);
    try {
      await db[table].put(await encryptRecord(table, { ...obj, id }));
    } catch (e) {
      await db[table].delete(id).catch(() => {});
      throw e;
    }
    return id;
  }
  // Brings every row to the current format: plain rows (interrupted enable) and
  // legacy un-bound blobs get encrypted/re-encrypted with the AAD binding.
  // Safe to re-run; each row is independent and readable in either state.
  async function normalizeEncryptedRows() {
    if (!encryptionKey) return;
    for (const table of ENC_TABLES) {
      const rows = await db[table].toArray();
      for (const row of rows) {
        if (row._enc && row._enc.v === 2) continue;
        const plain = await decryptRecord(row, table);
        await db[table].put(await encryptRecord(table, plain));
      }
    }
  }
  async function encUpdate(table, id, changes) {
    if (isWriteLocked()) throw new Error(LOCKED_WRITE_ERROR);
    if (!encryptionKey) return db[table].update(id, changes);
    const existing = await encGet(table, id);
    const merged = Object.assign({}, existing, changes);
    const encoded = await encryptRecord(table, merged);
    return db[table].update(id, encoded);
  }

  const ENC_TABLES = ['fixedExpenses', 'policies', 'policyRanges',
    'incomeForecasts', 'forecastLines',
    'mypPlans', 'mypFunds', 'mypFundRules', 'mypIncomeCategories', 'mypIncomeRanges',
    'mypExpenseCategories', 'mypExpenseRanges', 'mypBaselines', 'mypBaselineValues',
    'mypActuals', 'mypSavedForecasts'];

  // Rejects absurd stored/imported iteration counts (tampering, corruption): out of range -> legacy default.
  function safeIterations(v) {
    const n = parseInt(v, 10);
    return Number.isInteger(n) && n >= 100000 && n <= 5000000 ? n : PBKDF2_ITERATIONS_LEGACY_DEFAULT;
  }
  function getStoredIterations() {
    const stored = localStorage.getItem('budgetref-encryption-iterations');
    return stored ? safeIterations(stored) : PBKDF2_ITERATIONS_LEGACY_DEFAULT;
  }

  function isEncryptionEnabled() {
    try { return localStorage.getItem('budgetref-encryption-enabled') === 'true'; } catch (e) { return false; }
  }

  // The "enabled but no key loaded" gray zone — freshly loaded page before
  // unlocking, or after lockNow()/auto-lock/tab-close. Anything that writes
  // to an encrypted (or policyId-linked) table must treat this as read-only.
  // Defined once here so every write guard below checks the same thing,
  // instead of each call site (encAdd, encUpdate, confirmImport,
  // deleteFixedRow, ...) re-deriving it and risking getting it wrong.
  function isWriteLocked() {
    return isEncryptionEnabled() && !encryptionKey;
  }

  // Centralize the guard at the Dexie layer rather than per call site: this
  // fires on every add/put/update/delete against these tables, whether it
  // goes through encAdd()/encUpdate() or hits db[table] directly (e.g.
  // deleteFixedRow(), confirmImport()'s db.fixedExpenses.clear()). That way
  // no future write path can silently persist plaintext (or delete data)
  // while locked just by forgetting to check isWriteLocked() itself.
  const LOCKED_WRITE_ERROR = 'LOCKED_WRITE: cannot write while encryption is enabled but locked';
  [...ENC_TABLES, 'paidMarks'].forEach((table) => {
    db[table].hook('creating', () => { if (isWriteLocked()) throw new Error(LOCKED_WRITE_ERROR); });
    db[table].hook('updating', () => { if (isWriteLocked()) throw new Error(LOCKED_WRITE_ERROR); });
    db[table].hook('deleting', () => { if (isWriteLocked()) throw new Error(LOCKED_WRITE_ERROR); });
  });

  // Safety net: there shouldn't be a UI path that reaches a write while
  // locked (the lock overlay hides .container), and the hooks above make
  // every write path fail safe regardless — but if some future call site
  // still fires one, surface it the same way a normal locked interaction
  // would instead of leaving it as a silent console error.
  window.addEventListener('unhandledrejection', (event) => {
    if (event.reason && String(event.reason.message || event.reason).includes('LOCKED_WRITE')) {
      event.preventDefault();
      showToast('🔒 Locked — unlock before making changes');
      if (isEncryptionEnabled()) showUnlockOverlay();
    }
  });

  function updateEncNavBtn() {
    const btn = document.getElementById('enc-nav-btn');
    if (btn) btn.innerHTML = isEncryptionEnabled()
      ? '<i class="fas fa-lock"></i> Encryption: On'
      : '<i class="fas fa-lock-open"></i> Encryption: Off';
    const lockBtn = document.getElementById('lock-now-btn');
    if (lockBtn) lockBtn.classList.toggle('hidden-btn', !isEncryptionEnabled());
    setupAutoLock();
  }

  const AUTO_LOCK_IDLE_MS = 5 * 60 * 1000;
  let autoLockTimer = null;
  let autoLockListenersAttached = false;
  let lockingInProgress = false;
  // Remove decrypted content from the page, not just hide it behind the overlay.
  function clearSensitiveDom() {
    if (mypChart) { mypChart.destroy(); mypChart = null; }
    mypForecastData = [];
    pendingImportData = null;
    pendingEncryptedImport = null;
    ['fixed-tbody','fixed-report-container','policies-container','ins-summary-grid','forecasts-container',
     'myp-funds-tbody','myp-rules-tbody','myp-income-container','myp-expense-container',
     'mypSummaryCards','mypSnapshotCards','mypSnapshotYear','mypForecastTableHead','mypForecastTableBody',
     'mypBaselineTableHead','mypBaselineTableBody','mypPlanSelect','category-datalist'
    ].forEach((id) => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
    const wrap = document.getElementById('mypChartWrap'); if (wrap) wrap.style.display = 'none';
    document.querySelectorAll('.container input, .container textarea').forEach((el) => {
      if (el.type !== 'file') el.value = '';
    });
  }
  async function lockNow() {
    if (!isEncryptionEnabled() || lockingInProgress) return;
    lockingInProgress = true;
    clearTimeout(autoLockTimer);
    document.getElementById('unlock-passcode').value = '';
    document.getElementById('unlock-status').textContent = '';
    showUnlockOverlay(); // hide the UI immediately...
    try { await flushPendingSaves(); } catch (e) { /* allSettled never rejects */ }
    // ...then, with in-flight edits saved, drop the key and the decrypted DOM.
    encryptionKey = null;
    clearSensitiveDom();
    lockingInProgress = false;
  }
  function resetAutoLockTimer() {
    if (!isEncryptionEnabled() || encryptionKey === null) return;
    clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(() => lockNow(), AUTO_LOCK_IDLE_MS);
  }
  function setupAutoLock() {
    if (!isEncryptionEnabled()) { clearTimeout(autoLockTimer); return; }
    resetAutoLockTimer();
    if (autoLockListenersAttached) return;
    autoLockListenersAttached = true;
    ['mousedown', 'keydown', 'touchstart', 'scroll'].forEach((evt) => {
      document.addEventListener(evt, resetAutoLockTimer, { passive: true });
    });
    // NOTE: deliberately NOT locking on a plain visibilitychange-to-hidden.
    // That used to lock the instant you switched apps or another app briefly
    // covered this one, which made the lock screen show up constantly for
    // completely normal phone use. Locking now only happens for:
    //   1. The idle timer above (AUTO_LOCK_IDLE_MS of no interaction),
    //   2. Clicking "Lock Now" explicitly (lockNow()), or
    //   3. Actually closing/navigating away from the tab (below) — including
    //      the back/forward cache case, where the browser can otherwise
    //      restore the page (with the decryption key still sitting in JS
    //      memory) without asking for the passcode again.
    window.addEventListener('pagehide', () => {
      // save in-flight edits while the key is still loaded, then drop it
      flushPendingSaves().finally(() => { if (isEncryptionEnabled()) encryptionKey = null; });
    });
    window.addEventListener('pageshow', (e) => {
      if (e.persisted && isEncryptionEnabled()) lockNow();
    });
  }

  function openEncryptionModal() {
    const enabled = isEncryptionEnabled();
    document.getElementById('enc-modal-off').classList.toggle('hidden-btn', enabled);
    document.getElementById('enc-modal-on').classList.toggle('hidden-btn', !enabled);
    document.getElementById('enc-passcode-1').value = '';
    document.getElementById('enc-passcode-2').value = '';
    document.getElementById('enc-disable-passcode').value = '';
    document.getElementById('enc-modal-status').textContent = '';
    document.getElementById('enc-modal-status-2').textContent = '';
    document.getElementById('encryption-modal').classList.add('show');
  }
  function closeEncryptionModal() {
    document.getElementById('encryption-modal').classList.remove('show');
  }

  async function submitEnableEncryption() {
    const p1 = document.getElementById('enc-passcode-1').value;
    const p2 = document.getElementById('enc-passcode-2').value;
    const status = document.getElementById('enc-modal-status');
    if (!p1 || p1.length < 6) { status.textContent = '⚠️ Passcode must be at least 6 characters.'; status.style.color = 'var(--orange)'; return; }
    if (p1 !== p2) { status.textContent = '⚠️ Passcodes do not match.'; status.style.color = 'var(--orange)'; return; }
    status.textContent = 'Encrypting your data — this may take a moment...';
    status.style.color = 'var(--muted)';
    try {
      const { key, saltB64, iterations } = await deriveEncryptionKey(p1, null, PBKDF2_ITERATIONS);
      // Turn the "encrypted" flag on BEFORE touching any row. If the tab is closed
      // mid-migration the app then reopens locked, and the next unlock finishes
      // the job (normalizeEncryptedRows) instead of leaving unreadable mixed data.
      const canary = await encryptValue(key, ENC_CANARY_PLAINTEXT);
      localStorage.setItem('budgetref-encryption-salt', saltB64);
      localStorage.setItem('budgetref-encryption-iterations', String(iterations));
      localStorage.setItem('budgetref-encryption-canary', JSON.stringify(canary));
      localStorage.setItem('budgetref-encryption-enabled', 'true');
      await mirrorEncMeta();
      encryptionKey = key;
      await normalizeEncryptedRows();
      closeEncryptionModal();
      updateEncNavBtn();
      showToast('🔒 Encryption enabled — your data is now encrypted at rest');
      await renderFixedTable();
      await renderInsTable();
      await renderForecasts();
      await mypInitPlanner();
    } catch (e) {
      encryptionKey = null;
      if (isEncryptionEnabled()) {
        // flag already on: data is a safe mix; unlocking with the NEW passcode finishes the migration
        closeEncryptionModal();
        updateEncNavBtn();
        showToast('⚠️ Encryption setup was interrupted — unlock with your new passcode to finish');
        showUnlockOverlay();
      } else {
        status.textContent = '❌ Something went wrong: ' + e.message;
        status.style.color = 'var(--red)';
      }
    }
  }

  async function submitDisableEncryption() {
    const passcode = document.getElementById('enc-disable-passcode').value;
    const status = document.getElementById('enc-modal-status-2');
    if (!passcode) { status.textContent = '⚠️ Enter your current passcode to confirm.'; status.style.color = 'var(--orange)'; return; }
    status.textContent = 'Verifying passcode...';
    status.style.color = 'var(--muted)';
    try {
      const saltB64 = localStorage.getItem('budgetref-encryption-salt');
      const { key } = await deriveEncryptionKey(passcode, saltB64, getStoredIterations());
      const canary = JSON.parse(localStorage.getItem('budgetref-encryption-canary'));
      const decoded = await decryptValue(key, canary);
      if (decoded !== ENC_CANARY_PLAINTEXT) throw new Error('wrong passcode');
      encryptionKey = key;
      status.textContent = 'Decrypting your data — this may take a moment...';
      for (const table of ENC_TABLES) {
        const rows = await db[table].toArray();
        for (const row of rows) {
          const decoded2 = await decryptRecord(row, table);
          await db[table].put(decoded2);
        }
      }
      encryptionKey = null;
      localStorage.removeItem('budgetref-encryption-salt');
      localStorage.removeItem('budgetref-encryption-iterations');
      localStorage.removeItem('budgetref-encryption-canary');
      localStorage.removeItem('budgetref-encryption-enabled');
      try { await db.encMeta.clear(); } catch (e) { /* non-fatal */ }
      closeEncryptionModal();
      updateEncNavBtn();
      showToast('🔓 Encryption disabled — your data is stored as plaintext again');
      await renderFixedTable();
      await renderInsTable();
      await renderForecasts();
      await mypInitPlanner();
    } catch (e) {
      status.textContent = '❌ Incorrect passcode.';
      status.style.color = 'var(--red)';
    }
  }

  // ---- Step 5: plain mirror of key material in IndexedDB (salt/iterations/canary are not secret) ----
  const ENC_META_KEYS = {
    salt: 'budgetref-encryption-salt',
    iterations: 'budgetref-encryption-iterations',
    canary: 'budgetref-encryption-canary'
  };
  async function mirrorEncMeta() {
    try {
      const rows = [];
      for (const [k, ls] of Object.entries(ENC_META_KEYS)) {
        const v = localStorage.getItem(ls);
        if (v != null) rows.push({ key: k, value: v });
      }
      if (rows.length) await db.encMeta.bulkPut(rows);
    } catch (e) { console.warn('encMeta mirror failed', e); }
  }
  async function restoreEncMetaIfLost() {
    try {
      const intact = localStorage.getItem('budgetref-encryption-enabled') === 'true'
        && localStorage.getItem(ENC_META_KEYS.salt) && localStorage.getItem(ENC_META_KEYS.canary);
      if (intact) return;
      const m = Object.fromEntries((await db.encMeta.toArray()).map((r) => [r.key, r.value]));
      if (!m.salt || !m.canary) return;
      localStorage.setItem(ENC_META_KEYS.salt, m.salt);
      localStorage.setItem(ENC_META_KEYS.canary, m.canary);
      if (m.iterations) localStorage.setItem(ENC_META_KEYS.iterations, m.iterations);
      localStorage.setItem('budgetref-encryption-enabled', 'true');
    } catch (e) { console.warn('encMeta restore failed', e); }
  }

  function showUnlockOverlay() {
    document.documentElement.classList.add('locked-boot'); // hides .container, forces full-screen overlay
    document.getElementById('unlock-overlay').classList.add('show');
    document.getElementById('unlock-passcode').focus();
  }
  function hideUnlockOverlay() {
    document.getElementById('unlock-overlay').classList.remove('show');
    document.documentElement.classList.remove('locked-boot');
  }
  async function attemptUnlock() {
    if (lockingInProgress) return;
    const passcode = document.getElementById('unlock-passcode').value;
    const status = document.getElementById('unlock-status');
    if (!passcode) { status.textContent = 'Enter your passcode.'; return; }
    status.textContent = 'Unlocking...';
    status.style.color = 'var(--muted)';
    try {
      const saltB64 = localStorage.getItem('budgetref-encryption-salt');
      const { key } = await deriveEncryptionKey(passcode, saltB64, getStoredIterations());
      const canary = JSON.parse(localStorage.getItem('budgetref-encryption-canary'));
      const decoded = await decryptValue(key, canary);
      if (decoded !== ENC_CANARY_PLAINTEXT) throw new Error('wrong passcode');
      encryptionKey = key;
      status.textContent = 'Checking data format...';
      try { await normalizeEncryptedRows(); } catch (e) { console.warn('normalize failed (data still readable)', e); }
      hideUnlockOverlay();
      mirrorEncMeta();
      await renderFixedTable();
      await renderInsTable();
      await renderForecasts();
      await mypInitPlanner();
      gcOrphanedPaidMarks(); // catch-all sweep for any orphans left over from before this cleanup existed; not awaited so it doesn't delay unlock
    } catch (e) {
      console.error('Unlock failed:', e); // real cause (e.g. Dexie failed to load) lands here — don't assume it's always a wrong passcode
      status.textContent = '❌ Incorrect passcode. Try again.';
      status.style.color = 'var(--red)';
      document.getElementById('unlock-passcode').value = '';
      document.getElementById('unlock-passcode').focus();
    }
  }

  // ========== THEME ==========
  function initTheme() {
    const saved = localStorage.getItem('ref-theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeBtn(saved);
  }
  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('ref-theme', next);
    updateThemeBtn(next);
    mypRefreshChartTheme();
  }
  // Previously the forecast chart's colors were only set at render time, so switching
  // theme while a chart was already on screen left it showing the old theme's grid/tick/
  // bar colors until the next "Run Forecast" click. This updates the live chart in place.
  function mypRefreshChartTheme() {
    if (!mypChart) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? 'rgba(148,163,184,.15)' : 'rgba(15,23,42,.08)';
    const tickColor = isDark ? '#94a3b8' : '#55617a';
    const rootStyle = getComputedStyle(document.documentElement);
    mypChart.data.datasets[0].backgroundColor = hexToRgba(rootStyle.getPropertyValue('--green'), 0.75);
    mypChart.data.datasets[1].backgroundColor = hexToRgba(rootStyle.getPropertyValue('--red'), 0.75);
    mypChart.options.scales.x.ticks.color = tickColor;
    mypChart.options.scales.x.grid.color = gridColor;
    mypChart.options.scales.y.ticks.color = tickColor;
    mypChart.options.scales.y.grid.color = gridColor;
    mypChart.options.plugins.legend.labels.color = tickColor;
    mypChart.update();
  }
  function updateThemeBtn(theme) {
    const btn = document.getElementById('theme-btn');
    btn.innerHTML = theme === 'dark'
      ? '<i class="fas fa-moon"></i> Dark Mode'
      : '<i class="fas fa-sun"></i> Light Mode';
  }

  // ========== TABS ==========
  function switchTab(tab) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');
    document.getElementById('tabbtn-' + tab).classList.add('active');
  }

  // ========== HELPERS ==========
  function formatMoney(n) { return '$' + (n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

  // ========== MONEY-FORMATTED INPUTS (Income Forecast / Multi-Year Planner amount fields) ==========
  // These fields display as "$1,234.56" at rest, same look as formatMoney()
  // output, but need to stay plain-text-editable — so they're type="text"
  // rather than type="number" (a number input can't contain "$" or ","),
  // and switch to a bare, unformatted number while focused so typing isn't
  // fighting live-inserted commas/symbols. moneyInputParse() is the
  // counterpart used anywhere a formatted value gets read back out of the
  // DOM (both here and in any live same-block recalculation).
  function moneyInputFormat(n) { return formatMoney(parseFloat(n) || 0); }
  function moneyInputParse(str) { return parseFloat(String(str == null ? '' : str).replace(/[^0-9.-]/g, '')) || 0; }
  function moneyFieldFocus(el) {
    const raw = moneyInputParse(el.value);
    el.value = raw === 0 ? '' : String(raw);
    el.select();
  }
  function moneyFieldBlur(el) { el.value = moneyInputFormat(moneyInputParse(el.value)); }
  function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => t.classList.remove('show'), 2200);
  }
  // Debounce keyed per (id, field): editing field A then field B (or another
  // row) inside the delay no longer cancels A's save. Pending and in-flight
  // saves are tracked so they can be flushed on lock / page hide.
  const pendingSaves = new Map();
  const inflightSaves = new Set();
  let debounceSeq = 0;
  function debounce(fn, ms) {
    const fid = ++debounceSeq;
    return (...args) => {
      const key = fid + ':' + args[0] + ':' + args[1];
      const prev = pendingSaves.get(key);
      if (prev) clearTimeout(prev.timer);
      const run = () => {
        pendingSaves.delete(key);
        const p = Promise.resolve().then(() => fn(...args));
        inflightSaves.add(p);
        p.then(() => { inflightSaves.delete(p); },
               (e) => { inflightSaves.delete(p); return Promise.reject(e); }); // keep LOCKED_WRITE handler working
        return p;
      };
      pendingSaves.set(key, { timer: setTimeout(run, ms), run });
    };
  }
  function flushPendingSaves() {
    for (const [, save] of [...pendingSaves]) { clearTimeout(save.timer); save.run(); }
    return Promise.allSettled([...inflightSaves]);
  }
  window.addEventListener('pagehide', () => { flushPendingSaves(); });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flushPendingSaves();
  });

  // ========== FIXED EXPENSES TABLE ==========
  function sortRowsByCategory(rows) {
    // group rows so identical categories sit together; group position = category's first appearance,
    // so a brand-new row saved with an existing category slots into that category's group.
    const order = [];
    const seen = new Set();
    rows.forEach(r => {
      const cat = (r.category || '').trim();
      if (!seen.has(cat)) { seen.add(cat); order.push(cat); }
    });
    const orderIndex = {};
    order.forEach((c, i) => { orderIndex[c] = i; });
    return [...rows].sort((a, b) => {
      const ia = orderIndex[(a.category || '').trim()];
      const ib = orderIndex[(b.category || '').trim()];
      if (ia !== ib) return ia - ib;
      return (a.id || 0) - (b.id || 0);
    });
  }

  function populateCategoryDatalist(rows) {
    const cats = Array.from(new Set(rows.map(r => (r.category || '').trim()).filter(Boolean)))
      .sort((a, b) => a.localeCompare(b));
    document.getElementById('category-datalist').innerHTML =
      cats.map(c => `<option value="${escapeAttr(c)}"></option>`).join('');
  }

  // Free-text categories can't use a fixed color map (user can type anything), so hash the
  // category text to one of the app's existing theme colors — stays consistent across
  // renders and automatically follows light/dark theme since it's a CSS var reference.
  const CAT_PALETTE = ['orange', 'green', 'blue', 'purple', 'cyan', 'red', 'yellow'];
  function catColorVar(str) {
    const s = (str || '').trim().toLowerCase();
    if (!s) return 'var(--muted)';
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return `var(--${CAT_PALETTE[h % CAT_PALETTE.length]})`;
  }
  function hexToRgba(hex, alpha) {
    const h = (hex || '').trim().replace('#', '');
    const r = parseInt(h.substring(0, 2), 16), g = parseInt(h.substring(2, 4), 16), b = parseInt(h.substring(4, 6), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  async function renderFixedTable() {
    const rows = await encGetAll('fixedExpenses');
    populateCategoryDatalist(rows);
    const sorted = sortRowsByCategory(rows);
    const tbody = document.getElementById('fixed-tbody');
    document.getElementById('fixed-empty').style.display = rows.length ? 'none' : 'block';
    tbody.innerHTML = sorted.map(r => `
      <tr data-id="${r.id}">
        <td><div class="cat-cell" style="--cat-color:${catColorVar(r.category)}"><span class="cat-dot"></span><input type="text" class="f-cat" list="category-datalist" value="${escapeAttr(r.category||'')}" placeholder="Select or enter category" data-on-input="h38" data-a0="${r.id}" data-on-change="h39" data-a0="${r.id}"></div></td>
        <td><input type="text" class="f-item" value="${escapeAttr(r.item||'')}" placeholder="Item name" data-on-input="h40" data-a0="${r.id}"></td>
        <td><input type="text" inputmode="decimal" class="m-amt" value="${moneyInputFormat(r.monthlyAmt)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h43" data-a0="${r.id}"></td>
        <td>
          <select class="m-freq" data-on-change="h44" data-a0="${r.id}">
            <option value="12" ${r.freq==12?'selected':''}>Monthly</option>
            <option value="1" ${r.freq==1?'selected':''}>One-time</option>
          </select>
        </td>
        <td><input type="text" class="y-amt" readonly value="${formatMoney((r.monthlyAmt||0)*(r.freq||12))}"></td>
        <td><input type="text" class="f-note" value="${escapeAttr(r.note||'')}" placeholder="Notes" data-on-input="h45" data-a0="${r.id}"></td>
        <td><input type="text" class="f-due" value="${escapeAttr(r.dueDate||'')}" placeholder="e.g. 1st of every month" data-on-input="h46" data-a0="${r.id}"></td>
        <td><button class="icon-btn" data-on-click="h47" data-a0="${r.id}" title="Delete"><i class="fas fa-trash"></i></button></td>
      </tr>
    `).join('');
    calcFixedGrandTotal();
    renderFixedReport();
  }

  function recalcFixedRow(el) {
    const tr = el.closest('tr');
    const mAmt = moneyInputParse(tr.querySelector('.m-amt').value);
    const freq = parseFloat(tr.querySelector('.m-freq').value) || 12;
    tr.querySelector('.y-amt').value = formatMoney(mAmt * freq);
    calcFixedGrandTotal();
    renderFixedReport();
  }

  function calcFixedGrandTotal() {
    let total = 0;
    document.querySelectorAll('#fixed-tbody tr').forEach(tr => {
      const mAmt = moneyInputParse(tr.querySelector('.m-amt').value);
      const freq = parseFloat(tr.querySelector('.m-freq').value) || 12;
      total += mAmt * freq;
    });
    document.getElementById('fixed-grand-total').textContent = formatMoney(total);
    document.getElementById('fixed-grand-total-top').textContent = formatMoney(total);
    document.getElementById('fixed-monthly-avg-top').textContent = formatMoney(total / 12);
  }

  function renderFixedReport() {
    // read live values straight from the DOM (already sorted/grouped), in on-screen order
    const groups = {}; // category -> { total, items:[] }
    const order = [];
    document.querySelectorAll('#fixed-tbody tr').forEach(tr => {
      const category = (tr.querySelector('.f-cat').value || '').trim() || '(Uncategorized)';
      const item = (tr.querySelector('.f-item').value || '').trim() || '(Unnamed item)';
      const mAmt = moneyInputParse(tr.querySelector('.m-amt').value);
      const freq = parseFloat(tr.querySelector('.m-freq').value) || 12;
      const note = (tr.querySelector('.f-note').value || '').trim();
      const due = (tr.querySelector('.f-due').value || '').trim();
      const yearly = mAmt * freq;
      if (!groups[category]) { groups[category] = { total: 0, items: [] }; order.push(category); }
      groups[category].items.push({ item, mAmt, freq, yearly, note, due });
      groups[category].total += yearly;
    });

    const container = document.getElementById('fixed-report-container');
    document.getElementById('fixed-report-empty').style.display = order.length ? 'none' : 'block';

    container.innerHTML = order.map(cat => {
      const g = groups[cat];
      const rows = g.items.map(it => {
        const amountHtml = it.freq == 12
          ? `<div class="report-amt-yearly">${formatMoney(it.yearly)}/yr</div><div class="report-amt-monthly">(${formatMoney(it.mAmt)}/mo)</div>`
          : `<div class="report-amt-yearly">${formatMoney(it.yearly)}/yr</div>`;
        return `
          <tr>
            <td>${escapeAttr(it.item)}</td>
            <td>${amountHtml}</td>
            <td>${it.note ? escapeAttr(it.note) : '<span class="report-muted-dash">—</span>'}</td>
            <td>${it.due ? escapeAttr(it.due) : '<span class="report-muted-dash">—</span>'}</td>
          </tr>
        `;
      }).join('');
      return `
        <div class="report-category-block" style="--cat-color:${catColorVar(cat)}">
          <div class="report-category-head">
            <span class="report-category-name"><span class="cat-dot"></span>${escapeAttr(cat)}</span>
            <span class="report-category-total">${formatMoney(g.total)}/yr</span>
          </div>
          <div style="overflow-x:auto;">
            <table class="report-item-table">
              <thead><tr><th>Item</th><th>Amount</th><th>Notes/Ref</th><th>Due Date</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      `;
    }).join('');
  }

  const persistFixedField = debounce(async (id, field, value) => {
    await encUpdate('fixedExpenses', id, { [field]: value });
  }, 300);
  function updateFixedField(id, field, value) { persistFixedField(id, field, value); renderFixedReport(); }

  async function handleCategoryChange(id, value) {
    // immediate (non-debounced) write + full re-render so the row regroups with matching categories right away
    await encUpdate('fixedExpenses', id, { category: value });
    renderFixedTable();
  }

  async function addFixedRow() {
    await encAdd('fixedExpenses', { category:'', item:'', monthlyAmt:0, freq:12, note:'', dueDate:'' });
    renderFixedTable();
  }
  async function deleteFixedRow(id) {
    await db.fixedExpenses.delete(id);
    renderFixedTable();
  }

  // ========== INSURANCE: policies grouped, each with one or more year-range periods ==========
  async function renderInsTable() {
    const policies = await encGetAll('policies');
    const allRanges = await encGetAll('policyRanges');
    const container = document.getElementById('policies-container');
    document.getElementById('policies-empty').style.display = policies.length ? 'none' : 'block';

    container.innerHTML = policies.map(p => {
      const ranges = allRanges.filter(r => r.policyId === p.id).sort((a,b) => (a.fromYear||0) - (b.fromYear||0));
      const rangeRows = ranges.map(r => `
        <tr data-range-id="${r.id}">
          <td><input type="number" class="rg-from" value="${r.fromYear ?? new Date().getFullYear()}" data-on-input="h48" data-a0="${r.id}"></td>
          <td><input type="number" class="rg-to" value="${r.toYear ?? r.fromYear ?? new Date().getFullYear()}" data-on-input="h49" data-a0="${r.id}"></td>
          <td><input type="text" inputmode="decimal" class="rg-amt" value="${moneyInputFormat(r.amount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h50" data-a0="${r.id}"></td>
          <td><button class="icon-btn" data-on-click="h51" data-a0="${r.id}" title="Delete this range"><i class="fas fa-trash"></i></button></td>
        </tr>
      `).join('');

      return `
        <div class="policy-block" data-policy-id="${p.id}" style="--cat-color:${catColorVar(p.name)}">
          <div class="policy-header">
            <div class="policy-name-wrap">
              <label>Policy Name</label>
              <div class="cat-cell"><span class="cat-dot"></span><input type="text" class="policy-name" value="${escapeAttr(p.name||'')}" placeholder="e.g. Policy 1" data-on-input="h52" data-a0="${p.id}"></div>
            </div>
            <div class="policy-note-area" data-policy-id="${p.id}">
              ${p.note
                ? `<input type="text" class="policy-note-input" value="${escapeAttr(p.note)}" placeholder="dd/mm" data-on-input="h53" data-a0="${p.id}" data-on-blur="h54" data-a0="${p.id}">`
                : `<button type="button" class="note-add-btn" data-on-click="h55" data-a0="${p.id}"><i class="fas fa-plus"></i> Payment Date</button>`}
            </div>
            <button class="btn btn-sm btn-add add-range-btn" data-on-click="h56" data-a0="${p.id}" title="Add Payment Range"><i class="fas fa-plus"></i> Add Payment Range</button>
            <button class="icon-btn" data-on-click="h57" data-a0="${p.id}" title="Delete entire policy"><i class="fas fa-trash"></i></button>
          </div>
          <div style="overflow-x:auto;">
            <table class="range-table">
              <thead>
                <tr>
                  <th style="width:110px;">Start Year</th>
                  <th style="width:110px;">End Year</th>
                  <th style="width:140px;">Annual Premium ($)</th>
                  <th style="width:40px;"></th>
                </tr>
              </thead>
              <tbody>${rangeRows}</tbody>
            </table>
            ${ranges.length ? '' : '<div class="policy-empty-hint">No ranges yet — click the button above to add one</div>'}
          </div>
        </div>
      `;
    }).join('');

    renderInsSummary();
    document.querySelectorAll('.policy-note-input').forEach(autoSizeInput);
  }

  async function renderInsSummary() {
    // read live values straight from the DOM so summary updates instantly while typing
    const marks = await db.paidMarks.toArray();
    const markedSet = new Set(marks.map(m => m.policyId + '_' + m.year));

    const groups = {}; // year -> { total, entries:[{policyId,name,amount,payDate}], hiddenCount }
    document.querySelectorAll('.policy-block').forEach(block => {
      const policyId = parseInt(block.getAttribute('data-policy-id'));
      const nameInput = block.querySelector('.policy-name');
      const policyName = (nameInput && nameInput.value.trim()) || '(Unnamed policy)';
      const noteInput = block.querySelector('.policy-note-input');
      const payDate = (noteInput && noteInput.value.trim()) || '';
      block.querySelectorAll('tbody tr[data-range-id]').forEach(tr => {
        const from = parseInt(tr.querySelector('.rg-from').value) || 0;
        const to = parseInt(tr.querySelector('.rg-to').value) || from;
        const amt = moneyInputParse(tr.querySelector('.rg-amt').value);
        const lo = Math.min(from, to), hi = Math.max(from, to);
        for (let y = lo; y <= hi; y++) {
          if (!groups[y]) groups[y] = { total:0, entries:[], hiddenCount:0 };
          if (markedSet.has(policyId + '_' + y)) {
            groups[y].hiddenCount += 1;
          } else {
            groups[y].total += amt;
            groups[y].entries.push({ policyId, name: policyName, amount: amt, payDate });
          }
        }
      });
    });
    const years = Object.keys(groups).sort((a,b) => a - b);
    const grid = document.getElementById('ins-summary-grid');
    document.getElementById('ins-summary-empty').style.display = years.length ? 'none' : 'block';
    grid.innerHTML = years.map(y => {
      const detail = groups[y].entries
        .map(e => `<div class="summary-card-detail-row"><b title="${escapeAttr(e.name)}">${escapeAttr(e.name)}</b><span class="summary-card-right">${e.payDate ? `<span class="summary-card-paydate">${escapeAttr(e.payDate)}</span>` : ''}<span>${formatMoney(e.amount)}</span><button type="button" class="summary-entry-del" data-on-click="h58" data-a0="${e.policyId}" data-a1="${y}" title="Remove from this year (other years unaffected)"><i class="fas fa-xmark"></i></button></span></div>`)
        .join('');
      const hiddenNote = groups[y].hiddenCount > 0
        ? `<div class="summary-card-hidden-note">${groups[y].hiddenCount} item(s) removed · <button type="button" class="summary-restore-link" data-on-click="h59" data-a0="${y}">Restore</button></div>`
        : '';
      return `
      <div class="summary-card">
        <div class="summary-card-head">
          <span class="summary-card-year">${y}</span>
          <span class="summary-card-total">${formatMoney(groups[y].total)}</span>
        </div>
        ${detail}
        ${hiddenNote}
      </div>
    `;
    }).join('');
  }

  async function markEntryPaid(policyId, year) {
    await db.paidMarks.add({ policyId, year });
    renderInsSummary();
  }

  async function restoreYear(year) {
    const rows = await db.paidMarks.where('year').equals(year).toArray();
    for (const m of rows) await db.paidMarks.delete(m.id);
    renderInsSummary();
  }

  const persistPolicyField = debounce(async (id, field, value) => {
    await encUpdate('policies', id, { [field]: value });
  }, 300);
  function updatePolicyField(id, field, value) { persistPolicyField(id, field, value); }

  function showPolicyNoteInput(id) {
    const area = document.querySelector(`.policy-note-area[data-policy-id="${id}"]`);
    area.innerHTML = `<input type="text" class="policy-note-input" value="" placeholder="dd/mm" data-on-input="h53" data-a0="${id}" data-on-blur="h54" data-a0="${id}">`;
    const input = area.querySelector('input');
    input.focus();
    autoSizeInput(input);
  }

  function refreshPolicyNoteArea(id) {
    const area = document.querySelector(`.policy-note-area[data-policy-id="${id}"]`);
    const input = area.querySelector('input');
    const val = input ? input.value.trim() : '';
    if (!val) {
      area.innerHTML = `<button type="button" class="note-add-btn" data-on-click="h55" data-a0="${id}"><i class="fas fa-plus"></i> Payment Date</button>`;
    } else {
      autoSizeInput(input);
    }
    renderInsSummary();
  }

  function autoSizeInput(el) {
    // fits the input's width to its current text (fallback for browsers without CSS field-sizing support)
    const span = document.createElement('span');
    const cs = getComputedStyle(el);
    span.style.font = cs.font;
    span.style.letterSpacing = cs.letterSpacing;
    span.style.position = 'fixed';
    span.style.left = '-9999px';
    span.style.whiteSpace = 'pre';
    span.textContent = el.value || el.placeholder || '';
    document.body.appendChild(span);
    el.style.width = Math.min(280, Math.max(50, span.offsetWidth + 28)) + 'px';
    span.remove();
  }

  const persistRangeField = debounce(async (id, field, value) => {
    await encUpdate('policyRanges', id, { [field]: value });
  }, 300);
  function updateRangeField(id, field, value) { persistRangeField(id, field, value); }

  async function addPolicy() {
    const policyId = await encAdd('policies', { name:'', note:'' });
    const thisYear = new Date().getFullYear();
    await encAdd('policyRanges', { policyId, fromYear: thisYear, toYear: thisYear, amount: 0, note:'' });
    renderInsTable();
  }
  // A paidMark ({policyId, year}) hides that policy's premium from that
  // year's summary. It becomes orphaned once no *currently existing*
  // policyRange for that policy covers that year anymore — whether because
  // the whole policy was deleted (deletePolicy, zero ranges left) or just
  // the specific range that used to cover that year was removed/shrunk
  // (deleteRange, while another range for the same policy might still
  // legitimately cover it). Recomputing "which (policyId, year) pairs are
  // covered right now" from scratch handles both cases correctly with one
  // function, instead of writing separate range-intersection logic for the
  // deleteRange case. Cheap enough (personal-scale data) to just run it
  // after every delete rather than deferring to a periodic sweep.
  async function gcOrphanedPaidMarks() {
    if (isWriteLocked()) return; // can't decrypt ranges to know true coverage yet — next unlock/init will catch it
    const [marks, ranges] = await Promise.all([db.paidMarks.toArray(), encGetAll('policyRanges')]);
    if (!marks.length) return;
    const validKeys = new Set();
    ranges.forEach(r => {
      const from = r.fromYear ?? 0, to = r.toYear ?? from;
      const lo = Math.min(from, to), hi = Math.max(from, to);
      for (let y = lo; y <= hi; y++) validKeys.add(r.policyId + '_' + y);
    });
    const orphanIds = marks.filter(m => !validKeys.has(m.policyId + '_' + m.year)).map(m => m.id);
    if (orphanIds.length) await db.paidMarks.bulkDelete(orphanIds);
  }

  async function deletePolicy(id) {
    await db.policyRanges.where('policyId').equals(id).delete();
    await db.policies.delete(id);
    await gcOrphanedPaidMarks();
    renderInsTable();
  }

  async function addRange(policyId) {
    const allRanges = await encGetAll('policyRanges');
    const ranges = allRanges.filter(r => r.policyId === policyId);
    const lastTo = ranges.length ? Math.max(...ranges.map(r => r.toYear || r.fromYear || 0)) : new Date().getFullYear() - 1;
    const nextYear = (lastTo || new Date().getFullYear() - 1) + 1;
    await encAdd('policyRanges', { policyId, fromYear: nextYear, toYear: nextYear, amount: 0, note:'' });
    renderInsTable();
  }
  async function deleteRange(id) {
    await db.policyRanges.delete(id);
    await gcOrphanedPaidMarks();
    renderInsTable();
  }

  // ========== INCOME FORECAST (what-if scenarios, fully manual entry) ==========
  function forecastLineYearly(line) {
    if (line.kind === 'rental') return (parseFloat(line.amount) || 0) * 12;
    return (parseFloat(line.amount) || 0) * (parseFloat(line.ratePct) || 0) / 100;
  }

  async function renderForecasts() {
    const forecasts = await encGetAll('incomeForecasts');
    const allLines = await encGetAll('forecastLines');
    const container = document.getElementById('forecasts-container');
    const empty = document.getElementById('forecasts-empty');
    if (!forecasts.length) { container.innerHTML = ''; empty.style.display = ''; return; }
    empty.style.display = 'none';
    container.innerHTML = forecasts.map(f => {
      const lines = allLines.filter(l => l.forecastId === f.id);
      const accountLines = lines.filter(l => l.kind === 'account');
      const rentalLines = lines.filter(l => l.kind === 'rental');
      const yearlyTotal = lines.reduce((s, l) => s + forecastLineYearly(l), 0);

      const accountRows = accountLines.map(l => `
        <tr data-id="${l.id}">
          <td><input type="text" class="fl-label" value="${escapeAttr(l.label||'')}" placeholder="e.g. Unit Trust" data-on-input="h60" data-a0="${l.id}"></td>
          <td><input type="text" inputmode="decimal" class="fl-amt" value="${moneyInputFormat(l.amount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h61" data-a0="${l.id}"></td>
          <td><input type="number" class="fl-rate" step="0.01" value="${l.ratePct||0}" data-on-input="h62" data-a0="${l.id}"></td>
          <td class="fl-yearly" style="text-align:right;">${formatMoney(forecastLineYearly(l))}</td>
          <td><button class="icon-btn" data-on-click="h63" data-a0="${l.id}" title="Delete"><i class="fas fa-trash"></i></button></td>
        </tr>`).join('');

      const rentalRows = rentalLines.map(l => `
        <tr data-id="${l.id}">
          <td><input type="text" class="fl-label" value="${escapeAttr(l.label||'')}" placeholder="e.g. Condo Unit A" data-on-input="h60" data-a0="${l.id}"></td>
          <td><input type="text" inputmode="decimal" class="fl-amt" value="${moneyInputFormat(l.amount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h61" data-a0="${l.id}"></td>
          <td class="fl-yearly" style="text-align:right;">${formatMoney(forecastLineYearly(l))}</td>
          <td><button class="icon-btn" data-on-click="h63" data-a0="${l.id}" title="Delete"><i class="fas fa-trash"></i></button></td>
        </tr>`).join('');

      return `<div class="policy-block" data-forecast-id="${f.id}">
        <div class="policy-header">
          <div class="policy-name-wrap">
            <label>Scenario</label>
            <input type="text" class="policy-name" value="${escapeAttr(f.name||'')}" placeholder="e.g. Retirement Income" data-on-input="h64" data-a0="${f.id}">
          </div>
          <button class="icon-btn" data-on-click="h65" data-a0="${f.id}" title="Delete scenario"><i class="fas fa-trash"></i></button>
        </div>

        <div class="summary-title" style="margin-top:2px;"><i class="fas fa-building-columns"></i> Income-Generating Accounts</div>
        <table class="range-table">
          <thead><tr><th>Account / Source</th><th style="width:130px;">Amount ($)</th><th style="width:110px;">Rate (%/yr)</th><th style="width:130px;text-align:right;">Yearly Income</th><th style="width:36px;"></th></tr></thead>
          <tbody>${accountRows}</tbody>
        </table>
        ${accountLines.length ? '' : '<div class="policy-empty-hint">No accounts yet</div>'}
        <div class="toolbar"><button class="btn btn-sm btn-add add-range-btn" data-on-click="h66" data-a0="${f.id}"><i class="fas fa-plus"></i> Add Account</button></div>

        <div class="summary-title" style="margin-top:14px;"><i class="fas fa-house"></i> Rental / Fixed Monthly Income</div>
        <table class="range-table">
          <thead><tr><th>Source</th><th style="width:130px;">Monthly ($)</th><th style="width:130px;text-align:right;">Yearly Income</th><th style="width:36px;"></th></tr></thead>
          <tbody>${rentalRows}</tbody>
        </table>
        ${rentalLines.length ? '' : '<div class="policy-empty-hint">No rental/fixed income yet</div>'}
        <div class="toolbar"><button class="btn btn-sm btn-add add-range-btn" data-on-click="h67" data-a0="${f.id}"><i class="fas fa-plus"></i> Add Rental / Fixed Income</button></div>

        <div class="grand-total-banner" style="margin-top:14px;">
          <span>Scenario Total:</span>
          <span class="total-cell">${formatMoney(yearlyTotal)} / yr &nbsp;&middot;&nbsp; ${formatMoney(yearlyTotal/12)} / mo</span>
        </div>
      </div>`;
    }).join('');
  }

  async function addForecast() {
    await encAdd('incomeForecasts', { name: '' });
    renderForecasts();
  }

  const persistForecastField = debounce(async (id, field, value) => {
    await encUpdate('incomeForecasts', id, { [field]: value });
  }, 300);
  function updateForecastField(id, field, value) { persistForecastField(id, field, value); }

  async function deleteForecast(id) {
    if (!confirm('Delete this forecast scenario and all its lines?')) return;
    await db.forecastLines.where('forecastId').equals(id).delete();
    await db.incomeForecasts.delete(id);
    renderForecasts();
  }

  async function addForecastLine(forecastId, kind) {
    await encAdd('forecastLines', { forecastId, kind, label: '', amount: 0, ratePct: 0 });
    renderForecasts();
  }

  const persistForecastLineField = debounce(async (id, field, value) => {
    await encUpdate('forecastLines', id, { [field]: value });
  }, 300);
  function updateForecastLineField(id, field, value) { persistForecastLineField(id, field, value); }

  // Live-updates just the one row's "Yearly Income" cell plus the scenario's
  // total banner, without a full re-render — same reasoning as recalcFixedRow
  // below: keeps focus/cursor position in whichever input is being typed into.
  function recalcForecastRow(inputEl) {
    const tr = inputEl.closest('tr');
    const block = inputEl.closest('.policy-block');
    // .fl-amt reads use moneyInputParse rather than parseFloat: the row
    // being typed into is showing a bare number (moneyFieldFocus already
    // stripped it), but every *other* row's .fl-amt is still sitting in
    // its formatted "$1,234.56" resting state — plain parseFloat chokes on
    // the leading "$" and silently reads those rows as 0.
    const amt = moneyInputParse(tr.querySelector('.fl-amt').value);
    const rateInput = tr.querySelector('.fl-rate');
    const yearly = rateInput ? (amt * (parseFloat(rateInput.value) || 0) / 100) : (amt * 12);
    tr.querySelector('.fl-yearly').textContent = formatMoney(yearly);

    let total = 0;
    block.querySelectorAll('.range-table tbody tr').forEach(row => {
      const a = moneyInputParse(row.querySelector('.fl-amt').value);
      const r = row.querySelector('.fl-rate');
      total += r ? (a * (parseFloat(r.value) || 0) / 100) : (a * 12);
    });
    const totalCell = block.querySelector('.grand-total-banner .total-cell');
    if (totalCell) totalCell.textContent = `${formatMoney(total)} / yr \u00b7 ${formatMoney(total/12)} / mo`;
  }

  async function deleteForecastLine(id) {
    await db.forecastLines.delete(id);
    renderForecasts();
  }

  // ========== MULTI-YEAR PLANNER (staged multi-account cashflow projection, fully manual entry) ==========
  // Supports multiple named "plans" (e.g. one per household member, or
  // separate what-if setups) via mypPlans — every top-level entity
  // (accounts, income items, expense items, baselines, actuals) carries a
  // planId, so switching plans swaps the whole planner's data set. Child
  // rows (rules, ranges, baseline values) are scoped transitively through
  // their parent's id, so they don't need their own planId.
  let currentMypPlanId = null;
  let mypForecastData = [];
  let mypForecastFundsList = [];
  let mypChart = null;

  async function mypInitPlanner() {
    // Each step runs independently — a problem in one should never prevent
    // the rest of the planner from still rendering.
    try { await mypEnsureDefaultPlanAndLoad(); } catch (e) { console.error('mypEnsureDefaultPlanAndLoad failed:', e); }
    try { await mypRenderAll(); } catch (e) { console.error('mypRenderAll failed:', e); }
    try { await mypLoadOrClearForecastForCurrentPlan(); } catch (e) { console.error('mypLoadOrClearForecastForCurrentPlan failed:', e); }
  }

  function mypSwitchSubTab(tab) {
    document.querySelectorAll('#tab-myp .myp-subpanel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('#tab-myp .myp-subtab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('myp-sub-' + tab).classList.add('active');
    document.getElementById('myp-tabbtn-' + tab).classList.add('active');
    if (tab === 'baseline') mypRenderBaselineComparisonTable();
  }

  // ---------- Plans ----------
  async function mypEnsureDefaultPlanAndLoad() {
    let plans = await encGetAll('mypPlans');
    if (plans.length === 0) {
      await encAdd('mypPlans', { name: 'My Plan' });
      plans = await encGetAll('mypPlans');
    }
    let savedId = null;
    try { savedId = parseInt(localStorage.getItem('budgetref-current-myp-plan')); } catch (e) { /* ignore */ }
    currentMypPlanId = plans.some(p => p.id === savedId) ? savedId : plans[0].id;
    mypRenderPlanSelect(plans);
  }

  function mypRenderPlanSelect(plans) {
    const select = document.getElementById('mypPlanSelect');
    select.innerHTML = plans.map(p => `<option value="${p.id}">${escapeAttr(p.name || 'Unnamed plan')}</option>`).join('');
    select.value = currentMypPlanId;
  }

  async function mypSwitchPlan(id) {
    currentMypPlanId = parseInt(id);
    try { localStorage.setItem('budgetref-current-myp-plan', currentMypPlanId); } catch (e) { /* ignore */ }
    await mypRenderAll();
    await mypLoadOrClearForecastForCurrentPlan();
  }

  async function mypCreatePlan() {
    const name = prompt('Name this new plan (e.g. "Household" or "Retirement Scenario B"):');
    if (!name || !name.trim()) return;
    const newId = await encAdd('mypPlans', { name: name.trim() });
    mypRenderPlanSelect(await encGetAll('mypPlans'));
    await mypSwitchPlan(newId);
    showToast('Plan created!');
  }

  async function mypRenamePlan() {
    const plan = await encGet('mypPlans', currentMypPlanId);
    if (!plan) return;
    const name = prompt('Rename plan:', plan.name);
    if (!name || !name.trim()) return;
    await encUpdate('mypPlans', currentMypPlanId, { name: name.trim() });
    mypRenderPlanSelect(await encGetAll('mypPlans'));
    showToast('Plan renamed!');
  }

  async function mypDeletePlan() {
    const plans = await encGetAll('mypPlans');
    if (plans.length <= 1) { showToast("Can't delete your only plan"); return; }
    const plan = plans.find(p => p.id === currentMypPlanId);
    if (!plan) return;
    if (!confirm(`Delete plan "${plan.name}" and everything in it (accounts, rules, income, expenses, baselines)? This can't be undone.`)) return;

    const funds = await db.mypFunds.where('planId').equals(currentMypPlanId).toArray();
    for (const f of funds) await db.mypFundRules.where('fundId').equals(f.id).delete();
    await db.mypFunds.where('planId').equals(currentMypPlanId).delete();

    const incomeCats = await db.mypIncomeCategories.where('planId').equals(currentMypPlanId).toArray();
    for (const c of incomeCats) await db.mypIncomeRanges.where('categoryId').equals(c.id).delete();
    await db.mypIncomeCategories.where('planId').equals(currentMypPlanId).delete();

    const expenseCats = await db.mypExpenseCategories.where('planId').equals(currentMypPlanId).toArray();
    for (const c of expenseCats) await db.mypExpenseRanges.where('categoryId').equals(c.id).delete();
    await db.mypExpenseCategories.where('planId').equals(currentMypPlanId).delete();

    const baselines = await db.mypBaselines.where('planId').equals(currentMypPlanId).toArray();
    for (const b of baselines) await db.mypBaselineValues.where('baselineId').equals(b.id).delete();
    await db.mypBaselines.where('planId').equals(currentMypPlanId).delete();

    await db.mypActuals.where('planId').equals(currentMypPlanId).delete();
    await db.mypSavedForecasts.where('planId').equals(currentMypPlanId).delete();
    await db.mypPlans.delete(currentMypPlanId);

    showToast('Plan deleted');
    const remaining = await encGetAll('mypPlans');
    currentMypPlanId = remaining[0].id;
    try { localStorage.setItem('budgetref-current-myp-plan', currentMypPlanId); } catch (e) { /* ignore */ }
    mypRenderPlanSelect(remaining);
    await mypSwitchPlan(currentMypPlanId);
  }

  async function mypRenderAll() {
    await mypLoadFunds();
    await mypLoadRules();
    await mypLoadIncome();
    await mypLoadExpense();
  }

  // ---------- Accounts ----------
  async function mypLoadFunds() {
    const funds = (await encGetAll('mypFunds')).filter(f => f.planId === currentMypPlanId);
    const tbody = document.getElementById('myp-funds-tbody');
    document.getElementById('myp-funds-empty').style.display = funds.length ? 'none' : '';
    tbody.innerHTML = funds.map(f => `
      <tr data-id="${f.id}">
        <td><input type="text" class="mf-name" value="${escapeAttr(f.name||'')}" placeholder="e.g. Savings Account" data-on-input="h68" data-a0="${f.id}"></td>
        <td><input type="text" inputmode="decimal" class="mf-amt" value="${moneyInputFormat(f.initialAmount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h69" data-a0="${f.id}"></td>
        <td><input type="number" class="mf-rate" step="0.01" value="${f.returnRate||0}" data-on-input="h70" data-a0="${f.id}"></td>
        <td><button class="icon-btn" data-on-click="h71" data-a0="${f.id}" title="Delete"><i class="fas fa-trash"></i></button></td>
      </tr>`).join('');
  }

  async function addMypFund() {
    await encAdd('mypFunds', { planId: currentMypPlanId, name: '', initialAmount: 0, returnRate: 0 });
    await mypLoadFunds();
    await mypLoadRules(); // account picker in the rules table needs the new option
  }

  const persistMypFundField = debounce(async (id, field, value) => {
    await encUpdate('mypFunds', id, { [field]: value });
    if (field === 'name') mypLoadRules(); // rules table shows account names inline — keep them in sync
  }, 300);
  function updateMypFundField(id, field, value) { persistMypFundField(id, field, value); }

  async function deleteMypFund(id) {
    if (!confirm('Delete this account? Its staged rules will also be removed.')) return;
    await db.mypFundRules.where('fundId').equals(id).delete();
    await db.mypFunds.delete(id);
    showToast('Account deleted');
    await mypLoadFunds();
    await mypLoadRules();
  }

  // ---------- Staged Allocation Rules ----------
  async function mypLoadRules() {
    const funds = (await encGetAll('mypFunds')).filter(f => f.planId === currentMypPlanId);
    const fundIds = new Set(funds.map(f => f.id));
    const rules = (await encGetAll('mypFundRules')).filter(r => fundIds.has(r.fundId));
    const tbody = document.getElementById('myp-rules-tbody');
    document.getElementById('myp-rules-empty').style.display = rules.length ? 'none' : '';
    const fundOptionsFor = (selectedId) => funds.length
      ? funds.map(f => `<option value="${f.id}" ${f.id===selectedId?'selected':''}>${escapeAttr(f.name || 'Unnamed account')}</option>`).join('')
      : '<option value="">Add an account first</option>';
    tbody.innerHTML = rules.map(r => `
      <tr data-id="${r.id}">
        <td><input type="number" class="mr-start" value="${r.startYear??''}" data-on-input="h72" data-a0="${r.id}"></td>
        <td><input type="number" class="mr-end" value="${r.endYear??''}" data-on-input="h73" data-a0="${r.id}"></td>
        <td><select class="mr-fund" data-on-change="h74" data-a0="${r.id}">${fundOptionsFor(r.fundId)}</select></td>
        <td><input type="number" class="mr-priority" value="${r.priority||1}" data-on-input="h75" data-a0="${r.id}"></td>
        <td><input type="number" class="mr-alloc" step="0.01" value="${r.allocationPct||0}" data-on-input="h76" data-a0="${r.id}"></td>
        <td><button class="icon-btn" data-on-click="h77" data-a0="${r.id}" title="Delete"><i class="fas fa-trash"></i></button></td>
      </tr>`).join('');
  }

  async function addMypRule() {
    const funds = (await encGetAll('mypFunds')).filter(f => f.planId === currentMypPlanId);
    if (!funds.length) { showToast('Add an account first'); return; }
    const y = new Date().getFullYear();
    await encAdd('mypFundRules', { fundId: funds[0].id, startYear: y, endYear: y, priority: 1, allocationPct: 0 });
    await mypLoadRules();
  }

  const persistMypRuleField = debounce(async (id, field, value) => {
    await encUpdate('mypFundRules', id, { [field]: value });
  }, 300);
  function updateMypRuleField(id, field, value) {
    if (field === 'fundId') { encUpdate('mypFundRules', id, { fundId: value }); return; } // select change — commit immediately, no debounce needed
    persistMypRuleField(id, field, value);
  }

  async function deleteMypRule(id) {
    if (!confirm('Delete this staged rule?')) return;
    await db.mypFundRules.delete(id);
    showToast('Rule deleted');
    await mypLoadRules();
  }

  // ---------- Income Timeline (one block per item, same year-range pattern as Insurance policies above) ----------
  async function mypLoadIncome() {
    const cats = (await encGetAll('mypIncomeCategories')).filter(c => c.planId === currentMypPlanId);
    const allRanges = await encGetAll('mypIncomeRanges');
    const container = document.getElementById('myp-income-container');
    document.getElementById('myp-income-empty').style.display = cats.length ? 'none' : '';
    container.innerHTML = cats.map(c => {
      const ranges = allRanges.filter(r => r.categoryId === c.id);
      const rangeRows = ranges.map(r => `
        <tr data-id="${r.id}">
          <td><input type="number" class="mir-start" value="${r.startYear??''}" data-on-input="h78" data-a0="${r.id}"></td>
          <td><input type="number" class="mir-end" value="${r.endYear??''}" data-on-input="h79" data-a0="${r.id}"></td>
          <td><input type="text" inputmode="decimal" class="mir-amt" value="${moneyInputFormat(r.amount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h80" data-a0="${r.id}"></td>
          <td><button class="icon-btn" data-on-click="h81" data-a0="${r.id}" title="Delete this range"><i class="fas fa-trash"></i></button></td>
        </tr>`).join('');
      return `<div class="policy-block" data-cat-id="${c.id}">
        <div class="policy-header">
          <div class="policy-name-wrap">
            <label>Item</label>
            <input type="text" class="policy-name" value="${escapeAttr(c.name||'')}" placeholder="e.g. Salary" data-on-input="h82" data-a0="${c.id}">
          </div>
          <button class="btn btn-sm btn-add add-range-btn" data-on-click="h83" data-a0="${c.id}"><i class="fas fa-plus"></i> Add Year Range</button>
          <button class="icon-btn" data-on-click="h84" data-a0="${c.id}" title="Delete entire item"><i class="fas fa-trash"></i></button>
        </div>
        <table class="range-table">
          <thead><tr><th>Start Year</th><th>End Year</th><th style="width:140px;">Amount / yr ($)</th><th style="width:40px;"></th></tr></thead>
          <tbody>${rangeRows}</tbody>
        </table>
        ${ranges.length ? '' : '<div class="policy-empty-hint">No ranges yet — click the button above to add one</div>'}
      </div>`;
    }).join('');
  }

  async function addMypIncomeCat() {
    await encAdd('mypIncomeCategories', { planId: currentMypPlanId, name: '' });
    await mypLoadIncome();
  }
  const persistMypIncomeCatField = debounce(async (id, field, value) => {
    await encUpdate('mypIncomeCategories', id, { [field]: value });
  }, 300);
  function updateMypIncomeCatField(id, field, value) { persistMypIncomeCatField(id, field, value); }

  async function deleteMypIncomeCat(id) {
    if (!confirm('Delete this income item and its year ranges?')) return;
    await db.mypIncomeRanges.where('categoryId').equals(id).delete();
    await db.mypIncomeCategories.delete(id);
    showToast('Income item deleted');
    await mypLoadIncome();
  }

  async function addMypIncomeRange(categoryId) {
    const ranges = (await encGetAll('mypIncomeRanges')).filter(r => r.categoryId === categoryId);
    const lastTo = ranges.length ? Math.max(...ranges.map(r => r.endYear || r.startYear || 0)) : new Date().getFullYear() - 1;
    const nextYear = (lastTo || new Date().getFullYear() - 1) + 1;
    await encAdd('mypIncomeRanges', { categoryId, startYear: nextYear, endYear: nextYear, amount: 0 });
    await mypLoadIncome();
  }
  const persistMypIncomeRangeField = debounce(async (id, field, value) => {
    await encUpdate('mypIncomeRanges', id, { [field]: value });
  }, 300);
  function updateMypIncomeRangeField(id, field, value) { persistMypIncomeRangeField(id, field, value); }

  async function deleteMypIncomeRange(id) {
    await db.mypIncomeRanges.delete(id);
    await mypLoadIncome();
  }

  // ---------- Expense Budget (identical pattern to Income Timeline above) ----------
  async function mypLoadExpense() {
    const cats = (await encGetAll('mypExpenseCategories')).filter(c => c.planId === currentMypPlanId);
    const allRanges = await encGetAll('mypExpenseRanges');
    const container = document.getElementById('myp-expense-container');
    document.getElementById('myp-expense-empty').style.display = cats.length ? 'none' : '';
    container.innerHTML = cats.map(c => {
      const ranges = allRanges.filter(r => r.categoryId === c.id);
      const rangeRows = ranges.map(r => `
        <tr data-id="${r.id}">
          <td><input type="number" class="mer-start" value="${r.startYear??''}" data-on-input="h85" data-a0="${r.id}"></td>
          <td><input type="number" class="mer-end" value="${r.endYear??''}" data-on-input="h86" data-a0="${r.id}"></td>
          <td><input type="text" inputmode="decimal" class="mer-amt" value="${moneyInputFormat(r.amount)}" data-on-focus="h41" data-on-blur="h42" data-on-input="h87" data-a0="${r.id}"></td>
          <td><button class="icon-btn" data-on-click="h88" data-a0="${r.id}" title="Delete this range"><i class="fas fa-trash"></i></button></td>
        </tr>`).join('');
      return `<div class="policy-block" data-cat-id="${c.id}">
        <div class="policy-header">
          <div class="policy-name-wrap">
            <label>Item</label>
            <input type="text" class="policy-name" value="${escapeAttr(c.name||'')}" placeholder="e.g. Rent / Mortgage" data-on-input="h89" data-a0="${c.id}">
          </div>
          <button class="btn btn-sm btn-add add-range-btn" data-on-click="h90" data-a0="${c.id}"><i class="fas fa-plus"></i> Add Year Range</button>
          <button class="icon-btn" data-on-click="h91" data-a0="${c.id}" title="Delete entire item"><i class="fas fa-trash"></i></button>
        </div>
        <table class="range-table">
          <thead><tr><th>Start Year</th><th>End Year</th><th style="width:140px;">Amount / yr ($)</th><th style="width:40px;"></th></tr></thead>
          <tbody>${rangeRows}</tbody>
        </table>
        ${ranges.length ? '' : '<div class="policy-empty-hint">No ranges yet — click the button above to add one</div>'}
      </div>`;
    }).join('');
  }

  async function addMypExpenseCat() {
    await encAdd('mypExpenseCategories', { planId: currentMypPlanId, name: '' });
    await mypLoadExpense();
  }
  const persistMypExpenseCatField = debounce(async (id, field, value) => {
    await encUpdate('mypExpenseCategories', id, { [field]: value });
  }, 300);
  function updateMypExpenseCatField(id, field, value) { persistMypExpenseCatField(id, field, value); }

  async function deleteMypExpenseCat(id) {
    if (!confirm('Delete this expense item and its year ranges?')) return;
    await db.mypExpenseRanges.where('categoryId').equals(id).delete();
    await db.mypExpenseCategories.delete(id);
    showToast('Expense item deleted');
    await mypLoadExpense();
  }

  async function addMypExpenseRange(categoryId) {
    const ranges = (await encGetAll('mypExpenseRanges')).filter(r => r.categoryId === categoryId);
    const lastTo = ranges.length ? Math.max(...ranges.map(r => r.endYear || r.startYear || 0)) : new Date().getFullYear() - 1;
    const nextYear = (lastTo || new Date().getFullYear() - 1) + 1;
    await encAdd('mypExpenseRanges', { categoryId, startYear: nextYear, endYear: nextYear, amount: 0 });
    await mypLoadExpense();
  }
  const persistMypExpenseRangeField = debounce(async (id, field, value) => {
    await encUpdate('mypExpenseRanges', id, { [field]: value });
  }, 300);
  function updateMypExpenseRangeField(id, field, value) { persistMypExpenseRangeField(id, field, value); }

  async function deleteMypExpenseRange(id) {
    await db.mypExpenseRanges.delete(id);
    await mypLoadExpense();
  }

  // ---------- Forecast Engine ----------
  // If the current plan has a saved forecast, restore it into view (so
  // switching plans never leaves the Forecast sub-tab stuck showing a
  // different plan's numbers). Otherwise clears the forecast display.
  async function mypLoadOrClearForecastForCurrentPlan() {
    const saved = (await encGetAll('mypSavedForecasts')).find(s => s.planId === currentMypPlanId);
    if (saved) {
      mypForecastData = saved.tableData;
      mypForecastFundsList = saved.fundsList;
      document.getElementById('mypStartYear').value = saved.startYear;
      document.getElementById('mypEndYear').value = saved.endYear;
      mypRenderForecastOutputs(saved.summary, saved.fundsList, saved.tableData, saved.tableData.map(d => d.year));
    } else {
      mypForecastData = [];
      mypForecastFundsList = [];
      document.getElementById('mypSummaryCards').innerHTML = '';
      document.getElementById('mypSnapshotYear').innerHTML = '';
      document.getElementById('mypSnapshotCards').innerHTML = '';
      document.getElementById('mypForecastTableHead').innerHTML = '';
      document.getElementById('mypForecastTableBody').innerHTML = '';
      document.getElementById('mypForecastEmpty').style.display = '';
      document.getElementById('mypChartWrap').style.display = 'none';
      if (mypChart) { mypChart.destroy(); mypChart = null; }
    }
    await mypRenderBaselineComparisonTable();
  }

  async function mypRunForecast() {
    const startYear = parseInt(document.getElementById('mypStartYear').value);
    const endYear = parseInt(document.getElementById('mypEndYear').value);
    if (!startYear || !endYear || endYear < startYear) { showToast('Please enter a valid year range'); return; }

    const funds = (await encGetAll('mypFunds')).filter(f => f.planId === currentMypPlanId);
    const allRules = await encGetAll('mypFundRules');
    const incomeCats = (await encGetAll('mypIncomeCategories')).filter(c => c.planId === currentMypPlanId);
    const allIncomeRanges = await encGetAll('mypIncomeRanges');
    const expenseCats = (await encGetAll('mypExpenseCategories')).filter(c => c.planId === currentMypPlanId);
    const allExpenseRanges = await encGetAll('mypExpenseRanges');

    let currentBalances = {};
    funds.forEach(f => currentBalances[f.id] = parseFloat(f.initialAmount) || 0);

    const years = [], tableData = [];
    const summary = { totalIncome: 0, totalExpense: 0, totalInterest: 0 };

    for (let year = startYear; year <= endYear; year++) {
      years.push(year);

      const yearRules = funds.map(f => {
        const rule = allRules.find(r => r.fundId === f.id && year >= r.startYear && year <= r.endYear);
        return {
          id: f.id, name: f.name, returnRate: parseFloat(f.returnRate) || 0,
          allocationPct: rule ? (parseFloat(rule.allocationPct) || 0) : 0,
          priority: rule ? parseInt(rule.priority) : 99
        };
      });
      const totalAlloc = yearRules.reduce((s, r) => s + r.allocationPct, 0);
      const allocWeights = {};
      yearRules.forEach(r => allocWeights[r.id] = totalAlloc > 0 ? (r.allocationPct / totalAlloc) : (funds.length ? 1 / funds.length : 0));
      const sortedForDeficit = [...yearRules].sort((a, b) => a.priority - b.priority);

      let yearIncome = 0, yearExpense = 0;
      const incomeDetail = [], expenseDetail = [];
      incomeCats.forEach(c => {
        allIncomeRanges.filter(r => r.categoryId === c.id).forEach(r => {
          if (year >= r.startYear && year <= r.endYear) {
            const amt = parseFloat(r.amount) || 0;
            yearIncome += amt;
            if (amt) incomeDetail.push(`${escapeAttr(c.name)}: ${formatMoney(amt)}`);
          }
        });
      });
      expenseCats.forEach(c => {
        allExpenseRanges.filter(r => r.categoryId === c.id).forEach(r => {
          if (year >= r.startYear && year <= r.endYear) {
            const amt = parseFloat(r.amount) || 0;
            yearExpense += amt;
            if (amt) expenseDetail.push(`${escapeAttr(c.name)}: ${formatMoney(amt)}`);
          }
        });
      });

      const surplus = yearIncome - yearExpense;
      const fundFlows = [];
      if (surplus >= 0) {
        yearRules.forEach(f => {
          const add = surplus * allocWeights[f.id];
          currentBalances[f.id] += add;
          if (add > 0) fundFlows.push(`${escapeAttr(f.name)}: +${formatMoney(add)}`);
        });
      } else {
        let deficit = Math.abs(surplus);
        for (const f of sortedForDeficit) {
          if (deficit <= 0) break;
          const avail = currentBalances[f.id];
          const deduct = Math.min(avail, deficit);
          currentBalances[f.id] -= deduct;
          deficit -= deduct;
          if (deduct > 0) fundFlows.push(`${escapeAttr(f.name)}: -${formatMoney(deduct)} (P${f.priority})`);
        }
      }

      let yearInterest = 0;
      yearRules.forEach(f => {
        const interest = currentBalances[f.id] * (f.returnRate / 100);
        currentBalances[f.id] += interest;
        yearInterest += interest;
      });

      const totalAllFunds = funds.reduce((t, f) => t + (currentBalances[f.id] || 0), 0);
      summary.totalIncome += yearIncome;
      summary.totalExpense += yearExpense;
      summary.totalInterest += yearInterest;

      tableData.push({ year, income: yearIncome, expense: yearExpense, balance: surplus, interest: yearInterest, fundBalances: { ...currentBalances }, totalAllFunds, fundFlows, incomeDetail, expenseDetail });
    }

    mypForecastData = tableData;
    mypForecastFundsList = funds;

    mypRenderForecastOutputs(summary, funds, tableData, years);
    await mypSaveForecastSnapshot(startYear, endYear, summary, tableData, funds);
    await mypRenderBaselineComparisonTable();
  }

  // Renders summary cards, the chart, the year-snapshot dropdown, and the
  // year-by-year table from a forecast result — shared by a fresh run
  // (mypRunForecast) and restoring a previously saved snapshot.
  function mypRenderForecastOutputs(summary, funds, tableData, years) {
    document.getElementById('mypForecastEmpty').style.display = 'none';
    const netSurplus = summary.totalIncome - summary.totalExpense;
    document.getElementById('mypSummaryCards').innerHTML = `
      <div class="myp-stat-card"><div class="myp-stat-label">Total Income</div><div class="myp-stat-value" style="color:var(--green);">${formatMoney(summary.totalIncome)}</div></div>
      <div class="myp-stat-card"><div class="myp-stat-label">Total Expense</div><div class="myp-stat-value" style="color:var(--red);">${formatMoney(summary.totalExpense)}</div></div>
      <div class="myp-stat-card"><div class="myp-stat-label">Total Interest / Return</div><div class="myp-stat-value" style="color:var(--orange);">${formatMoney(summary.totalInterest)}</div></div>
      <div class="myp-stat-card"><div class="myp-stat-label">Net Surplus</div><div class="myp-stat-value" style="color:${netSurplus>=0?'var(--green)':'var(--red)'};">${netSurplus<0?'-':''}${formatMoney(Math.abs(netSurplus))}</div></div>`;

    const yearSelect = document.getElementById('mypSnapshotYear');
    yearSelect.innerHTML = years.map(y => `<option value="${y}">${y}</option>`).join('');
    mypUpdateYearSnapshot();

    document.getElementById('mypChartWrap').style.display = '';
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? 'rgba(148,163,184,.15)' : 'rgba(15,23,42,.08)';
    const tickColor = isDark ? '#94a3b8' : '#55617a';
    // Pull the *live* theme colors instead of hardcoding light-theme hex values —
    // previously this used fixed rgba() values that matched only the light theme,
    // so bars looked muddy/mismatched against the dark theme's brighter palette.
    const rootStyle = getComputedStyle(document.documentElement);
    const incomeColor = hexToRgba(rootStyle.getPropertyValue('--green'), 0.75);
    const expenseColor = hexToRgba(rootStyle.getPropertyValue('--red'), 0.75);
    if (mypChart) mypChart.destroy();
    mypChart = new Chart(document.getElementById('mypForecastChart').getContext('2d'), {
      type: 'bar',
      data: {
        labels: years,
        datasets: [
          { label: 'Income', data: tableData.map(d => d.income), backgroundColor: incomeColor },
          { label: 'Expense', data: tableData.map(d => d.expense), backgroundColor: expenseColor }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: { x: { ticks: { color: tickColor }, grid: { color: gridColor } }, y: { ticks: { color: tickColor }, grid: { color: gridColor } } },
        plugins: { legend: { labels: { color: tickColor } } }
      }
    });

    let th = '<th>Year</th><th>Income</th><th>Expense</th><th>Net</th><th>Interest</th>';
    funds.forEach(f => th += `<th>${escapeAttr(f.name || 'Unnamed account')}</th>`);
    th += '<th style="color:var(--blue);">Total All Accounts</th><th>Flows</th>';
    document.getElementById('mypForecastTableHead').innerHTML = th;
    document.getElementById('mypForecastTableBody').innerHTML = tableData.map(d => `
      <tr>
        <td><b>${d.year}</b></td>
        <td style="color:var(--green);">${formatMoney(d.income)}${d.incomeDetail.length ? `<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px;">${d.incomeDetail.join('<br>')}</div>` : ''}</td>
        <td style="color:var(--red);">${formatMoney(d.expense)}${d.expenseDetail.length ? `<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px;">${d.expenseDetail.join('<br>')}</div>` : ''}</td>
        <td style="color:${d.balance >= 0 ? 'var(--green)' : 'var(--red)'};">${d.balance<0?'-':''}${formatMoney(Math.abs(d.balance))}</td>
        <td style="color:var(--orange);">+${formatMoney(d.interest)}</td>
        ${funds.map(f => `<td>${formatMoney(d.fundBalances[f.id])}</td>`).join('')}
        <td style="font-weight:700;color:var(--blue);">${formatMoney(d.totalAllFunds)}</td>
        <td style="font-size:11px;">${d.fundFlows.join('<br>')}</td>
      </tr>`).join('');
  }

  // One saved snapshot per plan (replaces any existing one on re-run), so a
  // generated forecast survives closing the tab / switching plans and back.
  async function mypSaveForecastSnapshot(startYear, endYear, summary, tableData, funds) {
    const existing = (await db.mypSavedForecasts.where('planId').equals(currentMypPlanId).toArray())[0];
    const data = {
      planId: currentMypPlanId, startYear, endYear, summary, tableData,
      fundsList: funds.map(f => ({ id: f.id, name: f.name })),
      generatedAt: new Date().toISOString()
    };
    if (existing) await encUpdate('mypSavedForecasts', existing.id, data);
    else await encAdd('mypSavedForecasts', data);
  }

  function mypUpdateYearSnapshot() {
    const yearSelect = document.getElementById('mypSnapshotYear');
    const selectedYear = parseInt(yearSelect.value);
    const dataRow = mypForecastData.find(d => d.year === selectedYear);
    const container = document.getElementById('mypSnapshotCards');
    if (!dataRow) { container.innerHTML = ''; return; }
    let html = `<div class="myp-stat-card" style="border-color:var(--blue);"><div class="myp-stat-label">${selectedYear} Total All Accounts</div><div class="myp-stat-value" style="color:var(--blue);">${formatMoney(dataRow.totalAllFunds)}</div></div>`;
    mypForecastFundsList.forEach(f => {
      const bal = dataRow.fundBalances[f.id] || 0;
      html += `<div class="myp-stat-card"><div class="myp-stat-label">${escapeAttr(f.name || 'Unnamed account')}</div><div class="myp-stat-value">${formatMoney(bal)}</div></div>`;
    });
    container.innerHTML = html;
  }

  // ---------- Baseline vs. Actual ----------
  function mypVarianceCellsHtml(actualVal, lastBaselineVal) {
    if (actualVal !== '' && actualVal != null) {
      const diff = actualVal - lastBaselineVal;
      const pct = lastBaselineVal !== 0 ? ((diff / lastBaselineVal) * 100).toFixed(1) : '0.0';
      const color = diff > 0 ? 'var(--green)' : (diff < 0 ? 'var(--red)' : 'var(--muted)');
      const sign = diff > 0 ? '+' : (diff < 0 ? '-' : '');
      return `<td style="text-align:right;color:${color};font-weight:600;">${sign}${formatMoney(Math.abs(diff))}</td><td style="text-align:right;color:${color};font-weight:600;">${sign}${Math.abs(pct)}%</td>`;
    }
    return '<td style="text-align:right;color:var(--muted);">&mdash;</td><td style="text-align:right;color:var(--muted);">&mdash;</td>';
  }

  async function mypRenderBaselineComparisonTable() {
    const headerRow = document.getElementById('mypBaselineTableHead');
    const tbody = document.getElementById('mypBaselineTableBody');
    if (!mypForecastData.length) {
      headerRow.innerHTML = '';
      tbody.innerHTML = '<tr><td class="empty-hint">Generate a forecast on the Forecast sub-tab first</td></tr>';
      return;
    }
    const baselines = (await encGetAll('mypBaselines')).filter(b => b.planId === currentMypPlanId);
    const baselineValues = await encGetAll('mypBaselineValues');
    const actuals = (await encGetAll('mypActuals')).filter(a => a.planId === currentMypPlanId);

    const actualsByYear = {}; actuals.forEach(a => actualsByYear[a.year] = a);
    const baselineValMap = {};
    baselineValues.forEach(bv => {
      if (!baselineValMap[bv.baselineId]) baselineValMap[bv.baselineId] = {};
      baselineValMap[bv.baselineId][bv.year] = bv.amount;
    });

    let headHtml = '<th style="text-align:center;">Year</th><th style="text-align:center;color:var(--orange);">Live Forecast</th>';
    baselines.forEach(b => {
      headHtml += `<th style="text-align:center;color:var(--blue);">${escapeAttr(b.name)} <button class="icon-btn" title="Delete baseline column" data-on-click="h92" data-a0="${b.id}">&times;</button></th>`;
    });
    headHtml += '<th style="text-align:center;color:var(--green);">Actual (EOY)</th><th style="text-align:right;">Variance $</th><th style="text-align:right;">Variance %</th>';
    headerRow.innerHTML = headHtml;

    tbody.innerHTML = mypForecastData.map(row => {
      const yr = row.year;
      const liveVal = row.totalAllFunds;
      const actualRow = actualsByYear[yr];
      const actualVal = actualRow ? actualRow.amount : '';
      let lastBaselineVal = liveVal;
      let cols = `<td style="text-align:center;"><b>${yr}</b></td><td style="text-align:center;color:var(--orange);font-weight:600;">${formatMoney(liveVal)}</td>`;
      baselines.forEach(b => {
        const val = (baselineValMap[b.id] && baselineValMap[b.id][yr] != null) ? baselineValMap[b.id][yr] : 0;
        lastBaselineVal = val;
        cols += `<td style="text-align:center;color:var(--blue);font-weight:600;">${formatMoney(val)}</td>`;
      });
      cols += `<td style="text-align:center;">$ <input type="number" class="myp-actual-input" style="width:120px;display:inline-block;text-align:right;" value="${actualVal}" placeholder="Enter actual" autocomplete="off" data-on-change="h93" data-a0="${yr}"></td>`;
      cols += mypVarianceCellsHtml(actualVal, lastBaselineVal);
      return `<tr>${cols}</tr>`;
    }).join('');
  }

  async function mypFreezeBaseline() {
    if (!mypForecastData.length) { showToast('Generate a forecast first'); return; }
    const count = (await encGetAll('mypBaselines')).filter(b => b.planId === currentMypPlanId).length;
    const defaultName = `Baseline ${count + 1} (${new Date().toLocaleDateString()})`;
    const colName = prompt('Name this baseline column:', defaultName);
    if (!colName) return;
    const baselineId = await encAdd('mypBaselines', { name: colName, planId: currentMypPlanId });
    for (const d of mypForecastData) {
      await encAdd('mypBaselineValues', { baselineId, year: d.year, amount: d.totalAllFunds });
    }
    showToast('Baseline frozen!');
    await mypRenderBaselineComparisonTable();
  }

  async function mypDeleteBaseline(id) {
    if (!confirm('Delete this frozen baseline column?')) return;
    await db.mypBaselines.delete(id);
    await db.mypBaselineValues.where('baselineId').equals(id).delete();
    showToast('Baseline deleted');
    await mypRenderBaselineComparisonTable();
  }

  async function mypSaveActualResult(year, val) {
    const existing = (await db.mypActuals.where('year').equals(year).toArray()).find(a => a.planId === currentMypPlanId);
    if (val === '' || val === null) {
      if (existing) await db.mypActuals.delete(existing.id);
    } else {
      const amount = parseFloat(val) || 0;
      if (existing) await encUpdate('mypActuals', existing.id, { year, amount });
      else await encAdd('mypActuals', { year, amount, planId: currentMypPlanId });
    }
    await mypRenderBaselineComparisonTable();
  }


  function escapeAttr(str) {
    return String(str).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  // ========== EXPORT / IMPORT ==========
  async function exportJSON(nameSuffix) {
    const fixedExpenses = await encGetAll('fixedExpenses');
    const policies = await encGetAll('policies');
    const policyRanges = await encGetAll('policyRanges');
    const paidMarks = await db.paidMarks.toArray();
    const incomeForecasts = await encGetAll('incomeForecasts');
    const forecastLines = await encGetAll('forecastLines');
    const mypPlans = await encGetAll('mypPlans');
    const mypFunds = await encGetAll('mypFunds');
    const mypFundRules = await encGetAll('mypFundRules');
    const mypIncomeCategories = await encGetAll('mypIncomeCategories');
    const mypIncomeRanges = await encGetAll('mypIncomeRanges');
    const mypExpenseCategories = await encGetAll('mypExpenseCategories');
    const mypExpenseRanges = await encGetAll('mypExpenseRanges');
    const mypBaselines = await encGetAll('mypBaselines');
    const mypBaselineValues = await encGetAll('mypBaselineValues');
    const mypActuals = await encGetAll('mypActuals');
    const mypSavedForecasts = await encGetAll('mypSavedForecasts');
    const payload = {
      type: 'budget-reference-tables',
      version: 4,
      exportedAt: new Date().toISOString(),
      fixedExpenses,
      policies,
      policyRanges,
      paidMarks,
      incomeForecasts,
      forecastLines,
      mypPlans,
      mypFunds,
      mypFundRules,
      mypIncomeCategories,
      mypIncomeRanges,
      mypExpenseCategories,
      mypExpenseRanges,
      mypBaselines,
      mypBaselineValues,
      mypActuals,
      mypSavedForecasts
    };

    let fileContent;
    const shouldEncrypt = isEncryptionEnabled() && !!encryptionKey;
    if (shouldEncrypt) {
      // Data is encrypted at rest — keep the export encrypted too, under the
      // same passcode/salt, so an exported file is never a plaintext copy.
      const saltB64 = localStorage.getItem('budgetref-encryption-salt');
      const enc = await encryptValue(encryptionKey, payload);
      const encryptedPayload = {
        type: 'budget-reference-tables-encrypted',
        version: 3,
        exportedAt: new Date().toISOString(),
        salt: saltB64,
        iterations: getStoredIterations(),
        enc
      };
      fileContent = JSON.stringify(encryptedPayload, null, 2);
    } else {
      fileContent = JSON.stringify(payload, null, 2);
    }

    const blob = new Blob([fileContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0,10);
    a.href = url;
    a.download = `budget-reference-tables${nameSuffix || ''}_${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast(shouldEncrypt ? '🔒 Encrypted JSON file exported' : 'JSON file exported');
  }

  function isEncryptedExportFile(data) {
    return !!(data && data.type === 'budget-reference-tables-encrypted' && data.enc && data.salt);
  }

  function proceedWithImportData(data) {
    pendingImportData = data;
    const fCount = (data.fixedExpenses||[]).length;
    const pCount = data.policies ? data.policies.length : new Set((data.insurancePolicies||[]).map(r=>r.policyName)).size;
    const fcCount = (data.incomeForecasts||[]).length;
    const planCount = (data.mypPlans||[]).length;
    const extra = (fcCount || planCount)
      ? `, <b>${fcCount}</b> income forecast scenario(s) and <b>${planCount}</b> multi-year planner plan(s)`
      : '';
    document.getElementById('import-modal-body').innerHTML =
      `About to import <b>${fCount}</b> fixed expense record(s), <b>${pCount}</b> policy record(s)${extra}.<br><br>Importing will <b style="color:var(--red)">clear and replace</b> all current data. This cannot be undone. Continue?`;
    document.getElementById('import-modal').classList.add('show');
  }

  function handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';
    if (isWriteLocked()) {
      showToast('🔒 Locked — unlock before importing');
      showUnlockOverlay();
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (isEncryptedExportFile(data)) {
          pendingEncryptedImport = data;
          document.getElementById('import-decrypt-passcode').value = '';
          document.getElementById('import-decrypt-status').textContent = '';
          document.getElementById('import-decrypt-modal').classList.add('show');
          return;
        }
        if (!data.fixedExpenses && !data.policies && !data.insurancePolicies) {
          showToast('Invalid file format');
          return;
        }
        proceedWithImportData(data);
      } catch (err) {
        showToast('JSON parse failed: ' + err.message);
      }
    };
    reader.readAsText(file);
  }

  function closeImportDecryptModal() {
    document.getElementById('import-decrypt-modal').classList.remove('show');
    document.getElementById('import-decrypt-passcode').value = '';
    document.getElementById('import-decrypt-status').textContent = '';
    pendingEncryptedImport = null;
  }

  async function attemptImportDecrypt() {
    const passcode = document.getElementById('import-decrypt-passcode').value;
    const status = document.getElementById('import-decrypt-status');
    if (!passcode) { status.style.color = 'var(--orange)'; status.textContent = 'Enter the passcode.'; return; }
    if (!pendingEncryptedImport) return;
    status.style.color = 'var(--muted)';
    status.textContent = 'Decrypting...';
    try {
      const iterations = safeIterations(pendingEncryptedImport.iterations || PBKDF2_ITERATIONS_LEGACY_DEFAULT); // older export files predate this field
      const { key } = await deriveEncryptionKey(passcode, pendingEncryptedImport.salt, iterations);
      const data = await decryptValue(key, pendingEncryptedImport.enc);
      pendingEncryptedImport = null;
      document.getElementById('import-decrypt-modal').classList.remove('show');
      document.getElementById('import-decrypt-passcode').value = '';
      status.textContent = '';
      proceedWithImportData(data);
    } catch (err) {
      status.style.color = 'var(--red)';
      status.textContent = '❌ Incorrect passcode.';
    }
  }

  function closeImportModal() {
    document.getElementById('import-modal').classList.remove('show');
    pendingImportData = null;
  }

  // ---- import validation: coerce numeric fields, clamp years, drop non-object rows ----
  function importNum(v) { const n = Number(v); return Number.isFinite(n) ? n : 0; }
  function importYear(v) {
    const n = Math.round(Number(v));
    return Number.isFinite(n) ? Math.min(2200, Math.max(1900, n)) : new Date().getFullYear();
  }
  function importRows(x) { return Array.isArray(x) ? x.filter((r) => r && typeof r === 'object' && !Array.isArray(r)) : []; }
  const IMPORT_FIELD_RULES = {
    fixedExpenses: { num: ['monthlyAmt', 'freq'] },
    policyRanges: { num: ['amount'], year: ['fromYear', 'toYear'] },
    paidMarks: { year: ['year'] },
    forecastLines: { num: ['amount', 'ratePct'] },
    mypFunds: { num: ['initialAmount', 'returnRate'] },
    mypFundRules: { num: ['priority', 'allocationPct'], year: ['startYear', 'endYear'] },
    mypIncomeRanges: { num: ['amount'], year: ['startYear', 'endYear'] },
    mypExpenseRanges: { num: ['amount'], year: ['startYear', 'endYear'] },
    mypBaselineValues: { num: ['amount'], year: ['year'] },
    mypActuals: { num: ['amount'], year: ['year'] }
  };
  function cleanRow(table, row) {
    const r = { ...row };
    const rule = IMPORT_FIELD_RULES[table] || {};
    (rule.num || []).forEach((k) => { if (k in r) r[k] = importNum(r[k]); });
    (rule.year || []).forEach((k) => { if (k in r) r[k] = importYear(r[k]); });
    return r;
  }
  // Builds every row in memory with explicit sequential ids and remapped foreign
  // keys, so the DB write can be a single atomic transaction of plain IndexedDB ops.
  function buildImportRows(d) {
    const out = {};
    const put = (table, row) => {
      const arr = out[table] || (out[table] = []);
      const id = arr.length + 1;
      arr.push({ ...cleanRow(table, row), id });
      return id;
    };
    const fk = (map, v) => map[v] ?? importNum(v);

    for (const r of importRows(d.fixedExpenses)) { const { id, ...rest } = r; put('fixedExpenses', rest); }

    if (Array.isArray(d.policies)) {
      const idMap = {};
      for (const p of importRows(d.policies)) {
        const { id, ...rest } = p;
        const newId = put('policies', rest);
        if (id != null) idMap[id] = newId;
      }
      for (const r of importRows(d.policyRanges)) { const { id, policyId, ...rest } = r; put('policyRanges', { ...rest, policyId: fk(idMap, policyId) }); }
      for (const m of importRows(d.paidMarks)) { const { id, policyId, ...rest } = m; put('paidMarks', { ...rest, policyId: fk(idMap, policyId) }); }
    } else if (Array.isArray(d.insurancePolicies)) {
      // legacy (one row per policy per year) format — group into policies + merged year-ranges
      const byName = {};
      for (const r of importRows(d.insurancePolicies)) {
        const name = String(r.policyName || '');
        if (!byName[name]) byName[name] = [];
        byName[name].push({ year: r.year ? importYear(r.year) : 0, amount: importNum(r.amount), note: String(r.note || '') });
      }
      for (const name of Object.keys(byName)) {
        const rows = byName[name].sort((a, b) => a.year - b.year);
        const policyId = put('policies', { name, note: '' });
        let i = 0;
        while (i < rows.length) {
          let j = i;
          while (j + 1 < rows.length && rows[j+1].year === rows[j].year + 1 && rows[j+1].amount === rows[i].amount) j++;
          put('policyRanges', { policyId, fromYear: rows[i].year, toYear: rows[j].year, amount: rows[i].amount, note: rows[i].note || '' });
          i = j + 1;
        }
      }
    }

    if (Array.isArray(d.incomeForecasts)) {
      const forecastIdMap = {};
      for (const f of importRows(d.incomeForecasts)) {
        const { id, ...rest } = f;
        const newId = put('incomeForecasts', rest);
        if (id != null) forecastIdMap[id] = newId;
      }
      for (const l of importRows(d.forecastLines)) { const { id, forecastId, ...rest } = l; put('forecastLines', { ...rest, forecastId: fk(forecastIdMap, forecastId) }); }
    }

    if (Array.isArray(d.mypPlans)) {
      const planIdMap = {}, fundIdMap = {}, incomeCatIdMap = {}, expenseCatIdMap = {}, baselineIdMap = {};
      for (const p of importRows(d.mypPlans)) { const { id, ...rest } = p; const n = put('mypPlans', rest); if (id != null) planIdMap[id] = n; }
      for (const f of importRows(d.mypFunds)) { const { id, planId, ...rest } = f; const n = put('mypFunds', { ...rest, planId: fk(planIdMap, planId) }); if (id != null) fundIdMap[id] = n; }
      for (const r of importRows(d.mypFundRules)) { const { id, fundId, ...rest } = r; put('mypFundRules', { ...rest, fundId: fk(fundIdMap, fundId) }); }
      for (const c of importRows(d.mypIncomeCategories)) { const { id, planId, ...rest } = c; const n = put('mypIncomeCategories', { ...rest, planId: fk(planIdMap, planId) }); if (id != null) incomeCatIdMap[id] = n; }
      for (const r of importRows(d.mypIncomeRanges)) { const { id, categoryId, ...rest } = r; put('mypIncomeRanges', { ...rest, categoryId: fk(incomeCatIdMap, categoryId) }); }
      for (const c of importRows(d.mypExpenseCategories)) { const { id, planId, ...rest } = c; const n = put('mypExpenseCategories', { ...rest, planId: fk(planIdMap, planId) }); if (id != null) expenseCatIdMap[id] = n; }
      for (const r of importRows(d.mypExpenseRanges)) { const { id, categoryId, ...rest } = r; put('mypExpenseRanges', { ...rest, categoryId: fk(expenseCatIdMap, categoryId) }); }
      for (const b of importRows(d.mypBaselines)) { const { id, planId, ...rest } = b; const n = put('mypBaselines', { ...rest, planId: fk(planIdMap, planId) }); if (id != null) baselineIdMap[id] = n; }
      for (const v of importRows(d.mypBaselineValues)) { const { id, baselineId, ...rest } = v; put('mypBaselineValues', { ...rest, baselineId: fk(baselineIdMap, baselineId) }); }
      for (const a of importRows(d.mypActuals)) { const { id, planId, ...rest } = a; put('mypActuals', { ...rest, planId: fk(planIdMap, planId) }); }
      // saved forecast snapshots are self-contained blobs; only the plan FK is remapped
      for (const s2 of importRows(d.mypSavedForecasts)) { const { id, planId, ...rest } = s2; put('mypSavedForecasts', { ...rest, planId: fk(planIdMap, planId) }); }
    }
    return out;
  }

  async function confirmImport() {
    if (!pendingImportData) return;
    if (isWriteLocked()) {
      closeImportModal();
      showToast('🔒 Locked — unlock before importing');
      showUnlockOverlay();
      return;
    }
    const ALL_IMPORT_TABLES = [...ENC_TABLES, 'paidMarks'];
    try {
      // 1. safety net: download a backup of what is about to be replaced
      const counts = await Promise.all(ALL_IMPORT_TABLES.map((t) => db[t].count()));
      if (counts.some((c) => c > 0)) await exportJSON('-before-import');
      // 2. build + validate + encrypt everything in memory (no DB writes yet)
      const out = buildImportRows(pendingImportData);
      for (const t of ENC_TABLES) {
        if (out[t]) out[t] = await Promise.all(out[t].map((r) => encryptRecord(t, r)));
      }
      // 3. replace everything in ONE transaction: all-or-nothing
      await db.transaction('rw', ALL_IMPORT_TABLES.map((t) => db[t]), async () => {
        for (const t of ALL_IMPORT_TABLES) {
          await db[t].clear();
          if (out[t] && out[t].length) await db[t].bulkAdd(out[t]);
        }
      });
    } catch (e) {
      console.error('Import failed', e);
      closeImportModal();
      showToast('❌ Import failed — your existing data was not changed');
      return;
    }

    closeImportModal();
    await renderFixedTable();
    await renderInsTable();
    await renderForecasts();
    await mypInitPlanner();
    showToast('Import successful');
  }

  // ========== INIT ==========
  (async function init() {
    initTheme();
    await restoreEncMetaIfLost();
    updateEncNavBtn();
    if (isEncryptionEnabled()) {
      showUnlockOverlay(); // data stays locked until a correct passcode is entered
    } else {
      await renderFixedTable();
      await renderInsTable();
      await renderForecasts();
      await mypInitPlanner();
      gcOrphanedPaidMarks(); // catch-all sweep for any orphans left over from before this cleanup existed
    }
  })();

  // ========== PWA: SERVICE WORKER (offline caching) ==========
  // Registered from a relative path so the app works whether it's served
  // from a domain root or a GitHub Pages project subpath (e.g. /repo-name/).
  // No-ops harmlessly if opened directly from disk (file://) or if the
  // browser doesn't support service workers.
  if ('serviceWorker' in navigator && (location.protocol === 'http:' || location.protocol === 'https:')) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('sw.js').catch((err) => {
        console.warn('Service worker registration failed:', err);
      });
    });
  }

// ===== UI event handlers (replaces inline on*= attributes; lets the CSP drop script-src 'unsafe-inline') =====
// Markup carries data-on-<event>="hN" (+ data-a0.. numeric args); one delegated listener per event type dispatches here.
const UI_HANDLERS = {
  h1: (el, event, a) => { toggleTheme(); }, // click
  h2: (el, event, a) => { openEncryptionModal(); }, // click
  h3: (el, event, a) => { lockNow(); }, // click
  h4: (el, event, a) => { exportJSON(); }, // click
  h5: (el, event, a) => { document.getElementById('import-file-input').click(); }, // click
  h6: (el, event, a) => { handleImportFile(event); }, // change
  h7: (el, event, a) => { switchTab('fixed'); }, // click
  h8: (el, event, a) => { switchTab('ins'); }, // click
  h9: (el, event, a) => { switchTab('forecast'); }, // click
  h10: (el, event, a) => { switchTab('myp'); }, // click
  h11: (el, event, a) => { addFixedRow(); }, // click
  h12: (el, event, a) => { addPolicy(); }, // click
  h13: (el, event, a) => { addForecast(); }, // click
  h14: (el, event, a) => { mypSwitchPlan(el.value); }, // change
  h15: (el, event, a) => { mypCreatePlan(); }, // click
  h16: (el, event, a) => { mypRenamePlan(); }, // click
  h17: (el, event, a) => { mypDeletePlan(); }, // click
  h18: (el, event, a) => { mypSwitchSubTab('setup'); }, // click
  h19: (el, event, a) => { mypSwitchSubTab('forecast'); }, // click
  h20: (el, event, a) => { mypSwitchSubTab('baseline'); }, // click
  h21: (el, event, a) => { addMypFund(); }, // click
  h22: (el, event, a) => { addMypRule(); }, // click
  h23: (el, event, a) => { addMypIncomeCat(); }, // click
  h24: (el, event, a) => { addMypExpenseCat(); }, // click
  h25: (el, event, a) => { mypRunForecast(); }, // click
  h26: (el, event, a) => { mypUpdateYearSnapshot(); }, // change
  h27: (el, event, a) => { mypFreezeBaseline(); }, // click
  h28: (el, event, a) => { closeImportModal(); }, // click
  h29: (el, event, a) => { confirmImport(); }, // click
  h30: (el, event, a) => { if(event.key==='Enter') attemptImportDecrypt(); }, // keydown
  h31: (el, event, a) => { closeImportDecryptModal(); }, // click
  h32: (el, event, a) => { attemptImportDecrypt(); }, // click
  h33: (el, event, a) => { closeEncryptionModal(); }, // click
  h34: (el, event, a) => { submitEnableEncryption(); }, // click
  h35: (el, event, a) => { submitDisableEncryption(); }, // click
  h36: (el, event, a) => { if(event.key==='Enter') attemptUnlock(); }, // keydown
  h37: (el, event, a) => { attemptUnlock(); }, // click
  h38: (el, event, a) => { updateFixedField(a[0], 'category', el.value); }, // input
  h39: (el, event, a) => { handleCategoryChange(a[0], el.value); }, // change
  h40: (el, event, a) => { updateFixedField(a[0], 'item', el.value); }, // input
  h41: (el, event, a) => { moneyFieldFocus(el); }, // focus
  h42: (el, event, a) => { moneyFieldBlur(el); }, // blur
  h43: (el, event, a) => { updateFixedField(a[0], 'monthlyAmt', moneyInputParse(el.value)); recalcFixedRow(el); }, // input
  h44: (el, event, a) => { updateFixedField(a[0], 'freq', parseFloat(el.value)); recalcFixedRow(el); }, // change
  h45: (el, event, a) => { updateFixedField(a[0], 'note', el.value); }, // input
  h46: (el, event, a) => { updateFixedField(a[0], 'dueDate', el.value); }, // input
  h47: (el, event, a) => { deleteFixedRow(a[0]); }, // click
  h48: (el, event, a) => { updateRangeField(a[0], 'fromYear', parseInt(el.value)||0); renderInsSummary(); }, // input
  h49: (el, event, a) => { updateRangeField(a[0], 'toYear', parseInt(el.value)||0); renderInsSummary(); }, // input
  h50: (el, event, a) => { updateRangeField(a[0], 'amount', moneyInputParse(el.value)); renderInsSummary(); }, // input
  h51: (el, event, a) => { deleteRange(a[0]); }, // click
  h52: (el, event, a) => { updatePolicyField(a[0], 'name', el.value); renderInsSummary(); }, // input
  h53: (el, event, a) => { updatePolicyField(a[0], 'note', el.value); autoSizeInput(el); renderInsSummary(); }, // input
  h54: (el, event, a) => { refreshPolicyNoteArea(a[0]); }, // blur
  h55: (el, event, a) => { showPolicyNoteInput(a[0]); }, // click
  h56: (el, event, a) => { addRange(a[0]); }, // click
  h57: (el, event, a) => { deletePolicy(a[0]); }, // click
  h58: (el, event, a) => { markEntryPaid(a[0], a[1]); }, // click
  h59: (el, event, a) => { restoreYear(a[0]); }, // click
  h60: (el, event, a) => { updateForecastLineField(a[0],'label',el.value); }, // input
  h61: (el, event, a) => { updateForecastLineField(a[0],'amount',moneyInputParse(el.value)); recalcForecastRow(el); }, // input
  h62: (el, event, a) => { updateForecastLineField(a[0],'ratePct',parseFloat(el.value)||0); recalcForecastRow(el); }, // input
  h63: (el, event, a) => { deleteForecastLine(a[0]); }, // click
  h64: (el, event, a) => { updateForecastField(a[0],'name',el.value); }, // input
  h65: (el, event, a) => { deleteForecast(a[0]); }, // click
  h66: (el, event, a) => { addForecastLine(a[0],'account'); }, // click
  h67: (el, event, a) => { addForecastLine(a[0],'rental'); }, // click
  h68: (el, event, a) => { updateMypFundField(a[0],'name',el.value); }, // input
  h69: (el, event, a) => { updateMypFundField(a[0],'initialAmount',moneyInputParse(el.value)); }, // input
  h70: (el, event, a) => { updateMypFundField(a[0],'returnRate',parseFloat(el.value)||0); }, // input
  h71: (el, event, a) => { deleteMypFund(a[0]); }, // click
  h72: (el, event, a) => { updateMypRuleField(a[0],'startYear',parseInt(el.value)||0); }, // input
  h73: (el, event, a) => { updateMypRuleField(a[0],'endYear',parseInt(el.value)||0); }, // input
  h74: (el, event, a) => { updateMypRuleField(a[0],'fundId',parseInt(el.value)); }, // change
  h75: (el, event, a) => { updateMypRuleField(a[0],'priority',parseInt(el.value)||1); }, // input
  h76: (el, event, a) => { updateMypRuleField(a[0],'allocationPct',parseFloat(el.value)||0); }, // input
  h77: (el, event, a) => { deleteMypRule(a[0]); }, // click
  h78: (el, event, a) => { updateMypIncomeRangeField(a[0],'startYear',parseInt(el.value)||0); }, // input
  h79: (el, event, a) => { updateMypIncomeRangeField(a[0],'endYear',parseInt(el.value)||0); }, // input
  h80: (el, event, a) => { updateMypIncomeRangeField(a[0],'amount',moneyInputParse(el.value)); }, // input
  h81: (el, event, a) => { deleteMypIncomeRange(a[0]); }, // click
  h82: (el, event, a) => { updateMypIncomeCatField(a[0],'name',el.value); }, // input
  h83: (el, event, a) => { addMypIncomeRange(a[0]); }, // click
  h84: (el, event, a) => { deleteMypIncomeCat(a[0]); }, // click
  h85: (el, event, a) => { updateMypExpenseRangeField(a[0],'startYear',parseInt(el.value)||0); }, // input
  h86: (el, event, a) => { updateMypExpenseRangeField(a[0],'endYear',parseInt(el.value)||0); }, // input
  h87: (el, event, a) => { updateMypExpenseRangeField(a[0],'amount',moneyInputParse(el.value)); }, // input
  h88: (el, event, a) => { deleteMypExpenseRange(a[0]); }, // click
  h89: (el, event, a) => { updateMypExpenseCatField(a[0],'name',el.value); }, // input
  h90: (el, event, a) => { addMypExpenseRange(a[0]); }, // click
  h91: (el, event, a) => { deleteMypExpenseCat(a[0]); }, // click
  h92: (el, event, a) => { mypDeleteBaseline(a[0]); }, // click
  h93: (el, event, a) => { mypSaveActualResult(a[0], el.value); }, // change
};
(function () {
  const types = { click: 'click', input: 'input', change: 'change', keydown: 'keydown', focus: 'focusin', blur: 'focusout' };
  Object.keys(types).forEach((name) => {
    document.addEventListener(types[name], (event) => {
      const el = event.target && event.target.closest ? event.target.closest('[data-on-' + name + ']') : null;
      if (!el) return;
      const fn = UI_HANDLERS[el.getAttribute('data-on-' + name)];
      if (!fn) return;
      const a = [];
      for (let i = 0; el.dataset['a' + i] !== undefined; i++) a.push(Number(el.dataset['a' + i]));
      fn(el, event, a);
    });
  });
})();
