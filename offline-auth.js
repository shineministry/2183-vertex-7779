/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   v20260609-clean

   Authentication method: LOCAL PBKDF2 + SHA-256 server-hash,
   stored in IndexedDB (vaultOfflineDB). No server required after
   first online login.

   ALL 7 VAULT MODES are cached on the device after the first
   online login by any member. Every device can then authenticate
   any of the 7 modes fully offline.

   Algo types stored in vault_auth:
     'pbkdf2-sha256-200k' — current user, hashed locally (most secure)
     'sha256-server'      — all-members sync, hash from server env vars
     (legacy) plain       — v3 records, plain sha256, backward compat

   Public API:
     syncOfflineAuth()      — saves current user after online login
     syncAllMembersOffline()— fetches all 7 modes from backend, saves all
     offlineLogin(_, pass)  — full-password offline verify → secret | false
     idbSetVaultMeta(data)  — caches file list
     idbGetVaultMeta()      — returns cached file list
     idbSaveDoc(key, buf)   — caches encrypted document bytes
     idbGetDoc(key)         — returns cached encrypted document bytes
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260609-clean';

const _WORKER_URL = 'https://backend.shinumaths989.workers.dev';

// ── IndexedDB setup ────────────────────────────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 8;

function _openAuthDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_AUTH_DB_NAME, _AUTH_DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('pm_entries'))
                db.createObjectStore('pm_entries',  { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault_docs'))
                db.createObjectStore('vault_docs',  { keyPath: 'filename' });
            if (!db.objectStoreNames.contains('vault_meta'))
                db.createObjectStore('vault_meta',  { keyPath: 'key' });
            if (!db.objectStoreNames.contains('vault_auth'))
                db.createObjectStore('vault_auth',  { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault_notifications'))
                db.createObjectStore('vault_notifications', { keyPath: 'id', autoIncrement: true });
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

function _randomSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// PBKDF2 — used for current-user sync (typed password, 200k rounds)
async function _pbkdf2Hash(text, hexSalt, iterations = 200_000) {
    const enc    = new TextEncoder();
    const salt   = Uint8Array.from(hexSalt.match(/.{2}/g), h => parseInt(h, 16));
    const keyMat = await crypto.subtle.importKey(
        'raw', enc.encode(String(text)), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
        keyMat, 256
    );
    return Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// SHA-256 matching auth.js hashPassword() exactly:
// password.trim().normalize("NFKC") → SHA-256 → hex
async function _sha256AuthHash(password) {
    const normalized = String(password).trim().normalize('NFKC');
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(normalized)
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// Legacy plain SHA-256 (no normalize) — backward compat with v3 records
async function _sha256Legacy(text) {
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Write helpers ──────────────────────────────────────────────────────────

async function _saveAuthRecordLocal({ mode, password, secret, token }) {
    const salt         = _randomSalt();
    const passwordHash = await _pbkdf2Hash(password, salt);
    const loginHash    = await _sha256AuthHash(password);
    const db           = await _openAuthDB();

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode + '-pbkdf2',
            passwordHash,
            loginHash,
            salt,
            algo:         'pbkdf2-sha256-200k',
            secret:       String(secret || password),
            token:        token || '',
            mode,
            trusted:      true,
            savedAt:      Date.now()
        });
        tx.oncomplete = res;
        tx.onerror = tx.onabort = () => rej(tx.error);
    });
}

async function _saveAuthRecordFromServerHash({ mode, passwordHash, secret, token }) {
    const db = await _openAuthDB();

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode + '-sha256',
            passwordHash,
            algo:         'sha256-server',
            secret:       String(secret || ''),
            token:        token || '',
            mode,
            trusted:      true,
            savedAt:      Date.now()
        });
        tx.oncomplete = res;
        tx.onerror = tx.onabort = () => rej(tx.error);
    });
}

// ── syncOfflineAuth: save CURRENT logged-in user ───────────────────────────
async function syncOfflineAuth() {
    try {
        const password = window._pendingAuthPass || '';
        const secret   = window.masterPassword || '';
        const token    = sessionStorage.getItem('vaultSessionToken') ||
                         sessionStorage.getItem('vaultSession') || '';
        const mode     = sessionStorage.getItem('vaultMode') ||
                         window.VAULT_MODE || '';

        if (!password || !mode) {
            console.warn('[OfflineAuth] syncOfflineAuth: missing password or mode, skipping.');
            return;
        }

        await _saveAuthRecordLocal({ mode, password, secret, token });
        console.log('[OfflineAuth] Current user saved (PBKDF2) for mode:', mode);

    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

// ── Progress helpers (creates a floating toast, always visible) ──
let _offlineToastId = null;

function _showOfflineProgress() {
    _hideOfflineToast();
    const toast = document.createElement('div');
    toast.id = 'offline-toast';
    toast.innerHTML =
        '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span id="offline-toast-icon" style="font-size:20px;">💾</span>' +
            '<div style="flex:1;min-width:0;">' +
                '<div id="offline-toast-text" style="font-size:13px;font-weight:700;color:#4338ca;"></div>' +
                '<div style="margin-top:6px;height:6px;border-radius:3px;background:#c7d2fe;overflow:hidden;">' +
                    '<div id="offline-toast-bar" style="height:100%;width:0%;border-radius:3px;background:linear-gradient(90deg,#6366f1,#4f46e5);transition:width .3s;"></div>' +
                '</div>' +
                '<div id="offline-toast-label" style="font-size:11px;color:#6366f1;margin-top:3px;font-weight:600;">0 / 0</div>' +
            '</div>' +
        '</div>';
    Object.assign(toast.style, {
        position:'fixed', bottom:'20px', right:'20px', zIndex:'999999',
        background:'linear-gradient(135deg,#eef2ff,#e0e7ff)',
        border:'1px solid #c7d2fe', borderRadius:'12px',
        padding:'14px 18px', minWidth:'280px', maxWidth:'360px',
        boxShadow:'0 4px 20px rgba(0,0,0,0.15)',
        fontFamily:'system-ui,sans-serif', display:''
    });
    document.body.appendChild(toast);
}

function _hideOfflineToast() {
    const old = document.getElementById('offline-toast');
    if (!old) return;
    old.style.animation = 'toastFadeOut .25s ease forwards';
    setTimeout(() => { if (old.parentNode) old.remove(); }, 260);
    if (_offlineToastId) { clearTimeout(_offlineToastId); _offlineToastId = null; }
}

function _updateOfflineProgress(current, total) {
    const bar = document.getElementById('offline-toast-bar');
    const label = document.getElementById('offline-toast-label');
    const pct = total > 0 ? Math.round((current / total) * 100) : 0;
    if (bar) bar.style.width = `${pct}%`;
    if (label) label.textContent = `${current} / ${total} — ${pct}%`;
}

function _setOfflineProgressText(text) {
    const el = document.getElementById('offline-toast-text');
    if (el) el.textContent = text;
}

function _setOfflineProgressDone() {
    const icon = document.getElementById('offline-toast-icon');
    if (icon) icon.textContent = '✅';
    _setOfflineProgressText('✓ Site is ready for offline use');
    _updateOfflineProgress(1, 1);
    _offlineToastId = setTimeout(_hideOfflineToast, 10000);
}

// ── Check if offline data already cached (for "already ready" on subsequent logins) ──
async function _isOfflineDataCached() {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_meta', 'readonly')
                          .objectStore('vault_meta').get('offlineSyncComplete');
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        return !!row;
    } catch (e) { return false; }
}

async function _markOfflineSyncComplete() {
    try {
        const db = await _openAuthDB();
        const tx = db.transaction('vault_meta', 'readwrite');
        tx.objectStore('vault_meta').put({ key: 'offlineSyncComplete', value: true, savedAt: Date.now() });
    } catch (e) {
        console.warn('[OfflineAuth] Failed to mark sync complete:', e);
    }
}

// ── Silent re-auth: use stored SHA-256 login hash to get a fresh session token ─────
async function _silentReAuth() {
    try {
        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        // Find a pbkdf2 record that has a loginHash stored
        const record = allRecords.find(r => r.algo === 'pbkdf2-sha256-200k' && r.loginHash);
        if (!record || !record.loginHash) {
            console.warn('[OfflineAuth] _silentReAuth: no stored login hash found');
            return null;
        }

        const res = await fetch(`${_WORKER_URL}/get-secret`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: record.loginHash })
        });
        if (!res.ok) return null;
        const data = await res.json();
        return data.sessionToken || null;
    } catch (e) {
        console.warn('[OfflineAuth] _silentReAuth failed:', e.message);
        return null;
    }
}

// ── syncAllMembersOffline: fetch & cache ALL 7 modes ──────────────────────
async function syncAllMembersOffline(_retried) {
    _showOfflineProgress();
    _setOfflineProgressText('Preparing site for offline access...');
    _updateOfflineProgress(0, 0);

    const token = sessionStorage.getItem('vaultSessionToken') ||
                  sessionStorage.getItem('vaultSession') || '';

    if (!token) {
        _setOfflineProgressText('⚠️ No session — offline sync skipped');
        _updateOfflineProgress(1, 1);
        console.warn('[OfflineAuth] syncAllMembersOffline: no session token, skipping.');
        _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [] };
    }

    if (!navigator.onLine) {
        _setOfflineProgressText('⚡ Already offline — cache available');
        _updateOfflineProgress(1, 1);
        console.warn('[OfflineAuth] syncAllMembersOffline: offline, skipping.');
        _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [] };
    }

    // On subsequent logins, skip re-fetch and show "already ready"
    const alreadyCached = await _isOfflineDataCached();
    if (alreadyCached) {
        _setOfflineProgressText('✓ Site is ready for offline use');
        _updateOfflineProgress(1, 1);
        _setOfflineProgressDone();
        console.log('[OfflineAuth] Offline data already cached — skipping sync.');
        return { synced: 0, failed: [], skipped: true };
    }

    console.log('[OfflineAuth] Fetching all member credentials for offline caching...');

    let members = [];

    try {
        const res = await fetch(`${_WORKER_URL}/sync-offline-members`, {
            method:  'POST',
            headers: {
                'Content-Type':  'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || err.message || `HTTP ${res.status}`);
        }

        const data = await res.json();

        if (!data.success || !Array.isArray(data.members) || !data.members.length) {
            throw new Error('Backend returned no member data.');
        }

        members = data.members;
        _updateOfflineProgress(0, members.length);

    } catch (fetchErr) {
        console.warn('[OfflineAuth] /sync-offline-members failed:', fetchErr.message);
        const is401 = fetchErr.message.includes('401') || fetchErr.message.includes('Unauthorized');

        // If unauthorized (and not already a retry), try to silently re-authenticate using stored login hash
        if (is401 && !_retried) {
            const newToken = await _silentReAuth();
            if (newToken) {
                sessionStorage.setItem('vaultSessionToken', newToken);
                sessionStorage.setItem('vaultSession', newToken);
                console.log('[OfflineAuth] Re-authenticated, retrying sync...');
                // Retry the sync with the fresh token (pass _retried=true to prevent loops)
                return await syncAllMembersOffline(true);
            }
        }

        _setOfflineProgressText(is401
            ? '🔑 Session expired — log in again to enable offline access'
            : '⚠️ Sync failed: ' + fetchErr.message);
        _updateOfflineProgress(1, 1);
    _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [], error: fetchErr.message };
    }

    const failed = [];
    let   synced = 0;

    for (const m of members) {
        if (!m.mode || !m.passwordHash) {
            console.warn('[OfflineAuth] Skipping member with missing mode/passwordHash:', m.mode);
            _updateOfflineProgress(synced + failed.length + 1, members.length);
            continue;
        }
        try {
            await _saveAuthRecordFromServerHash({
                mode:         m.mode,
                passwordHash: m.passwordHash,
                secret:       m.secret || '',
                token:        m.token  || ''
            });
            synced++;
            _updateOfflineProgress(synced + failed.length, members.length);
            _setOfflineProgressText(`Caching: ${m.mode}`);
            console.log(`[OfflineAuth] ✓ Cached mode: ${m.mode}`);
        } catch (saveErr) {
            console.warn(`[OfflineAuth] ✗ Failed to cache mode ${m.mode}:`, saveErr.message);
            failed.push(m.mode);
            _updateOfflineProgress(synced + failed.length, members.length);
        }
    }

    _setOfflineProgressDone();
    _markOfflineSyncComplete();

    console.log(`[OfflineAuth] All-member sync done — ${synced}/${members.length} stored.${failed.length ? ' Failed: ' + failed.join(', ') : ''}`);
    return { synced, failed };
}

// ── offlineLogin: full-password path ──────────────────────────────────────
async function offlineLogin(_ignored, password) {
    try {
        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        if (!allRecords.length) {
            _showOfflineError('No offline credentials found. Please connect to the internet and log in once to enable offline access.');
            return false;
        }

        let match = null;

        for (const r of allRecords) {
            if (r.algo === 'pbkdf2-sha256-200k') {
                const derived = await _pbkdf2Hash(password, r.salt);
                if (derived === r.passwordHash) { match = r; break; }

            } else if (r.algo === 'sha256-server') {
                const derived = await _sha256AuthHash(password);
                if (derived === r.passwordHash) { match = r; break; }

            } else {
                const derived = await _sha256Legacy(password);
                if (derived === r.passwordHash) { match = r; break; }
            }
        }

        if (!match) {
            console.warn('[OfflineAuth] No matching record found across', allRecords.length, 'stored mode(s).');
            _showOfflineError('Incorrect password. Please try again.');
            return false;
        }

        _restoreSession(match, password);
        console.log('[OfflineAuth] Offline login OK, mode:', window.VAULT_MODE, '| algo:', match.algo);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        _showOfflineError('Offline authentication error. Please try again.');
        return false;
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

function _restoreSession(record, passwordFallback) {
    const secret = record.secret || String(passwordFallback || '');
    window.masterPassword = String(secret);
    window.VAULT_MODE     = record.mode || record.id;
    sessionStorage.setItem('vaultMode', window.VAULT_MODE);
    if (record.token) {
        sessionStorage.setItem('vaultSessionToken', record.token);
        sessionStorage.setItem('vaultSession',      record.token);
    } else {
        const offlineToken = 'offline-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
        sessionStorage.setItem('vaultSessionToken', offlineToken);
        sessionStorage.setItem('vaultSession',      offlineToken);
    }
}

// ── Animated wrong password error ─────────────────────────────────────────
function _showOfflineError(msg) {
    // Inject keyframes once
    if (!document.getElementById('_offlineAuthStyles')) {
        const style = document.createElement('style');
        style.id = '_offlineAuthStyles';
        style.textContent = `
            @keyframes _offlineShake {
                0%,100% { transform: translateX(0); }
                15%     { transform: translateX(-8px); }
                30%     { transform: translateX(8px); }
                45%     { transform: translateX(-6px); }
                60%     { transform: translateX(6px); }
                75%     { transform: translateX(-3px); }
                90%     { transform: translateX(3px); }
            }
            @keyframes _offlineFadeSlide {
                from { opacity: 0; transform: translateY(-10px) scale(0.97); }
                to   { opacity: 1; transform: translateY(0) scale(1); }
            }
            @keyframes _offlinePulse {
                0%,100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
                50%     { box-shadow: 0 0 0 6px rgba(239,68,68,0.18); }
            }
            #offline-auth-error {
                animation: _offlineFadeSlide .28s cubic-bezier(.34,1.56,.64,1) forwards,
                           _offlinePulse 1.2s ease 0.28s 2;
            }
            #offline-auth-error.shake {
                animation: _offlineShake .45s ease forwards;
            }
        `;
        document.head.appendChild(style);
    }

    const existing = document.getElementById('offline-auth-error');
    if (existing) {
        // Re-shake if already visible
        existing.classList.remove('shake');
        void existing.offsetWidth; // force reflow
        existing.classList.add('shake');
        const errMsg = existing.querySelector('.offline-err-msg');
        if (errMsg) errMsg.textContent = msg;
        return;
    }

    const box = document.createElement('div');
    box.id = 'offline-auth-error';
    box.style.cssText = `
        background: linear-gradient(135deg, rgba(239,68,68,0.13) 0%, rgba(185,28,28,0.09) 100%);
        border: 1.5px solid rgba(239,68,68,0.55);
        border-radius: 14px;
        padding: 14px 16px 12px;
        margin-top: 14px;
        display: flex;
        align-items: flex-start;
        gap: 11px;
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
        position: relative;
        overflow: hidden;
    `;

    box.innerHTML = `
        <div style="
            width:34px; height:34px; border-radius:50%;
            background:rgba(239,68,68,0.18);
            display:flex; align-items:center; justify-content:center;
            flex-shrink:0; font-size:17px; margin-top:1px;
        ">🔑</div>
        <div style="flex:1; min-width:0;">
            <div style="
                font-weight:800; color:#fca5a5; font-size:13px;
                margin-bottom:3px; letter-spacing:0.3px;
            ">Access Denied</div>
            <div class="offline-err-msg" style="
                font-size:12px; color:rgba(255,255,255,0.75);
                line-height:1.55;
            ">${msg}</div>
        </div>
        <button onclick="this.closest('#offline-auth-error').remove()" style="
            position:absolute; top:9px; right:10px;
            background:transparent; border:none; cursor:pointer;
            color:rgba(252,165,165,0.6); font-size:15px; line-height:1;
            padding:2px 4px; border-radius:4px;
            transition: color .15s;
        " onmouseenter="this.style.color='#fca5a5'" onmouseleave="this.style.color='rgba(252,165,165,0.6)'">✕</button>
        <div style="
            position:absolute; bottom:0; left:0; right:0; height:2px;
            background:linear-gradient(90deg, #ef4444, #b91c1c, #ef4444);
            background-size:200% 100%;
            animation: _offlineShake 0s; /* reuse @keyframes slot — no actual shake */
        "></div>
    `;

    // Also shake the password field
    const passField = document.getElementById('vault-pass');
    if (passField) {
        passField.style.borderColor = 'rgba(239,68,68,0.6)';
        passField.style.animation = '_offlineShake .45s ease';
        setTimeout(() => {
            passField.style.animation = '';
            passField.style.borderColor = '';
        }, 500);
    }

    const card = document.querySelector('#step1 .login-wrapper') || document.getElementById('step1');
    if (card) card.appendChild(box);
}

// ── idbSetVaultMeta / idbGetVaultMeta ──────────────────────────────────────

async function idbSetVaultMeta(data) {
    try {
        const db = await _openAuthDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('vault_meta', 'readwrite');
            tx.objectStore('vault_meta').put({
                key: 'allFilesData', value: data, savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });
        console.log('[OfflineAuth] Vault file list cached.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

async function idbGetVaultMeta() {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_meta', 'readonly')
                          .objectStore('vault_meta').get('allFilesData');
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        return row ? row.value : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}

// ── Trust device session restore ──────────────────────────────────────────
async function restoreTrustSession() {
    try {
        const trust = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
        if (!trust || !trust.member) return false;

        // Trust cookie itself expired (14-day window) — don't even try.
        if (!trust.expiry || trust.expiry <= Date.now()) {
            console.warn('[OfflineAuth] restoreTrustSession: trust info expired.');
            localStorage.removeItem('vaultTrustInfo');
            return false;
        }

        const modeToId = { shineil:'SHINEIL', brother:'KEVIN', father:'PARENTS', mother:'PARENTS', official:'OFFICIAL' };
        // IMPORTANT: resolve mode from the member mapping FIRST. A stale
        // sessionStorage.vaultMode (left over from before the inactivity
        // logout, or written earlier in this same reload by goToDashboard)
        // must never override the mode that actually matches this trusted member.
        const mode = modeToId[trust.member] || sessionStorage.getItem('vaultMode') || 'ADMIN';

        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        // STRICT match only — never fall back to allRecords[0] (another
        // member's secret). A wrong-but-present secret is worse than no
        // secret, because it fails decryption silently/confusingly later.
        const record = allRecords.find(r => r.mode === mode && r.secret);
        if (record && record.secret) {
            _restoreSession(record, '');
            console.log('[OfflineAuth] Trust session restored from IndexedDB for mode:', mode);
            return true;
        }

        // Fallback: use secret stored in trust info (set by saveTrustDevice
        // at original login time). This does not expire with the 1-hour
        // session token — the secret itself is the long-lived part.
        if (trust.secret) {
            window.masterPassword = String(trust.secret);
            window.VAULT_MODE = mode;
            sessionStorage.setItem('vaultMode', window.VAULT_MODE);
            if (trust.token) {
                sessionStorage.setItem('vaultSessionToken', trust.token);
                sessionStorage.setItem('vaultSession', trust.token);
            } else {
                // No usable token cached — synthesize an offline token so
                // later code doesn't choke on a missing session token.
                const offlineToken = 'offline-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
                sessionStorage.setItem('vaultSessionToken', offlineToken);
                sessionStorage.setItem('vaultSession', offlineToken);
            }
            console.log('[OfflineAuth] Trust session restored from vaultTrustInfo.secret for mode:', mode);
            return true;
        }

        console.warn('[OfflineAuth] restoreTrustSession: no secret found in IDB or trust info for mode:', mode);
        return false;
    } catch (e) {
        console.warn('[OfflineAuth] restoreTrustSession failed:', e);
        return false;
    }
}

function _isTrustDevice() {
    try {
        const trust = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
        return trust && trust.expiry > Date.now();
    } catch(e) {
        return false;
    }
}

// ── idbSaveDoc / idbGetDoc — encrypted document caching ───────────────────
// Used by viewer.js to cache encrypted bytes for offline document access.
// Key = docKey (e.g. "abc.enc"), value = ArrayBuffer.

async function idbSaveDoc(filename, arrayBuffer) {
    try {
        const db = await _openAuthDB();
        // Store as Uint8Array — ArrayBuffer is not directly storable in all browsers
        const bytes = new Uint8Array(arrayBuffer);
        await new Promise((res, rej) => {
            const tx = db.transaction('vault_docs', 'readwrite');
            tx.objectStore('vault_docs').put({
                filename,
                bytes,
                savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });
        console.log(`[OfflineAuth] Cached doc: ${filename} (${(arrayBuffer.byteLength / 1024).toFixed(1)} KB)`);
    } catch (e) {
        console.warn('[OfflineAuth] idbSaveDoc failed:', e);
    }
}

async function idbGetDoc(filename) {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_docs', 'readonly')
                          .objectStore('vault_docs').get(filename);
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        if (!row) return null;
        // Return as ArrayBuffer for compatibility with viewer.js
        return row.bytes instanceof Uint8Array
            ? row.bytes.buffer.slice(row.bytes.byteOffset, row.bytes.byteOffset + row.bytes.byteLength)
            : row.bytes;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetDoc failed:', e);
        return null;
    }
}
