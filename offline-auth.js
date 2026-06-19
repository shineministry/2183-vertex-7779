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
    const db           = await _openAuthDB();

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode,
            passwordHash,
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
            id:           mode,
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
        const secret   = sessionStorage.getItem('vault_session_secret') ||
                         window.masterPassword || '';
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

        syncAllMembersOffline().catch(e =>
            console.warn('[OfflineAuth] Background all-member sync failed:', e.message)
        );

    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

// ── Progress notification helpers ─────────────────────────────────────
let _cacheProgressToastTimer = null;

function _showCacheProgress() {
    const el = document.getElementById('cache-progress-toast');
    if (el) el.style.display = '';
}

function _updateCacheProgress(current, total) {
    const bar = document.getElementById('cache-progress-bar');
    const label = document.getElementById('cache-progress-label');
    if (bar) bar.style.width = total > 0 ? `${(current / total) * 100}%` : '0%';
    if (label) label.textContent = `${current} / ${total}`;
}

function _hideCacheProgress() {
    const el = document.getElementById('cache-progress-toast');
    if (el) {
        // Keep visible briefly so user sees completion, then fade
        clearTimeout(_cacheProgressToastTimer);
        _cacheProgressToastTimer = setTimeout(() => {
            el.style.display = 'none';
        }, 3000);
    }
}

// ── syncAllMembersOffline: fetch & cache ALL 7 modes ──────────────────────
async function syncAllMembersOffline() {
    const token = sessionStorage.getItem('vaultSessionToken') ||
                  sessionStorage.getItem('vaultSession') || '';

    if (!token) {
        console.warn('[OfflineAuth] syncAllMembersOffline: no session token, skipping.');
        return { synced: 0, failed: [] };
    }

    if (!navigator.onLine) {
        console.warn('[OfflineAuth] syncAllMembersOffline: offline, skipping.');
        return { synced: 0, failed: [] };
    }

    _showCacheProgress();
    _updateCacheProgress(0, 0);
    document.getElementById('cache-progress-text').textContent = 'Syncing offline credentials…';

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
        _updateCacheProgress(0, members.length);

    } catch (fetchErr) {
        console.warn('[OfflineAuth] /sync-offline-members failed:', fetchErr.message);
        document.getElementById('cache-progress-text').textContent = '⚠️ Sync failed: ' + fetchErr.message;
        _hideCacheProgress();
        return { synced: 0, failed: [], error: fetchErr.message };
    }

    const failed = [];
    let   synced = 0;

    for (const m of members) {
        if (!m.mode || !m.passwordHash) {
            console.warn('[OfflineAuth] Skipping member with missing mode/passwordHash:', m.mode);
            _updateCacheProgress(synced + failed.length + 1, members.length);
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
            _updateCacheProgress(synced + failed.length, members.length);
            document.getElementById('cache-progress-text').textContent = `Cached: ${m.mode}`;
            console.log(`[OfflineAuth] ✓ Cached mode: ${m.mode}`);
        } catch (saveErr) {
            console.warn(`[OfflineAuth] ✗ Failed to cache mode ${m.mode}:`, saveErr.message);
            failed.push(m.mode);
            _updateCacheProgress(synced + failed.length, members.length);
        }
    }

    document.getElementById('cache-progress-text').textContent = `✓ Offline cache ready (${synced}/${members.length})`;
    _hideCacheProgress();

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
    sessionStorage.setItem('vault_session_secret', window.masterPassword);
    sessionStorage.setItem('vaultMode', window.VAULT_MODE);
    if (record.token) {
        sessionStorage.setItem('vaultSessionToken', record.token);
        sessionStorage.setItem('vaultSession',      record.token);
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
        existing.querySelector('.offline-err-msg').textContent = msg;
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
