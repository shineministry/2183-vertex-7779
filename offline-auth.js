/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   v20260609-all-members-final

   Authentication method: LOCAL PBKDF2 + SHA-256 server-hash,
   stored in IndexedDB. No server contact required after first
   online login.

   ALL 7 VAULT MODES are cached on the device after the first
   online login by any member. Every device can then authenticate
   any of the 7 modes fully offline.

   Algo types stored in vault_auth:
     'pbkdf2-sha256-200k' — current user, hashed locally (most secure)
     'sha256-server'      — all-members sync, hash from server env vars
     (legacy) plain       — v3 records, plain sha256, backward compat

   Public API:
     syncOfflineAuth()         — saves current user after online login
     syncAllMembersOffline()   — fetches all 7 modes from backend, saves all
     offlineLogin(_, password) — full-password offline verify → secret | false
     offlinePinSetup(pin)      — enrols a 4–8 digit PIN for current mode
     offlinePinLogin(pin)      — authenticates with PIN offline
     clearOfflinePin()         — removes stored PIN
     idbSetVaultMeta(data)     — caches file list
     idbGetVaultMeta()         — returns cached file list
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260609-all-members-final';

const _WORKER_URL = 'https://backend.shinumaths989.workers.dev';

// ── IndexedDB setup ────────────────────────────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 5;

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
            if (!db.objectStoreNames.contains('pin_auth'))
                db.createObjectStore('pin_auth',    { keyPath: 'id' });
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
// Used to verify against server-side hashes (ADMIN_HASH, SHINEIL_HASH, etc.)
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

// For current-user sync: hash the typed password locally with PBKDF2
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

// For all-members sync: backend sends the env-var SHA-256 hash directly
// (same hash used by /get-secret for verification — no plaintext ever sent)
async function _saveAuthRecordFromServerHash({ mode, passwordHash, secret, token }) {
    const db = await _openAuthDB();

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode,
            passwordHash, // SHA-256 hex straight from server env var
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
/**
 * Called after every successful online login (existing hook in auth.js).
 * Saves the current member's credentials with PBKDF2.
 * Then fires syncAllMembersOffline() in the background to cache all 7.
 */
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

        // Background: cache all 7 members — doesn't block login flow
        syncAllMembersOffline().catch(e =>
            console.warn('[OfflineAuth] Background all-member sync failed:', e.message)
        );

    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

// ── syncAllMembersOffline: fetch & cache ALL 7 modes ──────────────────────
/**
 * Calls POST /sync-offline-members with the current session token.
 * Backend returns { success, members: [{ mode, passwordHash, secret, token }] }
 * where passwordHash is the SHA-256 hex already stored in the worker env vars —
 * no plaintext password ever sent over the wire.
 *
 * Each record is stored in vault_auth with algo: 'sha256-server'.
 * offlineLogin() verifies by hashing the typed password the same way
 * auth.js does (trim + NFKC normalize + SHA-256) and comparing.
 */
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

    } catch (fetchErr) {
        console.warn('[OfflineAuth] /sync-offline-members failed:', fetchErr.message);
        return { synced: 0, failed: [], error: fetchErr.message };
    }

    const failed = [];
    let   synced = 0;

    for (const m of members) {
        if (!m.mode || !m.passwordHash) {
            console.warn('[OfflineAuth] Skipping member with missing mode/passwordHash:', m.mode);
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
            console.log(`[OfflineAuth] ✓ Cached mode: ${m.mode}`);
        } catch (saveErr) {
            console.warn(`[OfflineAuth] ✗ Failed to cache mode ${m.mode}:`, saveErr.message);
            failed.push(m.mode);
        }
    }

    console.log(`[OfflineAuth] All-member sync done — ${synced}/${members.length} stored.${failed.length ? ' Failed: ' + failed.join(', ') : ''}`);
    return { synced, failed };
}

// ── offlineLogin: full-password path ──────────────────────────────────────
/**
 * Tries every record in vault_auth against the typed password.
 *
 * Three algo branches:
 *   'pbkdf2-sha256-200k' — derive with PBKDF2 + stored salt, compare
 *   'sha256-server'      — hash with trim+NFKC+SHA-256 (matches auth.js), compare
 *   legacy               — plain SHA-256 no normalize (v3 backward compat)
 *
 * Returns vault secret string on success, false on failure.
 */
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
                // Current-user path: PBKDF2 with per-record salt
                const derived = await _pbkdf2Hash(password, r.salt);
                if (derived === r.passwordHash) { match = r; break; }

            } else if (r.algo === 'sha256-server') {
                // All-members path: same SHA-256 as auth.js hashPassword()
                const derived = await _sha256AuthHash(password);
                if (derived === r.passwordHash) { match = r; break; }

            } else {
                // Legacy v3 records: plain SHA-256, no normalization
                const derived = await _sha256Legacy(password);
                if (derived === r.passwordHash) { match = r; break; }
            }
        }

        if (!match) {
            console.warn('[OfflineAuth] No matching record found across', allRecords.length, 'stored mode(s).');
            return false;
        }

        _restoreSession(match, password);
        console.log('[OfflineAuth] Offline login OK, mode:', window.VAULT_MODE, '| algo:', match.algo);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

// ── PIN enrolment & login ──────────────────────────────────────────────────

/**
 * Enrol a 4–8 digit numeric PIN for the current vault mode.
 * Must be called while a session is active.
 */
async function offlinePinSetup(pin) {
    if (!pin || !/^\d{4,8}$/.test(pin)) {
        alert('PIN must be 4–8 digits.');
        return false;
    }

    const mode   = sessionStorage.getItem('vaultMode') || window.VAULT_MODE || '';
    const secret = sessionStorage.getItem('vault_session_secret') || window.masterPassword || '';
    const token  = sessionStorage.getItem('vaultSessionToken') ||
                   sessionStorage.getItem('vaultSession') || '';

    if (!mode || !secret) {
        alert('Cannot save PIN: vault session not active.');
        return false;
    }

    try {
        const salt    = _randomSalt();
        const pinHash = await _pbkdf2Hash(pin, salt);

        const db = await _openAuthDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('pin_auth', 'readwrite');
            tx.objectStore('pin_auth').put({
                id:      `pin_${mode}`,
                pinHash,
                salt,
                algo:    'pbkdf2-sha256-200k',
                mode,
                secret,
                token,
                savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });

        console.log('[OfflineAuth] PIN enrolled for mode:', mode);
        return true;
    } catch (e) {
        console.error('[OfflineAuth] offlinePinSetup error:', e);
        return false;
    }
}

/**
 * Authenticate offline using a short numeric PIN.
 * Returns vault secret on success, false on failure.
 */
async function offlinePinLogin(pin) {
    if (!pin || !/^\d{4,8}$/.test(pin)) {
        _showOfflineError('Enter a valid 4–8 digit PIN.');
        return false;
    }

    try {
        const db = await _openAuthDB();
        const allPins = await new Promise((res, rej) => {
            const req = db.transaction('pin_auth', 'readonly')
                          .objectStore('pin_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        if (!allPins.length) {
            _showOfflineError('No PIN registered. Please log in online first and set a PIN.');
            return false;
        }

        let match = null;
        for (const r of allPins) {
            const derived = await _pbkdf2Hash(pin, r.salt);
            if (derived === r.pinHash) { match = r; break; }
        }

        if (!match) {
            console.warn('[OfflineAuth] PIN did not match any stored record.');
            return false;
        }

        _restoreSession(match, match.secret);
        console.log('[OfflineAuth] PIN offline login OK, mode:', window.VAULT_MODE);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlinePinLogin error:', e);
        return false;
    }
}

/** Remove the stored PIN for the current mode. */
async function clearOfflinePin() {
    const mode = sessionStorage.getItem('vaultMode') || window.VAULT_MODE || '';
    if (!mode) return;
    try {
        const db = await _openAuthDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('pin_auth', 'readwrite');
            tx.objectStore('pin_auth').delete(`pin_${mode}`);
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });
        console.log('[OfflineAuth] PIN cleared for mode:', mode);
    } catch (e) {
        console.warn('[OfflineAuth] clearOfflinePin error:', e);
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

function _showOfflineError(msg) {
    const existing = document.getElementById('offline-auth-error');
    if (existing) existing.remove();
    const box = document.createElement('div');
    box.id = 'offline-auth-error';
    box.style.cssText = `
        background:rgba(239,68,68,0.12);border:1px solid #ef4444;
        border-radius:12px;padding:14px 16px;margin-top:14px;
        font-size:13px;color:#fca5a5;line-height:1.5;animation:fadeInUp .3s ease;
    `;
    box.innerHTML = `⚠️ ${msg}
        <button onclick="this.parentElement.remove()" style="
            display:block;margin-top:8px;border:none;background:#ef4444;color:#fff;
            border-radius:6px;padding:5px 12px;font-size:11px;font-weight:700;cursor:pointer;">
            Dismiss
        </button>`;
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
