/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   v20260609-all-members

   Authentication method: LOCAL PBKDF2 PIN + full-password,
   stored in IndexedDB. No server contact required after first
   online login.

   ALL 7 VAULT MODES are cached on the device after the first
   online login by any member. Every device can then authenticate
   any of the 7 modes fully offline.

   Uses the EXISTING vaultOfflineDB (owned by features.js).
   DB version bumped to 5 to add pin_auth store.

   Public API:
     • syncOfflineAuth()              — saves current user after online login
     • syncAllMembersOffline()        — fetches all 7 modes from backend, saves all
     • offlineLogin(_, password)      — full-password offline verify → secret | false
     • offlinePinSetup(pin)           — enrols a 4–8 digit PIN for current mode
     • offlinePinLogin(pin)           — authenticates with PIN offline
     • clearOfflinePin()              — removes stored PIN
     • idbSetVaultMeta(data)          — caches file list
     • idbGetVaultMeta()              — returns cached file list
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260609-all-members';

const _WORKER_URL = 'https://backend.shinumaths989.workers.dev';

// All 7 vault mode identifiers — must match what your backend returns as result.mode
const ALL_VAULT_MODES = ['ADMIN', 'MEMBER1', 'MEMBER2', 'MEMBER3', 'MEMBER4', 'MEMBER5', 'MEMBER6'];

// ── IndexedDB setup ────────────────────────────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 5;   // bumped from 4 to ensure pin_auth store exists

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

// Legacy plain SHA-256 — backward compat with v3 records
async function _sha256(text) {
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Write one auth record to IndexedDB ────────────────────────────────────
async function _saveAuthRecord({ mode, password, secret, token }) {
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

// ── syncOfflineAuth: save CURRENT user only ────────────────────────────────
/**
 * Called after every successful online login (existing hook in auth.js).
 * Stores the current member's credentials into vault_auth.
 * Then automatically triggers syncAllMembersOffline() in the background.
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

        await _saveAuthRecord({ mode, password, secret, token });
        console.log('[OfflineAuth] Current user credentials saved for mode:', mode);

        // Kick off full sync in background — doesn't block the login flow
        syncAllMembersOffline().catch(e =>
            console.warn('[OfflineAuth] Background all-member sync failed:', e)
        );

    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

// ── syncAllMembersOffline: fetch & cache ALL 7 modes ──────────────────────
/**
 * Calls the backend /sync-offline-members endpoint (requires a valid session
 * token). The backend returns the plain-text secret (master password) and
 * session token for every vault mode. We PBKDF2-hash each one locally and
 * store into vault_auth, keyed by mode.
 *
 * Backend endpoint contract:
 *   POST /sync-offline-members
 *   Headers: Authorization: Bearer <sessionToken>
 *   Response: {
 *     success: true,
 *     members: [
 *       { mode: "ADMIN",   password: "...", secret: "...", token: "..." },
 *       { mode: "MEMBER1", password: "...", secret: "...", token: "..." },
 *       ...7 total
 *     ]
 *   }
 *
 * Returns: { synced: N, failed: [] } summary object.
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

    console.log('[OfflineAuth] Syncing all member credentials for offline access...');

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
            throw new Error(err.message || `HTTP ${res.status}`);
        }

        const data = await res.json();

        if (!data.success || !Array.isArray(data.members) || !data.members.length) {
            throw new Error('Backend returned no member data.');
        }

        members = data.members;

    } catch (fetchErr) {
        console.warn('[OfflineAuth] /sync-offline-members fetch failed:', fetchErr.message);
        // Don't crash — the current user was already saved by syncOfflineAuth()
        return { synced: 0, failed: ALL_VAULT_MODES, error: fetchErr.message };
    }

    // Hash and store each member's credentials into IndexedDB
    const failed  = [];
    let   synced  = 0;

    for (const m of members) {
        if (!m.mode || !m.password) {
            console.warn('[OfflineAuth] Skipping member with missing mode/password:', m);
            continue;
        }
        try {
            await _saveAuthRecord({
                mode:     m.mode,
                password: m.password,
                secret:   m.secret || m.password,
                token:    m.token  || ''
            });
            synced++;
            console.log(`[OfflineAuth] ✓ Cached credentials for mode: ${m.mode}`);
        } catch (saveErr) {
            console.warn(`[OfflineAuth] ✗ Failed to cache mode ${m.mode}:`, saveErr);
            failed.push(m.mode);
        }
    }

    console.log(`[OfflineAuth] All-member sync complete — ${synced}/${members.length} stored. Failed: [${failed.join(', ') || 'none'}]`);
    return { synced, failed };
}

// ── offlineLogin: full-password path ──────────────────────────────────────
/**
 * Scans ALL records in vault_auth. Supports PBKDF2 (new) and SHA-256 (legacy).
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
                const derived = await _pbkdf2Hash(password, r.salt);
                if (derived === r.passwordHash) { match = r; break; }
            } else {
                // Legacy v3 plain SHA-256
                const plain = await _sha256(password);
                if (plain === r.passwordHash) { match = r; break; }
            }
        }

        if (!match) {
            console.warn('[OfflineAuth] Password did not match any of the', allRecords.length, 'stored mode(s).');
            return false;
        }

        _restoreSession(match, password);
        console.log('[OfflineAuth] Full-password offline login OK, mode:', window.VAULT_MODE);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

// ── PIN enrolment & login ──────────────────────────────────────────────────

/**
 * Enrol a 4–8 digit numeric PIN for the current vault mode.
 * Must be called while a session is active (online or offline).
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
