/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Version: 20260607-bridge-v1

   Uses vaultOfflineDB (shared with features.js) for credential
   storage, AND writes a localStorage sentinel so any HTML-level
   "never been synced" guard can detect a prior online login.

   Public API:
     • syncOfflineAuth()              — save after online login
     • offlineLogin(_, password)      — returns secret or false
     • idbSetVaultMeta(data)          — cache file list
     • idbGetVaultMeta()              — return cached file list
     • hasOfflineCredentials()        — true if ever synced online
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260607-bridge-v1';

// ── DB shared with features.js ────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 3;

// ── localStorage sentinel key (checked by HTML guard) ─────────
const _LS_SYNCED_KEY  = 'vault_offline_synced';
const _LS_HASH_KEY    = 'vault_password_hash_offline';
const _LS_SECRET_KEY  = 'vault_session_secret_offline';
const _LS_TOKEN_KEY   = 'vaultSessionToken_offline';
const _LS_MODE_KEY    = 'vaultMode_offline';

// ── Open / upgrade the DB ─────────────────────────────────────
function _openAuthDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_AUTH_DB_NAME, _AUTH_DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;
            // Preserve existing stores created by features.js
            if (!db.objectStoreNames.contains('pm_entries'))
                db.createObjectStore('pm_entries', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault_docs'))
                db.createObjectStore('vault_docs', { keyPath: 'filename' });
            if (!db.objectStoreNames.contains('vault_meta'))
                db.createObjectStore('vault_meta', { keyPath: 'key' });
            if (!db.objectStoreNames.contains('vault_auth'))
                db.createObjectStore('vault_auth', { keyPath: 'id' });
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── SHA-256 (matches auth.js hashPassword exactly) ────────────
async function _sha256(text) {
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

/* =============================================================
   hasOfflineCredentials()
   Returns true if a successful online login has been synced.
   Checks both localStorage (fast) and IndexedDB (thorough).
   The HTML "never been synced" guard should call this.
   ============================================================= */
async function hasOfflineCredentials() {
    // Fast path — localStorage sentinel
    if (localStorage.getItem(_LS_SYNCED_KEY) === '1') return true;

    // Fallback — check IndexedDB directly
    try {
        const db = await _openAuthDB();
        const records = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });
        if (records.length > 0) {
            // Repair missing sentinel so future checks are fast
            localStorage.setItem(_LS_SYNCED_KEY, '1');
            return true;
        }
    } catch (e) {
        console.warn('[OfflineAuth] hasOfflineCredentials IDB check failed:', e);
    }
    return false;
}

/* =============================================================
   syncOfflineAuth()
   Called by auth.js after every successful ONLINE login.
   Saves hashed password + session secret to:
     1. vaultOfflineDB → vault_auth  (primary, keyed by mode)
     2. localStorage                 (sentinel + fallback)
   ============================================================= */
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
            console.warn('[OfflineAuth] syncOfflineAuth: missing password or mode — skipping.');
            return;
        }

        const passwordHash = await _sha256(password);

        // 1. Write to IndexedDB
        const db = await _openAuthDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('vault_auth', 'readwrite');
            tx.objectStore('vault_auth').put({
                id: mode,
                passwordHash,
                secret,
                token,
                mode,
                trusted: true,
                savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });

        // 2. Write localStorage sentinel + fallback values
        // (the HTML "never been synced" guard reads _LS_SYNCED_KEY)
        localStorage.setItem(_LS_SYNCED_KEY,  '1');
        localStorage.setItem(_LS_HASH_KEY,    passwordHash);
        localStorage.setItem(_LS_SECRET_KEY,  secret);
        localStorage.setItem(_LS_TOKEN_KEY,   token);
        localStorage.setItem(_LS_MODE_KEY,    mode);

        console.log('[OfflineAuth] Credentials synced for mode:', mode,
                    '| sentinel set in localStorage');
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(_, password)
   Scans ALL records in vault_auth and finds one whose
   passwordHash matches the typed password.
   Falls back to localStorage hash if IDB scan finds nothing.
   Returns the secret string on success, false on failure.
   ============================================================= */
async function offlineLogin(_ignored, password) {
    try {
        const inputHash = await _sha256(password);

        // ── Primary: scan IndexedDB ───────────────────────────
        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        let match = (allRecords || []).find(r => r.passwordHash === inputHash);

        // ── Fallback: localStorage hash ───────────────────────
        if (!match) {
            const lsHash = localStorage.getItem(_LS_HASH_KEY);
            if (lsHash && lsHash === inputHash) {
                // Reconstruct a minimal record from localStorage
                match = {
                    secret:  localStorage.getItem(_LS_SECRET_KEY) || password,
                    token:   localStorage.getItem(_LS_TOKEN_KEY)  || '',
                    mode:    localStorage.getItem(_LS_MODE_KEY)   || 'MEMBER'
                };
                console.log('[OfflineAuth] Matched via localStorage fallback.');
            }
        }

        if (!match) {
            console.warn('[OfflineAuth] No matching hash found.',
                         allRecords.length, 'IDB records checked.');
            return false;
        }

        // Restore session
        const secret = match.secret || password;
        window.masterPassword = String(secret);
        window.VAULT_MODE     = match.mode || match.id || '';
        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode', window.VAULT_MODE);
        if (match.token) {
            sessionStorage.setItem('vaultSessionToken', match.token);
            sessionStorage.setItem('vaultSession',      match.token);
        }

        console.log('[OfflineAuth] Login verified, mode:', window.VAULT_MODE);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta(data)
   Caches the full file list into vaultOfflineDB → vault_meta.
   Called by vault-data.js after loading files.json online.
   ============================================================= */
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
        console.log('[OfflineAuth] Vault file list cached in vault_meta.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

/* =============================================================
   idbGetVaultMeta()
   Returns the cached file list from vaultOfflineDB → vault_meta.
   Called by auth.js during offline login.
   ============================================================= */
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
