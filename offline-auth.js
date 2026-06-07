/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Simple, reliable offline login.

   KEY: stored and looked up by VAULT_MODE (e.g. 'ADMIN', 'SHINEIL')
   because that's the unique key the backend assigns per password.

   Public API:
     • syncOfflineAuth()         — saves after online login
     • offlineLogin(_, password) — returns secret or false
     • idbGetVaultMeta()         — returns cached file list
     • idbSetVaultMeta(data)     — caches file list
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260607-simple-v2';

const _DB_NAME    = 'ShineVaultOffline';
const _DB_VERSION = 4;           // bump forces clean schema migration
const _STORE_AUTH = 'trustedLogin';
const _STORE_META = 'vaultMeta';

// ── Open DB ───────────────────────────────────────────────────
function _openOfflineDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_DB_NAME, _DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;
            // Wipe all old stores (clears broken schemas from v1/v2/v3)
            Array.from(db.objectStoreNames).forEach(n => db.deleteObjectStore(n));
            // keyPath: 'id' matches the mode-ID key (ADMIN, SHINEIL, etc.)
            db.createObjectStore(_STORE_AUTH, { keyPath: 'id' });
            db.createObjectStore(_STORE_META, { keyPath: 'id' });
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── SHA-256 matching auth.js hashPassword() exactly ──────────
async function _sha256(text) {
    const normalized = String(text).trim().normalize('NFKC');
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(normalized)
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Generic put/get ───────────────────────────────────────────
async function _idbPut(store, value) {
    const db = await _openOfflineDB();
    return new Promise((res, rej) => {
        const tx = db.transaction(store, 'readwrite');
        tx.objectStore(store).put(value);
        tx.oncomplete = res;
        tx.onerror = tx.onabort = () => rej(tx.error);
    });
}

async function _idbGet(store, key) {
    const db = await _openOfflineDB();
    return new Promise((res, rej) => {
        const req = db.transaction(store, 'readonly').objectStore(store).get(key);
        req.onsuccess = () => res(req.result || null);
        req.onerror   = () => rej(req.error);
    });
}

async function _idbGetAll(store) {
    const db = await _openOfflineDB();
    return new Promise((res, rej) => {
        const req = db.transaction(store, 'readonly').objectStore(store).getAll();
        req.onsuccess = () => res(req.result || []);
        req.onerror   = () => rej(req.error);
    });
}

/* =============================================================
   syncOfflineAuth()
   Saves the current session keyed by VAULT_MODE (e.g. 'ADMIN').
   Called by auth.js after every successful online login.
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
            console.warn('[OfflineAuth] syncOfflineAuth: missing password or mode, skipping.');
            return;
        }

        const passwordHash = await _sha256(password);

        await _idbPut(_STORE_AUTH, {
            id: mode,          // e.g. 'ADMIN', 'SHINEIL', 'KEVIN', etc.
            passwordHash,
            secret,
            token,
            mode,
            trusted: true,
            savedAt: Date.now()
        });

        console.log('[OfflineAuth] Credentials saved for mode:', mode);
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(_, password)
   Hashes the typed password and scans ALL stored mode records
   until one matches. Returns the vault secret on success.
   ============================================================= */
async function offlineLogin(_ignored, password) {
    try {
        const inputHash = await _sha256(password);

        // Load all stored mode records and find the one whose hash matches
        const allRecords = await _idbGetAll(_STORE_AUTH);

        if (!allRecords.length) {
            console.warn('[OfflineAuth] No cached credentials found in DB.');
            return false;
        }

        const match = allRecords.find(r => r.passwordHash === inputHash);

        if (!match) {
            console.warn('[OfflineAuth] No matching password hash found across',
                         allRecords.length, 'stored modes.');
            return false;
        }

        // Restore session
        const secret = match.secret || password;
        window.masterPassword = String(secret);
        window.VAULT_MODE     = match.mode || match.id;
        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode', window.VAULT_MODE);
        if (match.token) {
            sessionStorage.setItem('vaultSessionToken', match.token);
            sessionStorage.setItem('vaultSession',      match.token);
        }

        console.log('[OfflineAuth] Login verified for mode:', match.mode || match.id);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta / idbGetVaultMeta
   ============================================================= */
async function idbSetVaultMeta(data) {
    try {
        await _idbPut(_STORE_META, { id: 'filelist', data });
        console.log('[OfflineAuth] Vault file list cached.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

async function idbGetVaultMeta() {
    try {
        const row = await _idbGet(_STORE_META, 'filelist');
        return row ? row.data : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}
