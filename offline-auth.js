/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Simple, reliable offline login.

   Architecture (per PDF recommendation):
     ONE DB → ONE store → ONE user → ONE hash → ONE comparison

   Public API (called by auth.js):
     • syncOfflineAuth()         — saves credentials after online login
     • offlineLogin(_, password) — verifies typed password; returns secret or false
     • idbGetVaultMeta()         — returns cached file list
     • idbSetVaultMeta(data)     — caches file list (called by vault-data.js)
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260607-simple-v1';

const _DB_NAME    = 'ShineVaultOffline';
const _DB_VERSION = 3;           // bumped → clears all old broken stores
const _STORE_AUTH = 'trustedLogin';
const _STORE_META = 'vaultMeta';

// ── Open DB — only TWO stores, clean schema ───────────────────
function _openOfflineDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_DB_NAME, _DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;

            // Wipe ALL old stores so broken schemas from previous versions
            // don't cause "object store was not found" errors.
            Array.from(db.objectStoreNames).forEach(name => {
                db.deleteObjectStore(name);
            });

            // Create the two stores we actually need — nothing else
            db.createObjectStore(_STORE_AUTH, { keyPath: 'username' });
            db.createObjectStore(_STORE_META, { keyPath: 'id' });
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── SHA-256 hex — same algorithm as auth.js hashPassword() ───
// NOTE: auth.js hashPassword() does .trim().normalize("NFKC") before hashing.
// We must match that exactly so the hash we store equals what auth.js produces.
async function _sha256(text) {
    const normalized = String(text).trim().normalize('NFKC');
    const buf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(normalized)
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

/* =============================================================
   syncOfflineAuth()
   Called by auth.js after EVERY successful online login.
   Saves ONLY the currently logged-in user under their username.
   ============================================================= */
async function syncOfflineAuth() {
    try {
        // The typed login password is stashed by auth.js before calling us
        const password = window._pendingAuthPass || '';
        const secret   = sessionStorage.getItem('vault_session_secret') ||
                         window.masterPassword || '';
        const token    = sessionStorage.getItem('vaultSessionToken') ||
                         sessionStorage.getItem('vaultSession') || '';
        const mode     = sessionStorage.getItem('vaultMode') ||
                         localStorage.getItem('vaultMode') || 'MEMBER';

        // Username = what the user typed in the name field (same key used at login)
        const usernameEl = document.getElementById('user-name');
        const username   = usernameEl
            ? usernameEl.value.trim().toLowerCase()
            : 'vault_user';

        if (!password) {
            console.warn('[OfflineAuth] syncOfflineAuth: no password available, skipping.');
            return;
        }

        const passwordHash = await _sha256(password);

        const db = await _openOfflineDB();
        const tx = db.transaction(_STORE_AUTH, 'readwrite');
        tx.objectStore(_STORE_AUTH).put({
            username,
            passwordHash,
            secret,
            token,
            mode,
            savedAt: Date.now()
        });

        await new Promise((res, rej) => {
            tx.oncomplete = res;
            tx.onerror    = () => rej(tx.error);
            tx.onabort    = () => rej(tx.error);
        });

        console.log('[OfflineAuth] Credentials saved for:', username);
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(_, password)
   The first argument is ignored (kept for API compatibility with
   auth.js which passes a memberId). We look up by the username
   the user types in the login form.
   Returns the vault secret string on success, false on failure.
   ============================================================= */
async function offlineLogin(_ignored, password) {
    try {
        // Username = what the user typed in the name field right now
        const usernameEl = document.getElementById('user-name');
        const username   = usernameEl
            ? usernameEl.value.trim().toLowerCase()
            : 'vault_user';

        const db   = await _openOfflineDB();
        const tx   = db.transaction(_STORE_AUTH, 'readonly');
        const req  = tx.objectStore(_STORE_AUTH).get(username);

        const row = await new Promise((res, rej) => {
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });

        if (!row) {
            console.warn('[OfflineAuth] No cached credentials for:', username);
            return false;
        }

        const inputHash = await _sha256(password);

        if (inputHash !== row.passwordHash) {
            console.warn('[OfflineAuth] Password mismatch for:', username);
            return false;
        }

        // Hash matched — restore session state
        const secret = row.secret || password;
        window.masterPassword = String(secret);
        window.VAULT_MODE     = row.mode || 'MEMBER';
        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode', window.VAULT_MODE);
        if (row.token) {
            sessionStorage.setItem('vaultSessionToken', row.token);
            sessionStorage.setItem('vaultSession',      row.token);
        }

        console.log('[OfflineAuth] Login verified for:', username);
        return window.masterPassword;   // truthy → auth.js treats as success

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta(data)
   Called by vault-data.js after loading files.json online.
   ============================================================= */
async function idbSetVaultMeta(data) {
    try {
        const db = await _openOfflineDB();
        const tx = db.transaction(_STORE_META, 'readwrite');
        tx.objectStore(_STORE_META).put({ id: 'filelist', data });
        await new Promise((res, rej) => {
            tx.oncomplete = res;
            tx.onerror    = () => rej(tx.error);
            tx.onabort    = () => rej(tx.error);
        });
        console.log('[OfflineAuth] Vault file list cached.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

/* =============================================================
   idbGetVaultMeta()
   Called by auth.js during offline login to restore the file list.
   ============================================================= */
async function idbGetVaultMeta() {
    try {
        const db  = await _openOfflineDB();
        const tx  = db.transaction(_STORE_META, 'readonly');
        const req = tx.objectStore(_STORE_META).get('filelist');
        const row = await new Promise((res, rej) => {
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        return row ? row.data : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}
