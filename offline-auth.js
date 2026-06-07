/* =============================================================
   OFFLINE AUTH  —  offline-auth.js

   Uses the EXISTING vaultOfflineDB (owned by features.js)
   and its vault_auth store — no new DB, no schema conflicts.

   Public API:
     • syncOfflineAuth()         — saves after online login
     • offlineLogin(_, password) — returns secret or false
     • idbSetVaultMeta(data)     — caches file list (delegates to features.js)
     • idbGetVaultMeta()         — returns cached file list (delegates to features.js)
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260607-offlinefix5';

// ── Same DB as features.js ────────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 3;   // bumped from features.js v2 to add vault_auth store

function _openAuthDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_AUTH_DB_NAME, _AUTH_DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;
            // Keep existing stores features.js created — only ADD vault_auth
            if (!db.objectStoreNames.contains('pm_entries')) {
                db.createObjectStore('pm_entries', { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains('vault_docs')) {
                db.createObjectStore('vault_docs', { keyPath: 'filename' });
            }
            if (!db.objectStoreNames.contains('vault_meta')) {
                db.createObjectStore('vault_meta', { keyPath: 'key' });
            }
            if (!db.objectStoreNames.contains('vault_auth')) {
                db.createObjectStore('vault_auth', { keyPath: 'id' });
            }
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── SHA-256 matching auth.js hashPassword() exactly ──────────
async function _sha256(text) {
    // No normalize — matches the hash format stored by syncOfflineAuth
    // (which uses window._pendingAuthPass — the raw typed password)
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

/* =============================================================
   syncOfflineAuth()
   Saves current session into vault_auth keyed by VAULT_MODE.
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

        // Belt-and-suspenders localStorage fallback
        // (startup.js / session.js check these keys to confirm the device has synced online)
        localStorage.setItem('vaultSessionToken_offline',    token);
        localStorage.setItem('vault_session_secret_offline', secret);
        localStorage.setItem('vaultMode_offline',            mode);
        localStorage.setItem('vault_password_hash_offline',  passwordHash);

        console.log('[OfflineAuth] Credentials saved for mode:', mode);
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(_, password)
   Scans ALL records in vault_auth, finds the one whose
   passwordHash matches the typed password.
   ============================================================= */
async function offlineLogin(_ignored, password) {
    try {
        const inputHash = await _sha256(password);

        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        if (!allRecords.length) {
            console.warn('[OfflineAuth] No cached credentials found in DB — trying localStorage fallback.');
            // localStorage fallback (set by syncOfflineAuth for startup.js compatibility)
            const storedHash = localStorage.getItem('vault_password_hash_offline');
            if (storedHash && storedHash === inputHash) {
                const secret = localStorage.getItem('vault_session_secret_offline') || password;
                const token  = localStorage.getItem('vaultSessionToken_offline') || '';
                const mode   = localStorage.getItem('vaultMode_offline') || 'MEMBER';
                window.masterPassword = String(secret);
                window.VAULT_MODE = mode;
                sessionStorage.setItem('vault_session_secret', window.masterPassword);
                sessionStorage.setItem('vaultMode', mode);
                if (token) { sessionStorage.setItem('vaultSessionToken', token); sessionStorage.setItem('vaultSession', token); }
                console.log('[OfflineAuth] Login via localStorage fallback, mode:', mode);
                return window.masterPassword;
            }
            return false;
        }

        const match = allRecords.find(r => r.passwordHash === inputHash);

        if (!match) {
            console.warn('[OfflineAuth] No matching hash found across',
                         allRecords.length, 'stored modes — trying localStorage fallback.');
            const storedHash = localStorage.getItem('vault_password_hash_offline');
            if (storedHash && storedHash === inputHash) {
                const secret = localStorage.getItem('vault_session_secret_offline') || password;
                const token  = localStorage.getItem('vaultSessionToken_offline') || '';
                const mode   = localStorage.getItem('vaultMode_offline') || 'MEMBER';
                window.masterPassword = String(secret);
                window.VAULT_MODE = mode;
                sessionStorage.setItem('vault_session_secret', window.masterPassword);
                sessionStorage.setItem('vaultMode', mode);
                if (token) { sessionStorage.setItem('vaultSessionToken', token); sessionStorage.setItem('vaultSession', token); }
                console.log('[OfflineAuth] Login via localStorage fallback, mode:', mode);
                return window.masterPassword;
            }
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

        console.log('[OfflineAuth] Login verified, mode:', window.VAULT_MODE);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta / idbGetVaultMeta
   Delegates to vaultOfflineDB → vault_meta (same as features.js)
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
