/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Version: 20260608-v5-versionfix

   THE ONLY FILE that opens vaultOfflineDB.
   All other scripts (features.js, viewer.js, vault-data.js)
   must call window.openVaultDB() instead of indexedDB.open().

   DB version history:
     v1 — original (pm_entries only, if any)
     v2 — features.js added: pm_entries, vault_docs, vault_meta
     v3 — offline-auth.js adds: vault_auth

   This file opens at v3 and handles the full v1→v2→v3 chain
   in one onupgradeneeded, so no other script can conflict.

   Public API (all global):
     window.openVaultDB()        — shared DB opener (use everywhere)
     syncOfflineAuth()           — save creds after online login
     offlineLogin(_, password)   — returns masterPassword or false
     idbSetVaultMeta(data)       — cache allFilesData
     idbGetVaultMeta()           — retrieve allFilesData
     idbSaveDoc(filename, buf)   — cache encrypted doc bytes
     idbGetDoc(filename)         — retrieve encrypted doc bytes
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260608-v5-versionfix';

const _VAULT_DB_NAME    = 'vaultOfflineDB';
const _VAULT_DB_VERSION = 3;   // single source of truth — never change in other files

/* =============================================================
   openVaultDB()  — THE ONLY indexedDB.open() in the codebase.
   Exported as window.openVaultDB so features.js / viewer.js /
   vault-data.js all call this instead of their own open().

   onupgradeneeded handles every version step in one pass:
     old v1 → creates all 4 stores
     old v2 → only adds vault_auth (pm_entries/vault_docs/vault_meta exist)
     fresh  → creates all 4 stores
   ============================================================= */
window.openVaultDB = function() {
    return new Promise(function(resolve, reject) {
        var req = indexedDB.open(_VAULT_DB_NAME, _VAULT_DB_VERSION);

        req.onupgradeneeded = function(e) {
            var db = e.target.result;
            // Create each store only if missing — safe for any prior version
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

        req.onblocked = function() {
            // Another tab has the DB open at an old version.
            // Tell the user to close other tabs and retry.
            console.warn('[VaultDB] DB upgrade blocked — close other tabs of this vault.');
        };

        req.onsuccess = function() { resolve(req.result); };
        req.onerror   = function() { reject(req.error); };
    });
};

// Internal shorthand — all functions in this file use this
var _openAuthDB = window.openVaultDB;

/* =============================================================
   _sha256(text)
   MUST match auth.js hashPassword() exactly:
     trim() → normalize("NFKC") → SHA-256 → hex string
   ============================================================= */
async function _sha256(text) {
    var normalized = String(text).trim().normalize('NFKC');
    var buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(normalized)
    );
    return Array.from(new Uint8Array(buf))
        .map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

/* =============================================================
   syncOfflineAuth()
   Call immediately after every successful online login.
   Saves hashed password + session keyed by VAULT_MODE.
   All 7 modes are stored separately so any mode works offline.
   ============================================================= */
async function syncOfflineAuth() {
    try {
        var password = window._pendingAuthPass || '';
        var secret   = sessionStorage.getItem('vault_session_secret') ||
                       window.masterPassword || '';
        var token    = sessionStorage.getItem('vaultSessionToken') ||
                       sessionStorage.getItem('vaultSession') || '';
        var mode     = sessionStorage.getItem('vaultMode') ||
                       window.VAULT_MODE || '';

        if (!password || !mode) {
            console.warn('[OfflineAuth] syncOfflineAuth: missing password or mode — skipping.');
            return;
        }

        var passwordHash = await _sha256(password);

        var db = await _openAuthDB();
        await new Promise(function(res, rej) {
            var tx = db.transaction('vault_auth', 'readwrite');
            tx.objectStore('vault_auth').put({
                id:           mode,
                passwordHash: passwordHash,
                secret:       secret,
                token:        token,
                mode:         mode,
                trusted:      true,
                savedAt:      Date.now()
            });
            tx.oncomplete          = res;
            tx.onerror = tx.onabort = function() { rej(tx.error); };
        });

        console.log('[OfflineAuth] Credentials synced for mode:', mode);
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(_, password)
   Scans ALL vault_auth records, finds the one whose
   passwordHash matches the typed password.
   Restores masterPassword + VAULT_MODE + sessionStorage.
   Returns the masterPassword string on success, false on failure.
   ============================================================= */
async function offlineLogin(_ignored, password) {
    try {
        var inputHash = await _sha256(password);

        var db = await _openAuthDB();
        var allRecords = await new Promise(function(res, rej) {
            var req = db.transaction('vault_auth', 'readonly')
                        .objectStore('vault_auth').getAll();
            req.onsuccess = function() { res(req.result || []); };
            req.onerror   = function() { rej(req.error); };
        });

        if (!allRecords.length) {
            console.warn('[OfflineAuth] vault_auth is empty — do one online login first.');
            return false;
        }

        var match = allRecords.find(function(r) {
            return r.passwordHash === inputHash;
        });

        if (!match) {
            console.warn('[OfflineAuth] No hash match across', allRecords.length, 'stored mode(s).');
            return false;
        }

        // Restore session exactly as the online flow does
        var secret = match.secret || password;
        window.masterPassword = String(secret);
        window.VAULT_MODE     = match.mode || match.id;
        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode',            window.VAULT_MODE);
        if (match.token) {
            sessionStorage.setItem('vaultSessionToken', match.token);
            sessionStorage.setItem('vaultSession',      match.token);
        }

        console.log('[OfflineAuth] Offline login OK — mode:', window.VAULT_MODE);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta / idbGetVaultMeta
   Caches allFilesData (file list) in vault_meta.
   ============================================================= */
async function idbSetVaultMeta(data) {
    try {
        var db = await _openAuthDB();
        await new Promise(function(res, rej) {
            var tx = db.transaction('vault_meta', 'readwrite');
            tx.objectStore('vault_meta').put({
                key: 'allFilesData', value: data, savedAt: Date.now()
            });
            tx.oncomplete          = res;
            tx.onerror = tx.onabort = function() { rej(tx.error); };
        });
        console.log('[OfflineAuth] File list cached in vault_meta.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

async function idbGetVaultMeta() {
    try {
        var db = await _openAuthDB();
        var row = await new Promise(function(res, rej) {
            var req = db.transaction('vault_meta', 'readonly')
                        .objectStore('vault_meta').get('allFilesData');
            req.onsuccess = function() { res(req.result || null); };
            req.onerror   = function() { rej(req.error); };
        });
        return row ? row.value : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}

/* =============================================================
   idbSaveDoc / idbGetDoc
   Cache encrypted document bytes in vault_docs so viewer.js
   can decrypt and display them when offline.
   ============================================================= */
async function idbSaveDoc(filename, arrayBuffer) {
    try {
        var db = await _openAuthDB();
        await new Promise(function(res, rej) {
            var tx = db.transaction('vault_docs', 'readwrite');
            tx.objectStore('vault_docs').put({
                filename: filename,
                data:     arrayBuffer,
                savedAt:  Date.now()
            });
            tx.oncomplete          = res;
            tx.onerror = tx.onabort = function() { rej(tx.error); };
        });
        console.log('[OfflineAuth] Doc cached:', filename);
    } catch (e) {
        console.warn('[OfflineAuth] idbSaveDoc failed for', filename, ':', e);
    }
}

async function idbGetDoc(filename) {
    try {
        var db = await _openAuthDB();
        var row = await new Promise(function(res, rej) {
            var req = db.transaction('vault_docs', 'readonly')
                        .objectStore('vault_docs').get(filename);
            req.onsuccess = function() { res(req.result || null); };
            req.onerror   = function() { rej(req.error); };
        });
        return row ? row.data : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetDoc failed for', filename, ':', e);
        return null;
    }
}
