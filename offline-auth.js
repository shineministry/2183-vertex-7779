/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Provides three functions called by auth.js:
     • syncOfflineAuth()   — called after online login to save credentials
     • offlineLogin()      — validates password offline, sets window.masterPassword
     • idbGetVaultMeta()   — returns cached file list for the dashboard
   Also provides:
     • idbSetVaultMeta()   — called by vault-data.js to cache file list
   ============================================================= */

const _OIDB_NAME    = 'ShineVaultOffline';
const _OIDB_VERSION = 1;

// ── Open the offline IndexedDB ────────────────────────────────
function _openOfflineDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_OIDB_NAME, _OIDB_VERSION);
        req.onupgradeneeded = e => {
            const db = e.target.result;
            // Stores credential hashes per member for offline password check
            if (!db.objectStoreNames.contains('authHashes')) {
                db.createObjectStore('authHashes', { keyPath: 'memberId' });
            }
            // Stores the vault file list (files.json response)
            if (!db.objectStoreNames.contains('vaultMeta')) {
                db.createObjectStore('vaultMeta', { keyPath: 'id' });
            }
            // Stores the encrypted master secret per member
            if (!db.objectStoreNames.contains('secrets')) {
                db.createObjectStore('secrets', { keyPath: 'memberId' });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── Generic IDB get/put helpers ───────────────────────────────
async function _idbGet(storeName, key) {
    const db = await _openOfflineDB();
    return new Promise((resolve, reject) => {
        const req = db.transaction(storeName, 'readonly')
                      .objectStore(storeName).get(key);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror   = () => reject(req.error);
    });
}

async function _idbPut(storeName, value) {
    const db = await _openOfflineDB();
    return new Promise((resolve, reject) => {
        const req = db.transaction(storeName, 'readwrite')
                      .objectStore(storeName).put(value);
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── SHA-256 helper (same as auth.js / viewer.js) ──────────────
async function _sha256(text) {
    const buf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

/* =============================================================
   syncOfflineAuth()
   Called by auth.js after every successful ONLINE login.
   Saves a hash of the master password and the master secret
   so offline login can verify the password and restore state.
   ============================================================= */
async function syncOfflineAuth() {
    try {
        const secret   = window.masterPassword || '';
        const token    = sessionStorage.getItem('vaultSessionToken') ||
                         sessionStorage.getItem('vaultSession') || '';
        const mode     = sessionStorage.getItem('vaultMode') || 'VIEWER';

        // Use 'main' as default memberId for single-member vaults;
        // for ADMIN vaults the member dropdown value is used at login time.
        const memberSel = document.getElementById('member-select');
        const memberId  = (memberSel && memberSel.value) ? memberSel.value : 'main';

        // Hash the secret so we can verify the password offline without
        // storing it in plain text.
        const secretHash = await _sha256(secret);

        await _idbPut('authHashes', { memberId, secretHash });
        await _idbPut('secrets',    { memberId, secret, token, mode });

        // Also persist to localStorage as a belt-and-suspenders fallback
        localStorage.setItem('vaultSessionToken_offline', token);
        localStorage.setItem('vault_session_secret_offline', secret);
        localStorage.setItem('vaultMode_offline', mode);

        console.log('[OfflineAuth] Credentials synced for offline use.');
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(memberId, password)
   Called by auth.js when navigator.onLine is false.
   Verifies the password against the stored hash, then restores
   window.masterPassword, sessionStorage tokens, and VAULT_MODE
   so the rest of the app works exactly as after an online login.
   Returns true on success, false on failure.
   ============================================================= */
async function offlineLogin(memberId, password) {
    try {
        // Try the provided memberId first, then fall back to 'main'
        const ids = [memberId, 'main'];
        let stored = null;
        let usedId = null;

        for (const id of ids) {
            stored = await _idbGet('authHashes', id);
            if (stored) { usedId = id; break; }
        }

        if (!stored) {
            showLoginError(
                'No Offline Data',
                'No offline credentials found. Please log in online at least once.'
            );
            return false;
        }

        // Verify password by hashing the entered password and comparing
        const enteredHash = await _sha256(password);
        if (enteredHash !== stored.secretHash) {
            showLoginError('Incorrect Password', 'The password you entered is incorrect.');
            return false;
        }

        // Password verified — restore full session state
        const savedSecret = await _idbGet('secrets', usedId);
        const secret = savedSecret ? savedSecret.secret : password;
        const token  = savedSecret ? savedSecret.token  : '';
        const mode   = savedSecret ? savedSecret.mode   : 'VIEWER';

        // Restore exactly the same vars auth.js sets after online login
        window.masterPassword = String(secret || password);
        window.VAULT_MODE     = mode;

        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode', mode);

        // Token may be expired for server calls, but it allows
        // viewer.js to pass the token guard and reach IndexedDB
        if (token) {
            sessionStorage.setItem('vaultSessionToken', token);
            sessionStorage.setItem('vaultSession',      token);
        }

        console.log('[OfflineAuth] Offline login successful.');
        return true;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        showLoginError('Offline Error', 'Could not verify offline credentials.');
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta(data)
   Called by vault-data.js after loading files.json online.
   Caches the full file list so the dashboard works offline.
   ============================================================= */
async function idbSetVaultMeta(data) {
    try {
        await _idbPut('vaultMeta', { id: 'filelist', data });
        console.log('[OfflineAuth] Vault file list cached.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

/* =============================================================
   idbGetVaultMeta()
   Called by auth.js during offline login to restore the file list.
   Returns the cached data object, or null if not cached.
   ============================================================= */
async function idbGetVaultMeta() {
    try {
        const row = await _idbGet('vaultMeta', 'filelist');
        return row ? row.data : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}
