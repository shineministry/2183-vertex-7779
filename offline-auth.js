/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   Provides these functions called by auth.js:
     • syncOfflineAuth()   — saves credentials after online login
     • offlineLogin(id, pass) — checks ONE member's stored hash;
                                returns the secret string or false
     • idbGetVaultMeta()   — returns cached file list
     • idbSetVaultMeta()   — caches file list (called by vault-data.js)
   ============================================================= */

const _OIDB_NAME    = 'ShineVaultOffline';
const _OIDB_VERSION = 2;  // bumped — forces onupgradeneeded on devices with broken empty v1 DB

// ── Known member IDs (must match auth.js MEMBER_IDS list) ────
const _MEMBER_IDS = ['main', 'shineil', 'brother', 'father', 'mother'];
const _DEFAULT_MEMBER_ID = 'main';

function _offlineMemberCandidates(memberId) {
    const requested = String(memberId || '').trim();
    if (requested && requested !== 'all') {
        return [requested, ..._MEMBER_IDS.filter(id => id !== requested)];
    }
    return [_DEFAULT_MEMBER_ID, ..._MEMBER_IDS.filter(id => id !== _DEFAULT_MEMBER_ID)];
}

// ── Open the offline IndexedDB ────────────────────────────────
function _openOfflineDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_OIDB_NAME, _OIDB_VERSION);
        req.onupgradeneeded = e => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('authHashes')) {
                db.createObjectStore('authHashes', { keyPath: 'memberId' });
            }
            if (!db.objectStoreNames.contains('vaultMeta')) {
                db.createObjectStore('vaultMeta', { keyPath: 'id' });
            }
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

// ── SHA-256 hex helper (matches auth.js / viewer.js) ─────────
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

   KEY DESIGN:
   - The VAULT SECRET (window.masterPassword / vault_session_secret)
     is the AES decryption key — it may differ from the typed password.
   - We must store a hash of the TYPED LOGIN PASSWORD so that
     offlineLogin() can verify what the user types at the login form.
   - We also store the secret so we can restore window.masterPassword.

   We save under EVERY plausible member ID so that auth.js can
   try all of them during offline login regardless of which dropdown
   value was selected at sync time.
   ============================================================= */
async function syncOfflineAuth() {
    try {
        const secret = sessionStorage.getItem('vault_session_secret') ||
                       window.masterPassword || '';
        const token  = sessionStorage.getItem('vaultSessionToken') ||
                       sessionStorage.getItem('vaultSession') || '';
        const mode   = sessionStorage.getItem('vaultMode') ||
                       localStorage.getItem('vaultMode') || 'MEMBER';

        // The login password is stashed temporarily in auth.js as
        // window._pendingAuthPass (cleared after login completes).
        // After it's cleared we fall back to the secret itself, which
        // works when the password and the secret are the same value.
        // Vault operators where secret ≠ password should ensure
        // _pendingAuthPass is still set when syncOfflineAuth() fires.
        const loginPassword = window._pendingAuthPass || secret;

        const passwordHash = await _sha256(loginPassword);

        // Determine which member ID is currently active.
        // member-select in the sidebar may show a meaningful value
        // after the dashboard opens; before that it may still be 'all'.
        // We save under the resolved ID AND under every fallback ID so
        // that auth.js can find the record regardless of which ID it tries.
        const memberSel    = document.getElementById('member-select');
        const activeMember = (memberSel && memberSel.value &&
                              memberSel.value !== 'all')
                             ? memberSel.value : 'main';

        // Build the set of IDs to write under (active first, then all others)
        const saveIds = [activeMember, ..._MEMBER_IDS.filter(id => id !== activeMember)];

        for (const mid of saveIds) {
            await _idbPut('authHashes', { memberId: mid, passwordHash });
            await _idbPut('secrets',    { memberId: mid, secret, token, mode });
        }

        // Belt-and-suspenders localStorage fallback
        localStorage.setItem('vaultSessionToken_offline',    token);
        localStorage.setItem('vault_session_secret_offline', secret);
        localStorage.setItem('vaultMode_offline',            mode);
        localStorage.setItem('vault_password_hash_offline',  passwordHash);

        console.log('[OfflineAuth] Credentials synced for all member IDs.');
    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

/* =============================================================
   offlineLogin(memberId, password)
   Called by auth.js once per member ID until one succeeds.
   auth.js iterates ALL_MEMBER_IDS itself; this function just
   checks ONE id and returns:
     - the secret string on success  (auth.js treats truthy = success)
     - false on hash mismatch or missing record
   It does NOT call showLoginError() — error display is left to
   auth.js so it can count attempts across all IDs correctly.
   ============================================================= */
async function offlineLogin(memberId, password) {
    try {
        const enteredHash = await _sha256(password);
        let matchedMemberId = null;
        let stored = null;

        for (const candidate of _offlineMemberCandidates(memberId)) {
            const row = await _idbGet('authHashes', candidate);
            if (row && row.passwordHash === enteredHash) {
                matchedMemberId = candidate;
                stored = row;
                break;
            }
        }

        if (!stored && localStorage.getItem('vault_password_hash_offline') === enteredHash) {
            matchedMemberId = _DEFAULT_MEMBER_ID;
            stored = { memberId: matchedMemberId, passwordHash: enteredHash };
        }

        if (!stored) return false;   // no matching cached password

        // Hash matched — load the associated secret
        const savedSecret = await _idbGet('secrets', matchedMemberId);
        const secret = savedSecret && savedSecret.secret
            ? savedSecret.secret
            : (localStorage.getItem('vault_session_secret_offline') || password);
        const token  = savedSecret && savedSecret.token
            ? savedSecret.token
            : (localStorage.getItem('vaultSessionToken_offline') || '');
        const mode   = savedSecret && savedSecret.mode
            ? savedSecret.mode
            : (localStorage.getItem('vaultMode_offline') || 'MEMBER');

        // Restore session state (auth.js will also set these, but
        // setting them here ensures nothing downstream is ever undefined)
        window.masterPassword = String(secret || password);
        window.VAULT_MODE     = mode;
        sessionStorage.setItem('vault_session_secret', window.masterPassword);
        sessionStorage.setItem('vaultMode', mode);
        if (token) {
            sessionStorage.setItem('vaultSessionToken', token);
            sessionStorage.setItem('vaultSession',      token);
        }

        console.log('[OfflineAuth] Password verified for member:', matchedMemberId);
        return window.masterPassword;   // truthy string — auth.js uses as the secret

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error for', memberId, e);
        return false;
    }
}

/* =============================================================
   idbSetVaultMeta(data)
   Called by vault-data.js after loading files.json online.
   Caches the full file list so the dashboard populates offline.
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
   Returns the cached data object, or null if not yet cached.
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
