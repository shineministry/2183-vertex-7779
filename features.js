/* =========================
   FEATURE 1: E2E ENCRYPTION
   (AES-256-GCM already used in
   openSecureFile – badge shown in
   navbar. No additional JS needed.)
========================= */

// ============ PASSWORD MANAGER ============
const WORKER_URL = 'https://backend.shinumaths989.workers.dev'; // your worker URL

// renderPMList, openPasswordManager, closePasswordManager are defined in index.html
if (typeof renderPMList !== 'function') {
  var renderPMList = function() { console.warn("renderPMList() not yet ready."); };
}
if (typeof openPasswordManager !== 'function') {
  function openPasswordManager() {
    const m = document.getElementById('passwordManagerModal');
    if (m) { m.classList.add('open'); renderPMList(); }
    _pmStartAutoLock();
  }
}
if (typeof closePasswordManager !== 'function') {
function closePasswordManager() {
  document.getElementById('passwordManagerModal').style.display = 'none';
  _pmStopAutoLock();
}
} // end if closePasswordManager

// ── Security: auto-lock the Password Manager after 2 minutes idle ──────────
// Closes the PM panel and re-blurs any visible passwords so they can't be
// left exposed on screen if the device is walked away from.
let _pmAutoLockTimer = null;
function _pmStartAutoLock() {
  _pmStopAutoLock();
  const reset = () => {
    clearTimeout(_pmAutoLockTimer);
    _pmAutoLockTimer = setTimeout(() => {
      const m = document.getElementById('passwordManagerModal');
      if (m && (m.classList.contains('open') || m.style.display !== 'none')) {
        m.classList.remove('open');
        m.style.display = 'none';
        document.querySelectorAll('#pm-entries-container input[type="text"][data-pm-pass]')
          .forEach(inp => inp.type = 'password');
        alert('🔒 Password Manager auto-locked after inactivity.');
      }
      _pmStopAutoLock();
    }, 120000);
  };
  ['mousemove','keydown','click','touchstart'].forEach(evt =>
    document.addEventListener(evt, reset, { passive: true })
  );
  _pmAutoLockResetFn = reset;
  reset();
}
let _pmAutoLockResetFn = null;
function _pmStopAutoLock() {
  clearTimeout(_pmAutoLockTimer);
  if (_pmAutoLockResetFn) {
    ['mousemove','keydown','click','touchstart'].forEach(evt =>
      document.removeEventListener(evt, _pmAutoLockResetFn)
    );
    _pmAutoLockResetFn = null;
  }
}

function togglePMPassword(buttonElement, inputId) {
  const passwordInput = document.getElementById(inputId);
  if (!passwordInput) return;

  if (passwordInput.type === 'password') {
    passwordInput.type = 'text';
    buttonElement.textContent = 'Hide';
  } else {
    passwordInput.type = 'password';
    buttonElement.textContent = 'Show';
  }
}

async function getAuthHeaders() {
  // Check every token key variant your vault system might be assigning
  const token = sessionStorage.getItem('vaultSessionToken') || 
                sessionStorage.getItem('vaultSession') || 
                sessionStorage.getItem('sessionToken') || 
                localStorage.getItem('sessionToken') || '';
                
  return { 
    'Content-Type': 'application/json', 
    'Authorization': `Bearer ${token}` 
  };
}

async function loadPMEntries() {
  // Always try network first (navigator.onLine is unreliable — can be true
  // even when the backend is unreachable). Fall back to IndexedDB on any error.
  try {
    const res = await fetch(`${WORKER_URL}/passwords`, { headers: await getAuthHeaders() });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || `HTTP ${res.status}`);
    }
    const data = await res.json();
    const entries = data.entries || [];
    // Sync fresh server list into IndexedDB for offline use
    await idbSyncPMEntries(entries).catch(() => {});
    return entries;
  } catch (err) {
    console.warn('loadPMEntries fetch failed, falling back to IndexedDB:', err);
    return idbGetAllPMEntries();
  }
}

async function savePMEntry() {
  const site     = document.getElementById('pm-site').value.trim();
  const username = document.getElementById('pm-username').value.trim();
  const password = document.getElementById('pm-password').value.trim();
  const notes    = document.getElementById('pm-notes').value.trim();
  const pmMemberEl = document.getElementById('pm-member'); const member   = (pmMemberEl ? pmMemberEl.value : '') || '';
  if (!site || !password) { alert('Site and password are required.'); return; }
  if (!member) { alert('Please select which member this password is for.'); return; }

  // Verify we actually have an auth token before attempting the save
  const headers = await getAuthHeaders();
  if (!headers['Authorization'] || headers['Authorization'] === 'Bearer ') {
    alert('❌ Not logged in. Please unlock your vault first.');
    return;
  }

  // Save to IndexedDB immediately (offline-first) so it's never lost
  const localId = Date.now().toString();
  await idbSavePMEntry({ id: localId, site, username, password, notes, member, _pendingSync: true })
    .catch(e => console.warn('[PM] Local IDB save failed:', e));

  // Clear form right away — data is safe in IDB
  document.getElementById('pm-site').value     = '';
  document.getElementById('pm-username').value = '';
  document.getElementById('pm-password').value = '';
  document.getElementById('pm-notes').value    = '';
  const memberSel = document.getElementById('pm-member');
  if (memberSel) memberSel.value = '';

  // Then try to sync to server
  try {
    const res = await fetch(`${WORKER_URL}/passwords`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ site, username, password, notes, member })
    });

    // Read body once – may be JSON or empty
    let data = {};
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json().catch(() => ({}));
    }

    if (!res.ok) {
      const msg = data.error || data.message || `Server error ${res.status}`;
      // Entry is saved locally; warn but don't block UI
      console.warn(`[PM] Server save failed (entry kept offline): ${msg}`);
      alert(`⚠️ Saved locally. Will sync when back online.\n(Server: ${msg})`);
      renderPMList();
      return;
    }

    // Server assigned a real ID — update the local IDB entry with it
    const serverId = data.id || localId;
    if (serverId !== localId) {
      await idbDeletePMEntry(localId).catch(() => {});
      await idbSavePMEntry({ id: serverId, site, username, password, notes, member }).catch(() => {});
    } else {
      // Clear the pending-sync flag
      await idbSavePMEntry({ id: localId, site, username, password, notes, member }).catch(() => {});
    }

    renderPMList();
  } catch (err) {
    // Network error — entry already saved to IDB above, just inform user
    console.warn('[PM] Network error during server sync (entry kept offline):', err);
    alert(`⚠️ Saved locally (offline). Will sync when back online.`);
    renderPMList();
  }
}

// ── Security: auto-clear clipboard after copying a PM password ─────────────
// Prevents a copied password from lingering on the clipboard where another
// app or person could paste it later.
function _pmCopyToClipboard(text, label) {
  navigator.clipboard.writeText(text);
  alert(label + ' (clipboard clears in 20s)');
  const snapshot = text;
  setTimeout(() => {
    navigator.clipboard.readText().then(cur => {
      if (cur === snapshot) navigator.clipboard.writeText('');
    }).catch(() => {});
  }, 20000);
}

async function copyPMPassword(id) {
  // Try server first; fall back to local IDB cache offline
  if (!navigator.onLine) {
    const entries = await idbGetAllPMEntries().catch(() => []);
    const entry = entries.find(e => e.id === id);
    if (entry && entry.password) {
      _pmCopyToClipboard(entry.password, '✅ Password copied! (offline)');
    } else {
      alert('❌ Password not available offline. Connect to the internet first.');
    }
    return;
  }
  try {
    const res = await fetch(`${WORKER_URL}/passwords/get-password`, {
      method: 'POST',
      headers: await getAuthHeaders(),
      body: JSON.stringify({ id })
    });
    const data = await res.json();
    if (data.password) {
      _pmCopyToClipboard(data.password, '✅ Password copied!');
    }
  } catch (err) {
    // Network failed — try IDB cache
    const entries = await idbGetAllPMEntries().catch(() => []);
    const entry = entries.find(e => e.id === id);
    if (entry && entry.password) {
      _pmCopyToClipboard(entry.password, '✅ Password copied! (cached)');
    } else {
      alert('❌ Could not copy password: ' + err.message);
    }
  }
}

async function renderPMList() {
  const container = document.getElementById('pm-entries-container'); 
  if (!container) {
    console.warn("Target element 'pm-entries-container' not found in HTML.");
    return;
  }

  container.innerHTML = '<div style="text-align:center; padding:12px; color:#64748b;">⏳ Fetching credentials...</div>';
  
  try {
    const entries = await loadPMEntries();
    container.innerHTML = '';

    if (!entries || entries.length === 0) {
      container.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:16px;">No saved passwords found.</div>';
      return;
    }

    entries.forEach(entry => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #f1f5f9; padding:10px 0; gap:10px;';
      
      row.innerHTML = `
        <div style="flex-grow:1; min-width:0;">
          <strong style="display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHTML(entry.site)}</strong>
          <span style="font-size:12px; color:#64748b; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHTML(entry.username || 'No username')}</span>
        </div>
        <div style="display:flex; gap:6px; flex-shrink:0;">
          <button onclick="copyPMPassword('${entry.id}')" style="padding:6px 10px; border-radius:6px; border:1px solid #cbd5e1; background:#fff; cursor:pointer;">📋 Copy</button>
          <button onclick="deletePMEntry('${entry.id}')" style="padding:6px 10px; border-radius:6px; border:none; background:#fee2e2; color:#ef4444; cursor:pointer;">🗑️ Delete</button>
        </div>
      `;
      container.appendChild(row);
    });
  } catch (err) {
    console.error("Failed to render password vault:", err);
    container.innerHTML = '<div style="text-align:center; color:#ef4444; padding:12px;">❌ Error loading vault list.</div>';
  }
}

// XSS Sanitizer Helper
function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag));
}

async function deletePMEntry(id) {
  if (!confirm('Delete this entry?')) return;
  try {
    if (navigator.onLine) {
      const res = await fetch(`${WORKER_URL}/passwords/delete`, {
        method: 'POST',
        headers: await getAuthHeaders(),
        body: JSON.stringify({ id })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.message || `HTTP ${res.status}`);
      }
    }
    // Always remove from local IndexedDB too
    await idbDeletePMEntry(id);
    renderPMList();
  } catch (err) {
    console.error('deletePMEntry error:', err);
    alert(`❌ Could not delete: ${err.message}`);
  }
}

/* =========================
   FEATURE 2: HOVER QUICK PREVIEW
========================= */

let previewTimeout = null;

// Cache: file.file -> ImageBitmap (rendered first page)
const previewCache = new Map();
// Track in-flight fetches so we don't double-fetch
const previewInFlight = new Map();

async function getPreviewBitmap(file) {

    if (previewCache.has(file.file))
        return previewCache.get(file.file);

    // If already fetching this file, wait for it
    if (previewInFlight.has(file.file))
        return previewInFlight.get(file.file);

    const promise = (async () => {

        // Use offline-aware fetch: tries network first, falls back to IndexedDB cache.
        // This means hover previews work even when the user is fully offline.
        const rawPassword =
            window.masterPassword || masterPassword;

        const buf =
            await fetchVaultDocWithOfflineFallback(file.file);

        const sLen =
            new Uint32Array(
                buf.slice(0, 4)
            )[0];

        if (
            sLen === 0 ||
            sLen > buf.byteLength - 32
        ) {
            throw new Error(
                "Corrupted file header."
            );
        }

        const settings =
            JSON.parse(
                new TextDecoder().decode(
                    buf.slice(4, 4 + sLen)
                )
            );

        const saltStart =
            4 + sLen;

        const saltEnd =
            saltStart + 16;

        const ivStart =
            saltEnd;

        const ivEnd =
            ivStart + 12;

        const salt =
            buf.slice(
                saltStart,
                saltEnd
            );

        const iv =
            buf.slice(
                ivStart,
                ivEnd
            );

        const enc =
            buf.slice(ivEnd);

        const phash =
            await sha256Bytes(
                masterPassword
            );

        const km =
            await crypto.subtle.importKey(
                "raw",
                phash,
                "PBKDF2",
                false,
                ["deriveKey"]
            );

        const key =
            await crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt:
                        new Uint8Array(
                            salt
                        ),
                    iterations:
                        settings.iterations,
                    hash:
                        settings.hash
                },
                km,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["decrypt"]
            );

        const dec =
            await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv:
                        new Uint8Array(
                            iv
                        )
                },
                key,
                enc
            );

        const pdf =
            await window.pdfjsLib
                .getDocument({
                    data: dec
                }).promise;

        const page =
            await pdf.getPage(1);

        const vp =
            page.getViewport({
                scale: 0.5
            });

        const offscreen =
            document.createElement(
                "canvas"
            );

        offscreen.width =
            vp.width;

        offscreen.height =
            vp.height;

        await page.render({
            canvasContext:
                offscreen.getContext(
                    "2d"
                ),
            viewport: vp
        }).promise;

        const bitmap =
            await createImageBitmap(
                offscreen
            );

        previewCache.set(
            file.file,
            bitmap
        );

        previewInFlight.delete(
            file.file
        );

        return bitmap;
    })();

    previewInFlight.set(
        file.file,
        promise
    );

    return promise;
}

async function startHoverPreview(file, e){
    clearTimeout(previewTimeout);
    previewTimeout = setTimeout(async ()=>{
        const tooltip = document.getElementById('previewTooltip');
        const canvas  = document.getElementById('previewCanvas');
        const label   = document.getElementById('previewLabel');
        label.textContent = file.name;
        tooltip.style.display = 'flex';
        positionTooltip(e);
        try{
            const bitmap = await getPreviewBitmap(file);
            canvas.width  = bitmap.width;
            canvas.height = bitmap.height;
            canvas.getContext('2d').drawImage(bitmap, 0, 0);
        }catch(err){
            canvas.width = 160; canvas.height = 90;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#f1f5f9';
            ctx.fillRect(0,0,160,90);
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Preview unavailable',80,50);
        }
    }, 40);
}

function positionTooltip(e){
    const tooltip = document.getElementById('previewTooltip');
    const x = e.clientX + 20;
    const y = e.clientY - 20;
    const maxX = window.innerWidth - 220;
    const maxY = window.innerHeight - 260;
    tooltip.style.left = Math.min(x,maxX) + 'px';
    tooltip.style.top  = Math.min(y,maxY) + 'px';
}

function hidePreviewTooltip(){
    clearTimeout(previewTimeout);
    document.getElementById('previewTooltip').style.display = 'none';
}

/* =========================
   FEATURE 3: SECURE SHARE LINKS
========================= */

let shareCurrentFile = null;

function openShareModal(file){
    shareCurrentFile = file;
    document.getElementById('share-doc-name').textContent = file.name;
    document.getElementById('share-link-result').style.display = 'none';
    document.getElementById('share-expiry').value = '24';
    document.getElementById('share-password').value = '';
    document.getElementById('shareModal').style.display = 'block';

   // Paste the reset here:
    if(document.getElementById('qr-box')) {
        document.getElementById('qr-box').style.display = 'none';
    }
    
    document.getElementById('shareModal').style.display = 'block';
}

function closeShareModal(){
    if (typeof window.animateCloseModal === 'function') {
        window.animateCloseModal('shareModal');
    } else {
        document.getElementById('shareModal').style.display = 'none';
    }
    shareCurrentFile = null;
}

async function generateShareLink(){

    if(!shareCurrentFile) return;

     // ADD THIS BLOCK ↓
  const masterPwd = window.masterPassword || masterPassword;
  if(!masterPwd) {
    alert('Cannot create share link: vault is not unlocked.');
    return;
  }
   
    const expiry =
    parseInt(
        document.getElementById(
        'share-expiry'
        ).value
    ) || 24;

    const password =
    document.getElementById(
    'share-password'
    ).value.trim();

    try{

        const res =
        await fetch(
            'https://backend.shinumaths989.workers.dev/create-share',
            {
                method:'POST',
                headers:{
                    'Content-Type':
                    'application/json'
                },
body: JSON.stringify({
  file: shareCurrentFile.file,
  name: shareCurrentFile.name,
  expiry: expiry,
  password: password || null,
  vaultKey: masterPwd
})
            }
        );

        const data =
        await res.json();

        if(data.token){

            const link =
            `${location.origin}/share.html?t=${data.token}`;

            document.getElementById(
            'share-link-text'
            ).textContent = link;

            document.getElementById(
            'share-link-result'
            ).style.display = 'block';

        }else{

            alert(
            'Could not create share link. Check backend.'
            );

        }

    }catch(err){

        console.error(err);

        // fallback client-side token
        const payload =
        btoa(JSON.stringify({

            file:
            shareCurrentFile.file,

            name:
            shareCurrentFile.name,

            exp:
            Date.now() +
            expiry * 3600000,

            pwd:
            password
            ? await window.sha256(password)
            : null,

            // real vault password
            vaultKey:
            window.masterPassword
        }));

        const link =
        `${location.origin}/share.html?t=${payload}`;

        document.getElementById(
        'share-link-text'
        ).textContent = link;

        document.getElementById(
        'share-link-result'
        ).style.display = 'block';
    }
}

function copyShareLink(){
    const text = document.getElementById('share-link-text').textContent;
    navigator.clipboard.writeText(text).then(()=>{
        alert('Link copied to clipboard!');
    }).catch(()=>{
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        alert('Link copied!');
    });
}

/* =========================
   FEATURE 4: OFFLINE ACCESS
   (Service Worker + Cloudflare R2 + IndexedDB)
========================= */

// ── IndexedDB helpers ──────────────────────────────────────────────────────
// NOTE: offline-auth.js (loaded first) owns the master DB schema and provides:
//   idbSaveDoc(filename, arrayBuffer)  — cache encrypted doc bytes
//   idbGetDoc(filename)                — retrieve cached doc bytes (ArrayBuffer)
//   idbSetVaultMeta(data)              — cache file list
//   idbGetVaultMeta()                  — retrieve file list
// This file only opens a connection for pm_entries (Password Manager).

const IDB_NAME    = 'vaultOfflineDB';
const IDB_VERSION = 8; // aligned with offline-auth.js _AUTH_DB_VERSION

function openIDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
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
      if (!db.objectStoreNames.contains('vault_notifications')) {
        db.createObjectStore('vault_notifications', { keyPath: 'id', autoIncrement: true });
      }
    };
    req.onsuccess  = e => resolve(e.target.result);
    req.onerror    = e => reject(e.target.error);
  });
}

async function idbSavePMEntry(entry) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pm_entries', 'readwrite');
    tx.objectStore('pm_entries').put(entry);
    tx.oncomplete = resolve;
    tx.onerror    = e => reject(e.target.error);
  });
}

async function idbDeletePMEntry(id) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pm_entries', 'readwrite');
    tx.objectStore('pm_entries').delete(id);
    tx.oncomplete = resolve;
    tx.onerror    = e => reject(e.target.error);
  });
}

async function idbGetAllPMEntries() {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pm_entries', 'readonly');
    const req = tx.objectStore('pm_entries').getAll();
    req.onsuccess = e => resolve(e.target.result || []);
    req.onerror   = e => reject(e.target.error);
  });
}

// Full replace of local PM cache with server list (strips deleted entries)
async function idbSyncPMEntries(serverEntries) {
  const db = await openIDB();
  return new Promise((resolve, reject) => {
    const tx    = db.transaction('pm_entries', 'readwrite');
    const store = tx.objectStore('pm_entries');
    store.clear();
    serverEntries.forEach(e => store.put(e));
    tx.oncomplete = resolve;
    tx.onerror    = e => reject(e.target.error);
  });
}

// ── Offline doc caching: all functions provided by offline-auth.js ───────────
//   idbSaveDoc(filename, arrayBuffer)  — stores encrypted bytes (Uint8Array)
//   idbGetDoc(filename)                — returns ArrayBuffer | null
//   idbSetVaultMeta(data)              — stores file list
//   idbGetVaultMeta()                  — returns file list | null

async function fetchVaultDocWithOfflineFallback(filename) {
  const isPhoto = filename.startsWith('photos/') || filename.startsWith('/photos/');
  const endpoint = isPhoto ? '/photos/' : '/docs/';
  const cleanName = filename.replace(/^(?:\/)?(?:photos|docs)\//, '');
  const url = `${WORKER_URL}${endpoint}${cleanName}`;
  const headers = { Authorization: (await getAuthHeaders()).Authorization };

  if (typeof idbGetDoc === 'function') {
    const precached = await idbGetDoc(filename).catch(() => null);
    if (precached) return precached;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    let res;
    try {
      res = await fetch(url, { headers, signal: controller.signal });
    } finally {
      clearTimeout(timeoutId);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = await res.arrayBuffer();
    if (typeof idbSaveDoc === 'function') {
      idbSaveDoc(filename, buf).catch(e => console.warn('[Offline] IDB write failed:', e));
    }
    return buf;
  } catch (err) {
    console.warn(`[Offline] Online fetch failed for ${filename}:`, err.message);
  }

  // ── Last resort: check IDB again (race: may have been cached since check) ─
  if (typeof idbGetDoc === 'function') {
    const cached = await idbGetDoc(filename);
    if (cached) return cached;
  }
  throw new Error('Document not available offline. Open it online first to cache it.');
}

// ── Pre-cache all visible vault docs after login ──────────────────────────────

async function preCacheVaultDocs(filesData) {
  // Do NOT gate on navigator.onLine — it's unreliable and would skip caching
  // even when the network is actually available. Let individual fetches fail
  // gracefully instead.

  const allFiles = [];
  Object.entries(filesData).forEach(([catName, cat]) => {
    if (Array.isArray(cat)) cat.forEach(f => allFiles.push({ ...f, category: f.category || catName }));
  });

  if (typeof idbSetVaultMeta === 'function') {
    await idbSetVaultMeta(filesData).catch(e => console.warn('[Offline] Meta save failed:', e));
  }

  const authHeaders = { Authorization: (await getAuthHeaders()).Authorization };

  for (const f of allFiles) {
    if (!f.file) continue;
    if (typeof idbGetDoc === 'function') {
      const existing = await idbGetDoc(f.file).catch(() => null);
      if (existing) { console.log(`[Offline cache] Already cached: ${f.file}`); continue; }
    }
    const isPhotoFile = f.category === 'PHOTOS' || /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(f.file);
    const routePrefix = isPhotoFile ? 'photos/' : 'docs/';
    try {
      const res = await fetch(`${WORKER_URL}/${routePrefix}${f.file}`, { headers: authHeaders });
      if (res.ok) {
        const buf = await res.arrayBuffer();
        if (typeof idbSaveDoc === 'function') await idbSaveDoc(f.file, buf);
        console.log(`[Offline cache] Cached: ${f.file}`);
      } else {
        console.warn(`[Offline cache] HTTP ${res.status} for: ${routePrefix}${f.file}`);
      }
    } catch (e) {
      console.warn(`[Offline cache] Skipped ${f.file}:`, e.message);
    }
  }
  console.log('[Offline cache] Pre-caching complete.');
}

// ── Logout: clears session + SW cache so login works cleanly again ─────────

/**
 * Call this from your logout button instead of (or in addition to) whatever
 * you're doing today.  It:
 *   1. Clears sessionStorage (vault tokens) and relevant localStorage keys
 *   2. Tells the SW to wipe its cache (fixes stale-shell login-after-logout bug)
 *   3. Redirects to / so the user lands on a fresh unauthenticated page
 *
 * Wire up your logout button: <button onclick="vaultLogout()">Logout</button>
 */
async function vaultLogout() {
  clearTimeout(inactivityTimer);
  if (typeof _sessionTimerInterval !== 'undefined' && _sessionTimerInterval) {
      clearInterval(_sessionTimerInterval);
      _sessionTimerInterval = null;
  }
  _inactivityMonitorAttached = false;

  // 1. Clear all vault session keys
  sessionStorage.removeItem('vaultSessionToken');
  sessionStorage.removeItem('vaultSession');
  sessionStorage.removeItem('sessionToken');
  sessionStorage.removeItem('vaultMode');
  localStorage.removeItem('sessionToken');
  // Wipe master password from memory
  if (typeof window.masterPassword !== 'undefined') window.masterPassword = null;

  // 2. Tell the SW to purge its shell cache so the next page load is a fresh
  //    network fetch — this is what fixes "login page broken after logout"
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage({ type: 'CLEAR_SESSION' });
    // Give the SW ~150ms to process the message before navigating away
    await new Promise(r => setTimeout(r, 150));
  }

  // 3. Navigate to root (login page) — hard reload bypasses any in-memory state
  window.location.href = '/';
}

// ── Offline/online detection + banner ─────────────────────────────────────

window.addEventListener('offline', () => {
  const banner = document.getElementById('offline-banner');
  if (banner) banner.style.display = 'block';
});
window.addEventListener('online', async () => {
  const banner = document.getElementById('offline-banner');
  if (banner) banner.style.display = 'none';
  // Re-sync PM entries when coming back online
  try {
    const entries = await loadPMEntries();
    console.log('[Online] PM entries re-synced:', entries.length);
  } catch (e) { /* silent */ }
});

// ── Service Worker registration ────────────────────────────────────────────
// NOTE: SW is already registered by index.html with the versioned URL
// (?v=SHINE_OFFLINE_FIX_VERSION). We only register here as a fallback for
// environments where index.html's inline script hasn't run yet.

if ('serviceWorker' in navigator && !navigator.serviceWorker.controller) {
  const swVersion = window.SHINE_OFFLINE_FIX_VERSION || 'default';
  navigator.serviceWorker.register('/sw.js', { updateViaCache: 'none' })
    .then(reg => {
      console.log('[SW] Registered, scope:', reg.scope);
      if (reg.waiting) reg.waiting.postMessage({ type: 'SKIP_WAITING' });
    })
    .catch(err => console.warn('[SW] Registration failed (expected in dev):', err));
}

/* =========================
   FEATURE 5: (Email Login Notification removed)
========================= */

/* =========================
   FEATURE 6: FAVOURITES / PIN DOCS
========================= */

let pinnedDocs = JSON.parse(localStorage.getItem('vaultPinned') || '[]');

function savePinned(){
    localStorage.setItem('vaultPinned', JSON.stringify(pinnedDocs));
}

function togglePin(file, btn){
    const idx = pinnedDocs.findIndex(p => p.file === file.file);
    if(idx === -1){
        pinnedDocs.push(file);
        btn.classList.add('pinned');
        btn.textContent = '⭐ Pinned';
    } else {
        pinnedDocs.splice(idx, 1);
        btn.classList.remove('pinned');
        btn.textContent = '☆ Pin';
    }
    savePinned();
    renderPinnedSection();
}

function renderPinnedSection(){
    const section = document.getElementById('pinned-section');
    const grid    = document.getElementById('pinned-grid');
    if(!pinnedDocs.length){
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';
    grid.innerHTML = '';
    pinnedDocs.forEach(file=>{
        const chip = document.createElement('div');
        chip.className = 'pinned-chip';
        chip.innerHTML = `📄 ${file.name} <span style="color:#ef4444;font-size:14px;margin-left:4px;" title="Unpin">✕</span>`;
chip.onclick = ()=> openSecureFile((file.category === 'PHOTOS' ? "photos/" : "docs/") + file.file, file.name);
       chip.querySelector('span').onclick = (e)=>{
            e.stopPropagation();
            pinnedDocs = pinnedDocs.filter(p => p.file !== file.file);
            savePinned();
            renderPinnedSection();
            // Re-render current category to update pin button states
            if(typeof currentCategory !== 'undefined' && typeof allFilesData !== 'undefined' && allFilesData[currentCategory]){
                renderFiles(allFilesData[currentCategory], currentCategory);
            }
        };
        grid.appendChild(chip);
    });
}

function showPinned(){
    renderPinnedSection();
    const section = document.getElementById('pinned-section');
    if(pinnedDocs.length){
        section.scrollIntoView({behavior:'smooth'});
    } else {
        alert('No pinned documents yet.\nClick ☆ Pin on any document card to favourite it.');
    }
}

/* =========================
   FEATURE 7: COMPARE 2 DOCS
========================= */

let compareQueue  = [];   // up to 2 files
let compareSide   = null; // 'left' | 'right' – for manual pick

function startCompareMode(){
    if(compareQueue.length === 0){
        alert('Click ⚖️ Compare on any two document cards first, then use this button — or use Compare from the cards directly.');
        return;
    }
    openCompareModal();
}

function addToCompare(file){
    // If already in queue, remove it
    const idx = compareQueue.findIndex(f => f.file === file.file);
    if(idx !== -1){
        compareQueue.splice(idx,1);
    } else {
        if(compareQueue.length >= 2) compareQueue.shift();
        compareQueue.push(file);
    }
    updateCompareBar();
    if(compareQueue.length === 2){
        if(confirm(`Compare "${compareQueue[0].name}" vs "${compareQueue[1].name}"?`)){
            openCompareModal();
        }
    }
}

function updateCompareBar(){
    const bar = document.getElementById('compare-bar');
    const txt = document.getElementById('compare-bar-text');
    if(compareQueue.length === 0){
        bar.style.display = 'none';
    } else {
        bar.style.display = 'flex';
        const names = compareQueue.map(f=>`"${f.name}"`).join(' vs ');
        txt.textContent = `⚖️ ${compareQueue.length === 1 ? 'Pick one more: ' + compareQueue[0].name : names}`;
    }
}

function clearCompare(){
    compareQueue = [];
    updateCompareBar();
}

async function openCompareModal(){
    document.getElementById('compareModal').style.display = 'block';
    if(compareQueue[0]) await renderComparePane('left',  compareQueue[0]);
    if(compareQueue[1]) await renderComparePane('right', compareQueue[1]);
}

function closeCompareModal(){
    if (typeof window.animateCloseModal === 'function') {
        window.animateCloseModal('compareModal');
    } else {
        document.getElementById('compareModal').style.display = 'none';
    }
}

async function renderComparePane(side, file){
    const titleEl = document.getElementById(`compare-${side}-title`);
    const contentEl = document.getElementById(`compare-${side}-content`);
    titleEl.textContent = file.name;
    contentEl.innerHTML = '<div class="compare-select-prompt">⏳ Decrypting & rendering…</div>';

    try {
        const rawPassword = window.masterPassword || masterPassword;

        // Use offline-aware fetch: serves from IndexedDB when offline.
        // No session token check needed — fetchVaultDocWithOfflineFallback
        // adds the Authorization header automatically when online.
        const buf = await fetchVaultDocWithOfflineFallback(file.file);
        const sLen = new Uint32Array(buf.slice(0,4))[0];
        if(sLen === 0 || sLen > buf.byteLength - 32) throw new Error('Corrupted file header.');

        const settings = JSON.parse(new TextDecoder().decode(buf.slice(4, 4 + sLen)));
        const saltStart = 4 + sLen;
        const saltEnd = saltStart + 16;
        const salt = buf.slice(saltStart, saltEnd);
        const ivStart = saltEnd;
        const ivEnd = ivStart + 12;
        const iv = buf.slice(ivStart, ivEnd);
        const encryptedData = buf.slice(ivEnd);

        // 2. Compute the correct byte array hash using the raw password string
        const pHash = await sha256Bytes(rawPassword);

        const km = await crypto.subtle.importKey(
            "raw", pHash, "PBKDF2", false, ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new Uint8Array(salt),
                iterations: settings.iterations,
                hash: settings.hash
            },
            km,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv) },
            key,
            encryptedData
        );

        // ==========================================
        // Render implementation for individual panes
        // ==========================================
        const pdf = await window.pdfjsLib.getDocument({ data: decrypted }).promise;
        contentEl.innerHTML = ""; // Clear loader

        for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {

            const page = await pdf.getPage(pageNum);

            // Get parent width
            const containerWidth = contentEl.clientWidth - 30;

            // Original PDF size
            const originalViewport = page.getViewport({ scale: 1 });

            // Auto fit scale
            const fitScale = containerWidth / originalViewport.width;

            // Apply user zoom INSIDE viewer only
            const safeScale = Math.max(fitScale, 0.8);

            const viewport = page.getViewport({ scale: safeScale });

            // Create canvas
            const canvas = document.createElement('canvas');

            canvas.className = 'pdf-page';

            // Responsive styling
            canvas.style.display = "block";
            canvas.style.margin = "0 auto 14px auto";
            canvas.style.width = "100%";
            canvas.style.maxWidth = "100%";
            canvas.style.height = "auto";
            canvas.style.borderRadius = "12px";
            canvas.style.boxShadow = "0 4px 18 rgba(0,0,0,.12)";

            // Render
            const context = canvas.getContext('2d');
            canvas.width = viewport.width;
            canvas.height = viewport.height;

            await page.render({
                canvasContext: context,
                viewport: viewport
            }).promise;

            contentEl.appendChild(canvas);
        }

    } catch (err) {
        console.error(err);
        contentEl.innerHTML = `<div class="compare-select-prompt" style="color:var(--danger)">❌ Decryption Failed: ${err.message}</div>`;
    }
}
   
function pickCompareDoc(side){
    compareSide = side;
    closeCompareModal();
    alert(`Click ⚖️ Compare on the document you want for side ${side === 'left' ? 'A (Left)' : 'B (Right)'}, then re-open Compare.`);
}

/* =========================
   FEATURE 8: DOC EXPIRY REMINDER
========================= */

async function checkDocExpiryReminders(){
    if (typeof allFilesData === 'undefined') return;
    const allFiles = [];
    Object.values(allFilesData).forEach(cat=>{
        if(Array.isArray(cat)) cat.forEach(f=>{ if(f.expiry) allFiles.push(f); });
    });
    if(!allFiles.length) return;
    const expiringSoon = allFiles.filter(f=>{
        const days = Math.ceil((new Date(f.expiry) - new Date()) / 86400000);
        return days >= 0 && days <= 30;
    });
    if(!expiringSoon.length) return;
    try{
        await fetch(
            'https://backend.shinumaths989.workers.dev/expiry-reminder',
            {
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body: JSON.stringify({
                    docs: expiringSoon.map(f=>({
                        name:   f.name,
                        expiry: f.expiry,
                        daysLeft: Math.ceil((new Date(f.expiry) - new Date()) / 86400000)
                    }))
                })
            }
        );
        console.log('Expiry reminder sent for', expiringSoon.length, 'document(s)');
    }catch(err){
        console.warn('Expiry reminder failed:', err);
    }
}

function saveTrustDevice() {
  const cb = document.getElementById('trust-device');
  if (cb && cb.checked) {
    const mode = sessionStorage.getItem('vaultMode') || 'ADMIN';
    const modeToMember = { SHINEIL:'shineil', KEVIN:'brother', PARENTS:'father', SHINEIL_PARENTS:'shineil', KEVIN_PARENTS:'brother', OFFICIAL:'official', ADMIN:'shineil' };
    const member = modeToMember[mode] || 'shineil';
    const token = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession') || '';
    const existing = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
    // Always save the current session token (tokens expire after 1 hour, so reusing old ones causes 401)
    const savedToken = token || (existing && existing.token) || '';
    // Save the master password secret so trusted sessions can decrypt files
    const secret = window.masterPassword || (existing && existing.secret) || '';
    localStorage.setItem('vaultTrustInfo', JSON.stringify({
      member,
      user: (document.getElementById('user-name')?.value || '').trim(),
      token: savedToken,
      secret: secret,
      expiry: Date.now() + 14 * 86400000
    }));
  }
}

// Post-init hook: called at end of onCaptchaSuccess after initVault()
function vaultPostInit(){
  saveTrustDevice();
   const mode = sessionStorage.getItem("vaultMode");

const sel = document.getElementById("member-select");

const members = {

ADMIN: ["shineil","brother","father","mother","official"],

OFFICIAL: ["official"],

PARENTS: ["father","mother"],

SHINEIL_PARENTS: ["shineil","father","mother"],

KEVIN_PARENTS: ["brother","father","mother"],

KEVIN: ["brother"],

SHINEIL: ["shineil"]

}[mode] || ["shineil"];

const labels = {

shineil: "SHINEIL MATHIAS",

brother: "KEVIN MATHIAS",

father: "STEPHEN MATHIAS",

mother: "KANCHAN MATHIAS",

official: "OFFICIAL DOCUMENTS"

};

if (sel) {
  sel.innerHTML = members

.map(m => `<option value="${m}">${labels[m]}</option>`)

.join("");

    if (mode === "SHINEIL_PARENTS") sel.value = "shineil";
    if (mode === "KEVIN_PARENTS")   sel.value = "brother";
    if (mode === "PARENTS")         sel.value = "father";
    if (mode === "SHINEIL")         sel.value = "shineil";
    if (mode === "KEVIN")           sel.value = "brother";
    if (mode === "OFFICIAL")        sel.value = "official";
}
   if (sel) setTimeout(() => sel.dispatchEvent(new Event("change")), 0);

   // ── Hide member dropdown for non-ADMIN modes ──
const memberSelectWrap = document.getElementById('sidebar-controls-wrap');

const multiMemberModes = [
    "ADMIN",
    "PARENTS",
    "SHINEIL_PARENTS",
    "KEVIN_PARENTS"
];

   const currentMode = sessionStorage.getItem("vaultMode");
if (!multiMemberModes.includes(currentMode) && memberSelectWrap) {
    memberSelectWrap.style.display = "none";
}

    renderPinnedSection();
    setTimeout(checkDocExpiryReminders, 2000);
    // Load notifications and show badge/bubble
setTimeout(() => initVaultNotifications().catch(() => {}), 400);

    // ── Eagerly decrypt photos in the background so they're warm by the time
    // the user opens PHOTOS, and so opening a photo doesn't take 5-10s.
    // Goes through the shared, concurrency-limited decrypt queue in
    // viewer.js, so this doesn't fire 20+ simultaneous fetch+decrypt calls.
    setTimeout(() => {
      try {
        if (typeof getAllPhotos === 'function' && typeof preDecryptAllPhotos === 'function') {
          preDecryptAllPhotos(getAllPhotos());
        }
      } catch (e) {
        console.warn('[Photos] Eager pre-decrypt kickoff failed:', e);
      }
    }, 200);

    // ── Pre-cache vault docs into IndexedDB for offline access ──
    // Runs after a short delay so it doesn't compete with the initial render
    setTimeout(async () => {
      if (typeof allFilesData !== 'undefined' && allFilesData) {
        await preCacheVaultDocs(allFilesData).catch(e => console.warn('[Offline] Pre-cache error:', e));
      }
    }, 3000);

   // ── Sync all member credentials for offline login ──
   setTimeout(() => {
       if (typeof syncAllMembersOffline === 'function') {
           syncAllMembersOffline().catch(e =>
               console.warn('[OfflineAuth] Background all-member sync failed:', e.message)
           );
       }
   }, 1000);

   setTimeout(() => {
    if (typeof window._repairRefresh === 'function') window._repairRefresh();
}, 500);

    // ── Member filter: read URL param ──
    const urlParams = new URLSearchParams(window.location.search);
    const sharedMember = urlParams.get('member');
    if (sharedMember) {
        const sel = document.getElementById('member-select');
        if (sel) {
            sel.value = sharedMember;
            sel.disabled = true; // lock dropdown when opened via shared link
        }
    }

    // ── Member filter: re-render current category on dropdown change (once) ──
    const selEl = document.getElementById('member-select');
    if (selEl && !selEl.dataset.vaultListenerAttached) {
        selEl.dataset.vaultListenerAttached = '1';
        selEl.addEventListener('change', () => {
            const activeLi = document.querySelector('#cat-list li.active');
            if (activeLi) activeLi.click();
        });
    }
}

function getCurrentVaultMember() {
  const sel = document.getElementById('member-select');
  if (sel && sel.value && sel.value !== 'all') return sel.value;

  const mode = window.VAULT_MODE || sessionStorage.getItem('vaultMode') || 'ADMIN';
  const map = {
    SHINEIL: 'shineil',
    KEVIN: 'brother',
    OFFICIAL: 'official',
    PARENTS: 'father',
    SHINEIL_PARENTS: 'shineil',
    KEVIN_PARENTS: 'brother',
    ADMIN: null  // ADMIN reads from dropdown, already handled above
  };
  return map[mode] || 'shineil';
}
window.getCurrentVaultMember = getCurrentVaultMember;

// ═══════════════════════════════════════════════════════════════
//  VAULT NOTIFICATIONS SYSTEM
//  Reads published notifications from IndexedDB (written by notify.html)
//  Shows badge count on bell + welcome bubble on login
// ═══════════════════════════════════════════════════════════════

const NOTIF_IDB_NAME    = 'vaultOfflineDB';
const NOTIF_IDB_VERSION = 8; // aligned with offline-auth.js _AUTH_DB_VERSION

function openNotifIDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(NOTIF_IDB_NAME, NOTIF_IDB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('pm_entries'))         db.createObjectStore('pm_entries',          { keyPath: 'id' });
      if (!db.objectStoreNames.contains('vault_docs'))         db.createObjectStore('vault_docs',          { keyPath: 'filename' });
      if (!db.objectStoreNames.contains('vault_meta'))         db.createObjectStore('vault_meta',          { keyPath: 'key' });
      if (!db.objectStoreNames.contains('vault_auth'))         db.createObjectStore('vault_auth',          { keyPath: 'id' });
      if (!db.objectStoreNames.contains('vault_notifications'))db.createObjectStore('vault_notifications', { keyPath: 'id', autoIncrement: true });
    };
    req.onsuccess  = e => resolve(e.target.result);
    req.onerror    = e => reject(e.target.error);
  });
}

async function idbGetNotifications() {
  try {
    const db = await openNotifIDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('vault_notifications', 'readonly');
      const req = tx.objectStore('vault_notifications').getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror   = () => resolve([]);
    });
  } catch { return []; }
}

async function idbMarkNotifRead(id) {
  try {
    const db = await openNotifIDB();
    const tx = db.transaction('vault_notifications', 'readwrite');
    const store = tx.objectStore('vault_notifications');
    const rec = await new Promise(r => { const g = store.get(id); g.onsuccess = () => r(g.result); });
    if (rec) { rec.read = true; store.put(rec); }
  } catch {}
}

// Called by vaultPostInit — loads notifications and shows badge + bubble
async function initVaultNotifications() {
  // Sync from Firestore — server is the single source of truth for all devices
  try {
    const currentUserForSync = sessionStorage.getItem('vaultUser') || 'all';
    const res = await fetch(`${WORKER_URL}/get-notifications`, {
      method: 'POST',
      headers: await getAuthHeaders(),
      body: JSON.stringify({ user: currentUserForSync, vaultUser: currentUserForSync })
    });
    if (res.ok) {
      const data = await res.json();
      const serverNotifs = data.notifications || [];

      // Preserve read-status from local IDB, then replace local with server list
      // This handles: new notifs added on other devices AND deletions by admin
      const local = await idbGetNotifications();
      const readSet = new Set(local.filter(n => n.read).map(n => n._key || String(n.id)));

      const db = await openNotifIDB();
      await new Promise((resolve, reject) => {
        const tx = db.transaction('vault_notifications', 'readwrite');
        tx.objectStore('vault_notifications').clear();
        tx.oncomplete = resolve;
        tx.onerror = reject;
      });
      const db2 = await openNotifIDB();
      const tx2 = db2.transaction('vault_notifications', 'readwrite');
      const store2 = tx2.objectStore('vault_notifications');
      for (const n of serverNotifs) {
        const key = n._key || String(n.id);
        store2.put({ ...n, read: readSet.has(key) ? true : (n.read || false) });
      }
      await new Promise((resolve, reject) => { tx2.oncomplete = resolve; tx2.onerror = reject; });
    } else {
      console.warn(`[Notifications] get-notifications HTTP ${res.status}: ${await res.text().catch(() => '')}`);
    }
  } catch (e) {
    // Server endpoint not available — use local IDB only
    console.warn('[Notifications] Server sync failed, using local IDB only:', e.message);
  }

  const all = await idbGetNotifications();
  const currentUser = sessionStorage.getItem('vaultUser') || 'all';
  // Filter: show Global or targeted to this user
  const relevant = all.filter(n => {
    if (n.type === 'global') return true;
    if (n.type === 'targeted') {
      const targets = (n.targets || '').toLowerCase().split(',').map(x => x.trim());
      return targets.includes(currentUser.toLowerCase()) || targets.includes('all');
    }
    return true;
  }).sort((a,b) => (b.timestamp||0) - (a.timestamp||0));

  const unread = relevant.filter(n => !n.read);
  _updateNotifBadge(unread.length);

  // Float ALL relevant notifications one-by-one on every login,
  // even ones already marked read in a previous session.
  if (relevant.length > 0) {
    _showNotifBubbleQueue(relevant);
  }
}

function _showNotifBubbleQueue(notes, idx = 0) {
  if (idx >= notes.length) return;
  _showNotifWelcomeBubble(notes, idx);
  const delay = 6000; // each bubble shows for 6s before the next floats in
  setTimeout(() => {
    dismissNotifBubble();
    setTimeout(() => _showNotifBubbleQueue(notes, idx + 1), 300);
  }, delay);
}

function _updateNotifBadge(count) {
  const dot   = document.getElementById('notifDot');
  const badge = document.getElementById('notifCount');
  if (!dot || !badge) return;
  if (count > 0) {
    dot.style.display   = 'none';
    badge.style.display = 'block';
    badge.textContent   = count > 9 ? '9+' : count;
  } else {
    dot.style.display   = 'none';
    badge.style.display = 'none';
  }
}

function _showNotifWelcomeBubble(notes, idx = 0) {
  const bubble = document.getElementById('notifWelcomeBubble');
  if (!bubble) return;
  const preview = document.getElementById('bubbleNotifPreview');
  const current = notes[idx];
  if (preview && current) {
    const pCls = current.priority || 'info';
    const pEmojis = { info:'ℹ️', warning:'⚠️', urgent:'🔴' };
    preview.innerHTML = `<strong style="color:#f8fafc;">${pEmojis[pCls]||'ℹ️'} ${escHtml(current.title || 'Admin Notification')}</strong><br><span style="color:#cbd5e1;">${escHtml((current.body || '').substring(0, 80))}${(current.body||'').length > 80 ? '…' : ''}</span>`;
  }
  // Show progress indicator when there are multiple queued notifications
  let progress = document.getElementById('bubbleNotifProgress');
  if (notes.length > 1) {
    if (!progress) {
      progress = document.createElement('div');
      progress.id = 'bubbleNotifProgress';
      progress.style.cssText = 'margin-top:6px;font-size:10px;color:#94a3b8;text-align:right;';
      bubble.appendChild(progress);
    }
    progress.textContent = `${idx + 1} / ${notes.length}`;
    progress.style.display = 'block';
  } else if (progress) {
    progress.style.display = 'none';
  }
  bubble.style.display = 'block';
  bubble.style.opacity = '1';
  bubble.style.transform = 'none';
  bubble.style.animation = 'notifBubblePop .35s cubic-bezier(.34,1.56,.64,1)';
}

function dismissNotifBubble() {
  const bubble = document.getElementById('notifWelcomeBubble');
  if (bubble) { bubble.style.opacity='0'; bubble.style.transform='scale(.92)'; bubble.style.transition='.2s'; setTimeout(() => bubble.style.display='none', 200); }
}

function openNotifBubble() {
  dismissNotifBubble();
  toggleNotifications();
}

function toggleNotifications() {
  const panel = document.getElementById('notifPanel');
  if (!panel) return;
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  if (!isOpen) {
    _renderNotifPanel();
    dismissNotifBubble();
  }
}

async function _renderNotifPanel() {
  try {
    const listEl = document.getElementById('notifList');
    if (!listEl) return;
  const all = await idbGetNotifications();
  const currentUser = sessionStorage.getItem('vaultUser') || 'all';
  const relevant = all.filter(n => {
    if (n.type === 'global') return true;
    if (n.type === 'targeted') {
      const targets = (n.targets || '').toLowerCase().split(',').map(x => x.trim());
      return targets.includes(currentUser.toLowerCase()) || targets.includes('all');
    }
    return true;
  }).sort((a,b) => (b.timestamp||0) - (a.timestamp||0));

  if (relevant.length === 0) {
    listEl.innerHTML = '<div style="text-align:center;color:#94a3b8;padding:24px;font-size:13px;">No notifications yet</div>';
    return;
  }
  listEl.innerHTML = relevant.map(n => {
    const pCls = n.priority || 'info';
    const pColors = { info: {bg:'rgba(59,130,246,.2)',c:'#93c5fd'}, warning: {bg:'rgba(245,158,11,.2)',c:'#fcd34d'}, urgent: {bg:'rgba(239,68,68,.2)',c:'#fca5a5'} };
    const pc = pColors[pCls] || pColors.info;
    return `
    <div id="notif-item-${n.id}" onclick="markNotifRead('${n.id}')" style="padding:10px 12px;border-radius:10px;margin-bottom:6px;cursor:pointer;background:${n.read ? 'transparent' : 'rgba(59,130,246,.07)'};border:1px solid ${n.read ? 'transparent' : 'rgba(59,130,246,.15)'};transition:.2s;">
      <div style="display:flex;align-items:flex-start;gap:8px;">
        <span style="font-size:18px;flex-shrink:0;">${n.type === 'global' ? '📢' : '🎯'}</span>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:${n.read ? '600' : '800'};font-size:13px;color:#0f172a;margin-bottom:2px;">${escHtml(n.title||'Notification')}</div>
          <div style="font-size:12px;color:#475569;line-height:1.5;">${escHtml(n.body||'')}</div>
          <div style="font-size:10px;color:#94a3b8;margin-top:4px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <span style="display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;font-weight:800;background:${pc.bg};color:${pc.c};">${pCls.toUpperCase()}</span>
            <span>${n.type === 'global' ? '🌐 Global' : '🎯 ' + escHtml(n.targets || 'Targeted')}</span>
            <span>${n.timestamp ? new Date(n.timestamp).toLocaleString() : ''}</span>
          </div>
        </div>
        ${!n.read ? '<span style="width:8px;height:8px;border-radius:50%;background:#3b82f6;flex-shrink:0;margin-top:4px;"></span>' : ''}
      </div>
    </div>`;
  }).join('');
  } catch (e) {
    if (listEl) listEl.innerHTML = '<div style="text-align:center;color:#94a3b8;padding:24px;font-size:13px;">⚠️ Could not load notifications</div>';
  }
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function markNotifRead(id) {
  await idbMarkNotifRead(id);
  const el = document.getElementById(`notif-item-${id}`);
  if (el) { el.style.background='transparent'; el.style.border='1px solid transparent'; const dot = el.querySelector('span[style*="8px;border-radius:50%;background:#3b82f6"]'); if(dot) dot.remove(); }
  // Recount unread
  const all = await idbGetNotifications();
  const unread = all.filter(n => !n.read);
  _updateNotifBadge(unread.length);
}

async function markAllNotifsRead() {
  const all = await idbGetNotifications();
  for (const n of all) if (!n.read) await idbMarkNotifRead(n.id);
  _updateNotifBadge(0);
  _renderNotifPanel();
}

// Close notif panel when clicking outside
document.addEventListener('click', function(e) {
  const panel = document.getElementById('notifPanel');
  const btn   = document.getElementById('notifBellBtn');
  if (panel && panel.style.display !== 'none' && !panel.contains(e.target) && btn && !btn.contains(e.target)) {
    panel.style.display = 'none';
  }
});

// Bubble pop animation
(function() {
  const s = document.createElement('style');
  s.textContent = `@keyframes notifBubblePop { from { opacity:0; transform:scale(.85) translateY(-6px); } to { opacity:1; transform:scale(1) translateY(0); } }`;
  document.head.appendChild(s);
})();
