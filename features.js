/* =========================
   FEATURE 1: E2E ENCRYPTION
   (AES-256-GCM already used in
   openSecureFile – badge shown in
   navbar. No additional JS needed.)
========================= */

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

        // SAME AUTH AS openSecureFile()
        const rawPassword =
            window.masterPassword || masterPassword;

        const token =
            await window.sha256(rawPassword);

        const sessionToken =
    sessionStorage.getItem("vaultSession");

const previewSessionToken =
    sessionStorage.getItem("vaultSessionToken") ||
    sessionStorage.getItem("vaultSession");

const res = await fetch(
    "https://backend.shinumaths989.workers.dev/docs/" + file.file,
    {
        headers: {
            "Authorization":
                "Bearer " + previewSessionToken
        }
    }
);

        if (!res.ok) {
            const eb =
                await res.json()
                .catch(() => ({}));

            throw new Error(
                eb.message ||
                `HTTP ${res.status}`
            );
        }

        const rct =
            res.headers.get("content-type") || "";

        if (rct.includes("application/json")) {
            const eb =
                await res.json();

            throw new Error(
                eb.message ||
                "JSON error"
            );
        }

        const buf =
            await res.arrayBuffer();

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
    document.getElementById('shareModal').style.display = 'none';
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
   (Cloudflare R2 + Service Worker)
========================= */

// Offline/online detection
window.addEventListener('offline', ()=>{
    document.getElementById('offline-banner').style.display = 'block';
});
window.addEventListener('online', ()=>{
    document.getElementById('offline-banner').style.display = 'none';
});

// Register Service Worker for offline caching
if('serviceWorker' in navigator){
    navigator.serviceWorker.register('/sw.js').catch(()=>{
        // sw.js not present in dev environment – silently ignore
    });
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
        chip.onclick = ()=> openSecureFile("docs/" + file.file, file.name);
        chip.querySelector('span').onclick = (e)=>{
            e.stopPropagation();
            pinnedDocs = pinnedDocs.filter(p => p.file !== file.file);
            savePinned();
            renderPinnedSection();
            // Re-render current category to update pin button states
            if(currentCategory && allFilesData[currentCategory]){
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
    document.getElementById('compareModal').style.display = 'none';
}

async function renderComparePane(side, file){
    const titleEl = document.getElementById(`compare-${side}-title`);
    const contentEl = document.getElementById(`compare-${side}-content`);
    titleEl.textContent = file.name;
    contentEl.innerHTML = '<div class="compare-select-prompt">⏳ Decrypting & rendering…</div>';

    try {
        const rawPassword = window.masterPassword || masterPassword;

        // FIX: use the real session token (same as openSecureFile/initVault)
        const vaultSessionToken =
            sessionStorage.getItem("vaultSessionToken") ||
            sessionStorage.getItem("vaultSession");

        if (!vaultSessionToken) throw new Error("Missing session token. Please log in again.");

        const res = await fetch("https://backend.shinumaths989.workers.dev/docs/" + file.file, {
            headers: {
                "Authorization": "Bearer " + vaultSessionToken
            }
        });

        if(!res.ok){
            const eb = await res.json().catch(()=>({}));
            throw new Error(eb.message || `HTTP ${res.status}`);
        }
        const rct2 = res.headers.get('content-type') || '';
        if(rct2.includes('application/json')){
            const eb = await res.json();
            throw new Error(eb.message || 'JSON error');
        }

        const buf = await res.arrayBuffer();
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

    const page =
    await pdf.getPage(pageNum);

    // Get parent width
    const containerWidth =
    contentEl.clientWidth - 30;

    // Original PDF size
    const originalViewport =
    page.getViewport({
        scale: 1
    });

    // Auto fit scale
    const fitScale =
    containerWidth /
    originalViewport.width;

    // Apply user zoom INSIDE viewer only
    const safeScale =
Math.max(
    fitScale,
    0.8
);

const viewport =
page.getViewport({
    scale: safeScale
});

    // Create canvas
    const canvas =
    document.createElement(
        'canvas'
    );

    canvas.className =
    'pdf-page';

    // Responsive styling
    canvas.style.display =
    "block";

    canvas.style.margin =
    "0 auto 14px auto";

    canvas.style.width =
    "100%";

    canvas.style.maxWidth =
    "100%";

    canvas.style.height =
    "auto";

    canvas.style.borderRadius =
    "12px";

    canvas.style.boxShadow =
    "0 4px 18px rgba(0,0,0,.12)";

    // Render
    const context =
    canvas.getContext('2d');

    canvas.width =
    viewport.width;

    canvas.height =
    viewport.height;

    await page.render({
        canvasContext:
        context,
        viewport:
        viewport
    }).promise;

    contentEl.appendChild(
    canvas
);
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

// Post-init hook: called at end of onCaptchaSuccess after initVault()
function vaultPostInit(){
   // ── Hide member dropdown for non-ADMIN modes ──
    const mode = sessionStorage.getItem("vaultMode");
    const memberSelectWrap = document.getElementById('member-select')?.parentElement;
    if (mode !== "ADMIN" && memberSelectWrap) {
        memberSelectWrap.style.display = "none";
    }

    renderPinnedSection();
    setTimeout(checkDocExpiryReminders, 2000);

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

    // ── Member filter: re-render current category on dropdown change ──
    document.getElementById('member-select')?.addEventListener('change', () => {
        const activeLi = document.querySelector('#cat-list li.active');
        if (activeLi) activeLi.click();
    });
}