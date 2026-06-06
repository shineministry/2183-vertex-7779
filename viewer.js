/* =========================
   INDEXED DB HELPER
========================= */

function openVaultDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("ShineVaultFiles", 1);
        request.onupgradeneeded = event => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains("secureFiles")) {
                db.createObjectStore("secureFiles", { keyPath: "path" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror  = () => reject(request.error);
    });
}

/* =========================
   OPEN FILE
========================= */

async function openSecureFile(
path,
displayName){

    if(!window.masterPassword){

 const savedSecret =
 sessionStorage.getItem(
 "vault_session_secret"
 );

 if(savedSecret){

  window.masterPassword =
  savedSecret;

 } else {

  alert(
  "Session not unlocked. Please log in again."
  );

  return;
 }
}

    try {
    const vaultSessionToken =
        sessionStorage.getItem("vaultSessionToken") ||
        sessionStorage.getItem("vaultSession");

    if (!vaultSessionToken) {
        throw new Error("Missing vault session token. Please log in again.");
    }

    // =========================
    // FETCH: ONLINE → backend, OFFLINE → IndexedDB
    // =========================

    let buffer;

    if (navigator.onLine) {

        // ONLINE MODE
        const res = await fetch("https://backend.shinumaths989.workers.dev/" + path, {
            headers: {
                "Authorization": "Bearer " + vaultSessionToken
            }
        });

        // GUARD: catch backend error responses before treating as binary
        if (!res.ok) {
            const ct = res.headers.get('content-type') || '';
            if (ct.includes('application/json')) {
                const errBody = await res.json();
                throw new Error(errBody.message || `Server error: HTTP ${res.status}`);
            }
            throw new Error(`Server error: HTTP ${res.status}`);
        }
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
            const errBody = await res.json();
            throw new Error(errBody.message || 'Backend returned JSON instead of encrypted file.');
        }

        buffer = await res.arrayBuffer();

        // SAVE ENCRYPTED COPY TO INDEXEDDB FOR OFFLINE USE
        try {
            const db  = await openVaultDB();
            const tx  = db.transaction("secureFiles", "readwrite");
            tx.objectStore("secureFiles").put({
                path: path,
                data: buffer.slice(0) // slice so the original isn't detached
            });
        } catch (cacheErr) {
            console.warn("Offline cache write failed:", cacheErr);
        }

    } else {

        // OFFLINE MODE — serve from IndexedDB
        try {
            const db    = await openVaultDB();
            const tx    = db.transaction("secureFiles", "readonly");
            const saved = await new Promise((resolve, reject) => {
                const req = tx.objectStore("secureFiles").get(path);
                req.onsuccess = () => resolve(req.result);
                req.onerror   = () => reject(req.error);
            });

            if (!saved || !saved.data) {
                alert("You are offline and this file has not been cached yet.\nPlease open it once while online to enable offline access.");
                return;
            }

            buffer = saved.data;

        } catch (dbErr) {
            console.error("IndexedDB read failed:", dbErr);
            alert("You are offline and the local cache could not be read.");
            return;
        }

    }

        // SETTINGS LENGTH

        const settingsLength =
        new Uint32Array(
            buffer.slice(0,4)
        )[0];

        // GUARD: validate header before slicing
        if(settingsLength === 0 || settingsLength > buffer.byteLength - 32){
            throw new Error('Corrupted file header: backend may have returned an error response.');
        }

        // SETTINGS JSON

        const settingsBytes =
        buffer.slice(
            4,
            4 + settingsLength
        );

        const settingsText =
        new TextDecoder()
        .decode(settingsBytes);

        const settings =
        JSON.parse(settingsText);

        // SALT

        const saltStart =
        4 + settingsLength;

        const saltEnd =
        saltStart + 16;

        const salt =
        buffer.slice(
            saltStart,
            saltEnd
        );

        // IV

        const ivStart =
        saltEnd;

        const ivEnd =
        ivStart + 12;

        const iv =
        buffer.slice(
            ivStart,
            ivEnd
        );

        // ENCRYPTED DATA

        const encryptedData =
        buffer.slice(ivEnd);

        // HASH PASSWORD

        const passwordHash =
        await sha256Bytes(
            window.masterPassword
        );

        // IMPORT HASH

        const keyMaterial =
        await crypto.subtle.importKey(
            "raw",
            passwordHash,
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        // DERIVE AES KEY

        const key =
        await crypto.subtle.deriveKey(
            {
                name:"PBKDF2",

                salt:new Uint8Array(
                    salt
                ),

                iterations:
                settings.iterations,

                hash:
                settings.hash

            },

            keyMaterial,

            {
                name:"AES-GCM",
                length:256
            },

            false,

            ["decrypt"]
        );

        // DECRYPT

        const decrypted =
        await crypto.subtle.decrypt(
            {
                name:"AES-GCM",

                iv:new Uint8Array(
                    iv
                )
            },

            key,

            encryptedData
        );

// Save a copy before pdfjsLib detaches the ArrayBuffer
currentDecryptedPdf = decrypted.slice(0);

// =========================
// PDF.JS
// =========================

const pdfjsLib = window.pdfjsLib;

// Use CDN worker when online; fall back to fake worker (in-thread) when offline.
// The fake worker is slower but fully functional — all pages still render.
if (navigator.onLine) {
    pdfjsLib.GlobalWorkerOptions.workerSrc =
        'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
} else {
    // Disable external worker — pdf.js falls back to running in the main thread
    pdfjsLib.GlobalWorkerOptions.workerSrc = '';
}

// LOAD PDF

const loadingTask =
pdfjsLib.getDocument({
    data: decrypted
});

const pdf =
await loadingTask.promise;

// CONTAINER

const container =
document.getElementById(
'pdf-render-container'
);

const sidebar =
document.getElementById(
'pdf-sidebar'
);

container.innerHTML = "";
sidebar.innerHTML = "";

// =========================
// TOOLBAR
// =========================

const toolbar = document.createElement('div');
toolbar.style.position = "sticky";
toolbar.style.top = "0";
toolbar.style.zIndex = "50";
toolbar.style.display = "flex";
toolbar.style.gap = "8px";
toolbar.style.justifyContent = "center";
toolbar.style.alignItems = "center";
toolbar.style.padding = "10px 12px";
toolbar.style.background = "#1e293b";
toolbar.style.borderBottom = "1px solid #334155";
toolbar.style.flexWrap = "wrap";

// ZOOM OUT
const zoomOutBtn = document.createElement('button');
zoomOutBtn.innerText = "− Out";

// ZOOM LEVEL INDICATOR LABEL
const zoomLabel = document.createElement('span');
zoomLabel.style.display = "flex";
zoomLabel.style.alignItems = "center";
zoomLabel.style.fontWeight = "800";
zoomLabel.style.color = "white";
zoomLabel.style.minWidth = "58px";
zoomLabel.style.justifyContent = "center";
zoomLabel.style.fontSize = "13px";
zoomLabel.style.background = "rgba(255,255,255,0.1)";
zoomLabel.style.borderRadius = "8px";
zoomLabel.style.padding = "4px 8px";

// ZOOM IN
const zoomInBtn = document.createElement('button');
zoomInBtn.innerText = "+ In";

// ZOOM RESET
const zoomResetBtn = document.createElement('button');
zoomResetBtn.innerText = "⟳ Fit";

// DOWNLOAD
const downloadBtn = document.createElement('button');
downloadBtn.innerText = "⬇ Download";

// ─── DEVICE DETECTION ───────────────────────────────────────
// PC/Laptop: non-touch device AND wide screen
const isDesktop = (
    !('ontouchstart' in window) &&
    !navigator.maxTouchPoints &&
    window.innerWidth >= 1024
);

// ─── ZOOM STATE (desktop only) ───────────────────────────────
let currentZoom = getInitialZoom();

function getInitialZoom() {
    if (!isDesktop) return 1.0; // mobile always fits full width
    const screenWidth = window.innerWidth;
    if (screenWidth <= 1280) return 0.9;
    return 1.0;
}

function updateZoomButtonUI() {
    if (!isDesktop) return;
    zoomLabel.innerText = Math.round(currentZoom * 100) + "%";
    zoomInBtn.disabled   = currentZoom >= 10.0;
    zoomOutBtn.disabled  = currentZoom <= 0.1;
    zoomInBtn.style.opacity  = currentZoom >= 10.0 ? "0.3" : "1";
    zoomOutBtn.style.opacity = currentZoom <= 0.1  ? "0.3" : "1";
    zoomInBtn.style.cursor   = currentZoom >= 10.0 ? "not-allowed" : "pointer";
    zoomOutBtn.style.cursor  = currentZoom <= 0.1  ? "not-allowed" : "pointer";
}

zoomInBtn.onclick = async () => {
    if (!isDesktop || currentZoom >= 10.0) return;
    const savedPage = getCurrentVisiblePage();
    currentZoom = +(currentZoom + 0.25).toFixed(2);
    updateZoomButtonUI();
    await renderAllPages();
    scrollToPage(savedPage);
};

zoomOutBtn.onclick = async () => {
    if (!isDesktop || currentZoom <= 0.1) return;
    const savedPage = getCurrentVisiblePage();
    currentZoom = +(currentZoom - 0.25).toFixed(2);
    updateZoomButtonUI();
    await renderAllPages();
    scrollToPage(savedPage);
};

zoomResetBtn.onclick = async () => {
    if (!isDesktop) return;
    const savedPage = getCurrentVisiblePage();
    currentZoom = getInitialZoom();
    updateZoomButtonUI();
    await renderAllPages();
    scrollToPage(savedPage);
};

// ─── BUTTON STYLING ──────────────────────────────────────────
[zoomOutBtn, zoomInBtn, downloadBtn].forEach(btn => {
    btn.style.padding = "10px 16px";
    btn.style.border = "none";
    btn.style.borderRadius = "12px";
    btn.style.cursor = "pointer";
    btn.style.fontWeight = "700";
    btn.style.background = "#2563eb";
    btn.style.color = "white";
    btn.style.fontSize = "13px";
    btn.style.touchAction = "manipulation";
    btn.style.minHeight = "42px";
});
zoomResetBtn.style.cssText = "padding:10px 16px;border:none;border-radius:12px;cursor:pointer;font-weight:700;background:#475569;color:white;font-size:13px;touch-action:manipulation;min-height:42px;";
downloadBtn.style.background = "#059669";

// ─── HIDE ZOOM CONTROLS ON MOBILE/TABLET ─────────────────────
if (!isDesktop) {
    zoomOutBtn.style.display  = "none";
    zoomInBtn.style.display   = "none";
    zoomResetBtn.style.display = "none";
    zoomLabel.style.display   = "none";
}

updateZoomButtonUI();

// ─── ASSEMBLE TOOLBAR ────────────────────────────────────────
toolbar.appendChild(zoomOutBtn);
toolbar.appendChild(zoomLabel);
toolbar.appendChild(zoomInBtn);
toolbar.appendChild(zoomResetBtn);
toolbar.appendChild(downloadBtn);
container.appendChild(toolbar);

// =========================
// RE-RENDER CANVAS PIPELINE
// =========================

// Helper: get the page number currently most visible in the container
function getCurrentVisiblePage() {
    const scrollTop = container.scrollTop;
    // toolbar height offset
    const toolbarH = toolbar.offsetHeight || 52;
    for (let p = 1; p <= pdf.numPages; p++) {
        const el = document.getElementById('page-' + p);
        if (!el) continue;
        const elTop = el.offsetTop - toolbarH;
        const elBottom = elTop + el.offsetHeight;
        if (elBottom > scrollTop) return p;
    }
    return 1;
}

// Helper: scroll so that page N is at the top of the view
function scrollToPage(pageNum) {
    requestAnimationFrame(() => {
        const el = document.getElementById('page-' + pageNum);
        if (!el) return;
        const toolbarH = toolbar.offsetHeight || 52;
        container.scrollTop = el.offsetTop - toolbarH - 10;
    });
}

// Pinch-to-zoom support — desktop only (mobile uses native browser pinch)
let pinchStartDist = null;
let pinchStartZoom = null;
let pinchSavedPage = 1;

if (isDesktop) {
container.addEventListener('touchstart', (e) => {
    if (e.touches.length === 2) {
        pinchStartDist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        pinchStartZoom = currentZoom;
        pinchSavedPage = getCurrentVisiblePage();
        e.preventDefault();
    }
}, { passive: false });

container.addEventListener('touchmove', (e) => {
    if (e.touches.length === 2 && pinchStartDist !== null) {
        const dist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        const ratio = dist / pinchStartDist;
        const newZoom = Math.min(10, Math.max(0.3, +(pinchStartZoom * ratio).toFixed(2)));
        // Apply CSS-only visual scale during pinch (no re-render mid-gesture)
        const wrapper = document.getElementById('pdf-canvas-wrapper');
        if (wrapper) {
            wrapper.style.transformOrigin = 'top center';
            wrapper.style.transform = `scale(${newZoom / pinchStartZoom})`;
            wrapper.style.transition = 'transform 0.05s ease-out';
        }
        currentZoom = newZoom;
        updateZoomButtonUI();
        e.preventDefault();
    }
}, { passive: false });

container.addEventListener('touchend', async (e) => {
    if (pinchStartDist !== null && e.touches.length < 2) {
        // Reset visual transform and do a real render at the new zoom
        const wrapper = document.getElementById('pdf-canvas-wrapper');
        if (wrapper) {
            wrapper.style.transform = '';
            wrapper.style.transition = '';
        }
        pinchStartDist = null;
        await renderAllPages();
        scrollToPage(pinchSavedPage);
        pinchStartZoom = null;
    }
}, { passive: true });

} // end if (isDesktop) pinch block

async function renderAllPages() {

    // MAIN WRAPPER — reuse or create
    let pageWrapContainer = document.getElementById('pdf-canvas-wrapper');
    if (!pageWrapContainer) {
        pageWrapContainer = document.createElement('div');
        pageWrapContainer.id = 'pdf-canvas-wrapper';
        pageWrapContainer.style.width = '100%';
        container.appendChild(pageWrapContainer);
    }

    // CLEAR OLD PAGES
    pageWrapContainer.innerHTML = "";
    sidebar.innerHTML = "";

    // LOOP THROUGH ALL PAGES
    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {

        const page = await pdf.getPage(pageNum);

        // =========================
        // SIDEBAR THUMBNAIL
        // =========================
        let thumbWrap = null;

        if (!window.LITE_MODE) {
            const thumbViewport = page.getViewport({ scale: 0.25 });
            const thumbCanvas   = document.createElement('canvas');
            const thumbCtx      = thumbCanvas.getContext('2d');

            // Set canvas internal dimensions to actual pixel size
            thumbCanvas.width  = thumbViewport.width;
            thumbCanvas.height = thumbViewport.height;

            // Render thumbnail BEFORE appending so it has a valid context
            await new Promise(r => requestAnimationFrame(r));

const renderTask = page.render({
    canvasContext: thumbCtx,
    viewport: thumbViewport
});

await renderTask.promise;

            // CSS width:100% makes it fit the dark sidebar column — this is correct for thumbs
            // because the thumb canvas resolution is already set, width:100% just scales display
            thumbCanvas.style.width = '100%';
           thumbCanvas.style.height = 'auto';
thumbCanvas.style.objectFit = 'contain';
thumbWrap = document.createElement('div');
thumbWrap.className = 'pdf-thumb';
thumbWrap.appendChild(thumbCanvas);

// ✅ Use createElement instead of innerHTML += (which destroys the canvas)
const pageLabel = document.createElement('div');
pageLabel.style.cssText = 'color:white;font-size:11px;text-align:center;';
pageLabel.textContent = `Page ${pageNum}`;
thumbWrap.appendChild(pageLabel);

sidebar.appendChild(thumbWrap);
        }

        // =========================
        // FULL PAGE VIEW — device-aware rendering
        // =========================

        const containerWidth = Math.max(container.clientWidth - 40, 300);
        const naturalViewport = page.getViewport({ scale: 1 });
        const fitScale = containerWidth / naturalViewport.width;

        let finalScale;
        if (isDesktop) {
            // Desktop: respect zoom level
            finalScale = fitScale * currentZoom;
        } else {
            // Mobile/tablet: render at physical pixel density for maximum sharpness
            // devicePixelRatio = 2 on Retina/AMOLED, 3 on high-end phones
            const dpr = Math.min(window.devicePixelRatio || 1, 3);
            finalScale = fitScale * dpr;
        }

        const viewport = page.getViewport({ scale: finalScale });

        // Card wrapper
        const pageWrap = document.createElement('div');
        pageWrap.id = 'page-' + pageNum;
        pageWrap.style.cssText = `
            display:block;
            margin:0 auto 24px auto;
            background:white;
            border-radius:14px;
            box-shadow:0 8px 22px rgba(0,0,0,0.25);
            padding:10px;
            width:fit-content;
            min-width:0;
            max-width:100%;
        `;

        const canvas  = document.createElement('canvas');
        const context = canvas.getContext('2d');

        if (isDesktop) {
            // Desktop: canvas pixel size = render size
            canvas.width  = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            canvas.style.display      = 'block';
            canvas.style.borderRadius = '10px';
        } else {
            // Mobile: canvas is rendered at high-DPI but CSS-scaled down to fit screen
            // This gives crisp text even on small screens
            const dpr = Math.min(window.devicePixelRatio || 1, 3);
            const displayWidth  = Math.floor(containerWidth);
            const displayHeight = Math.floor(containerWidth / naturalViewport.width * naturalViewport.height);
            canvas.width  = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            canvas.style.display      = 'block';
            canvas.style.borderRadius = '10px';
            canvas.style.width        = displayWidth  + 'px';
            canvas.style.height       = displayHeight + 'px';
            canvas.style.maxWidth     = '100%';
        }

        pageWrap.appendChild(canvas);
        pageWrapContainer.appendChild(pageWrap);

        // Render once — no duplicate render call
        await page.render({ canvasContext: context, viewport }).promise;

        // Thumbnail click → scroll to this page
        if (thumbWrap) {
            thumbWrap.onclick = () => pageWrap.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

// INITIAL RENDER
await renderAllPages();

// Second render after modal layout settles (so container.clientWidth is accurate)
setTimeout(async () => { await renderAllPages(); scrollToPage(1); }, 150);

// =========================
// DOWNLOAD SECURELY
// =========================

downloadBtn.onclick = async () => {

    try {

        if (!currentDecryptedPdf) {

            alert('No file loaded.');
            return;

        }

        // PASSWORD GATE
        const enteredPass =
        prompt('Enter download password:');

        if (enteredPass === null)
        return;

        try {

            const enteredHash =
await window.sha256(
    enteredPass
);

const passkeyRes =
await fetch(
 "https://backend.shinumaths989.workers.dev/get-secret",
 {
   method:"POST",
   headers:{
     "Content-Type":
     "application/json"
   },

   body: JSON.stringify({
      hash: enteredHash
   })
 }
);
            const passkeyResult =
            await passkeyRes.json();

            if (
                !passkeyResult ||
                !passkeyResult.success
            ) {

                alert(
                    passkeyResult.message ||
                    'Incorrect download password.'
                );

                return;
            }

        } catch (fetchErr) {

            console.error(fetchErr);

            alert(
                'Could not verify password.'
            );

            return;
        }

        // DOWNLOAD PDF

        const pdfBlob =
        new Blob(
            [new Uint8Array(currentDecryptedPdf)],
            {
                type: 'application/pdf'
            }
        );

        const url =
        URL.createObjectURL(pdfBlob);

        const a =
        document.createElement('a');

        a.href = url;

        a.download =
        displayName + '.pdf';

        document.body.appendChild(a);

        a.click();

        a.remove();

        URL.revokeObjectURL(url);

    } catch (err) {

        console.error(err);

        alert('Download failed.');

    }

};

// SHOW MODAL

document.getElementById(
    'modal'
).style.display = 'block';

document.getElementById(
    'modal-title'
).textContent =
displayName;

} catch (e) {

    console.error(e);

    if (e instanceof TypeError && e.message === 'Failed to fetch') {
        alert("You are offline and this file has not been cached yet.\nPlease open it once while online to enable offline access.");
    } else {
        alert("Access Denied: Could not decrypt file.");
    }

}

}
/* =========================
   CLOSE MODAL
========================= */

function closeModal(){

    document.getElementById(
    'modal').style.display =
    'none';

    document.getElementById(
    'watermark').style.display =
    'none';

    if(currentBlobUrl){

        URL.revokeObjectURL(
        currentBlobUrl);

        currentBlobUrl = null;
    }

    currentDecryptedPdf = null;
}

/* =========================
   SECURITY
========================= */

document.addEventListener(
"contextmenu",
e=>{

    sendSecurityAlert(
    "Right click attempt detected"
    );

    e.preventDefault();

});
document.onkeydown =
function(e){

    if(
        e.ctrlKey &&
        (
            e.key==='s' ||
            e.key==='p' ||
            e.key==='u'
        )
    ){

   sendSecurityAlert(
"Blocked keyboard shortcut attempt: " + e.key
);

e.preventDefault();
    }
};
