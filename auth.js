/* =========================
   GLOBAL VARIABLES
========================= */
var masterPassword = "";

let sessionSeconds = 3600;

   let failedAttempts = 0;
let lockUntil = 0;

   let inactivityTimer;
let currentBlobUrl = null;
let currentDecryptedPdf = null;
   
let sessionStartTime = null;

   let sessionId = crypto.randomUUID();
let allFilesData = {};
let currentCategory = "";
   
   async function sha256Bytes(text){

    const enc =
    new TextEncoder();

    const hashBuffer =
    await crypto.subtle.digest(
        "SHA-256",
        enc.encode(text)
    );

    return new Uint8Array(
        hashBuffer
    );
}

/* =========================
   LITE MODE ENGINE
========================= */

window.LITE_MODE = false;

function detectLiteMode() {

    // Manual override
    const saved =
    localStorage.getItem(
        "vault-lite-mode"
    );

    if(saved !== null){

        window.LITE_MODE =
        saved === "true";

        document.body.classList.toggle(
            "lite-mode",
            window.LITE_MODE
        );

        return;
    }

    const cpu =
    navigator.hardwareConcurrency || 4;

    const memory =
    navigator.deviceMemory || 8;

    const isMobile =
    /Android|iPhone|iPad|iPod|Mobile/i
    .test(navigator.userAgent);

    const smallScreen =
    window.innerWidth <= 768;

    // Desktop/Laptop → NEVER lite automatically
    if(!isMobile){

        window.LITE_MODE =
        false;

    } else {

        // Mobile only
        window.LITE_MODE =

            cpu <= 4 ||

            memory <= 4 ||

            smallScreen;
    }

    document.body.classList.toggle(
        "lite-mode",
        window.LITE_MODE
    );


}

function toggleLiteMode(){

    window.LITE_MODE =
        !window.LITE_MODE;

    document.body.classList.toggle(
        "lite-mode",
        window.LITE_MODE
    );

    localStorage.setItem(
        "vault-lite-mode",
        window.LITE_MODE
    );

    location.reload();
}

detectLiteMode();

function notifyBackendLogout(reason = "Logged out.") {

    const visitorInput = document.getElementById("user-name");
    const visitorName = visitorInput ? visitorInput.value : "";

    const logPayload = JSON.stringify({
        visitorName,
        logoutTime: new Date().toLocaleString(),
        status: reason
    });

    const sessionPayload = JSON.stringify({
        sessionId,
        visitor: visitorName,
        active: false,
        endedAt: new Date().toISOString(),
        reason
    });

    try {
        fetch(
            "https://backend.shinumaths989.workers.dev/save-visitor-log",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: logPayload,
                keepalive: true
            }
        ).catch(() => {});
    } catch(e) {}

    try {
        fetch(
            "https://backend.shinumaths989.workers.dev/register-session",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: sessionPayload,
                keepalive: true
            }
        ).catch(() => {});
    } catch(e) {}
}

function logoutVault( reason = "Logged out." ) {

    clearTimeout( inactivityTimer );

    notifyBackendLogout(reason);

    // Wipe session storage entirely
    sessionStorage.clear();

    // Clear memory string values
    window.masterPassword = null;
    masterPassword = "";
    failedAttempts = 0;

    // FIX: Force clear inputs so the browser doesn't submit stale/cached text values
    if (document.getElementById("user-name")) document.getElementById("user-name").value = "";
    if (document.getElementById("user-purpose")) document.getElementById("user-purpose").value = "";
    if (document.getElementById("vault-pass")) document.getElementById("vault-pass").value = "";
    if (document.getElementById("terms-tick")) document.getElementById("terms-tick").checked = false;

    // FIX: Reset reCAPTCHA if it was initialized
    try {
        if (typeof grecaptcha !== 'undefined') {
            grecaptcha.reset();
        }
    } catch(e) { console.log(e); }

    alert(reason);

    // Hard refresh to completely clear window context
    location.reload(true);
}

function resetInactivityTimer() {

  clearTimeout(
    inactivityTimer
  );

  inactivityTimer =
    setTimeout(() => {

      logoutVault(
        "Logged out due to inactivity (2 minutes)."
      );

    }, 2 * 60 * 1000);
}

[
  "mousemove",
  "mousedown",
  "keypress",
  "scroll",
  "touchstart"
].forEach(event => {

  document.addEventListener(
    event,
    resetInactivityTimer
  );

});
   
/* =========================
   CLOCK
========================= */

document.addEventListener('DOMContentLoaded', () => {
    // Automatically retrieve the master password if the user is already authenticated
    const savedSecret = sessionStorage.getItem("vault_session_secret");
    if (savedSecret) {
        masterPassword = savedSecret;
        window.masterPassword = savedSecret;
    }

    updateClock();
    setInterval(updateClock, 1000);
});

function updateClock(){

    return;

}

/* ========================= STEP 1 ========================= */
async function hashPassword(password) {
  const normalized = password
    .trim()
    .normalize("NFKC");

  const encoder = new TextEncoder();
  const data = encoder.encode(normalized);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
   
async function showStep2() {

   clearTimeout(
    inactivityTimer
);

    const now = Date.now();

    if (now < lockUntil) {
        const remaining =
            Math.ceil(
                (lockUntil - now) / 1000
            );

        alert(
            `Too many wrong attempts.\nTry again in ${remaining} seconds.`
        );

        return;
    }

    const visitorName =
        document
        .getElementById(
            "user-name"
        )
        .value.trim();

    const pass =
        document
        .getElementById(
            "vault-pass"
        )
        .value.trim();

    const purpose =
        document
        .getElementById(
            "user-purpose"
        )
        .value.trim();

    if (
        !visitorName ||
        !purpose ||
        !pass
    ) {
        alert(
            "Full Name, Purpose, and Password are required."
        );
        return;
    }

    // Show loading state on button
    const loginBtn = document.querySelector('#step1 .btn-primary');
    const originalBtnText = loginBtn ? loginBtn.textContent : '';
    if (loginBtn) {
        loginBtn.textContent = '🔐 Connecting...';
        loginBtn.disabled = true;
        loginBtn.style.opacity = '0.7';
    }

    const restoreLoginBtn = () => {
        if (loginBtn) {
            loginBtn.textContent = originalBtnText;
            loginBtn.disabled = false;
            loginBtn.style.opacity = '1';
        }
    };

    const showLoginError = (title, detail) => {
        const existing = document.getElementById('login-error-box');
        if (existing) existing.remove();
        const box = document.createElement('div');
        box.id = 'login-error-box';
        box.style.cssText = `
            background:#fef2f2;
            border:1px solid #fca5a5;
            border-radius:14px;
            padding:16px 18px;
            margin-top:12px;
            text-align:left;
            animation:fadeInUp .3s ease;
        `;
        box.innerHTML = `
            <div style="font-weight:800;color:#dc2626;font-size:14px;margin-bottom:6px;">⚠️ ${title}</div>
            <div style="font-size:12.5px;color:#7f1d1d;line-height:1.6;">${detail}</div>
            <button onclick="this.parentElement.remove()" style="
                margin-top:10px;border:none;background:#dc2626;color:white;
                border-radius:8px;padding:6px 14px;font-size:12px;font-weight:700;cursor:pointer;">
                Dismiss
            </button>
        `;
        const card = document.querySelector('#step1 .step-card');
        if (card) card.appendChild(box);
        else alert(title + ': ' + detail);
    };

    // Fetch with timeout helper
    const fetchWithTimeout = (url, options, ms = 12000) => {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), ms);
        return fetch(url, { ...options, signal: controller.signal })
            .finally(() => clearTimeout(tid));
    };

    try {

        // store password in memory only
        masterPassword = pass;

        // hash password
        const hash =
            await hashPassword(
                pass
            );

        let res;
        try {
            res = await fetchWithTimeout(
                "https://backend.shinumaths989.workers.dev/get-secret",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ hash })
                },
                12000
            );
        } catch (fetchErr) {
            restoreLoginBtn();
            if (fetchErr.name === 'AbortError') {
                showLoginError(
                    'Connection Timed Out',
                    'The secure server took too long to respond. Check your internet connection and try again.'
                );
            } else if (!navigator.onLine) {
                showLoginError(
                    'No Internet Connection',
                    'Your device appears to be offline. Please connect to Wi-Fi or mobile data and try again.'
                );
            } else {
                showLoginError(
                    'Cannot Reach Secure Server',
                    'Your network may be blocking the connection. Try switching between Wi-Fi and mobile data, or disable a VPN if active.'
                );
            }
            return;
        }

        if (res.status >= 500) {
            restoreLoginBtn();
            showLoginError(
                'Server Temporarily Unavailable',
                'The secure backend returned an error (HTTP ' + res.status + '). Please wait a moment and try again.'
            );
            return;
        }

        const contentType =
            res.headers.get(
                "content-type"
            ) || "";

        if (
            !res.ok &&
            contentType.includes(
                "text/html"
            )
        ) {
            restoreLoginBtn();
            showLoginError(
                'Access Blocked by Firewall',
                'The vault firewall rejected this connection. This may be due to your network or location.'
            );
            return;
        }

        let result = {};
        try {
            result = await res.json();
        } catch {
            restoreLoginBtn();
            showLoginError(
                'Invalid Server Response',
                'The server returned an unexpected response. Please try again.'
            );
            return;
        }

        // failed login
        if (
            !res.ok ||
            !result.success ||
            !result.authorized
        ) {

            restoreLoginBtn();
            failedAttempts++;

            if (
                failedAttempts >= 5
            ) {

                sendSecurityAlert(
                    "Multiple failed password attempts"
                );

                lockUntil =
                    Date.now() +
                    300000;

                failedAttempts = 0;

                showLoginError(
                    'Vault Locked',
                    'Too many failed attempts. The vault is locked for 5 minutes for security.'
                );

            } else {

                showLoginError(
                    'Wrong Access Key',
                    `Incorrect password. You have ${5 - failedAttempts} attempt${5 - failedAttempts === 1 ? '' : 's'} remaining.`
                );
            }

            return;
        }

        // SUCCESS LOGIN
        if (loginBtn) {
            loginBtn.textContent = '✓ Authenticated';
            loginBtn.style.background = 'linear-gradient(135deg,#16a34a,#15803d)';
            loginBtn.style.opacity = '1';
        }

        sessionStorage.setItem(
            "vaultSessionToken",
            result.sessionToken
        );

        sessionStorage.setItem(
    "vaultSession",
    result.sessionToken
);

// START 2-MINUTE TIMER
resetInactivityTimer();

// Use the master encryption password returned by the backend (not the user's
// login password) — all files are encrypted with the admin master password,
// so every mode needs it to decrypt, regardless of which key they logged in with.
window.masterPassword =
    result.secret
    ? String(result.secret)
    : String(pass);

// Also persist so passkey / session-restore path can find it
if(result.secret){
    sessionStorage.setItem("vault_session_secret", result.secret);
}

   window.VAULT_MODE=
result.mode;

   sessionStorage.setItem("vaultMode", result.mode);

       if(

window.VAULT_MODE
!=="ADMIN"

){

document
.getElementById(
"share-gear"
)
.style.display=
"none";

}

masterPassword = window.masterPassword;

        failedAttempts = 0;

        sessionStartTime =
            new Date();

        const step1 =
            document.getElementById(
                "step1"
            );

        step1.style.pointerEvents =
            "none";

        step1.classList.add(
            "slide-up-exit"
        );

        setTimeout(() => {

            step1.style.display =
                "none";

            document.getElementById(
                "step2"
            ).style.display =
                "flex";

        }, 700);

    } catch (e) {

        restoreLoginBtn();
        console.error(e);
        showLoginError(
            'Connection Error',
            e.message || 'Could not connect to the secure backend. Please check your internet and try again.'
        );
    }
}

/* =========================
   STEP 2
========================= */

function showStep3(){

    if(!document.getElementById(
    'terms-tick').checked){

        alert(
        "You must agree to the declaration."
        );

        return;
    }

    const step2 =
    document.getElementById(
    'step2');

    step2.style.pointerEvents =
    "none";

    step2.classList.add(
    'slide-up-exit');

    setTimeout(()=>{

        step2.style.display =
        'none';

        document.getElementById(
        'step3').style.display =
        'flex';

    },700);

}

/* =========================
   CAPTCHA
========================= */

function onCaptchaSuccess(){

    document.getElementById(
    'loading-msg').style.display =
    'block';

    setTimeout(()=>{

        document.getElementById(
        'step3').classList.add(
        'slide-up-exit');

        setTimeout(()=>{

            document.getElementById(
            'step3').style.display =
            'none';

const dash =
document.getElementById(
'vault-dashboard');

dash.style.display = 'flex';

dash.classList.add(
'dashboard-enter');

            saveAccessLog();

   registerActiveSession();

           saveVisitorLog({

    visitorName:
    document.getElementById(
    'user-name').value,

    purpose:
    document.getElementById(
    'user-purpose').value,

    loginTime:
    new Date().toLocaleString(),

    device:
    /Mobi|Android/i.test(
    navigator.userAgent)
    ? "Mobile"
    : "Desktop",

    browser:
    navigator.userAgent,

    platform:
    navigator.platform,

    screen:
    `${screen.width}x${screen.height}`,

    timezone:
    Intl.DateTimeFormat()
    .resolvedOptions()
    .timeZone

});

            initVault().then(() => {
                vaultPostInit();
            }).catch(err => {
                console.error("initVault failed:", err);
                vaultPostInit(); // still run post-init even on error
            });

            startSessionTimer();

            startInactivityMonitor();

   listenForForceLogout();

        },700);

    },1200);

}

   async function saveVisitorLog(data){

    let ip = "Unknown";

    let location = "Unknown";

    try{

        const res =
        await fetch(
        "https://ipapi.co/json/"
        );

        const info =
        await res.json();

        ip =
        info.ip || "Unknown";

        location =
        `${info.city}, ${info.region}, ${info.country_name}`;

    }catch(e){

        console.log(
        "IP fetch failed",
        e
        );

    }

    try{

        await fetch(
            "https://backend.shinumaths989.workers.dev/save-visitor-log",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    visitorName: data.visitorName,
                    purpose: data.purpose,
                    loginTime: new Date().toLocaleString(),
                    device: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                    browser: navigator.userAgent,
                    platform: navigator.platform,
                    screen: `${screen.width}x${screen.height}`,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    ipAddress: ip,
                    location: location
                })
            }
        );

    }catch(err){

        console.error(
        "Visitor log error:",
        err
        );

    }

}

   async function sendSecurityAlert(reason){

    try{

        const visitorName =
        document.getElementById(
        'user-name'
        ).value || "Unknown";

        const purpose =
        document.getElementById(
        'user-purpose'
        ).value || "Unknown";

        let ip = "Unknown";
        let location = "Unknown";

        try{

            const res =
            await fetch(
            "https://ipapi.co/json/"
            );

            const info =
            await res.json();

            ip =
            info.ip || "Unknown";

            location =
            `${info.city}, ${info.country_name}`;

        }catch(e){}

        await fetch(
        "https://backend.shinumaths989.workers.dev/security-alert",
        {

            method:"POST",

            headers:{
                "Content-Type":"application/json"
            },

            body:JSON.stringify({

                embeds:[{

                    title:
                    "🚨 SUSPICIOUS VAULT ACTIVITY",

                    color:16711680,

                    fields:[

                        {
                            name:"Visitor",
                            value:visitorName,
                            inline:true
                        },

                        {
                            name:"Purpose",
                            value:purpose,
                            inline:true
                        },

                        {
                            name:"Reason",
                            value:reason,
                            inline:false
                        },

                        {
                            name:"IP Address",
                            value:ip,
                            inline:true
                        },

                        {
                            name:"Location",
                            value:location,
                            inline:true
                        },

                        {
                            name:"Device",
                            value:
                            navigator.userAgent
                            .slice(0,100),
                            inline:false
                        }

                    ],

                    timestamp:
                    new Date().toISOString()

                }]

            })

        });

    }catch(err){

        console.error(
        "Discord alert failed",
        err
        );

    }

}

   async function registerActiveSession(){

    try{

        await fetch(
            "https://backend.shinumaths989.workers.dev/register-session",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sessionId: sessionId,
                    visitor: document.getElementById('user-name').value,
                    active: true,
                    createdAt: new Date().toISOString()
                })
            }
        );

    }catch(e){

        console.log(e);

    }

}

      async function listenForForceLogout(){

    // Poll the Worker every 15 seconds to check if admin force-logged this session out
    setInterval(async ()=>{

        try{

            const res = await fetch(
                "https://backend.shinumaths989.workers.dev/check-session",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sessionId: sessionId })
                }
            );

            if(!res.ok) return;

            const data = await res.json();

            if(data.forceLogout){

                alert(
                "Administrator terminated your session."
                );

                location.reload();

            }

        }catch(e){

            // Silently fail - don't disrupt the session on network hiccup

        }

    }, 15000);

}