/* =========================
   ADMIN NOTIFICATIONS
========================= */

function getNotifications(){
    try{ return JSON.parse(localStorage.getItem('adminNotifications') || '[]'); }
    catch(e){ return []; }
}

function renderNotifications(){
    const list = document.getElementById('notifList');
    const dot  = document.getElementById('notifDot');
    if(!list) return;
    const notes = getNotifications();
    if(notes.length === 0){
        list.innerHTML = '<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px;">No notifications</div>';
        if(dot) dot.style.display = 'none';
        return;
    }
    list.innerHTML = notes.slice().reverse().map(n => `
        <div style="padding:10px;border-radius:10px;margin-bottom:6px;background:#f8fafc;border:1px solid var(--border-color);">
            <div style="font-weight:700;font-size:12.5px;color:var(--text-main);">${(n.title||'Admin Notice')}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">${n.msg||''}</div>
            <div style="font-size:10.5px;color:var(--text-muted);margin-top:4px;opacity:.7;">${n.date||''}</div>
        </div>
    `).join('');
    const unread = notes.filter(n => !n.read).length;
    if(dot) dot.style.display = unread > 0 ? 'block' : 'none';
}

function toggleNotifications(){
    const panel = document.getElementById('notifPanel');
    if(!panel) return;
    const open = panel.style.display === 'block';
    panel.style.display = open ? 'none' : 'block';
    if(!open){
        renderNotifications();
        const notes = getNotifications().map(n => ({...n, read:true}));
        localStorage.setItem('adminNotifications', JSON.stringify(notes));
        const dot = document.getElementById('notifDot');
        if(dot) dot.style.display = 'none';
    }
}

// Admin helper: call from console as
// addAdminNotification("Title", "Message")
function addAdminNotification(title, msg){
    const notes = getNotifications();
    notes.push({ title, msg, date: new Date().toLocaleString(), read:false });
    localStorage.setItem('adminNotifications', JSON.stringify(notes));
    renderNotifications();
}

document.addEventListener('click', (e)=>{
    const panel = document.getElementById('notifPanel');
    const btn = document.getElementById('notifBellBtn');
    if(!panel || panel.style.display !== 'block') return;
    if(!panel.contains(e.target) && e.target !== btn && !btn.contains(e.target)){
        panel.style.display = 'none';
    }
});

document.addEventListener('DOMContentLoaded', renderNotifications);


    const dash =
    document.getElementById(
    'vault-dashboard');

    if(document.hidden){

        dash.style.filter =
        "blur(18px)";

    }else{

        dash.style.filter =
        "blur(0px)";
    }

});

   function saveAccessLog(){

    const logs =
    JSON.parse(
    localStorage.getItem(
    'vaultLogs'
    ) || '[]');

    const visitorName =
    document.getElementById(
    'user-name').value;

    const purpose =
    document.getElementById(
    'user-purpose').value;

    const loginTime =
    new Date().toLocaleString();

    const device =
    /Mobi|Android/i.test(
    navigator.userAgent)
    ? "Mobile"
    : "Desktop";

    const browser =
    navigator.userAgent;

    const platform =
    navigator.platform;

    const screenSize =
    `${screen.width}x${screen.height}`;

    const timezone =
    Intl.DateTimeFormat()
    .resolvedOptions()
    .timeZone;

    logs.push({

        visitorName,
        purpose,
        loginTime,
        device,
        browser,
        platform,
        screenSize,
        timezone

    });

    localStorage.setItem(
    'vaultLogs',
    JSON.stringify(logs)
    );

}

async function openLogs(){

    document.getElementById(
    'logModal'
    ).style.display =
    'block';

    const body =
    document.getElementById(
    'logBody'
    );

    body.innerHTML = "";

    try{

const res = await fetch(
    "https://backend.shinumaths989.workers.dev/get-logs",
    {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            browser: navigator.userAgent,
            platform: navigator.platform
        })
    }
);

if(!res.ok) throw new Error("Failed to load logs");

const logs = await res.json();

        logs.forEach(log=>{

            body.innerHTML += `

            <tr>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.visitorName || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.purpose || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.loginTime || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.device || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.browser || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.platform || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.screen || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.timezone || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.ipAddress || '-'}
                </td>

                <td style="padding:10px;border:1px solid #ddd;">
                    ${log.location || '-'}
                </td>

            </tr>

            `;

        });

    }catch(e){

        console.error(e);

    }

}

function closeLogs(){

    document.getElementById(
    'logModal').style.display =
    'none';

}

/* =========================
   PASSKEY ACCESS
========================= */

/* ========================= MODE B: PASSKEY FLOW ========================= */
async function requestPasskeyAccess() {
    const visitorName = document.getElementById('user-name').value.trim();
    const purpose = document.getElementById('user-purpose').value.trim();

    if (!visitorName || !purpose) {
        alert("Please enter your Full Name and Purpose of Access first before submitting a passkey request.");
        return;
    }

    document.getElementById('step1').style.display = 'none';
    document.getElementById('passkey-wait').style.display = 'flex';

    let trackingId = "";

    // 1. Submit the initial request payload to generate a Firestore document tracking track
    try {
        const initRes = await fetch("https://backend.shinumaths989.workers.dev/request-passkey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                visitorNameName: visitorName,
                purposeOfAccess: purpose,
                timestamp: new Date().toISOString()
            })
        });

        const initData = await initRes.json();
        if (initData && initData.requestId) {
            trackingId = initData.requestId;
        } else {
            throw new Error("Failed to allocate an administrative tracking request payload identifier.");
        }
    } catch (err) {
        alert("Failed to register access record: " + err.message);
        document.getElementById('passkey-wait').style.display = 'none';
        document.getElementById('step1').style.display = 'flex';
        return;
    }

    // 2. Poll the worker securely using the allocated document identifier
    const checkInterval = setInterval(async () => {
        try {
            const pollRes = await fetch("https://backend.shinumaths989.workers.dev/check-passkey", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    requestId: trackingId
                })
            });

            if (pollRes.status === 200) {
                clearInterval(checkInterval);
                const data = await pollRes.json();
                
                if (data.success && data.secret) {
                    // Inject the decrypted master password dynamically 
                    masterPassword = data.secret;
                    window.masterPassword = data.secret;
                    sessionStorage.setItem("vault_session_secret", data.secret);
                    
                    // Route to legal screen to keep pipeline consistent
                    document.getElementById('passkey-wait').style.display = 'none';
                    document.getElementById('step2').style.display = 'flex';
                }
            } else if (pollRes.status === 403) {
                // Keep waiting silently (admin hasn't clicked 'Approve' yet or denied it)
                const data = await pollRes.json().catch(() => ({}));
                if (data.error && data.error.includes("denied")) {
                    clearInterval(checkInterval);
                    alert("Your request for administrative authorization was declined.");
                    location.reload();
                }
            }
        } catch (e) {
            console.log("Polling connection drop, retrying...", e);
        }
    }, 3000); // Check status every 3 seconds
}