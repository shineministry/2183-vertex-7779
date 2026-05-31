/* =========================
   START SESSION
========================= */
function startSessionTimer(){

    const timer =
    document.getElementById(
    'session-timer');

    setInterval(()=>{

        sessionSeconds--;

        const mins =
        Math.floor(
        sessionSeconds / 60);

        const secs =
        sessionSeconds % 60;

        timer.textContent =
        `${mins}:${secs<10?'0':''}${secs}`;

        if(sessionSeconds<=0){

            logoutVault("Session Expired.")

        }

    },1000);

}

/* =========================
   INACTIVITY
========================= */

function startInactivityMonitor(){

    const reset = ()=>{

        clearTimeout(
        inactivityTimer);

        inactivityTimer =
        setTimeout(()=>{

            logoutVault("Logged out due to inactivity.")

        },120000);

    };

    window.onclick = reset;

    window.onmousemove = reset;

    window.onkeydown = reset;

    reset();

}

/* ========================= LOGOUT ========================= */
async function logout(message="") {
 if (message) {
 alert(message);
 }
 notifyBackendLogout(message || "Logged out.");
 try {
 await fetch(
 "https://backend.shinumaths989.workers.dev/save-visitor-log",
 {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({
 visitorName: document.getElementById( 'user-name' ).value,
 logoutTime: new Date() .toLocaleString(),
 status: "Logged Out"
 })
 }
 );
 } catch(e) { console.error( "Logout log error:", e ); }

 // Wipe session storage entirely
 sessionStorage.clear(); 

// On logout, call:
await fetch('https://backend.shinumaths989.workers.dev/logout', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionId: window.currentSessionId }) // must be stored at login
});
   
 // Clear memory password
 window.masterPassword = null;
 masterPassword = null;

 // FIX: Clear DOM states to prevent input caching bugs
 if (document.getElementById("user-name")) document.getElementById("user-name").value = "";
 if (document.getElementById("user-purpose")) document.getElementById("user-purpose").value = "";
 if (document.getElementById("vault-pass")) document.getElementById("vault-pass").value = "";
 if (document.getElementById("terms-tick")) document.getElementById("terms-tick").checked = false;

 try {
     if (typeof grecaptcha !== 'undefined') {
         grecaptcha.reset();
     }
 } catch(e) {}

 location.reload(true);
}