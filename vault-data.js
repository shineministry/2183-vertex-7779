/* =========================
   INIT VAULT
========================= */

async function initVault() {
try {

    // GET TEMP SESSION TOKEN
    const sessionToken =
        sessionStorage.getItem("vaultSession");

    // check login
    if (!sessionToken) {
        throw new Error(
            "No active secure session. Please login again."
        );
    }

    // Try network first; fall back to IndexedDB (vault_meta) when offline
    let data = {};
    try {
        const res = await fetch(
            "https://backend.shinumaths989.workers.dev/files.json",
            { headers: { "Authorization": "Bearer " + sessionToken } }
        );

        // 🛡️ Firewall / backend errors
        if (!res.ok) {
            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('text/html')) {
                throw new Error("Security Exception: Domain rejected by Gateway Firewall.");
            }
            throw new Error(`Server returned HTTP status ${res.status}`);
        }

        const raw = await res.json();
        // Normalise: backend may return either
        //   a) category-keyed object  { "Passport": [{...}], "ID": [{...}] }
        //   b) flat array             [ {name, file, member, category}, ... ]
        if (Array.isArray(raw)) {
            raw.forEach(file => {
                const cat = file.category || file.type || "Documents";
                if (!data[cat]) data[cat] = [];
                data[cat].push(file);
            });
        } else if (raw && typeof raw === 'object') {
            data = raw;
        } else {
            throw new Error("Unexpected response format from files.json");
        }

        // Cache file list for offline use
        if (typeof idbSetVaultMeta === 'function') {
            idbSetVaultMeta(data).catch(() => {});
        }

    } catch (netErr) {
        // Network failed — try cached file list from IndexedDB
        if (typeof idbGetVaultMeta === 'function') {
            const cached = await idbGetVaultMeta();
            if (cached) {
                data = cached;
                console.log('[initVault] Using cached file list (offline mode).');
            } else {
                throw new Error('No internet and no cached file list. Log in online first.');
            }
        } else {
            throw netErr;
        }
    }

    allFilesData = data;

    const list = document.getElementById('cat-list');
    list.innerHTML = "";

    const mode = window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "VIEWER";
    const currentMember = document.getElementById('member-select')?.value || 'all';

    // Backend already filters by mode — show ALL returned categories.
    // The frontend should NOT re-filter here; trust the backend.
    const categories = Object.keys(data);

    if (categories.length === 0) {
        list.innerHTML = '<li style="color:var(--muted);font-size:12px;pointer-events:none;font-weight:normal;">No documents found</li>';
        return;
    }

    // Category icon map for dark sidebar
    const CAT_ICONS = {
        'HOME': '🏠', 'PROFILE': '👤', 'Guardian': '👥', 'Visa': '✈️', 'Finance': '💰',
        'School': '🎓', 'Personal': '👤', 'Residence': '🏡', 'Church': '✝️',
        'Education': '📚', 'Identity': '🪪', 'Legal': '⚖️', 'Financial': '💳',
        'Ministry': '🕊️', 'Medical': '🏥', 'Insurance': '🛡️', 'Tax': '📋',
        'Property': '🏠', 'Vehicle': '🚗', 'Travel': '🌍', 'Work': '💼',
        'Bank': '🏦', 'Documents': '📄', 'Certificates': '🏅'
    };
    function getCatIcon(cat) {
        return CAT_ICONS[cat] || CAT_ICONS[Object.keys(CAT_ICONS).find(k => cat.toLowerCase().includes(k.toLowerCase()))] || '📁';
    }

    categories.forEach(cat => {
        const li = document.createElement('li');
        const icon = getCatIcon(cat);
        li.innerHTML = `<span style="font-size:15px;">${icon}</span><span>${cat}</span>`;

        li.onclick = () => {
            if (cat === "PROFILE") {
    document.querySelectorAll('#cat-list li')
        .forEach(el => el.classList.remove('active'));
    li.classList.add('active');
    showProfile();
    return;
}

            document.querySelectorAll('#cat-list li')
                .forEach(el => el.classList.remove('active'));
            li.classList.add('active');

            const selectedMember =
                document.getElementById('member-select')?.value || 'all';

            let filteredFiles = data[cat] || [];

            if (selectedMember !== 'all') {
                filteredFiles = filteredFiles.filter(file =>
                    Array.isArray(file.members)
                        ? file.members.includes(selectedMember)
                        : (file.member === selectedMember || !file.member)
                );
            }

            renderFiles(filteredFiles, cat);
        };

        list.appendChild(li);
    });

    // Auto-click HOME first
    const firstCategory = list.querySelector('li');
if (firstCategory) firstCategory.click();

} catch (e) {

    console.error("initVault error:", e);

    document.getElementById('cat-title').textContent = "Vault System Locked";

    const grid = document.getElementById('file-grid');
    grid.innerHTML = `
    <div style="
        grid-column:1/-1;
        padding:30px;
        text-align:center;
        color:var(--danger);
        font-weight:700;
    ">
        🚨 ${e.message || "Failed to load secure database."}
    </div>`;
}
}

/* =========================
   PROFILES DATA (module scope)
========================= */
const profiles = {

shineil:{
image:"profile.png",
name:"SHINEIL KEITH MATHIAS",
role:"Founder of SHINE MINISTRY • Student • Public Speaker • Digital Creator",

personal:`
<b>Full Name:</b> Shineil Keith Mathias<br>
<b>Date of Birth:</b> 7 March 2010<br>
<b>Gender:</b> Male<br>
<b>Nationality:</b> Indian<br>
<b>Location:</b> Khandala, Pune
`,

contact:`
<b>Phone:</b> +91 8605586173<br>
<b>Email:</b> shinumaths989@gmail.com<br>
<b>Website:</b> shine-ministry.com<br>
<b>Instagram:</b> @shinu_vordenker_7
`,

education:`
Don Bosco High School<br>
2020–2026<br>
Secondary Education
`,

skills:`
• Public Speaking<br>
• Leadership<br>
• Mathematics<br>
• Web Editing
`,

languages:`
English — Fluent<br>
Hindi — Fluent<br>
German — Basic
`,

achievements:`
• Green House Captain<br>
• Debate Awards<br>
• Student Recognition
`,

experience:`
Founder — SHINE MINISTRY<br>
Digital Projects<br>
Leadership Activities
`,

projects:`
Secure Vault<br>
SHINE MINISTRY<br>
PDF Systems
`,

goals:`
Technology<br>
Education<br>
Leadership
`,

faith:`
Founder of SHINE MINISTRY<br>
Christian Service
`,

about:`
Student with strong communication,
leadership and ministry interests.
`,

hobbies:`
Debating, technology,
public speaking, reading
`
},



brother:{

image:"ProfileK.png",
name:"KEVIN SHREESH MATHIAS",
role:"Bartender • Hospitality",

personal:`
<b>Name:</b> Kevin Shreesh Mathias<br>
<b>Location:</b> Pune<br>
<b>Industry:</b> Hospitality
`,

contact:`
Add Number<br>
Add Email
`,

education:`
Guardian School — SSC<br>
IHM Mumbai<br>
Flair Mania Bartending Academy
`,

skills:`
• Bartending<br>
• Customer Service<br>
• POS<br>
• Inventory
`,

languages:`
English<br>
Hindi
`,

achievements:`
Assistant Bartender — Bombay Cartel<br>
Assistant Bartender — Janwani
`,

experience:`
2023–2025 Bombay Cartel<br>
Present — Janwani
`,

projects:`
Hospitality Training<br>
Service Experience
`,

goals:`
Career Growth<br>
Hospitality Industry
`,

faith:`-`,

about:`
Hospitality professional with
bartending and customer service experience.
`,

hobbies:`
Service industry,
teamwork,
food & beverage
`
},



father:{
image:"ProfileSt.png",
name:"STEPHEN CONDRAD MATHIAS",
role:"Father",
personal:`Add`,
contact:`+91 99216 68744, +91 93707 50143`,
education:`Add`,
skills:`Add`,
languages:`English, Hindi, Konkani, Tulu, Kannada`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Roman Catholic`,
about:`Add`,
hobbies:`Add`
},



mother:{
image:"mother.png",
name:"KANCHAN MATHIAS",
role:"Mother",
personal:`Add`,
contact:`Add`,
education:`Add`,
skills:`Add`,
languages:`Add`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Add`,
about:`Add`,
hobbies:`Add`
}

};

// ── Category summaries (item 2): short blurb shown above each category's
// file grid so the user knows at a glance what the category contains. ──
const CAT_SUMMARIES = {
    'Visa':         'Visa applications, approvals, and travel authorization documents.',
    'Guardian':     'Guardian access records and authorizations for trusted contacts.',
    'School':       'School admission, report cards, and academic records.',
    'Finance':      'Bank statements, financial records, and money-related documents.',
    'Financial':    'Bank statements, financial records, and money-related documents.',
    'Personal':     'Personal identification and miscellaneous personal records.',
    'Residence':    'Residence proofs, rental agreements, and address records.',
    'Church':       'Church and ministry related certificates and records.',
    'Education':    'Academic certificates, mark sheets, and education history.',
    'Identity':     'Government-issued identity documents (ID cards, passports, etc.).',
    'Legal':        'Legal declarations, agreements, and official legal paperwork.',
    'Ministry':     'Ministry activity records and related documentation.',
    'Medical':      'Medical reports, prescriptions, and health records.',
    'Insurance':    'Insurance policies, claims, and coverage documents.',
    'Tax':          'Tax filings, receipts, and related financial paperwork.',
    'Property':     'Property ownership, deeds, and related legal documents.',
    'Vehicle':      'Vehicle registration, insurance, and ownership documents.',
    'Travel':       'Travel itineraries, bookings, and trip-related documents.',
    'Work':         'Employment, work experience, and professional documents.',
    'Bank':         'Bank account statements and related financial documents.',
    'Certificates': 'Awards, certifications, and recognition documents.'
};

function getCatSummary(cat) {
    return CAT_SUMMARIES[cat]
        || CAT_SUMMARIES[Object.keys(CAT_SUMMARIES).find(k => cat.toLowerCase().includes(k.toLowerCase()))]
        || `Documents related to ${cat}.`;
}



function buildHomeDashboard(){

    const categories = Object.keys(allFilesData || {});
    let totalFiles = 0;
    categories.forEach(c => totalFiles += (allFilesData[c] || []).length);

    let recents = [];
    try{ recents = JSON.parse(localStorage.getItem('recentFiles') || '[]'); }catch(e){}

    const historyHTML = recents.length
        ? recents.slice(0,8).map(r => `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;background:#f8fafc;border:1px solid var(--border);margin-bottom:8px;">
                <div style="overflow:hidden;">
                    <div style="font-weight:700;font-size:12.5px;color:var(--text-main, #0f172a);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">📄 ${r.name}</div>
                    <div style="font-size:10.5px;color:var(--muted);margin-top:2px;">${r.category || ''} · ${r.date || ''}</div>
                </div>
            </div>`).join('')
        : `<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px;">No files viewed yet</div>`;

    const categoriesHTML = categories.length
        ? categories.map(c => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-radius:12px;background:#f8fafc;border:1px solid var(--border);margin-bottom:8px;">
                <div style="font-weight:700;font-size:12.5px;color:var(--text-main, #0f172a);">📁 ${c}</div>
                <div style="font-size:11px;font-weight:800;color:var(--accent);background:#eff6ff;padding:3px 10px;border-radius:999px;">${(allFilesData[c]||[]).length}</div>
            </div>`).join('')
        : `<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px;">No categories</div>`;

    return `
    <div style="grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:8px;">
        <div style="background:white;border:1px solid var(--border);border-radius:20px;padding:22px;display:flex;align-items:center;gap:16px;">
            <div style="font-size:30px;">🗂️</div>
            <div>
                <div style="font-size:11px;font-weight:800;letter-spacing:.5px;color:var(--muted);">NO. OF FILES IN VAULT</div>
                <div style="font-size:24px;font-weight:900;color:var(--accent);">${totalFiles}</div>
            </div>
        </div>
        <div style="background:white;border:1px solid var(--border);border-radius:20px;padding:22px;display:flex;align-items:center;gap:16px;">
            <div style="font-size:30px;">🛡️</div>
            <div>
                <div style="font-size:11px;font-weight:800;letter-spacing:.5px;color:var(--muted);">SECURITY STATUS</div>
                <div style="font-size:18px;font-weight:900;color:var(--success,#16a34a);">Protected · AES-256</div>
            </div>
        </div>
    </div>

    <div style="grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin-bottom:8px;">
        <div class="profile-box" style="text-align:left;">
            <h3>🕘 Files History</h3>
            ${historyHTML}
        </div>
        <div class="profile-box" style="text-align:left;">
            <h3>📚 Categories</h3>
            ${categoriesHTML}
        </div>
    </div>
    `;
}

function renderFiles(
files,
category){

   const profiles = {

shineil:{
image:"profile.png",
name:"SHINEIL KEITH MATHIAS",
role:"Founder of SHINE MINISTRY • Student • Public Speaker • Digital Creator",

personal:`
<b>Full Name:</b> Shineil Keith Mathias<br>
<b>Date of Birth:</b> 7 March 2010<br>
<b>Gender:</b> Male<br>
<b>Nationality:</b> Indian<br>
<b>Location:</b> Khandala, Pune
`,

contact:`
<b>Phone:</b> +91 8605586173<br>
<b>Email:</b> shinumaths989@gmail.com<br>
<b>Website:</b> shine-ministry.com<br>
<b>Instagram:</b> @shinu_vordenker_7
`,

education:`
Don Bosco High School<br>
2020–2026<br>
Secondary Education
`,

skills:`
• Public Speaking<br>
• Leadership<br>
• Mathematics<br>
• Web Editing
`,

languages:`
English — Fluent<br>
Hindi — Fluent<br>
German — Basic
`,

achievements:`
• Green House Captain<br>
• Debate Awards<br>
• Student Recognition
`,

experience:`
Founder — SHINE MINISTRY<br>
Digital Projects<br>
Leadership Activities
`,

projects:`
Secure Vault<br>
SHINE MINISTRY<br>
PDF Systems
`,

goals:`
Technology<br>
Education<br>
Leadership
`,

faith:`
Founder of SHINE MINISTRY<br>
Christian Service
`,

about:`
Student with strong communication,
leadership and ministry interests.
`,

hobbies:`
Debating, technology,
public speaking, reading
`
},



brother:{

image:"ProfileK.png",
name:"KEVIN SHREESH MATHIAS",
role:"Bartender • Hospitality",

personal:`
<b>Name:</b> Kevin Shreesh Mathias<br>
<b>Location:</b> Pune<br>
<b>Industry:</b> Hospitality
`,

contact:`
Add Number<br>
Add Email
`,

education:`
Guardian School — SSC<br>
IHM Mumbai<br>
Flair Mania Bartending Academy
`,

skills:`
• Bartending<br>
• Customer Service<br>
• POS<br>
• Inventory
`,

languages:`
English<br>
Hindi
`,

achievements:`
Assistant Bartender — Bombay Cartel<br>
Assistant Bartender — Janwani
`,

experience:`
2023–2025 Bombay Cartel<br>
Present — Janwani
`,

projects:`
Hospitality Training<br>
Service Experience
`,

goals:`
Career Growth<br>
Hospitality Industry
`,

faith:`-`,

about:`
Hospitality professional with
bartending and customer service experience.
`,

hobbies:`
Service industry,
teamwork,
food & beverage
`
},



father:{
image:"ProfileSt.png",
name:"STEPHEN CONDRAD MATHIAS",
role:"Father",
personal:`Add`,
contact:`+91 99216 68744, +91 93707 50143`,
education:`Add`,
skills:`Add`,
languages:`English, Hindi, Konkani, Tulu, Kannada`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Roman Catholic`,
about:`Add`,
hobbies:`Add`
},



mother:{
image:"mother.png",
name:"KANCHAN MATHIAS",
role:"Mother",
personal:`Add`,
contact:`Add`,
education:`Add`,
skills:`Add`,
languages:`Add`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Add`,
about:`Add`,
hobbies:`Add`
}

};
   
   currentCategory = category;

    document.getElementById(
    'cat-title').textContent =
    category;

    const grid =
    document.getElementById(
    'file-grid');

   if(category==="HOME"){

// For non-admin modes the dropdown is hidden, so derive member from VAULT_MODE
const modeToMember = {
    "SHINEIL": "shineil",
    "KEVIN": "brother",
    "KEVIN_PARENTS": "brother",
    "SHINEIL_PARENTS": "shineil",
    "PARENTS": "father",
    "OFFICIAL": "shineil",
    "ADMIN": null
};

const vaultMode = window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "ADMIN";
const dropdownVal = document.getElementById("member-select").value;

// Admin uses dropdown; other modes use their assigned member
const member =
document.getElementById('member-select')?.value || 'shineil';

const profile =
profiles[member] || profiles.shineil;


grid.innerHTML=`

${buildHomeDashboard()}

<div style="
grid-column:1/-1;
background:white;
border:1px solid var(--border);
border-radius:24px;
padding:35px;">


<div style="
display:flex;
gap:25px;
flex-wrap:wrap;
margin-bottom:30px;">

<img src="${p.image}"
style="
width:150px;
height:150px;
border-radius:24px;
object-fit:cover;">

<div>

<h1 style="
color:var(--accent);">

${p.name}

</h1>

<div style="
color:var(--muted);">

${p.role}

</div>

</div>
</div>



<div style="
display:grid;
grid-template-columns:
repeat(auto-fit,minmax(260px,1fr));
gap:20px;">

<div class="profile-box">
<h3>Personal Details</h3>
${p.personal}
</div>

<div class="profile-box">
<h3>Contact</h3>
${p.contact}
</div>

<div class="profile-box">
<h3>Education</h3>
${p.education}
</div>

<div class="profile-box">
<h3>Skills</h3>
${p.skills}
</div>

<div class="profile-box">
<h3>Languages</h3>
${p.languages}
</div>

<div class="profile-box">
<h3>Achievements</h3>
${p.achievements}
</div>

<div class="profile-box">
<h3>Experience</h3>
${p.experience}
</div>

<div class="profile-box">
<h3>Projects</h3>
${p.projects}
</div>

<div class="profile-box">
<h3>Future Goals</h3>
${p.goals}
</div>

<div class="profile-box">
<h3>Faith / Ministry</h3>
${p.faith}
</div>

</div>



<div style="
margin-top:25px;
background:#eff6ff;
padding:24px;
border-radius:18px;">

<h3>About Me</h3>

${p.about}

</div>



<div style="
margin-top:25px;
background:#f8fafc;
padding:24px;
border-radius:18px;">

<h3>Hobbies & Interests</h3>

${p.hobbies}

</div>



<div style="
margin-top:25px;
background:#f8fafc;
padding:24px;
border-radius:18px;">

<h3>Timeline</h3>

2010 — Born<br>
2020 — Education<br>
2024 — Projects<br>
2025 — Present

</div>

</div>

`;

return;
}
   
    grid.innerHTML = "";

    const visibleFiles =
window.LITE_MODE
? files.slice(0,20)
: files;

visibleFiles.forEach(file=>{

        const card =
        document.createElement(
        'div');

        card.className =
        'file-card';

        // EXPIRY BADGE
        let expiryBadge = '';
        if(file.expiry){
            const daysLeft = Math.ceil(
                (new Date(file.expiry) - new Date()) / 86400000
            );
            if(daysLeft < 0){
                expiryBadge = `<div class="expiry-badge expiry-danger">⚠️ Expired</div>`;
            } else if(daysLeft <= 30){
                expiryBadge = `<div class="expiry-badge expiry-warn">⏳ Expires in ${daysLeft}d</div>`;
            } else {
                expiryBadge = `<div class="expiry-badge expiry-ok">✓ Valid ${daysLeft}d</div>`;
            }
        }

        const isPinned = pinnedDocs.some(p => p.file === file.file);

        card.innerHTML = `
        <div style="
        font-size:48px;
        margin-bottom:12px;">
            📄
        </div>

        <div style="
        font-weight:800;
        line-height:1.5;">
            ${file.name}
        </div>

        ${expiryBadge}

        <div class="card-actions">
            <button class="card-btn card-btn-pin ${isPinned ? 'pinned' : ''}"
                onclick="event.stopPropagation();togglePin(${JSON.stringify(file).replace(/"/g,'&quot;')},this)">
                ${isPinned ? '⭐ Pinned' : '☆ Pin'}
            </button>
            <button class="card-btn card-btn-share"
                onclick="event.stopPropagation();openShareModal(${JSON.stringify(file).replace(/"/g,'&quot;')})">
                🔗 Share
            </button>
            <button class="card-btn card-btn-compare"
                onclick="event.stopPropagation();addToCompare(${JSON.stringify(file).replace(/"/g,'&quot;')})">
                ⚖️ Compare
            </button>
        </div>
        `;

        card.onclick = ()=>{

            openSecureFile(
                "docs/" + file.file,
                file.name
            );

        };

// HOVER QUICK PREVIEW
        card.addEventListener('mouseenter', (e) => {
            // 📱 Check to disable hover previews on phones, tablets, and mobile touch devices
            if (window.matchMedia("(max-width: 768px)").matches || ('ontouchstart' in window) || navigator.maxTouchPoints > 0) {
                return; // Stop right here, don't show the preview
            }
            if(!window.LITE_MODE){
    startHoverPreview(file, e);
            }
        });

        card.addEventListener('mousemove', (e) => {
            // 📱 Check to disable position tracking on other devices
            if (window.matchMedia("(max-width: 768px)").matches || ('ontouchstart' in window) || navigator.maxTouchPoints > 0) {
                return;
            }
            positionTooltip(e);
        });

        card.addEventListener('mouseleave', () => {
            hidePreviewTooltip();
        });

        grid.appendChild(card);

    });

}

function renderProfile(memberKey) {

    const profile = profiles[memberKey];

    if (!profile) return;

    document.getElementById("profile-avatar").innerHTML = "👤";

    document.getElementById("profile-name").textContent =
        profile.name || "";

    document.getElementById("profile-role").textContent =
        profile.role || "";

    document.getElementById("profile-details").innerHTML = `
        <div><b>Personal</b><br>${profile.personal || "-"}</div>
        <div><b>Contact</b><br>${profile.contact || "-"}</div>
        <div><b>Education</b><br>${profile.education || "-"}</div>
        <div><b>Skills</b><br>${profile.skills || "-"}</div>
        <div><b>Languages</b><br>${profile.languages || "-"}</div>
        <div><b>Achievements</b><br>${profile.achievements || "-"}</div>
        <div><b>Experience</b><br>${profile.experience || "-"}</div>
        <div><b>Projects</b><br>${profile.projects || "-"}</div>
        <div><b>Goals</b><br>${profile.goals || "-"}</div>
        <div><b>Faith</b><br>${profile.faith || "-"}</div>
        <div><b>About</b><br>${profile.about || "-"}</div>
        <div><b>Hobbies</b><br>${profile.hobbies || "-"}</div>
    `;
}

async function unifiedSearch(){

    const query =
    document.getElementById(
        'unified-search'
    ).value.toLowerCase().trim();

    if(!query){

        if(currentCategory &&
        allFilesData[currentCategory]){

            renderFiles(
                allFilesData[currentCategory],
                currentCategory
            );
        }

        return;
    }

    let results = [];

    // FILE NAME SEARCH

    Object.keys(allFilesData)
    .forEach(category=>{

        const files =
        allFilesData[category];

        if(!Array.isArray(files)) return;

        files.forEach(file=>{

            if(
                file.name
                .toLowerCase()
                .includes(query)
            ){

                results.push({
                    ...file,
                    category,
                    source:"Filename"
                });

            }

        });

    });

    renderSearchResults(results);

}

   function renderSearchResults(results){

    document.getElementById(
        'cat-title'
    ).textContent =
    `Search Results (${results.length})`;

    const grid =
    document.getElementById(
        'file-grid'
    );

    grid.innerHTML = "";

    if(results.length === 0){

        grid.innerHTML = `
        <div style="
        grid-column:1/-1;
        text-align:center;
        padding:40px;
        background:white;
        border-radius:20px;">
            No matching files found.
        </div>
        `;

        return;
    }

    results.forEach(file=>{

        const card =
        document.createElement('div');

        card.className =
        'file-card';

        card.innerHTML = `

        <div style="
        font-size:48px;
        margin-bottom:12px;">
            📄
        </div>

        <div style="
        font-weight:800;
        line-height:1.5;">
            ${file.name}
        </div>

        <div style="
        margin-top:10px;
        color:var(--muted);
        font-size:.85rem;">
            ${file.category}
        </div>

        <div style="
        margin-top:6px;
        color:#2563eb;
        font-size:.75rem;
        font-weight:700;">
            ${file.source}
        </div>

        `;

        card.onclick = ()=>{

            openSecureFile(
                "docs/" + file.file,
                file.name
            );

        };

        grid.appendChild(card);

    });

}

document.addEventListener("DOMContentLoaded", () => {

    const memberSelect =
        document.getElementById("member-select");

    if (!memberSelect) return;

    renderProfile(memberSelect.value === "all"
        ? "shineil"
        : memberSelect.value);

    memberSelect.addEventListener("change", () => {

        const selected =
            memberSelect.value === "all"
            ? "shineil"
            : memberSelect.value;

        renderProfile(selected);
    });
});
