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

    const res = await fetch(
        "https://backend.shinumaths989.workers.dev/files.json",
        {
            headers: {
                "Authorization": "Bearer " + sessionToken
            }
        }
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
    // ── Normalise: backend may return either
    //    a) category-keyed object  { "Passport": [{...}], "ID": [{...}] }
    //    b) flat array             [ {name, file, member, category}, ... ]
    //    Convert (b) → (a) so the rest of the code always works the same way.
    let data = {};
    if (Array.isArray(raw)) {
        // Flat array — group by category field (fallback: "Documents")
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

    allFilesData = data;

    // Cache file list to IndexedDB so offline login can restore the dashboard
    if (typeof idbSetVaultMeta === 'function') {
        idbSetVaultMeta(data).catch(e => console.warn('[VaultData] idbSetVaultMeta failed:', e));
    }

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

    // ── Inject HOME profile item first ──
    const homeLi = document.createElement('li');
    homeLi.textContent = '🏠 HOME';
    homeLi.onclick = () => {
        document.querySelectorAll('#cat-list li')
            .forEach(el => el.classList.remove('active'));
        homeLi.classList.add('active');
        renderFiles([], 'HOME');
    };
    list.appendChild(homeLi);

    categories.forEach(cat => {
        const li = document.createElement('li');
        li.textContent = cat;

        li.onclick = () => {
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
    homeLi.classList.add('active');
    homeLi.click();

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
   FILES
========================= */

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
const member = (vaultMode === "ADMIN")
    ? (dropdownVal || "shineil")
    : (modeToMember[vaultMode] || dropdownVal || "shineil");

const p =
profiles[member]
|| profiles.shineil;


grid.innerHTML=`

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
