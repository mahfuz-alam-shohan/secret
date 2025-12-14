/* === APPLICATION LOGIC (ROBUST VERSION) === */

const API_BASE = '/api';
let authToken = localStorage.getItem('auth_token');
const urlParams = new URLSearchParams(window.location.search);
const secretId = urlParams.get('id');
let countdownInterval;
let pages = [];
let currentPage = 0;
let isEnvelopeOpen = false; // Flag to prevent double clicks

// === ENTRY POINT ===
window.onload = async () => {
    try {
        if (secretId) {
            console.log("Mode: Viewer");
            await initViewer(secretId);
            document.getElementById('view-app').classList.remove('hidden');
        } else if (authToken) {
            console.log("Mode: Dashboard");
            await initDashboard();
            document.getElementById('admin-app').classList.remove('hidden');
        } else {
            console.log("Mode: Login");
            document.getElementById('login-app').classList.remove('hidden');
        }
    } catch(e) {
        console.error("Critical Init Error:", e);
        // Fallback: remove loader anyway so user isn't staring at white screen
    } finally {
        setTimeout(() => document.getElementById('app-loader').classList.add('opacity-0', 'pointer-events-none'), 500);
    }
};

/* ===========================
   VIEWER LOGIC (FIXED)
   =========================== */

async function initViewer(id) {
    try {
        const res = await fetch(`${API_BASE}/secret/${id}`);
        const data = await res.json();
        
        if(data.error) throw new Error(data.error);

        // --- LOVE LETTER MODE ---
        if (data.type === 'love-letter') {
            const container = document.getElementById('view-love');
            container.classList.remove('hidden');
            
            // Setup Content
            paginateContent(data.content);
            
            // Setup Timer
            if (data.settings && data.settings.remaining_seconds > 0) {
                startTimer(data.settings.remaining_seconds, 'love-timer', 'love-timer-container');
            }

            // --- FAIL-SAFE CLICK HANDLER ---
            // We attach the listener to the ENTIRE container, not just the envelope.
            // This ensures clicks anywhere on the desk trigger the open.
            container.addEventListener('click', () => triggerEnvelopeOpen());
            container.addEventListener('touchstart', (e) => {
                // Prevent ghost clicks but allow scroll
                // e.preventDefault(); 
                triggerEnvelopeOpen();
            }, { passive: true });

        } 
        // --- STANDARD MODE ---
        else {
            const container = document.getElementById('view-standard');
            container.classList.remove('hidden');
            document.getElementById('view-content-std').innerText = data.content;
            
            if (data.settings && data.settings.remaining_seconds > 0) {
                const w = document.getElementById('std-warning');
                w.classList.remove('hidden'); w.style.display = 'flex';
                startTimer(data.settings.remaining_seconds, 'std-timer');
            }
        }

    } catch(e) {
        document.getElementById('view-error').classList.remove('hidden');
        document.getElementById('view-error-msg').innerText = e.message || "Secret unavailable";
    }
}

function triggerEnvelopeOpen() {
    if (isEnvelopeOpen) return; // Prevent double trigger
    isEnvelopeOpen = true;

    console.log("Opening Envelope Sequence Started...");

    const stage = document.getElementById('envelope-stage');
    
    // 1. Animate Flap / Seal
    stage.classList.add('opening');

    // 2. Wait for flap animation, then zoom/fade
    setTimeout(() => {
        stage.classList.add('opened');
        
        // 3. Show Reading Overlay
        document.getElementById('reading-overlay').classList.add('active');
    }, 600);
}

// === PAGINATION SYSTEM ===
function paginateContent(text) {
    const charsPerPage = 500; 
    pages = [];
    let paragraphs = text.split('\n');
    let buffer = "";
    
    paragraphs.forEach(para => {
        if ((buffer.length + para.length) < charsPerPage) {
            buffer += para + "\n\n";
        } else {
            if (buffer.length > 0) pages.push(buffer);
            buffer = para + "\n\n";
        }
    });
    if (buffer.length > 0) pages.push(buffer);
    if (pages.length === 0) pages.push(text);

    const container = document.getElementById('book-content');
    if (container) {
        container.innerHTML = '';
        pages.forEach((txt, idx) => {
            const d = document.createElement('div');
            d.className = `page-slide ${idx === 0 ? 'active' : ''}`;
            d.innerText = txt;
            container.appendChild(d);
        });
    }
    updateNav();
}

// Global Nav Functions (attached to window for HTML access)
window.nextPage = function(e) {
    if(e) e.stopPropagation(); // Prevent bubbling to container click
    if (currentPage < pages.length - 1) showPage(currentPage + 1);
};

window.prevPage = function(e) {
    if(e) e.stopPropagation();
    if (currentPage > 0) showPage(currentPage - 1);
};

function showPage(index) {
    const els = document.querySelectorAll('.page-slide');
    if(index > currentPage) {
        els[currentPage].classList.add('prev');
        els[currentPage].classList.remove('active');
    } else {
        els[currentPage].classList.remove('active');
        els[currentPage].classList.remove('prev');
    }
    currentPage = index;
    els[currentPage].classList.remove('prev');
    els[currentPage].classList.add('active');
    updateNav();
}

function updateNav() {
    const prev = document.querySelector('.nav-prev');
    const next = document.querySelector('.nav-next');
    if(prev) prev.classList.toggle('disabled', currentPage === 0);
    if(next) next.classList.toggle('disabled', currentPage === pages.length - 1);
}

// === ADMIN & UTILS ===

// Login
const loginForm = document.getElementById('form-login');
if(loginForm) {
    loginForm.onsubmit = async (e) => {
        e.preventDefault();
        const u = document.getElementById('login-user').value;
        const p = document.getElementById('login-pass').value;
        try {
            const res = await fetch(`${API_BASE}/login`, { method: 'POST', body: JSON.stringify({username:u, password:p}) });
            const data = await res.json();
            if(data.token) { localStorage.setItem('auth_token', data.token); location.reload(); }
            else throw new Error();
        } catch(e) { document.getElementById('login-error').classList.remove('hidden'); }
    };
}

// Dashboard
async function initDashboard() {
    try {
        const res = await fetch(`${API_BASE}/dashboard`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if(res.status === 401) { localStorage.removeItem('auth_token'); location.reload(); return; }
        
        const data = await res.json();
        const safeSet = (id, val) => { const el = document.getElementById(id); if(el) el.innerText = val; };
        
        safeSet('stat-active', data.stats.active_secrets);
        safeSet('stat-views', data.stats.total_views);
        safeSet('stat-burned', data.stats.burned_secrets);
        
        const lRes = await fetch(`${API_BASE}/secrets-list`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        const list = await lRes.json();
        const tbody = document.getElementById('table-secrets');
        
        if (tbody) {
            tbody.innerHTML = '';
            list.secrets.forEach(s => {
                tbody.innerHTML += `
                <tr class="hover:bg-slate-50 border-b border-slate-50">
                    <td class="px-6 py-4"><span class="px-2 py-0.5 rounded-full text-xs font-bold ${s.is_active?'bg-green-100 text-green-700':'bg-red-50 text-red-500'}">${s.is_active?'Active':'Burned'}</span></td>
                    <td class="px-6 py-4 capitalize text-slate-500">${s.type}</td>
                    <td class="px-6 py-4 font-mono text-xs text-slate-400">${s.id.substring(0,8)}...</td>
                    <td class="px-6 py-4 text-center font-bold">${s.view_count}</td>
                    <td class="px-6 py-4 text-right"><button onclick="deleteSecret('${s.id}')" class="text-red-400 hover:text-red-600"><i class="fas fa-trash"></i></button></td>
                </tr>`;
            });
        }
    } catch(e) { console.error("Dash Error:", e); }
}

// Create Form
const createForm = document.getElementById('form-create');
if(createForm) {
    createForm.onsubmit = async (e) => {
        e.preventDefault();
        const body = {
            content: document.getElementById('inp-content').value,
            type: document.querySelector('input[name="secret_type"]:checked').value,
            max_views: document.getElementById('inp-views').value,
            expiry_seconds: document.getElementById('inp-ttl').value
        };
        const res = await fetch(`${API_BASE}/secret`, { method:'POST', headers:{'Authorization':`Bearer ${authToken}`}, body: JSON.stringify(body) });
        const data = await res.json();
        document.getElementById('result-url').value = `${location.origin}?id=${data.id}`;
        document.getElementById('modal-success').classList.remove('hidden');
    };
}

// Helpers
window.updateTypeUI = function() {
    const val = document.querySelector('input[name="secret_type"]:checked').value;
    const t = document.getElementById('opt-text');
    const l = document.getElementById('opt-love-letter');
    if(!t || !l) return;
    
    if(val === 'text') {
        t.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all border-brand-600 bg-brand-50`;
        l.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all border-slate-100 hover:bg-slate-50`;
    } else {
        l.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all border-pink-500 bg-pink-50`;
        t.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all border-slate-100 hover:bg-slate-50`;
    }
};

window.deleteSecret = async function(id) {
    if(confirm("Destroy?")) {
        await fetch(`${API_BASE}/secret/${id}`, { method:'DELETE', headers:{'Authorization':`Bearer ${authToken}`} });
        initDashboard();
    }
};

window.copyResult = function() { 
    document.getElementById('result-url').select(); document.execCommand('copy'); alert('Copied!'); 
};

window.navTo = function(p) {
    document.querySelectorAll('.page-view').forEach(x => x.classList.add('hidden'));
    document.getElementById('page-'+p).classList.remove('hidden');
};

window.refreshData = function() { initDashboard(); };
window.logout = function() { localStorage.removeItem('auth_token'); location.reload(); };

function startTimer(seconds, textId, containerId) {
    const el = document.getElementById(textId);
    if(containerId) document.getElementById(containerId).classList.remove('hidden');
    let t = seconds;
    el.innerText = fmt(t);
    countdownInterval = setInterval(() => {
        t--; el.innerText = fmt(t);
        if(t <= 0) {
            clearInterval(countdownInterval);
            document.body.innerHTML = ''; document.body.style.background = '#000';
            setTimeout(() => location.reload(), 100);
        }
    }, 1000);
}
function fmt(s) { const m=Math.floor(s/60); const sc=s%60; return `${m}:${sc.toString().padStart(2,'0')}`; }
