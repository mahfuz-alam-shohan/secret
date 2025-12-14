/* === APPLICATION LOGIC === */
const API_BASE = '/api';
let authToken = localStorage.getItem('auth_token');
const urlParams = new URLSearchParams(window.location.search);
const secretId = urlParams.get('id');
let countdownInterval;
let pages = [];
let currentPage = 0;

// === INITIALIZATION ===
window.onload = async () => {
    try {
        if (secretId) {
            await initViewer(secretId);
            document.getElementById('view-app').classList.remove('hidden');
        } else if (authToken) {
            await initDashboard();
            document.getElementById('admin-app').classList.remove('hidden');
        } else {
            document.getElementById('login-app').classList.remove('hidden');
        }
    } catch(e) {
        console.error("Init Error:", e);
    } finally {
        setTimeout(() => document.getElementById('app-loader').classList.add('opacity-0', 'pointer-events-none'), 500);
    }
};

// === AUTHENTICATION ===
const loginForm = document.getElementById('form-login');
if (loginForm) {
    loginForm.onsubmit = async (e) => {
        e.preventDefault();
        const u = document.getElementById('login-user').value;
        const p = document.getElementById('login-pass').value;
        try {
            const res = await fetch(`${API_BASE}/login`, { method: 'POST', body: JSON.stringify({username:u, password:p}) });
            const data = await res.json();
            if(data.token) { 
                localStorage.setItem('auth_token', data.token); 
                location.reload(); 
            } else throw new Error();
        } catch(e) { 
            document.getElementById('login-error').classList.remove('hidden'); 
        }
    };
}

function logout() { localStorage.removeItem('auth_token'); location.reload(); }

// === ADMIN DASHBOARD ===
async function initDashboard() {
    try {
        const res = await fetch(`${API_BASE}/dashboard`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if(res.status === 401) return logout();
        
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

if (document.getElementById('form-create')) {
    document.getElementById('form-create').onsubmit = async (e) => {
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

// Function to handle global updates for the create form UI
window.updateTypeUI = function() {
    const val = document.querySelector('input[name="secret_type"]:checked').value;
    const t = document.getElementById('opt-text');
    const l = document.getElementById('opt-love-letter');
    if(!t || !l) return;
    
    const activeClass = "border-brand-600 bg-brand-50";
    const inactiveClass = "border-slate-100 hover:bg-slate-50";
    const loveActiveClass = "border-pink-500 bg-pink-50";

    if(val === 'text') {
        t.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all ${activeClass}`;
        l.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all ${inactiveClass}`;
    } else {
        l.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all ${loveActiveClass}`;
        t.className = `cursor-pointer border-2 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all ${inactiveClass}`;
    }
};

window.deleteSecret = async function(id) {
    if(confirm("Destroy?")) {
        await fetch(`${API_BASE}/secret/${id}`, { method:'DELETE', headers:{'Authorization':`Bearer ${authToken}`} });
        initDashboard();
    }
};

// === VIEWER LOGIC ===
async function initViewer(id) {
    try {
        const res = await fetch(`${API_BASE}/secret/${id}`);
        const data = await res.json();
        if(data.error) throw new Error(data.error);

        if (data.type === 'love-letter') {
            const loveView = document.getElementById('view-love');
            loveView.classList.remove('hidden');
            
            // Attach Click Listeners HERE to ensure they work
            const wrapper = document.getElementById('love-wrapper');
            if(wrapper) {
                wrapper.addEventListener('click', openEnvelope);
                wrapper.addEventListener('touchstart', (e) => { e.preventDefault(); openEnvelope(); });
            }

            paginateContent(data.content);
            if(data.settings.remaining_seconds > 0) startTimer(data.settings.remaining_seconds, 'love-timer', 'love-timer-container');
        } else {
            document.getElementById('view-standard').classList.remove('hidden');
            document.getElementById('view-content-std').innerText = data.content;
            if(data.settings.remaining_seconds > 0) {
                const w = document.getElementById('std-warning');
                w.classList.remove('hidden'); w.style.display = 'flex';
                startTimer(data.settings.remaining_seconds, 'std-timer');
            }
        }
    } catch(e) {
        document.getElementById('view-error').classList.remove('hidden');
        document.getElementById('view-error-msg').innerText = e.message;
    }
}

// === ENVELOPE INTERACTION ===
function openEnvelope() {
    const env = document.getElementById('love-envelope');
    if(!env.classList.contains('open')) {
        console.log("Opening Envelope...");
        env.classList.add('open');
        
        // Sequence: Open Flap -> Slide Paper Preview -> Zoom In
        setTimeout(() => {
            const stage = document.getElementById('love-stage');
            const overlay = document.getElementById('reading-overlay');
            if(stage) stage.classList.add('zoomed-out');
            if(overlay) overlay.classList.add('active');
        }, 800);
    }
}

// === PAGINATION ===
function paginateContent(text) {
    const charsPerPage = 550; 
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
    if (pages.length === 0) pages.push(text); // Fallback

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
    
    // Check if we need nav buttons
    if(pages.length <= 1) {
        document.querySelectorAll('.nav-btn').forEach(b => b.style.display = 'none');
    } else {
        updateNavButtons();
    }
}

window.nextPage = function() {
    if (currentPage < pages.length - 1) showPage(currentPage + 1);
};

window.prevPage = function() {
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
    updateNavButtons();
}

function updateNavButtons() {
    const prev = document.querySelector('.nav-prev');
    const next = document.querySelector('.nav-next');
    if(prev) prev.classList.toggle('disabled', currentPage === 0);
    if(next) next.classList.toggle('disabled', currentPage === pages.length - 1);
}

// === TIMER & UTILS ===
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

window.copyResult = function() { 
    const e = document.getElementById('result-url');
    e.select(); document.execCommand('copy'); alert('Copied!'); 
};

window.navTo = function(p) {
    document.querySelectorAll('.page-view').forEach(x => x.classList.add('hidden'));
    document.getElementById('page-'+p).classList.remove('hidden');
};

window.refreshData = function() { initDashboard(); };
