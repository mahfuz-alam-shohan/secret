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
    if (secretId) {
        // Viewer Mode
        await initViewer(secretId);
        document.getElementById('view-app').classList.remove('hidden');
    } else if (authToken) {
        // Dashboard Mode
        await initDashboard();
        document.getElementById('admin-app').classList.remove('hidden');
    } else {
        // Login Mode
        document.getElementById('login-app').classList.remove('hidden');
    }
    // Fade out loader
    setTimeout(() => document.getElementById('app-loader').classList.add('opacity-0', 'pointer-events-none'), 500);
};

// === AUTHENTICATION ===
if (document.getElementById('form-login')) {
    document.getElementById('form-login').onsubmit = async (e) => {
        e.preventDefault();
        const u = document.getElementById('login-user').value;
        const p = document.getElementById('login-pass').value;
        try {
            const res = await fetch(`${API_BASE}/login`, { method: 'POST', body: JSON.stringify({username:u, password:p}) });
            const data = await res.json();
            if(data.token) { 
                localStorage.setItem('auth_token', data.token); 
                location.reload(); 
            } else {
                throw new Error();
            }
        } catch(e) { 
            document.getElementById('login-error').classList.remove('hidden'); 
        }
    };
}

function logout() { 
    localStorage.removeItem('auth_token'); 
    location.reload(); 
}

// === ADMIN DASHBOARD ===
async function initDashboard() {
    try {
        const res = await fetch(`${API_BASE}/dashboard`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if(res.status === 401) return logout();
        
        const data = await res.json();
        const elActive = document.getElementById('stat-active');
        const elViews = document.getElementById('stat-views');
        const elBurned = document.getElementById('stat-burned');

        if(elActive) elActive.innerText = data.stats.active_secrets;
        if(elViews) elViews.innerText = data.stats.total_views;
        if(elBurned) elBurned.innerText = data.stats.burned_secrets;
        
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
    } catch(e) { console.error("Dashboard Error:", e); }
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

function updateTypeUI() {
    const val = document.querySelector('input[name="secret_type"]:checked').value;
    const t = document.getElementById('opt-text');
    const l = document.getElementById('opt-love-letter');
    if(val === 'text') {
        t.className = "cursor-pointer border-2 border-brand-600 bg-brand-50 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all";
        l.className = "cursor-pointer border-2 border-slate-100 hover:bg-pink-50 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all";
    } else {
        l.className = "cursor-pointer border-2 border-pink-500 bg-pink-50 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all";
        t.className = "cursor-pointer border-2 border-slate-100 hover:bg-brand-50 p-4 rounded-lg flex flex-col items-center gap-2 text-center transition-all";
    }
}

async function deleteSecret(id) {
    if(confirm("Destroy?")) {
        await fetch(`${API_BASE}/secret/${id}`, { method:'DELETE', headers:{'Authorization':`Bearer ${authToken}`} });
        initDashboard();
    }
}

// === VIEWER LOGIC ===
async function initViewer(id) {
    try {
        const res = await fetch(`${API_BASE}/secret/${id}`);
        const data = await res.json();
        if(data.error) throw new Error(data.error);

        if (data.type === 'love-letter') {
            document.getElementById('view-love').classList.remove('hidden');
            paginateContent(data.content);
            if(data.settings.remaining_seconds > 0) startTimer(data.settings.remaining_seconds, 'love-timer', 'love-timer-container');
        } else {
            document.getElementById('view-standard').classList.remove('hidden');
            document.getElementById('view-content-std').innerText = data.content;
            if(data.settings.remaining_seconds > 0) {
                document.getElementById('std-warning').classList.remove('hidden');
                document.getElementById('std-warning').style.display = 'flex';
                startTimer(data.settings.remaining_seconds, 'std-timer');
            }
        }
    } catch(e) {
        document.getElementById('view-error').classList.remove('hidden');
        document.getElementById('view-error-msg').innerText = e.message;
    }
}

// === BOOKLET PAGINATION SYSTEM ===
function paginateContent(text) {
    const charsPerPage = 600; // Configurable limit
    pages = [];
    let paragraphs = text.split('\n');
    let currentPageText = "";
    
    paragraphs.forEach(para => {
        if ((currentPageText.length + para.length) < charsPerPage) {
            currentPageText += para + "\n\n";
        } else {
            if (currentPageText.length > 0) pages.push(currentPageText);
            if (para.length > charsPerPage) {
                // Split giant paragraphs
                let chunks = para.match(new RegExp('.{1,' + charsPerPage + '}', 'g'));
                chunks.forEach((chunk, i) => {
                        if (i < chunks.length - 1) pages.push(chunk);
                        else currentPageText = chunk + "\n\n";
                });
            } else {
                currentPageText = para + "\n\n";
            }
        }
    });
    if (currentPageText.length > 0) pages.push(currentPageText);
    
    // Render
    const container = document.getElementById('book-content');
    const dots = document.getElementById('page-dots');
    if (!container || !dots) return;

    container.innerHTML = '';
    dots.innerHTML = '';
    
    pages.forEach((pageContent, idx) => {
        const pageDiv = document.createElement('div');
        pageDiv.className = `book-page ${idx === 0 ? 'active' : ''}`;
        pageDiv.innerText = pageContent;
        container.appendChild(pageDiv);

        const dot = document.createElement('div');
        dot.className = `dot ${idx === 0 ? 'active' : ''}`;
        dots.appendChild(dot);
    });

    // Setup Nav
    if (pages.length <= 1) {
        const prev = document.querySelector('.nav-prev');
        const next = document.querySelector('.nav-next');
        if (prev) prev.style.display = 'none';
        if (next) next.style.display = 'none';
    } else {
        updateNavButtons();
    }
    
    setupSwipe(container);
}

function openEnvelope() {
    const env = document.getElementById('love-envelope');
    if(!env.classList.contains('open')) {
        env.classList.add('open');
        setTimeout(() => {
            document.getElementById('love-stage').classList.add('faded');
            document.getElementById('reading-overlay').classList.add('active');
        }, 800);
    }
}

function nextPage() {
    if (currentPage < pages.length - 1) showPage(currentPage + 1);
}

function prevPage() {
    if (currentPage > 0) showPage(currentPage - 1);
}

function showPage(index) {
    const pageEls = document.querySelectorAll('.book-page');
    const dotEls = document.querySelectorAll('.dot');
    
    if (index > currentPage) {
        pageEls[currentPage].classList.add('slide-left');
        pageEls[currentPage].classList.remove('active');
    } else {
            pageEls[currentPage].classList.remove('active');
            pageEls[currentPage].style.transform = 'translateX(20px)';
    }

    currentPage = index;
    pageEls[currentPage].classList.remove('slide-left');
    pageEls[currentPage].style.transform = 'translateX(0)';
    pageEls[currentPage].classList.add('active');

    dotEls.forEach(d => d.classList.remove('active'));
    dotEls[currentPage].classList.add('active');

    updateNavButtons();
}

function updateNavButtons() {
    const prev = document.querySelector('.nav-prev');
    const next = document.querySelector('.nav-next');
    if (prev) prev.classList.toggle('disabled', currentPage === 0);
    if (next) next.classList.toggle('disabled', currentPage === pages.length - 1);
}

function setupSwipe(element) {
    let touchStartX = 0;
    let touchEndX = 0;
    element.addEventListener('touchstart', e => { touchStartX = e.changedTouches[0].screenX; }, false);
    element.addEventListener('touchend', e => {
        touchEndX = e.changedTouches[0].screenX;
        if (touchEndX < touchStartX - 50) nextPage();
        if (touchEndX > touchStartX + 50) prevPage();
    }, false);
}

// === UTILS ===
function startTimer(seconds, textId, containerId) {
    const text = document.getElementById(textId);
    if(containerId) {
        const c = document.getElementById(containerId);
        if(c) c.classList.remove('hidden');
    }
    let timeLeft = seconds;
    text.innerText = formatTime(timeLeft);
    
    countdownInterval = setInterval(() => {
        timeLeft--;
        text.innerText = formatTime(timeLeft);
        if (timeLeft <= 0) {
            clearInterval(countdownInterval);
            document.body.innerHTML = ''; document.body.style.background='black';
            setTimeout(() => location.reload(), 100);
        }
    }, 1000);
}

function formatTime(s) { const m=Math.floor(s/60); const sec=s%60; return `${m}:${sec.toString().padStart(2,'0')}`; }

function copyResult() { 
    const el = document.getElementById('result-url');
    if(el) { el.select(); document.execCommand('copy'); alert('Copied!'); }
}

function navTo(p) { 
    document.querySelectorAll('.page-view').forEach(x=>x.classList.add('hidden')); 
    const target = document.getElementById('page-'+p);
    if(target) target.classList.remove('hidden'); 
}

function refreshData() { initDashboard(); }
