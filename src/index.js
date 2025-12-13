// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

// --- UTILS ---
async function safeQuery(env, query, ...args) {
    try {
        if (!env.DB) throw new Error("DB_BINDING_MISSING");
        return await env.DB.prepare(query).bind(...args).run();
    } catch (e) {
        console.error("DB Query Error:", e.message);
        throw new Error(`DB_ERROR: ${e.message}`);
    }
}

async function safeSelect(env, query, ...args) {
    try {
        if (!env.DB) throw new Error("DB_BINDING_MISSING");
        return await env.DB.prepare(query).bind(...args).first();
    } catch (e) {
        console.error("DB Select Error:", e.message);
        throw new Error(`DB_ERROR: ${e.message}`);
    }
}

async function safeSelectAll(env, query, ...args) {
    try {
        if (!env.DB) throw new Error("DB_BINDING_MISSING");
        return await env.DB.prepare(query).bind(...args).all();
    } catch (e) {
        console.error("DB SelectAll Error:", e.message);
        throw new Error(`DB_ERROR: ${e.message}`);
    }
}

// --- INIT DB & AUTO-UPGRADE SCHEME ---
async function initDB(env) {
    // 1. SELF-HEALING: Check for old schema
    try {
        await env.DB.prepare("SELECT is_active FROM secrets LIMIT 1").first();
    } catch (e) {
        if (e.message && e.message.includes("no such column")) {
            console.log("Old schema detected! Dropping incompatible 'secrets' table...");
            await env.DB.prepare("DROP TABLE IF EXISTS secrets").run();
        }
    }

    // 2. Ensure Tables Exist
    const queries = [
        `CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );`,
        `CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
        );`,
        `CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            type TEXT DEFAULT 'text',
            content TEXT,
            metadata TEXT DEFAULT '{}',
            max_views INTEGER DEFAULT 1,
            expiry_seconds INTEGER DEFAULT 0,
            view_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            burned_at INTEGER DEFAULT NULL,
            first_viewed_at INTEGER DEFAULT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );`,
        `CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_id TEXT NOT NULL,
            ip_address TEXT,
            country TEXT,
            city TEXT,
            user_agent TEXT,
            device_type TEXT,
            viewed_at INTEGER DEFAULT (strftime('%s', 'now'))
        );`
    ];
    
    for (const q of queries) {
        await safeQuery(env, q);
    }
}

// --- WORKER HANDLER ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // CORS
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Custom-Auth',
            'Content-Type': 'application/json'
        };

        if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders });

        // --- FILE SERVING (R2) ---
        // Route: /file/key-name
        if (path.startsWith('/file/')) {
            const key = path.replace('/file/', '');
            if (!env.BUCKET) return new Response("Storage Not Configured", { status: 500 });
            
            const object = await env.BUCKET.get(key);
            if (!object) return new Response("File Not Found", { status: 404 });

            const headers = new Headers();
            object.writeHttpMetadata(headers);
            headers.set('etag', object.httpEtag);
            
            return new Response(object.body, { headers });
        }

        if (path.startsWith('/api')) {
            try {
                await initDB(env);

                // --- PUBLIC API ---

                // 1. GET SECRET
                const secretMatch = path.match(/^\/api\/secret\/(.+)$/);
                if (secretMatch && method === 'GET') {
                    const secretId = secretMatch[1];
                    const now = Math.floor(Date.now() / 1000);

                    let secret = await safeSelect(env, "SELECT * FROM secrets WHERE id = ?", secretId);

                    if (!secret) return new Response(JSON.stringify({ error: "Message not found." }), { status: 404, headers: corsHeaders });

                    // Log Access
                    const ip = request.headers.get('CF-Connecting-IP') || 'Unknown';
                    const country = request.cf?.country || 'Unknown';
                    const city = request.cf?.city || 'Unknown';
                    const ua = request.headers.get('User-Agent') || 'Unknown';
                    const device = ua.includes('Mobile') ? 'Mobile' : 'Desktop';
                    
                    await safeQuery(env, "INSERT INTO access_logs (secret_id, ip_address, country, city, user_agent, device_type) VALUES (?, ?, ?, ?, ?, ?)", secretId, ip, country, city, ua, device);

                    // Validation & Burning Logic
                    if (secret.is_active === 0) return new Response(JSON.stringify({ error: "Message has been burned." }), { status: 410, headers: corsHeaders });

                    if (secret.first_viewed_at !== null && secret.expiry_seconds > 0) {
                        if ((now - secret.first_viewed_at) > secret.expiry_seconds) {
                            await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                            return new Response(JSON.stringify({ error: "Message expired." }), { status: 410, headers: corsHeaders });
                        }
                    }

                    if (secret.view_count >= secret.max_views) {
                        await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                        return new Response(JSON.stringify({ error: "Max views reached." }), { status: 410, headers: corsHeaders });
                    }

                    // Increment
                    if (secret.first_viewed_at === null) {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1, first_viewed_at = ? WHERE id = ?", now, secretId);
                    } else {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1 WHERE id = ?", secretId);
                    }

                    if (secret.view_count + 1 > secret.max_views) {
                         await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                    }

                    return new Response(JSON.stringify({ 
                        type: secret.type,
                        content: secret.content, 
                        metadata: JSON.parse(secret.metadata || '{}'),
                        settings: { expiry: secret.expiry_seconds } 
                    }), { status: 200, headers: corsHeaders });
                }

                // --- ADMIN API ---
                
                // 2. CHECK SETUP
                if (path === '/api/check-setup' && method === 'GET') {
                    const res = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                    return new Response(JSON.stringify({ setupRequired: (res?.count || 0) === 0 }), { status: 200, headers: corsHeaders });
                }

                // 3. SETUP
                if (path === '/api/setup' && method === 'POST') {
                    const res = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                    if ((res?.count || 0) > 0) return new Response(JSON.stringify({ error: "Setup already done." }), { status: 403, headers: corsHeaders });
                    const body = await request.json();
                    const salt = generateSalt();
                    const hash = await hashPassword(body.password, salt);
                    await safeQuery(env, "INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)", body.username, hash, salt);
                    return new Response(JSON.stringify({ success: true }), { status: 201, headers: corsHeaders });
                }

                // 4. LOGIN
                if (path === '/api/login' && method === 'POST') {
                    const body = await request.json();
                    const user = await safeSelect(env, "SELECT * FROM admins WHERE username = ?", body.username);
                    if (!user || !(await verifyPassword(user.password_hash, body.password, user.salt))) {
                        return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
                    }
                    const token = generateSessionId();
                    await safeQuery(env, "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", token, user.id, Math.floor(Date.now()/1000) + 86400);
                    return new Response(JSON.stringify({ token: token, message: "OK" }), { status: 200, headers: corsHeaders });
                }

                // --- AUTH MIDDLEWARE FOR PROTECTED ROUTES ---
                const authHeader = request.headers.get('Authorization');
                const token = authHeader ? authHeader.split(' ')[1] : null;
                
                // We allow access to upload without token if it's protected by other means, 
                // but for security, let's assume uploads need admin token OR we make it public (risky).
                // Let's require token for uploads.
                
                // 5. UPLOAD FILE (Protected)
                if (path === '/api/upload' && method === 'POST') {
                     if (!token) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
                     // Verify Token
                     const session = await safeSelect(env, "SELECT id FROM sessions WHERE id = ? AND expires_at > ?", token, Math.floor(Date.now() / 1000));
                     if (!session) return new Response(JSON.stringify({ error: "Invalid Session" }), { status: 401, headers: corsHeaders });

                     if (!env.BUCKET) return new Response(JSON.stringify({ error: "R2 Bucket Not Configured" }), { status: 500, headers: corsHeaders });

                     const contentType = request.headers.get("Content-Type") || "application/octet-stream";
                     const filename = request.headers.get("X-File-Name") || `upload-${crypto.randomUUID()}`;
                     const key = `${crypto.randomUUID()}-${filename}`;
                     
                     // Put into R2
                     await env.BUCKET.put(key, request.body, {
                         httpMetadata: { contentType: contentType }
                     });

                     return new Response(JSON.stringify({ url: `/file/${key}`, key: key }), { status: 200, headers: corsHeaders });
                }

                if (!token) return new Response(JSON.stringify({ error: "No Token" }), { status: 401, headers: corsHeaders });
                
                // Verify Session for remaining routes
                const session = await safeSelect(env, "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?", token, Math.floor(Date.now() / 1000));
                if (!session) return new Response(JSON.stringify({ error: "Invalid Session" }), { status: 401, headers: corsHeaders });

                // 6. DASHBOARD
                if (path === '/api/dashboard' && method === 'GET') {
                    const active = await safeSelect(env, "SELECT COUNT(*) as count FROM secrets WHERE is_active = 1");
                    const burned = await safeSelect(env, "SELECT COUNT(*) as count FROM secrets WHERE is_active = 0");
                    const logs = await safeSelect(env, "SELECT COUNT(*) as count FROM access_logs");
                    return new Response(JSON.stringify({ username: session.username, stats: { active_secrets: active?.count || 0, burned_secrets: burned?.count || 0, total_views: logs?.count || 0 } }), { status: 200, headers: corsHeaders });
                }

                // 7. CREATE SECRET
                if (path === '/api/secret' && method === 'POST') {
                    const body = await request.json();
                    const id = crypto.randomUUID();
                    const type = body.type || 'text';
                    const metadata = JSON.stringify(body.metadata || {});
                    await safeQuery(env, "INSERT INTO secrets (id, type, content, metadata, max_views, expiry_seconds) VALUES (?, ?, ?, ?, ?, ?)", id, type, body.content, metadata, body.max_views || 1, body.expiry_seconds || 0);
                    return new Response(JSON.stringify({ id: id }), { status: 201, headers: corsHeaders });
                }

                // 8. LIST & LOGS
                if (path === '/api/secrets-list' && method === 'GET') {
                    const rows = await safeSelectAll(env, "SELECT id, type, created_at, view_count, max_views, is_active FROM secrets ORDER BY created_at DESC LIMIT 50");
                    return new Response(JSON.stringify({ secrets: rows?.results || [] }), { status: 200, headers: corsHeaders });
                }
                if (path.match(/^\/api\/secret\/logs\/(.+)$/) && method === 'GET') {
                    const logs = await safeSelectAll(env, "SELECT * FROM access_logs WHERE secret_id = ? ORDER BY viewed_at DESC", path.split('/').pop());
                    return new Response(JSON.stringify({ logs: logs?.results || [] }), { status: 200, headers: corsHeaders });
                }

                // 9. DELETE & RESET
                if (path.match(/^\/api\/secret\/(.+)$/) && method === 'DELETE') {
                    const sid = path.split('/').pop();
                    await safeQuery(env, "DELETE FROM secrets WHERE id = ?", sid);
                    await safeQuery(env, "DELETE FROM access_logs WHERE secret_id = ?", sid);
                    return new Response(JSON.stringify({ message: "Deleted" }), { status: 200, headers: corsHeaders });
                }
                if (path === '/api/reset' && method === 'DELETE') {
                    await safeQuery(env, "DROP TABLE IF EXISTS secrets");
                    await safeQuery(env, "DROP TABLE IF EXISTS access_logs");
                    return new Response(JSON.stringify({ message: "Data Cleared" }), { status: 200, headers: corsHeaders });
                }

                return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: corsHeaders });
            } catch (err) {
                return new Response(JSON.stringify({ error: "SERVER ERROR: " + err.message }), { status: 500, headers: corsHeaders });
            }
        }

        try { return await env.ASSETS.fetch(request); } catch (e) { return new Response("Frontend Not Found", { status: 404 }); }
    }
};
