// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

// --- SAFETY WRAPPER FOR DB ---
// We wrap DB calls to prevent the worker from crashing completely
async function safeQuery(env, query, ...args) {
    try {
        if (!env.DB) throw new Error("DB_BINDING_MISSING");
        return await env.DB.prepare(query).bind(...args).run();
    } catch (e) {
        console.error("DB Error:", e.message);
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

// Initialize tables if they don't exist
async function initDB(env) {
    const queries = [
        `CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
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
            FOREIGN KEY (user_id) REFERENCES admins(id)
        );`,
        `CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            max_views INTEGER DEFAULT 1,
            expiry_seconds INTEGER DEFAULT 0,
            view_count INTEGER DEFAULT 0,
            first_viewed_at INTEGER DEFAULT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );`
    ];

    for (const q of queries) {
        await safeQuery(env, q);
    }
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // --- GLOBAL HEADERS ---
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Content-Type': 'application/json'
        };

        if (method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        // Only handle /api/ paths
        if (path.startsWith('/api')) {
            try {
                // FORCE INIT DB ON EVERY API CALL TO BE SAFE
                await initDB(env);

                // 1. PUBLIC: GET SECRET
                const secretMatch = path.match(/^\/api\/secret\/(.+)$/);
                if (secretMatch && method === 'GET') {
                    const secretId = secretMatch[1];
                    const now = Math.floor(Date.now() / 1000);

                    const secret = await safeSelect(env, "SELECT * FROM secrets WHERE id = ?", secretId);

                    if (!secret) {
                        return new Response(JSON.stringify({ error: "Message not found." }), { status: 404, headers: corsHeaders });
                    }

                    // Check Time Expiry
                    if (secret.first_viewed_at !== null && secret.expiry_seconds > 0) {
                        if ((now - secret.first_viewed_at) > secret.expiry_seconds) {
                            await safeQuery(env, "DELETE FROM secrets WHERE id = ?", secretId);
                            return new Response(JSON.stringify({ error: "Message expired." }), { status: 410, headers: corsHeaders });
                        }
                    }

                    // Check View Limit
                    if (secret.view_count >= secret.max_views) {
                        await safeQuery(env, "DELETE FROM secrets WHERE id = ?", secretId);
                        return new Response(JSON.stringify({ error: "Max views reached." }), { status: 410, headers: corsHeaders });
                    }

                    // Increment View
                    if (secret.first_viewed_at === null) {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1, first_viewed_at = ? WHERE id = ?", now, secretId);
                    } else {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1 WHERE id = ?", secretId);
                    }

                    return new Response(JSON.stringify({ 
                        content: secret.content, 
                        settings: { expiry: secret.expiry_seconds } 
                    }), { status: 200, headers: corsHeaders });
                }

                // 2. CHECK SETUP
                if (path === '/api/check-setup' && method === 'GET') {
                    const res = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                    const count = res ? (res.count || 0) : 0;
                    return new Response(JSON.stringify({ setupRequired: count === 0 }), { status: 200, headers: corsHeaders });
                }

                // 3. SETUP
                if (path === '/api/setup' && method === 'POST') {
                    const res = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                    if ((res?.count || 0) > 0) return new Response(JSON.stringify({ error: "Setup done." }), { status: 403, headers: corsHeaders });

                    const body = await request.json();
                    if (!body.username || !body.password) throw new Error("Missing fields");

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
                        return new Response(JSON.stringify({ error: "Bad credentials" }), { status: 401, headers: corsHeaders });
                    }

                    const token = generateSessionId();
                    await safeQuery(env, "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", token, user.id, Math.floor(Date.now()/1000) + 86400);
                    
                    return new Response(JSON.stringify({ token: token, message: "OK" }), { status: 200, headers: corsHeaders });
                }

                // --- AUTH MIDDLEWARE FOR DASHBOARD/CREATE ---
                const authHeader = request.headers.get('Authorization');
                const token = authHeader ? authHeader.split(' ')[1] : null;
                
                if (!token) {
                    return new Response(JSON.stringify({ error: "No Token" }), { status: 401, headers: corsHeaders });
                }

                const session = await safeSelect(env, "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?", token, Math.floor(Date.now() / 1000));
                
                if (!session) {
                    return new Response(JSON.stringify({ error: "Invalid Session" }), { status: 401, headers: corsHeaders });
                }

                // 5. DASHBOARD
                if (path === '/api/dashboard' && method === 'GET') {
                    const stats = await safeSelect(env, "SELECT COUNT(*) as count FROM secrets");
                    return new Response(JSON.stringify({ 
                        message: `Welcome, ${session.username}`,
                        stats: { active_secrets: stats?.count || 0 }
                    }), { status: 200, headers: corsHeaders });
                }

                // 6. CREATE SECRET
                if (path === '/api/secret' && method === 'POST') {
                    const body = await request.json();
                    const id = crypto.randomUUID();
                    await safeQuery(env, 
                        "INSERT INTO secrets (id, content, max_views, expiry_seconds) VALUES (?, ?, ?, ?)", 
                        id, body.content, body.max_views || 1, body.expiry_seconds || 0
                    );
                    return new Response(JSON.stringify({ id: id }), { status: 201, headers: corsHeaders });
                }

                // 7. RESET
                if (path === '/api/reset' && method === 'DELETE') {
                    await safeQuery(env, "DROP TABLE IF EXISTS secrets");
                    await safeQuery(env, "DROP TABLE IF EXISTS sessions");
                    await safeQuery(env, "DROP TABLE IF EXISTS admins");
                    return new Response(JSON.stringify({ message: "Reset Done" }), { status: 200, headers: corsHeaders });
                }

                return new Response(JSON.stringify({ error: "Unknown Endpoint" }), { status: 404, headers: corsHeaders });

            } catch (err) {
                // THE ULTIMATE CATCH-ALL
                return new Response(JSON.stringify({ error: "CRITICAL SERVER ERROR: " + err.message }), { status: 500, headers: corsHeaders });
            }
        }

        // Static Assets Fallback
        try {
            return await env.ASSETS.fetch(request);
        } catch (e) {
            return new Response("Frontend Not Found", { status: 404 });
        }
    }
};
