// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

async function safeQuery(env, query, ...args) {
    if (!env.DB) throw new Error("DB_BINDING_MISSING");
    try {
        return await env.DB.prepare(query).bind(...args).run();
    } catch (e) {
        console.error("DB Query Error:", e.message);
        throw new Error(`DB_ERROR: ${e.message}`);
    }
}

async function safeSelect(env, query, ...args) {
    if (!env.DB) throw new Error("DB_BINDING_MISSING");
    return await env.DB.prepare(query).bind(...args).first();
}

async function safeSelectAll(env, query, ...args) {
    if (!env.DB) throw new Error("DB_BINDING_MISSING");
    return await env.DB.prepare(query).bind(...args).all();
}

async function initDB(env) {
    // Basic table creation
    const queries = [
        `CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')));`,
        `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE);`,
        `CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, type TEXT DEFAULT 'text', content TEXT, metadata TEXT DEFAULT '{}', max_views INTEGER DEFAULT 1, expiry_seconds INTEGER DEFAULT 0, view_count INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, burned_at INTEGER DEFAULT NULL, first_viewed_at INTEGER DEFAULT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')));`,
        `CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, secret_id TEXT NOT NULL, ip_address TEXT, country TEXT, city TEXT, user_agent TEXT, device_type TEXT, viewed_at INTEGER DEFAULT (strftime('%s', 'now')));`
    ];
    for (const q of queries) await safeQuery(env, q);
}

const jsonResp = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        if (method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, DELETE', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });

        if (path.startsWith('/api')) {
            await initDB(env);

            // 1. GET SECRET (Public)
            const secretMatch = path.match(/^\/api\/secret\/([a-zA-Z0-9-]+)$/);
            if (secretMatch && method === 'GET') {
                const secretId = secretMatch[1];
                const now = Math.floor(Date.now() / 1000);

                let secret = await safeSelect(env, "SELECT * FROM secrets WHERE id = ?", secretId);

                if (!secret) return jsonResp({ error: "Message not found." }, 404);

                // Logging (Async)
                ctx.waitUntil(safeQuery(env, "INSERT INTO access_logs (secret_id, ip_address, country, city, user_agent, device_type) VALUES (?, ?, ?, ?, ?, ?)", secretId, request.headers.get('CF-Connecting-IP') || 'Unknown', request.cf?.country || 'XX', request.cf?.city || 'Unknown', request.headers.get('User-Agent') || 'Unknown', 'Web'));

                // Validation
                if (secret.is_active === 0) return jsonResp({ error: "Message has been burned." }, 410);

                // Time Check
                let remaining = 0;
                if (secret.expiry_seconds > 0) {
                    // If first_viewed_at is NULL, we set it NOW effectively for the check, but update DB later
                    const firstView = secret.first_viewed_at || now;
                    const elapsed = now - firstView;
                    remaining = Math.max(0, secret.expiry_seconds - elapsed);

                    if (elapsed > secret.expiry_seconds) {
                        await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                        return jsonResp({ error: "Message expired." }, 410);
                    }
                }

                // View Count Check
                if (secret.view_count >= secret.max_views) {
                    await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                    return jsonResp({ error: "Max views reached." }, 410);
                }

                // Increment Logic
                if (secret.first_viewed_at === null) {
                    await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1, first_viewed_at = ? WHERE id = ?", now, secretId);
                } else {
                    await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1 WHERE id = ?", secretId);
                }

                if (secret.view_count + 1 > secret.max_views) {
                     await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                }

                return jsonResp({ 
                    type: secret.type,
                    content: secret.content, 
                    metadata: JSON.parse(secret.metadata || '{}'),
                    settings: { 
                        expiry: secret.expiry_seconds,
                        remaining_seconds: remaining 
                    } 
                });
            }

            // 2. AUTH & SETUP
            if (path === '/api/setup' && method === 'POST') {
                const c = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                if ((c?.count || 0) > 0) return jsonResp({ error: "Already setup." }, 403);
                const { username, password } = await request.json();
                const salt = generateSalt();
                const hash = await hashPassword(password, salt);
                await safeQuery(env, "INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)", username, hash, salt);
                return jsonResp({ success: true }, 201);
            }

            if (path === '/api/login' && method === 'POST') {
                const { username, password } = await request.json();
                const user = await safeSelect(env, "SELECT * FROM admins WHERE username = ?", username);
                if (!user || !(await verifyPassword(user.password_hash, password, user.salt))) return jsonResp({ error: "Invalid" }, 401);
                const token = generateSessionId();
                await safeQuery(env, "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", token, user.id, Math.floor(Date.now()/1000) + 86400);
                return jsonResp({ token });
            }

            // PROTECTED
            const auth = request.headers.get('Authorization');
            const token = auth ? auth.split(' ')[1] : null;
            if (!token) return jsonResp({ error: "Unauthorized" }, 401);
            
            const session = await safeSelect(env, "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?", token, Math.floor(Date.now() / 1000));
            if (!session) return jsonResp({ error: "Invalid Session" }, 401);

            if (path === '/api/dashboard') {
                const a = await safeSelect(env, "SELECT COUNT(*) as c FROM secrets WHERE is_active = 1");
                const b = await safeSelect(env, "SELECT COUNT(*) as c FROM secrets WHERE is_active = 0");
                const v = await safeSelect(env, "SELECT COUNT(*) as c FROM access_logs");
                return jsonResp({ username: session.username, stats: { active_secrets: a?.c || 0, burned_secrets: b?.c || 0, total_views: v?.c || 0 } });
            }

            if (path === '/api/secret' && method === 'POST') {
                const body = await request.json();
                const id = crypto.randomUUID();
                const type = body.type || 'text';
                await safeQuery(env, "INSERT INTO secrets (id, type, content, metadata, max_views, expiry_seconds) VALUES (?, ?, ?, ?, ?, ?)", id, type, body.content, '{}', body.max_views || 1, body.expiry_seconds || 0);
                return jsonResp({ id }, 201);
            }

            if (path === '/api/secrets-list') {
                const l = await safeSelectAll(env, "SELECT id, type, created_at, view_count, max_views, is_active FROM secrets ORDER BY created_at DESC LIMIT 50");
                return jsonResp({ secrets: l?.results || [] });
            }

            if (path.match(/^\/api\/secret\/(.+)$/) && method === 'DELETE') {
                const id = path.split('/').pop();
                await safeQuery(env, "DELETE FROM secrets WHERE id = ?", id);
                await safeQuery(env, "DELETE FROM access_logs WHERE secret_id = ?", id);
                return jsonResp({ message: "Deleted" });
            }
            
            return jsonResp({ error: "Not Found" }, 404);
        }

        try { return await env.ASSETS.fetch(request); } catch (e) { return new Response("Frontend Not Found", { status: 404 }); }
    }
};
