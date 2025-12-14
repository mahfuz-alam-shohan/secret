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
        `CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, type TEXT DEFAULT 'text', content TEXT, metadata TEXT DEFAULT '{}', max_views INTEGER DEFAULT 1, expiry_seconds INTEGER DEFAULT 0, allow_reply INTEGER DEFAULT 0, view_count INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, burned_at INTEGER DEFAULT NULL, first_viewed_at INTEGER DEFAULT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')));`,
        `CREATE TABLE IF NOT EXISTS replies (id INTEGER PRIMARY KEY AUTOINCREMENT, secret_id TEXT NOT NULL, content TEXT NOT NULL, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE);`,
        `CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, secret_id TEXT NOT NULL, ip_address TEXT, country TEXT, city TEXT, user_agent TEXT, device_type TEXT, viewed_at INTEGER DEFAULT (strftime('%s', 'now')));`
    ];
    for (const q of queries) await safeQuery(env, q);

    // Migration attempt for existing DBs (ignore error if column exists)
    try { await safeQuery(env, "ALTER TABLE secrets ADD COLUMN allow_reply INTEGER DEFAULT 0;"); } catch(e) {}
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

                // Check for Reply capability on missing/burned secrets
                if (!secret || secret.is_active === 0) {
                     // If it's burned/missing, but we need to check if we can reply
                     // We need the record to exist to check allow_reply. If deleted completely, we can't.
                     // But our logic soft-deletes via is_active=0.
                     if (secret && secret.allow_reply === 1) {
                        // Check if a reply already exists
                        const existingReply = await safeSelect(env, "SELECT id FROM replies WHERE secret_id = ?", secretId);
                        if (!existingReply) {
                            return jsonResp({ error: "Burned", can_reply: true }, 410);
                        }
                     }
                     return jsonResp({ error: "Message not found or burned." }, 410);
                }

                // Logging (Async)
                ctx.waitUntil(safeQuery(env, "INSERT INTO access_logs (secret_id, ip_address, country, city, user_agent, device_type) VALUES (?, ?, ?, ?, ?, ?)", secretId, request.headers.get('CF-Connecting-IP') || 'Unknown', request.cf?.country || 'XX', request.cf?.city || 'Unknown', request.headers.get('User-Agent') || 'Unknown', 'Web'));

                // Time Check
                let remaining = 0;
                if (secret.expiry_seconds > 0) {
                    const firstView = secret.first_viewed_at || now;
                    const elapsed = now - firstView;
                    remaining = Math.max(0, secret.expiry_seconds - elapsed);

                    if (elapsed > secret.expiry_seconds) {
                        await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                        // Check reply logic immediately after burn
                        if (secret.allow_reply === 1) {
                            const reply = await safeSelect(env, "SELECT id FROM replies WHERE secret_id = ?", secretId);
                            if (!reply) return jsonResp({ error: "Expired", can_reply: true }, 410);
                        }
                        return jsonResp({ error: "Message expired." }, 410);
                    }
                }

                // View Count Check
                if (secret.view_count >= secret.max_views) {
                    await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                     // Check reply logic immediately after burn
                     if (secret.allow_reply === 1) {
                        const reply = await safeSelect(env, "SELECT id FROM replies WHERE secret_id = ?", secretId);
                        if (!reply) return jsonResp({ error: "Max views reached", can_reply: true }, 410);
                    }
                    return jsonResp({ error: "Max views reached." }, 410);
                }

                // Increment Logic
                if (secret.first_viewed_at === null) {
                    await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1, first_viewed_at = ? WHERE id = ?", now, secretId);
                } else {
                    await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1 WHERE id = ?", secretId);
                }

                // Double check if this view killed it (max_views = 1, view_count becomes 1)
                // We return content THIS time, but next time it will be burned.
                if (secret.view_count + 1 > secret.max_views) {
                     await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                }

                return jsonResp({
                    type: secret.type,
                    content: secret.content,
                    metadata: JSON.parse(secret.metadata || '{}'),
                    allow_reply: secret.allow_reply,
                    max_views: secret.max_views,
                    view_count: secret.view_count + 1,
                    settings: {
                        expiry: secret.expiry_seconds,
                        remaining_seconds: remaining
                    }
                });
            }

            // 2. POST REPLY (Public)
            if (path === '/api/reply' && method === 'POST') {
                const { secret_id, content } = await request.json();
                if(!secret_id || !content) return jsonResp({error: "Missing data"}, 400);

                const secret = await safeSelect(env, "SELECT allow_reply FROM secrets WHERE id = ?", secret_id);
                if (!secret) return jsonResp({ error: "Invalid ID" }, 404);
                if (secret.allow_reply !== 1) return jsonResp({ error: "Replies not allowed" }, 403);

                const existing = await safeSelect(env, "SELECT id FROM replies WHERE secret_id = ?", secret_id);
                if (existing) return jsonResp({ error: "Reply already sent" }, 409);

                await safeQuery(env, "INSERT INTO replies (secret_id, content) VALUES (?, ?)", secret_id, content);
                return jsonResp({ success: true });
            }

            // 3. AUTH & SETUP
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
                const allowReply = body.allow_reply ? 1 : 0;
                await safeQuery(env, "INSERT INTO secrets (id, type, content, metadata, max_views, expiry_seconds, allow_reply) VALUES (?, ?, ?, ?, ?, ?, ?)", id, type, body.content, '{}', body.max_views || 1, body.expiry_seconds || 0, allowReply);
                return jsonResp({ id }, 201);
            }

            if (path === '/api/secrets-list') {
                // Fetch secrets AND check if they have a reply
                const l = await safeSelectAll(env, `
                    SELECT s.id, s.type, s.created_at, s.view_count, s.max_views, s.is_active, r.content as reply_content 
                    FROM secrets s 
                    LEFT JOIN replies r ON s.id = r.secret_id 
                    ORDER BY s.created_at DESC LIMIT 50
                `);
                return jsonResp({ secrets: l?.results || [] });
            }

            if (path.match(/^\/api\/secret\/(.+)$/) && method === 'DELETE') {
                const id = path.split('/').pop();
                await safeQuery(env, "DELETE FROM secrets WHERE id = ?", id);
                await safeQuery(env, "DELETE FROM access_logs WHERE secret_id = ?", id);
                await safeQuery(env, "DELETE FROM replies WHERE secret_id = ?", id);
                return jsonResp({ message: "Deleted" });
            }
            
            return jsonResp({ error: "Not Found" }, 404);
        }

        try { return await env.ASSETS.fetch(request); } catch (e) { return new Response("Frontend Not Found", { status: 404 }); }
    }
};
