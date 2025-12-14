// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

/**
 * Executes a prepared statement safely.
 * @param {Object} env - The environment bindings.
 * @param {string} query - SQL query.
 * @param {...any} args - Query arguments.
 * @returns {Promise<any>}
 */
async function safeQuery(env, query, ...args) {
    if (!env.DB) throw new Error("Database binding (DB) is missing.");
    try {
        return await env.DB.prepare(query).bind(...args).run();
    } catch (e) {
        console.error(`DB_WRITE_ERROR: ${e.message} | Query: ${query}`);
        throw new Error("Database operation failed.");
    }
}

/**
 * Selects a single row safely.
 * @param {Object} env - The environment bindings.
 * @param {string} query - SQL query.
 * @param {...any} args - Query arguments.
 * @returns {Promise<any|null>}
 */
async function safeSelect(env, query, ...args) {
    if (!env.DB) throw new Error("Database binding (DB) is missing.");
    try {
        return await env.DB.prepare(query).bind(...args).first();
    } catch (e) {
        console.error(`DB_READ_ERROR: ${e.message} | Query: ${query}`);
        throw new Error("Database retrieval failed.");
    }
}

/**
 * Selects all matching rows.
 * @returns {Promise<{results: any[]}>}
 */
async function safeSelectAll(env, query, ...args) {
    if (!env.DB) throw new Error("Database binding (DB) is missing.");
    try {
        return await env.DB.prepare(query).bind(...args).all();
    } catch (e) {
        console.error(`DB_READ_ALL_ERROR: ${e.message}`);
        throw new Error("Database retrieval failed.");
    }
}

/**
 * Initializes the database schema if needed.
 * Includes a self-healing mechanism for schema changes.
 */
async function initDB(env) {
    // Check for schema compatibility (basic check for 'secrets' table integrity)
    try {
        await env.DB.prepare("SELECT is_active FROM secrets LIMIT 1").first();
    } catch (e) {
        if (e.message && e.message.includes("no such column")) {
            console.warn("Schema mismatch detected. Resetting 'secrets' table.");
            await env.DB.prepare("DROP TABLE IF EXISTS secrets").run();
        }
    }

    const definitions = [
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

    for (const sql of definitions) {
        await safeQuery(env, sql);
    }
}

/**
 * Helper to standard JSON responses
 */
const jsonResponse = (data, status = 200) => 
    new Response(JSON.stringify(data), { 
        status, 
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        } 
    });

const errorResponse = (msg, status = 400) => jsonResponse({ error: msg }, status);

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // Handle CORS Preflight
        if (method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                }
            });
        }

        // --- PUBLIC FILE SERVING (R2) ---
        if (path.startsWith('/file/')) {
            if (!env.BUCKET) return errorResponse("Storage service unavailable.", 503);
            const key = path.replace('/file/', '');
            const object = await env.BUCKET.get(key);
            
            if (!object) return errorResponse("File not found.", 404);

            const headers = new Headers();
            object.writeHttpMetadata(headers);
            headers.set('etag', object.httpEtag);
            return new Response(object.body, { headers });
        }

        // --- API ROUTES ---
        if (path.startsWith('/api')) {
            try {
                // Ensure DB is ready
                await initDB(env);

                // 1. GET SECRET (Public)
                const secretMatch = path.match(/^\/api\/secret\/([a-zA-Z0-9-]+)$/);
                if (secretMatch && method === 'GET') {
                    const secretId = secretMatch[1];
                    const now = Math.floor(Date.now() / 1000);

                    let secret = await safeSelect(env, "SELECT * FROM secrets WHERE id = ?", secretId);

                    if (!secret) return errorResponse("Transmission not found or ID is invalid.", 404);

                    // --- LOGGING ---
                    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
                    const country = request.cf?.country || 'XX';
                    const city = request.cf?.city || 'Unknown';
                    const ua = request.headers.get('User-Agent') || 'Unknown';
                    const device = ua.includes('Mobile') ? 'Mobile' : 'Desktop';
                    
                    // Fire and forget logging (don't await)
                    ctx.waitUntil(
                        safeQuery(env, 
                            "INSERT INTO access_logs (secret_id, ip_address, country, city, user_agent, device_type) VALUES (?, ?, ?, ?, ?, ?)", 
                            secretId, ip, country, city, ua, device
                        )
                    );

                    // --- ACCESS CONTROL & BURNING ---
                    if (secret.is_active === 0) return errorResponse("Transmission has been burned.", 410);

                    // Check time expiry
                    if (secret.first_viewed_at !== null && secret.expiry_seconds > 0) {
                        if ((now - secret.first_viewed_at) > secret.expiry_seconds) {
                            await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                            return errorResponse("Transmission expired.", 410);
                        }
                    }

                    // Check view limits (Strictly enforce before showing)
                    if (secret.view_count >= secret.max_views) {
                        await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                        return errorResponse("Transmission limit reached.", 410);
                    }

                    // Increment Views
                    if (secret.first_viewed_at === null) {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1, first_viewed_at = ? WHERE id = ?", now, secretId);
                    } else {
                        await safeQuery(env, "UPDATE secrets SET view_count = view_count + 1 WHERE id = ?", secretId);
                    }

                    // Burn check immediately after increment
                    if (secret.view_count + 1 > secret.max_views) {
                        // Mark as burned for NEXT time (current user still sees it now)
                        await safeQuery(env, "UPDATE secrets SET is_active = 0, burned_at = ?, content = NULL WHERE id = ?", now, secretId);
                    }

                    return jsonResponse({
                        type: secret.type,
                        content: secret.content,
                        metadata: JSON.parse(secret.metadata || '{}'),
                        settings: { expiry: secret.expiry_seconds }
                    });
                }

                // 2. SETUP & AUTH
                if (path === '/api/setup' && method === 'POST') {
                    const count = await safeSelect(env, "SELECT COUNT(*) as count FROM admins");
                    if ((count?.count || 0) > 0) return errorResponse("System already initialized.", 403);
                    
                    const { username, password } = await request.json();
                    if (!username || !password) return errorResponse("Missing credentials.", 400);

                    const salt = generateSalt();
                    const hash = await hashPassword(password, salt);
                    await safeQuery(env, "INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)", username, hash, salt);
                    
                    return jsonResponse({ success: true, message: "Admin initialized." }, 201);
                }

                if (path === '/api/login' && method === 'POST') {
                    const { username, password } = await request.json();
                    const user = await safeSelect(env, "SELECT * FROM admins WHERE username = ?", username);
                    
                    if (!user || !(await verifyPassword(user.password_hash, password, user.salt))) {
                        return errorResponse("Invalid credentials.", 401);
                    }

                    const token = generateSessionId();
                    // 24 Hour Session
                    const expires = Math.floor(Date.now()/1000) + 86400; 
                    await safeQuery(env, "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)", token, user.id, expires);
                    
                    return jsonResponse({ token, message: "Authenticated." });
                }

                // --- PROTECTED ROUTES MIDDLEWARE ---
                const authHeader = request.headers.get('Authorization');
                const token = authHeader ? authHeader.split(' ')[1] : null;

                if (!token) return errorResponse("Unauthorized access.", 401);

                const session = await safeSelect(env, 
                    "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?", 
                    token, Math.floor(Date.now() / 1000)
                );

                if (!session) return errorResponse("Session expired or invalid.", 401);

                // 3. DASHBOARD STATS
                if (path === '/api/dashboard' && method === 'GET') {
                    const active = await safeSelect(env, "SELECT COUNT(*) as count FROM secrets WHERE is_active = 1");
                    const burned = await safeSelect(env, "SELECT COUNT(*) as count FROM secrets WHERE is_active = 0");
                    const logs = await safeSelect(env, "SELECT COUNT(*) as count FROM access_logs");
                    
                    return jsonResponse({
                        username: session.username,
                        stats: {
                            active_secrets: active?.count || 0,
                            burned_secrets: burned?.count || 0,
                            total_views: logs?.count || 0
                        }
                    });
                }

                // 4. CREATE SECRET
                if (path === '/api/secret' && method === 'POST') {
                    const body = await request.json();
                    if (!body.content) return errorResponse("Payload cannot be empty.", 400);

                    const id = crypto.randomUUID();
                    const type = body.type || 'text';
                    const metadata = JSON.stringify(body.metadata || {});
                    
                    await safeQuery(env, 
                        "INSERT INTO secrets (id, type, content, metadata, max_views, expiry_seconds) VALUES (?, ?, ?, ?, ?, ?)", 
                        id, type, body.content, metadata, body.max_views || 1, body.expiry_seconds || 0
                    );

                    return jsonResponse({ id, message: "Transmission created." }, 201);
                }

                // 5. LIST SECRETS
                if (path === '/api/secrets-list' && method === 'GET') {
                    const data = await safeSelectAll(env, 
                        "SELECT id, type, created_at, view_count, max_views, is_active FROM secrets ORDER BY created_at DESC LIMIT 50"
                    );
                    return jsonResponse({ secrets: data?.results || [] });
                }

                // 6. VIEW LOGS
                const logMatch = path.match(/^\/api\/secret\/logs\/(.+)$/);
                if (logMatch && method === 'GET') {
                    const logs = await safeSelectAll(env, 
                        "SELECT * FROM access_logs WHERE secret_id = ? ORDER BY viewed_at DESC", 
                        logMatch[1]
                    );
                    return jsonResponse({ logs: logs?.results || [] });
                }

                // 7. DELETE SECRET
                const delMatch = path.match(/^\/api\/secret\/(.+)$/);
                if (delMatch && method === 'DELETE') {
                    const sid = delMatch[1];
                    await safeQuery(env, "DELETE FROM secrets WHERE id = ?", sid);
                    // We also clean up logs for total secrecy
                    await safeQuery(env, "DELETE FROM access_logs WHERE secret_id = ?", sid);
                    return jsonResponse({ message: "Transmission and logs destroyed." });
                }

                return errorResponse("Endpoint not found.", 404);

            } catch (err) {
                console.error("SERVER_ERROR", err);
                return errorResponse("Internal Server Error", 500);
            }
        }

        // --- FALLBACK (SERVE FRONTEND) ---
        // If no API route matched, we serve the frontend
        try {
            return await env.ASSETS.fetch(request);
        } catch (e) {
            return new Response("Service Unavailable", { status: 503 });
        }
    }
};
