// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

async function initDB(env) {
  if (!env.DB) throw new Error("Database binding 'DB' not found.");
  
  // Create Admins
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );
  `).run();

  // Create Sessions
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (user_id) REFERENCES admins(id)
    );
  `).run();

  // Create Secrets
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS secrets (
      id TEXT PRIMARY KEY,
      content TEXT NOT NULL,
      max_views INTEGER DEFAULT 1,
      expiry_seconds INTEGER DEFAULT 0,
      view_count INTEGER DEFAULT 0,
      first_viewed_at INTEGER DEFAULT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );
  `).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (path.startsWith('/api')) {
      try {
        // --- PUBLIC: VIEW SECRET (GET /api/secret/:id) ---
        // We use regex to match /api/secret/SOME_ID
        const secretMatch = path.match(/^\/api\/secret\/(.+)$/);
        if (secretMatch && method === 'GET') {
            await initDB(env);
            const secretId = secretMatch[1];
            const now = Math.floor(Date.now() / 1000);

            // 1. Fetch Secret
            const secret = await env.DB.prepare("SELECT * FROM secrets WHERE id = ?").bind(secretId).first();

            if (!secret) {
                return new Response(JSON.stringify({ error: "Message not found or expired." }), { status: 404, headers: corsHeaders });
            }

            // 2. Logic: Time Expiry
            // If it has been viewed before, check if time limit passed
            if (secret.first_viewed_at !== null && secret.expiry_seconds > 0) {
                const timeElapsed = now - secret.first_viewed_at;
                if (timeElapsed > secret.expiry_seconds) {
                    // Delete and 404
                    ctx.waitUntil(env.DB.prepare("DELETE FROM secrets WHERE id = ?").bind(secretId).run());
                    return new Response(JSON.stringify({ error: "Message expired." }), { status: 410, headers: corsHeaders });
                }
            }

            // 3. Logic: View Count Limit
            if (secret.view_count >= secret.max_views) {
                 // Should have been deleted, but just in case
                 ctx.waitUntil(env.DB.prepare("DELETE FROM secrets WHERE id = ?").bind(secretId).run());
                 return new Response(JSON.stringify({ error: "Max views reached." }), { status: 410, headers: corsHeaders });
            }

            // 4. Update State (Increment views, set first_viewed_at if needed)
            let updateQuery = "UPDATE secrets SET view_count = view_count + 1";
            const updateArgs = [];

            if (secret.first_viewed_at === null) {
                updateQuery += ", first_viewed_at = ?";
                updateArgs.push(now);
            }
            updateQuery += " WHERE id = ?";
            updateArgs.push(secretId);

            // Execute update
            await env.DB.prepare(updateQuery).bind(...updateArgs).run();

            // 5. Check if we should delete IMMEDIATELY after this view (if views reached max AND no timer set, or if views reached max and timer doesn't matter)
            // Actually, we usually let the timer run out if there is one. 
            // BUT, if max_views is strictly 1, we might want to burn it now? 
            // The requirement says "broken after set time... OR max devices".
            // We will let the next check kill it, or we can clean up now.
            // Let's keep it simple: We return the content now. The NEXT person will get the 410 error.

            return new Response(JSON.stringify({ content: secret.content, settings: { expiry: secret.expiry_seconds } }), { status: 200, headers: corsHeaders });
        }

        // --- ADMIN ROUTES BELOW ---

        // AUTH CHECK HELPER
        const verifyAuth = async (req) => {
            const token = (req.headers.get('Authorization') || '').split(' ')[1];
            if (!token) return null;
            return await env.DB.prepare("SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?").bind(token, Math.floor(Date.now() / 1000)).first();
        };

        // 1. CREATE SECRET (POST /api/secret)
        if (path === '/api/secret' && method === 'POST') {
             const user = await verifyAuth(request);
             if (!user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });

             let body;
             try { body = await request.json(); } catch(e) { throw new Error("Invalid JSON"); }
             const { content, max_views, expiry_seconds } = body;

             if (!content) return new Response(JSON.stringify({ error: "Content is required" }), { status: 400, headers: corsHeaders });

             const id = crypto.randomUUID();
             
             await env.DB.prepare(
                 "INSERT INTO secrets (id, content, max_views, expiry_seconds) VALUES (?, ?, ?, ?)"
             ).bind(id, content, max_views || 1, expiry_seconds || 0).run();

             return new Response(JSON.stringify({ id, message: "Secret created" }), { status: 201, headers: corsHeaders });
        }

        // 2. CHECK SETUP
        if (path === '/api/check-setup' && method === 'GET') {
          await initDB(env);
          const res = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
          return new Response(JSON.stringify({ setupRequired: (res?.count || 0) === 0 }), { status: 200, headers: corsHeaders });
        }

        // 3. SETUP
        if (path === '/api/setup' && method === 'POST') {
          await initDB(env);
          const res = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
          if ((res?.count || 0) > 0) return new Response(JSON.stringify({ error: "Setup completed." }), { status: 403, headers: corsHeaders });

          const body = await request.json();
          if (!body.username || !body.password || body.password.length < 6) return new Response(JSON.stringify({ error: "Invalid input." }), { status: 400, headers: corsHeaders });

          const salt = generateSalt();
          const hash = await hashPassword(body.password, salt);
          await env.DB.prepare("INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)").bind(body.username, hash, salt).run();
          return new Response(JSON.stringify({ message: "Admin created" }), { status: 201, headers: corsHeaders });
        }

        // 4. LOGIN
        if (path === '/api/login' && method === 'POST') {
          const body = await request.json();
          await initDB(env);
          const user = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(body.username).first();
          
          if (!user || !(await verifyPassword(user.password_hash, body.password, user.salt))) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
          }

          const sessionId = generateSessionId();
          await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, user.id, Math.floor(Date.now()/1000) + 86400).run();
          return new Response(JSON.stringify({ token: sessionId, message: "Login successful" }), { status: 200, headers: corsHeaders });
        }

        // 5. DASHBOARD
        if (path === '/api/dashboard' && method === 'GET') {
          const auth = request.headers.get('Authorization');
          const token = auth ? auth.split(' ')[1] : null;
          if (!token) return new Response(JSON.stringify({ error: "Missing Token" }), { status: 401, headers: corsHeaders });

          const session = await env.DB.prepare(
            "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?"
          ).bind(token, Math.floor(Date.now() / 1000)).first();

          if (!session) return new Response(JSON.stringify({ error: "Session Invalid" }), { status: 401, headers: corsHeaders });

          // Get active secrets stats
          const activeSecrets = await env.DB.prepare("SELECT COUNT(*) as count FROM secrets").first();

          return new Response(JSON.stringify({ 
            message: `Welcome back, ${session.username}`,
            stats: { active_sessions: 1, active_secrets: activeSecrets?.count || 0 }
          }), { status: 200, headers: corsHeaders });
        }

        // 6. ULTIMATE RESET
        if (path === '/api/reset' && method === 'DELETE') {
           const token = (request.headers.get('Authorization') || '').split(' ')[1];
           if (!token) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
           
           const session = await env.DB.prepare("SELECT user_id FROM sessions WHERE id = ?").bind(token).first();
           if (!session) return new Response(JSON.stringify({ error: "Invalid Token" }), { status: 401, headers: corsHeaders });

           await env.DB.prepare("DROP TABLE IF EXISTS secrets").run();
           await env.DB.prepare("DROP TABLE IF EXISTS sessions").run();
           await env.DB.prepare("DROP TABLE IF EXISTS admins").run();
           return new Response(JSON.stringify({ message: "System Reset." }), { status: 200, headers: corsHeaders });
        }

        return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: corsHeaders });

      } catch (err) {
        return new Response(JSON.stringify({ error: "Server Error: " + err.message }), { status: 500, headers: corsHeaders });
      }
    }

    try {
      const asset = await env.ASSETS.fetch(request);
      if (asset.status === 404) return new Response("404", { status: 404 });
      return asset;
    } catch (e) { return new Response("Not Found", { status: 404 }); }
  }
};
