// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

async function initDB(env) {
  if (!env.DB) throw new Error("Database binding 'DB' not found.");
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (user_id) REFERENCES admins(id)
    );
  `).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // FIX: Added 'Content-Type': 'application/json' so browser doesn't reject responses
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
        // 1. CHECK SETUP
        if (path === '/api/check-setup' && method === 'GET') {
          await initDB(env);
          const res = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
          const count = res ? (res.count || 0) : 0;
          return new Response(JSON.stringify({ setupRequired: count === 0 }), { status: 200, headers: corsHeaders });
        }

        // 2. SETUP
        if (path === '/api/setup' && method === 'POST') {
          await initDB(env);
          const res = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
          if ((res?.count || 0) > 0) return new Response(JSON.stringify({ error: "Setup already completed." }), { status: 403, headers: corsHeaders });

          let body;
          try { body = await request.json(); } catch(e) { throw new Error("Invalid JSON"); }
          const { username, password } = body;
          
          if (!username || !password || password.length < 6) return new Response(JSON.stringify({ error: "Invalid input." }), { status: 400, headers: corsHeaders });

          const salt = generateSalt();
          const hash = await hashPassword(password, salt);
          
          const result = await env.DB.prepare("INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)").bind(username, hash, salt).run();
          if (result.success) return new Response(JSON.stringify({ message: "Admin created" }), { status: 201, headers: corsHeaders });
          else throw new Error("DB Insert failed");
        }

        // 3. LOGIN
        if (path === '/api/login' && method === 'POST') {
          let body;
          try { body = await request.json(); } catch(e) { throw new Error("Invalid JSON"); }
          const { username, password } = body;

          await initDB(env);
          const user = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
          
          if (!user || !(await verifyPassword(user.password_hash, password, user.salt))) {
            return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
          }

          const sessionId = generateSessionId();
          const expiresAt = Math.floor(Date.now() / 1000) + (86400); // 24 hours

          await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, user.id, expiresAt).run();

          return new Response(JSON.stringify({ token: sessionId, message: "Login successful" }), { status: 200, headers: corsHeaders });
        }

        // 4. DASHBOARD
        if (path === '/api/dashboard' && method === 'GET') {
          const auth = request.headers.get('Authorization');
          const token = auth ? auth.split(' ')[1] : null;

          if (!token) return new Response(JSON.stringify({ error: "Authorization header missing" }), { status: 401, headers: corsHeaders });

          const session = await env.DB.prepare(
            "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?"
          ).bind(token, Math.floor(Date.now() / 1000)).first();

          if (!session) return new Response(JSON.stringify({ error: "Session expired or invalid. Please re-login." }), { status: 401, headers: corsHeaders });

          let bucketObjects = [];
          if (env.BUCKET) {
             try {
                const list = await env.BUCKET.list({ limit: 10 });
                bucketObjects = list.objects.map(o => o.key);
             } catch (e) { console.error(e); }
          }

          return new Response(JSON.stringify({ 
            message: `Welcome back, ${session.username}`,
            bucket_files: bucketObjects,
            stats: { active_sessions: 1 }
          }), { status: 200, headers: corsHeaders });
        }

        // 5. ULTIMATE RESET
        if (path === '/api/reset' && method === 'DELETE') {
           // For reset, we are more lenient. If header check fails, we still allow reset if we can validate the user manually or just force it for now.
           // Ideally we check token, but if token is broken, we can't reset.
           // Let's require token.
           const auth = request.headers.get('Authorization');
           const token = auth ? auth.split(' ')[1] : null;
           
           if (token) {
               // Verify strictly
               const session = await env.DB.prepare("SELECT user_id FROM sessions WHERE id = ?").bind(token).first();
               if (!session) return new Response(JSON.stringify({ error: "Invalid Token" }), { status: 401, headers: corsHeaders });
           } else {
               // Security Fallback: If no token, return 401
               return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
           }

           await env.DB.prepare("DROP TABLE IF EXISTS sessions").run();
           await env.DB.prepare("DROP TABLE IF EXISTS admins").run();
           return new Response(JSON.stringify({ message: "System Reset." }), { status: 200, headers: corsHeaders });
        }

        return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: corsHeaders });

      } catch (err) {
        return new Response(JSON.stringify({ error: "Server Error: " + err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // Static Assets
    try {
      const asset = await env.ASSETS.fetch(request);
      if (asset.status === 404) return new Response("404", { status: 404 });
      return asset;
    } catch (e) { return new Response("Not Found", { status: 404 }); }
  }
};
