// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

// Helper to ensure tables exist (Cloudflare Free Tier Friendly: Minimal operations)
async function initDB(env) {
  // We use "IF NOT EXISTS" so this is safe to run.
  // We combine queries to save round trips if possible, but D1 usually handles separate prepares well.
  
  const createAdmins = `
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );
  `;

  const createSessions = `
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (user_id) REFERENCES admins(id)
    );
  `;

  // Execute schema creation
  // We don't batch these to ensure we can catch specific errors if one fails
  await env.DB.prepare(createAdmins).run();
  await env.DB.prepare(createSessions).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS Headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // --- API ROUTES ---

    // 1. CHECK SETUP STATUS (GET /api/check-setup)
    // Called by frontend to see if we need to create the first admin
    if (path === '/api/check-setup' && method === 'GET') {
      try {
        await initDB(env); // Ensure DB exists
        const countResult = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
        const setupRequired = countResult.count === 0;
        return new Response(JSON.stringify({ setupRequired }), { status: 200, headers: corsHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ error: "DB Init failed: " + err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 2. SETUP / REGISTER (POST /api/setup)
    // Only works if no admins exist
    if (path === '/api/setup' && method === 'POST') {
      try {
        await initDB(env);
        
        // SECURITY CHECK: Ensure no admins exist
        const countResult = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
        if (countResult.count > 0) {
          return new Response(JSON.stringify({ error: "Setup already completed. Please login." }), { status: 403, headers: corsHeaders });
        }

        const { username, password } = await request.json();
        
        if (!username || !password || password.length < 6) {
          return new Response(JSON.stringify({ error: "Invalid input. Password min 6 chars." }), { status: 400, headers: corsHeaders });
        }

        const salt = generateSalt();
        const hash = await hashPassword(password, salt);
        
        const result = await env.DB.prepare(
          "INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)"
        ).bind(username, hash, salt).run();

        if (result.success) {
          return new Response(JSON.stringify({ message: "Admin setup complete. You can now login." }), { status: 201, headers: corsHeaders });
        } else {
          throw new Error("DB Insert failed");
        }
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 3. LOGIN (POST /api/login)
    if (path === '/api/login' && method === 'POST') {
      try {
        const { username, password } = await request.json();

        // Check user
        const user = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
        
        if (!user || !(await verifyPassword(user.password_hash, password, user.salt))) {
          return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
        }

        // Clean up old sessions (Basic housekeeping for free tier, removing expired ones)
        // We do this async without awaiting to not block the login response
        ctx.waitUntil(env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Math.floor(Date.now() / 1000)).run());

        // Create Session
        const sessionId = generateSessionId();
        const expiresAt = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // 24 hours

        await env.DB.prepare(
          "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(sessionId, user.id, expiresAt).run();

        return new Response(JSON.stringify({ token: sessionId, message: "Login successful" }), { status: 200, headers: corsHeaders });

      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 4. DASHBOARD DATA (GET /api/dashboard)
    if (path === '/api/dashboard' && method === 'GET') {
      const authHeader = request.headers.get('Authorization');
      const token = authHeader ? authHeader.split(' ')[1] : null;

      if (!token) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
      }

      const session = await env.DB.prepare(
        "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?"
      ).bind(token, Math.floor(Date.now() / 1000)).first();

      if (!session) {
        return new Response(JSON.stringify({ error: "Invalid or expired token" }), { status: 401, headers: corsHeaders });
      }

      let bucketObjects = [];
      try {
         const list = await env.BUCKET.list({ limit: 5 });
         bucketObjects = list.objects.map(o => o.key);
      } catch (e) {
         console.log("Bucket Empty or Error", e);
      }

      return new Response(JSON.stringify({ 
        message: `Welcome back, ${session.username}`,
        bucket_files: bucketObjects,
        stats: {
          active_sessions: 1 
        }
      }), { status: 200, headers: corsHeaders });
    }

    // --- STATIC ASSET SERVING ---
    try {
      return await env.ASSETS.fetch(request);
    } catch (e) {
      return new Response("Not Found", { status: 404 });
    }
  }
};
