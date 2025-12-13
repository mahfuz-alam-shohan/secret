// src/index.js
import { generateSalt, hashPassword, verifyPassword, generateSessionId } from './security.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS Headers for frontend access
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // --- API ROUTES ---

    // 1. REGISTER (POST /api/register)
    if (path === '/api/register' && method === 'POST') {
      try {
        const { username, password } = await request.json();
        
        // Basic Validation
        if (!username || !password || password.length < 6) {
          return new Response(JSON.stringify({ error: "Invalid input. Password min 6 chars." }), { status: 400, headers: corsHeaders });
        }

        // Check if user exists
        const existing = await env.DB.prepare("SELECT id FROM admins WHERE username = ?").bind(username).first();
        if (existing) {
          return new Response(JSON.stringify({ error: "Username taken" }), { status: 409, headers: corsHeaders });
        }

        // Hash and Store
        const salt = generateSalt();
        const hash = await hashPassword(password, salt);
        
        const result = await env.DB.prepare(
          "INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)"
        ).bind(username, hash, salt).run();

        if (result.success) {
          return new Response(JSON.stringify({ message: "Admin created successfully" }), { status: 201, headers: corsHeaders });
        } else {
          throw new Error("DB Insert failed");
        }
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 2. LOGIN (POST /api/login)
    if (path === '/api/login' && method === 'POST') {
      try {
        const { username, password } = await request.json();

        const user = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
        
        if (!user || !(await verifyPassword(user.password_hash, password, user.salt))) {
          return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: corsHeaders });
        }

        // Create Session
        const sessionId = generateSessionId();
        // Expires in 24 hours
        const expiresAt = Math.floor(Date.now() / 1000) + (24 * 60 * 60);

        await env.DB.prepare(
          "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(sessionId, user.id, expiresAt).run();

        return new Response(JSON.stringify({ token: sessionId, message: "Login successful" }), { status: 200, headers: corsHeaders });

      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 3. DASHBOARD DATA (GET /api/dashboard) - Protected Route
    if (path === '/api/dashboard' && method === 'GET') {
      const authHeader = request.headers.get('Authorization');
      const token = authHeader ? authHeader.split(' ')[1] : null;

      if (!token) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
      }

      // Validate Session
      const session = await env.DB.prepare(
        "SELECT sessions.*, admins.username FROM sessions JOIN admins ON sessions.user_id = admins.id WHERE sessions.id = ? AND sessions.expires_at > ?"
      ).bind(token, Math.floor(Date.now() / 1000)).first();

      if (!session) {
        return new Response(JSON.stringify({ error: "Invalid or expired token" }), { status: 401, headers: corsHeaders });
      }

      // Check R2 Bucket (Example Usage)
      // List files in the 'secret' bucket just to show it works
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
          active_sessions: 1 // Placeholder for real stats
        }
      }), { status: 200, headers: corsHeaders });
    }

    // Default 404
    return new Response("Not Found", { status: 404, headers: corsHeaders });
  }
};
