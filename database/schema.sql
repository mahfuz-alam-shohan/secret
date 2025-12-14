-- SECURE PLATFORM SCHEMA
-- Optimized for SQLite (Cloudflare D1)

-- Cleanup (Enable only during development or reset)
-- DROP TABLE IF EXISTS access_logs;
-- DROP TABLE IF EXISTS secrets;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS admins;

-- 1. ADMINISTRATORS
-- Stores authenticated admin users. Passwords must be hashed.
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- 2. ACTIVE SESSIONS
-- Tracks valid login tokens.
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
);

-- 3. SECRETS (TRANSMISSIONS)
-- Core payload data.
-- 'content' is nullable to allow "burning" (removing data) while keeping the record.
-- 'is_active' determines if the secret can be viewed.
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    type TEXT DEFAULT 'text',              -- 'text' or 'proposal'
    content TEXT,                          -- The sensitive payload
    metadata TEXT DEFAULT '{}',            -- JSON extra data
    max_views INTEGER DEFAULT 1,           -- How many times it can be opened
    expiry_seconds INTEGER DEFAULT 0,      -- 0 = No timer (burns on view count only)
    view_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,           -- 1 = Live, 0 = Destroyed
    burned_at INTEGER DEFAULT NULL,        -- Timestamp of destruction
    first_viewed_at INTEGER DEFAULT NULL,  -- Timer starts here
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- 4. ACCESS TELEMETRY
-- Logs who accessed the secrets. 
-- Note: GDPR/Privacy compliance may require periodic purging of this table.
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT NOT NULL,
    ip_address TEXT,
    country TEXT,
    city TEXT,
    user_agent TEXT,
    device_type TEXT,
    viewed_at INTEGER DEFAULT (strftime('%s', 'now'))
);
