-- Drop tables to start fresh with new architecture
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS admins;

-- 1. ADMINS
CREATE TABLE admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- 2. SESSIONS
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
);

-- 3. SECRETS (Updated for Rich Content & Soft Delete)
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    type TEXT DEFAULT 'text',              -- 'text', 'proposal', 'threat', 'party'
    content TEXT,                          -- Main encrypted content (can be NULL if burned)
    metadata TEXT DEFAULT '{}',            -- JSON: { backgroundUrl, musicUrl, animationSpeed, etc. }
    max_views INTEGER DEFAULT 1,
    expiry_seconds INTEGER DEFAULT 0,      -- 0 means 'burn immediately after max_views'
    view_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,           -- 1 = Active, 0 = Burned/Expired
    burned_at INTEGER DEFAULT NULL,        -- Timestamp when it was destroyed
    first_viewed_at INTEGER DEFAULT NULL,  -- Timestamp when first person opened it
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- 4. ACCESS LOGS (New Surveillance)
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id TEXT NOT NULL,
    ip_address TEXT,
    country TEXT,
    city TEXT,
    user_agent TEXT,
    device_type TEXT,
    viewed_at INTEGER DEFAULT (strftime('%s', 'now'))
    -- Note: We do NOT cascade delete here because we want logs even after secret burns
);
