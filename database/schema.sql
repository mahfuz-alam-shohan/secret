-- SECURE PLATFORM SCHEMA (Updated for Love Letter Feature)

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    type TEXT DEFAULT 'text',              -- 'text' OR 'love-letter'
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
