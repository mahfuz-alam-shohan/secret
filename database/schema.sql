-- Drop tables to start fresh (includes the new secrets table)
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
    FOREIGN KEY (user_id) REFERENCES admins(id)
);

-- 3. SECRETS (New Table)
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    max_views INTEGER DEFAULT 1,
    expiry_seconds INTEGER DEFAULT 0, -- 0 means 'burn immediately after max_views'
    view_count INTEGER DEFAULT 0,
    first_viewed_at INTEGER DEFAULT NULL, -- Timestamp when first person opened it
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
