DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS shift_logs;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT CHECK(role IN ('Whitelist Manager', 'Shift Monitor')) NOT NULL
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    device_name TEXT DEFAULT 'Unknown Device',
    status TEXT CHECK(status IN ('green', 'yellow', 'red')) DEFAULT 'yellow',
    is_blocked INTEGER DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE shift_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    handled_by TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    notes TEXT
);

-- Seed initial test accounts (Password for both accounts is: password123)
INSERT INTO users (username, password_hash, email, role) VALUES 
('manager', 'scrypt:32768:8:1$hgrv7cMGFUOGDIjr$5c7825352039fa5bf13a0498f314d504d79d28ca4b649691bfe2082337967293e7833e07ab823e9266cf74546b27b57cf8f8aba309013e85420061ccc92ca04e', 'janjerick3002@gmail.com', 'Whitelist Manager'),
('staff', 'scrypt:32768:8:1$hgrv7cMGFUOGDIjr$5c7825352039fa5bf13a0498f314d504d79d28ca4b649691bfe2082337967293e7833e07ab823e9266cf74546b27b57cf8f8aba309013e85420061ccc92ca04e', 'staff@netguardian.local', 'Shift Monitor');

