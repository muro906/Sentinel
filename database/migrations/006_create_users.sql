CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(200) NOT NULL,
    email           TEXT,
    role            VARCHAR(20)  NOT NULL CHECK (role IN ('analyst','senior_analyst','admin')),
    is_active       BOOLEAN DEFAULT TRUE,
    status          TEXT NOT NULL DEFAULT 'approved',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login      TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status   ON users(status);

-- Default admin — password: sentinel_dev
-- CHANGE before any real deployment.
-- New hash: python -c "from passlib.context import CryptContext; print(CryptContext(['bcrypt']).hash('your_password'))"
INSERT INTO users (username, hashed_password, role, status) VALUES
  ('admin@sentinel',
   '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
   'admin',
   'approved')
ON CONFLICT (username) DO NOTHING;