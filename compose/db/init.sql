CREATE TABLE users (
    id bigint primary key generated always as identity,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- CREATE TABLE sessions (
--     id bigint primary key generated always as identity,
--     user_id ULID REFERENCES users(id) ON DELETE CASCADE,
--     token TEXT UNIQUE NOT NULL,
--     created_at TIMESTAMPTZ DEFAULT NOW(),
--     expires_at TIMESTAMPTZ NOT NULL,
--     deleted_at TIMESTAMPTZ DEFAULT NULL -- Soft delete timestamp
-- );
--
-- CREATE TABLE password_resets (
--     id bigint primary key generated always as identity,
--     user_id ULID REFERENCES users(id) ON DELETE CASCADE,
--     reset_token TEXT UNIQUE NOT NULL,
--     expires_at TIMESTAMPTZ NOT NULL,
--     created_at TIMESTAMPTZ DEFAULT NOW(),
--     deleted_at TIMESTAMPTZ DEFAULT NULL -- Soft delete timestamp
-- );
--
