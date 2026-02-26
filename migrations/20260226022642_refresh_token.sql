-- Refresh token + session tables (for rotation/revocation)

-- Ensure we can generate UUIDs
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Logical session per device/app install/browser profile.
-- A user can have multiple sessions.
CREATE TABLE IF NOT EXISTS auth_sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users ("userId") ON DELETE CASCADE,

    -- DPoP binding (cnf.jkt). Nullable for Step1/Step2, filled for Step2/Step3.
    dpop_jkt     text,

    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_revoked_at ON auth_sessions(revoked_at);

-- Refresh tokens are opaque to clients, but we store only a hash.
-- We keep each rotation as a new row; old rows are marked used/revoked and linked.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,

    -- Store a hash (e.g., SHA-256) of the opaque refresh token.
    token_hash    bytea NOT NULL,

    issued_at     timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,

    -- Rotation / audit
    used_at       timestamptz,
    revoked_at    timestamptz,

    -- Points to the newer token minted when this one was used (rotation).
    replaced_by   uuid REFERENCES refresh_tokens(id)
);

-- Token hash must be unique.
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Lookups by session, cleanup by expiry.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Optional: ensure only one "current" refresh token per session at a time.
-- A token is considered current when it is not revoked and not replaced.
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_tokens_current_per_session
ON refresh_tokens(session_id)
WHERE revoked_at IS NULL AND replaced_by IS NULL;
