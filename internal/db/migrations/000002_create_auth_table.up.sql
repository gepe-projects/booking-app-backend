-- Users Auth Data
CREATE TABLE IF NOT EXISTS auth_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL, -- FK to users(id)
    provider VARCHAR(20) NOT NULL, -- 'local' | 'google'
    provider_id TEXT, -- Google sub ID
    email VARCHAR(255) NOT NULL,
    password_hash TEXT, -- null if oauth
    created_at TIMESTAMPTZ DEFAULT now(),

    UNIQUE (provider, provider_id),
    UNIQUE (provider, email)
);

-- Refresh Token Table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL, -- FK to users(id)
    device TEXT,
    user_agent TEXT,
    ip_address TEXT,
    refresh_token TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_identities_user_id ON auth_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_identities_email ON auth_identities(email);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
