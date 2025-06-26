-- Table: users (global scope)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    phone_number VARCHAR(20),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    avatar_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT valid_role CHECK (role IN ('user', 'superadmin', 'tenant_admin', 'tenant_staff'))
);

-- Table: user_metadata (optional, JSONB flexible info)
CREATE TABLE IF NOT EXISTS user_metadata (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT now(),

    CONSTRAINT valid_metadata CHECK (jsonb_typeof(metadata) = 'object' OR metadata IS NULL)
);

-- Index for faster lookup (optional)
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_metadata_user_id ON user_metadata(user_id);