-- name: CreateAuthIdentity :one
INSERT INTO auth_identities (
  id, user_id, provider, provider_id, email, password_hash
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAuthByEmail :one
SELECT * FROM auth_identities WHERE email = $1 AND provider = 'local' LIMIT 1;

-- name: GetAuthByProvider :one
SELECT * FROM auth_identities WHERE provider = $1 AND provider_id = $2 LIMIT 1;

-- name: DeleteAuthIdentityByID :exec
DELETE FROM auth_identities WHERE id = $1;