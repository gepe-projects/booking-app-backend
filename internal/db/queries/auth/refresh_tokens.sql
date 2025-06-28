-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
  id, user_id, device, user_agent, ip_address, refresh_token, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetRefreshTokenByToken :one
SELECT * FROM refresh_tokens
WHERE refresh_token = $1
LIMIT 1;

-- name: RevokeRefreshTokenByToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE refresh_token = $1;

-- name: RevokeAllRefreshTokenExcept :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE user_id = $1
  AND id != $2
  AND revoked_at IS NULL;

-- name: RevokeAllRefreshTokensByUser :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE user_id = $1
  AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokenByUserID :exec
DELETE FROM refresh_tokens
WHERE user_id = $1
  AND expires_at < NOW();

-- name: GetActiveRefreshTokensByUserID :many
SELECT * FROM refresh_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: GetRefreshTokenByID :one
SELECT * FROM refresh_tokens
WHERE id = $1
LIMIT 1;
