-- name: CreateUser :one
INSERT INTO users (
    id,email, full_name, phone_number, role, avatar_url
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL;

-- name: GetUserWithMetadata :one
SELECT 
  u.id,
  u.email,
  u.full_name,
  u.phone_number,
  u.role,
  u.avatar_url,
  u.created_at AS user_created_at,
  u.updated_at AS user_updated_at,
  u.deleted_at,

  m.metadata,
  m.created_at AS metadata_created_at
FROM users u
LEFT JOIN user_metadata m ON m.user_id = u.id
WHERE u.id = $1 AND u.deleted_at IS NULL;


-- name: ListUsers :many
SELECT *
FROM users
WHERE deleted_at IS NULL
  AND (
    LOWER(email) LIKE LOWER('%' || sqlc.narg('search') || '%')
    OR LOWER(full_name) LIKE LOWER('%' || sqlc.narg('search') || '%')
  )
ORDER BY created_at DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

