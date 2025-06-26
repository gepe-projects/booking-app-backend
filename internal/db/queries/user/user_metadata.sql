-- name: CreateUserMetadata :exec
INSERT INTO user_metadata (
  user_id,
  metadata
) VALUES (
  $1,$2
);

-- name: GetUserMetadata :one
SELECT * FROM user_metadata WHERE user_id = $1;