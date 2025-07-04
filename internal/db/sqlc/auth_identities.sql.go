// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: auth_identities.sql

package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const createAuthIdentity = `-- name: CreateAuthIdentity :one
INSERT INTO auth_identities (
  id, user_id, provider, provider_id, email, password_hash
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, provider, provider_id, email, password_hash, created_at
`

type CreateAuthIdentityParams struct {
	ID           uuid.UUID   `json:"id"`
	UserID       uuid.UUID   `json:"user_id"`
	Provider     string      `json:"provider"`
	ProviderID   pgtype.Text `json:"provider_id"`
	Email        string      `json:"email"`
	PasswordHash pgtype.Text `json:"password_hash"`
}

func (q *Queries) CreateAuthIdentity(ctx context.Context, arg CreateAuthIdentityParams) (AuthIdentity, error) {
	row := q.db.QueryRow(ctx, createAuthIdentity,
		arg.ID,
		arg.UserID,
		arg.Provider,
		arg.ProviderID,
		arg.Email,
		arg.PasswordHash,
	)
	var i AuthIdentity
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Provider,
		&i.ProviderID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return i, err
}

const deleteAuthIdentityByID = `-- name: DeleteAuthIdentityByID :exec
DELETE FROM auth_identities WHERE id = $1
`

func (q *Queries) DeleteAuthIdentityByID(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, deleteAuthIdentityByID, id)
	return err
}

const getAuthByEmail = `-- name: GetAuthByEmail :one
SELECT id, user_id, provider, provider_id, email, password_hash, created_at FROM auth_identities WHERE email = $1 AND provider = 'local' LIMIT 1
`

func (q *Queries) GetAuthByEmail(ctx context.Context, email string) (AuthIdentity, error) {
	row := q.db.QueryRow(ctx, getAuthByEmail, email)
	var i AuthIdentity
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Provider,
		&i.ProviderID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return i, err
}

const getAuthByProvider = `-- name: GetAuthByProvider :one
SELECT id, user_id, provider, provider_id, email, password_hash, created_at FROM auth_identities WHERE provider = $1 AND provider_id = $2 LIMIT 1
`

type GetAuthByProviderParams struct {
	Provider   string      `json:"provider"`
	ProviderID pgtype.Text `json:"provider_id"`
}

func (q *Queries) GetAuthByProvider(ctx context.Context, arg GetAuthByProviderParams) (AuthIdentity, error) {
	row := q.db.QueryRow(ctx, getAuthByProvider, arg.Provider, arg.ProviderID)
	var i AuthIdentity
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Provider,
		&i.ProviderID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return i, err
}
