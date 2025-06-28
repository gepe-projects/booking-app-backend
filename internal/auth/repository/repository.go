package repository

import (
	"context"

	db "booking-app/internal/db/sqlc"

	"github.com/google/uuid"
)

type AuthRepository interface {
	CreateAuthIdentity(ctx context.Context, arg db.CreateAuthIdentityParams) (db.AuthIdentity, error)
	GetAuthByEmail(ctx context.Context, email string) (db.AuthIdentity, error)
	GetAuthByProvider(ctx context.Context, arg db.GetAuthByProviderParams) (db.AuthIdentity, error)
	DeleteAuthIdentityByID(ctx context.Context, id uuid.UUID) error

	CreateRefreshToken(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
	GetRefreshTokenByToken(ctx context.Context, refreshToken string) (db.RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, id uuid.UUID) (db.RefreshToken, error)
	GetActiveRefreshTokensByUserID(ctx context.Context, userID uuid.UUID) ([]db.RefreshToken, error)

	RevokeRefreshTokenByToken(ctx context.Context, refreshToken string) error
	RevokeAllRefreshTokenExcept(ctx context.Context, arg db.RevokeAllRefreshTokenExceptParams) error
	RevokeAllRefreshTokensByUser(ctx context.Context, userID uuid.UUID) error

	DeleteExpiredRefreshTokenByUserID(ctx context.Context, userID uuid.UUID) error
}

type authRepository struct {
	store db.Store
}

func NewAuthRepository(store db.Store) AuthRepository {
	return &authRepository{
		store: store,
	}
}

func (ar *authRepository) CreateAuthIdentity(ctx context.Context, arg db.CreateAuthIdentityParams) (db.AuthIdentity, error) {
	return ar.store.CreateAuthIdentity(ctx, arg)
}

func (ar *authRepository) GetAuthByEmail(ctx context.Context, email string) (db.AuthIdentity, error) {
	return ar.store.GetAuthByEmail(ctx, email)
}

func (ar *authRepository) GetAuthByProvider(ctx context.Context, arg db.GetAuthByProviderParams) (db.AuthIdentity, error) {
	return ar.store.GetAuthByProvider(ctx, arg)
}

func (ar *authRepository) DeleteAuthIdentityByID(ctx context.Context, id uuid.UUID) error {
	return ar.store.DeleteAuthIdentityByID(ctx, id)
}

func (ar *authRepository) CreateRefreshToken(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error) {
	return ar.store.CreateRefreshToken(ctx, arg)
}

func (ar *authRepository) GetRefreshTokenByToken(ctx context.Context, token string) (db.RefreshToken, error) {
	return ar.store.GetRefreshTokenByToken(ctx, token)
}

func (ar *authRepository) GetRefreshTokenByID(ctx context.Context, id uuid.UUID) (db.RefreshToken, error) {
	return ar.store.GetRefreshTokenByID(ctx, id)
}

func (ar *authRepository) GetActiveRefreshTokensByUserID(ctx context.Context, userID uuid.UUID) ([]db.RefreshToken, error) {
	return ar.store.GetActiveRefreshTokensByUserID(ctx, userID)
}

func (ar *authRepository) RevokeRefreshTokenByToken(ctx context.Context, refreshToken string) error {
	return ar.store.RevokeRefreshTokenByToken(ctx, refreshToken)
}

func (ar *authRepository) RevokeAllRefreshTokenExcept(ctx context.Context, arg db.RevokeAllRefreshTokenExceptParams) error {
	return ar.store.RevokeAllRefreshTokenExcept(ctx, arg)
}

func (ar *authRepository) RevokeAllRefreshTokensByUser(ctx context.Context, userID uuid.UUID) error {
	return ar.store.RevokeAllRefreshTokensByUser(ctx, userID)
}

func (ar *authRepository) DeleteExpiredRefreshTokenByUserID(ctx context.Context, userID uuid.UUID) error {
	return ar.store.DeleteExpiredRefreshTokenByUserID(ctx, userID)
}
