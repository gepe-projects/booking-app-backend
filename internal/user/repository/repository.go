package user

import (
	"context"

	db "booking-app/internal/db/sqlc"
	logger "booking-app/pkg"

	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, req db.CreateuserWithMetadataParams) (db.User, error)
	ListUsers(ctx context.Context, req db.ListUsersParams) ([]db.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserWithMetadata(ctx context.Context, id uuid.UUID) (db.GetUserWithMetadataRow, error)
}

type userRepository struct {
	store db.Store
}

func NewUserRepository(store db.Store) UserRepository {
	return &userRepository{
		store: store,
	}
}

func (ur *userRepository) CreateUser(ctx context.Context, req db.CreateuserWithMetadataParams) (user db.User, err error) {
	result, err := ur.store.CreateUserWithMetadata(ctx, req)
	if err != nil {
		logger.Log.Errorf("Err Repository create user: %v", err)
		return
	}
	user = result.User
	return
}

func (ur *userRepository) ListUsers(ctx context.Context, req db.ListUsersParams) (users []db.User, err error) {
	users, err = ur.store.ListUsers(ctx, req)
	if err != nil {
		logger.Log.Errorf("Err Repository list users: %v", err)
		return
	}
	return
}

func (ur *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (user db.User, err error) {
	user, err = ur.store.GetUserByID(ctx, id)
	if err != nil {
		logger.Log.Errorf("Err Repository get user by id: %v", err)
		return
	}
	return
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (user db.User, err error) {
	user, err = ur.store.GetUserByEmail(ctx, email)
	if err != nil {
		logger.Log.Errorf("Err Repository get user by email: %v", err)
		return
	}
	return
}

func (ur *userRepository) GetUserWithMetadata(ctx context.Context, id uuid.UUID) (user db.GetUserWithMetadataRow, err error) {
	user, err = ur.store.GetUserWithMetadata(ctx, id)
	if err != nil {
		logger.Log.Errorf("Err Repository get user by id: %v", err)
		return
	}
	return
}
