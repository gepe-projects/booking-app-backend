package service

import (
	"context"
	"time"

	db "booking-app/internal/db/sqlc"
	dto "booking-app/internal/user/dto"
	ur "booking-app/internal/user/repository"
	logger "booking-app/pkg"
	"booking-app/pkg/helper"

	"github.com/google/uuid"
)

type UserService interface {
	CreateUser(ctx context.Context, req dto.RegisterUserRequest) (dto.UserResponse, error)
	ListUsers(ctx context.Context, arg db.ListUsersParams) ([]dto.UserResponse, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (dto.UserResponse, error)
	GetUserWithMetadata(ctx context.Context, id uuid.UUID) (db.GetUserWithMetadataRow, error)
}

type userService struct {
	userRepo ur.UserRepository
}

func NewUserService(userRepo ur.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (us *userService) CreateUser(ctx context.Context, req dto.RegisterUserRequest) (dto.UserResponse, error) {
	arg := db.CreateuserWithMetadataParams{
		CreateUserParams: db.CreateUserParams{
			ID:          req.ID,
			Email:       req.Email,
			FullName:    helper.StringToPGTextValid(req.FullName),
			PhoneNumber: helper.StringToPGText(req.PhoneNumber),
			Role:        "user",
			AvatarUrl:   helper.StringToPGText(req.AvatarURL),
		},
		UserMetadata: db.UserMetadata{
			UserAgent: "",
		},
	}

	user, err := us.userRepo.CreateUser(ctx, arg)
	if err != nil {
		logger.Log.Errorf("failed to create user with metadata: %v", err)
		return dto.UserResponse{}, err
	}

	response := dto.UserResponse{
		ID:          user.ID,
		Email:       user.Email,
		FullName:    helper.PGTextToStringOrNil(user.FullName),
		PhoneNumber: helper.PGTextToStringOrNil(user.PhoneNumber),
		Role:        user.Role,
		AvatarUrl:   helper.PGTextToStringOrNil(user.AvatarUrl),
		CreatedAt:   helper.PGTimestamptzToTime(user.CreatedAt),
		UpdatedAt:   helper.PGTimestamptzToTime(user.UpdatedAt),
		DeletedAt:   helper.PGTimestamptzToTimePtr(user.DeletedAt),
	}

	return response, nil
}

func (us *userService) GetUserByID(ctx context.Context, id uuid.UUID) (dto.UserResponse, error) {
	result, err := us.userRepo.GetUserByID(ctx, id)
	if err != nil {
		logger.Log.Errorf("failed to get user by id: %v", err)
		return dto.UserResponse{}, err
	}

	time.Sleep(5 * time.Second)

	response := dto.UserResponse{
		ID:          result.ID,
		Email:       result.Email,
		FullName:    helper.PGTextToStringOrNil(result.FullName),
		PhoneNumber: helper.PGTextToStringOrNil(result.PhoneNumber),
		Role:        result.Role,
		AvatarUrl:   helper.PGTextToStringOrNil(result.AvatarUrl),
		CreatedAt:   helper.PGTimestamptzToTime(result.CreatedAt),
		UpdatedAt:   helper.PGTimestamptzToTime(result.UpdatedAt),
		DeletedAt:   helper.PGTimestamptzToTimePtr(result.DeletedAt),
	}

	return response, nil
}

func (us *userService) GetUserByEmail(ctx context.Context, email string) (dto.UserResponse, error) {
	result, err := us.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		logger.Log.Errorf("failed to get user by email: %v", err)
		return dto.UserResponse{}, err
	}

	response := dto.UserResponse{
		ID:          result.ID,
		Email:       result.Email,
		FullName:    helper.PGTextToStringOrNil(result.FullName),
		PhoneNumber: helper.PGTextToStringOrNil(result.PhoneNumber),
		Role:        result.Role,
		AvatarUrl:   helper.PGTextToStringOrNil(result.AvatarUrl),
		CreatedAt:   helper.PGTimestamptzToTime(result.CreatedAt),
		UpdatedAt:   helper.PGTimestamptzToTime(result.UpdatedAt),
		DeletedAt:   helper.PGTimestamptzToTimePtr(result.DeletedAt),
	}

	return response, nil
}

func (us *userService) GetUserWithMetadata(ctx context.Context, id uuid.UUID) (db.GetUserWithMetadataRow, error) {
	return us.userRepo.GetUserWithMetadata(ctx, id)
}

func (us *userService) ListUsers(ctx context.Context, arg db.ListUsersParams) ([]dto.UserResponse, error) {
	result, err := us.userRepo.ListUsers(ctx, arg)
	if err != nil {
		logger.Log.Errorf("failed to get list users: %v", err)
		return nil, err
	}

	var response []dto.UserResponse
	for _, item := range result {
		response = append(response, dto.UserResponse{
			ID:          item.ID,
			Email:       item.Email,
			FullName:    helper.PGTextToStringOrNil(item.FullName),
			PhoneNumber: helper.PGTextToStringOrNil(item.PhoneNumber),
			Role:        item.Role,
			AvatarUrl:   helper.PGTextToStringOrNil(item.AvatarUrl),
			CreatedAt:   helper.PGTimestamptzToTime(item.CreatedAt),
			UpdatedAt:   helper.PGTimestamptzToTime(item.UpdatedAt),
			DeletedAt:   helper.PGTimestamptzToTimePtr(item.DeletedAt),
		})
	}

	return response, nil
}
