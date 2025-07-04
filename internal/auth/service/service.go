package service

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"math/big"
	"time"

	"booking-app/internal/auth/dto"
	ar "booking-app/internal/auth/repository"
	db "booking-app/internal/db/sqlc"
	ur "booking-app/internal/user/repository"
	logger "booking-app/pkg"
	"booking-app/pkg/config"
	"booking-app/pkg/constants"
	"booking-app/pkg/helper"
	"booking-app/pkg/util"

	"github.com/google/uuid"
)

type AuthService interface {
	Register(ctx context.Context, req dto.RegisterRequest) error
	Login(ctx context.Context, req dto.LoginRequest) (dto.LoginResponse, error)
	RefreshToken(ctx context.Context, req dto.RequestRefreshToken) (dto.ResponseRefreshToken, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAllOtherDevices(ctx context.Context, refreshToken string) error
	GetJWKS() (any, error)
}

type authService struct {
	authRepo       ar.AuthRepository
	userRepo       ur.UserRepository
	passwordHasher helper.PasswordHasher
	tokenManager   util.TokenManager
	config         *config.AppConfig
}

func NewAuthService(
	authRepo ar.AuthRepository,
	userRepo ur.UserRepository,
	passwordHasher helper.PasswordHasher,
	tokenManager util.TokenManager,
	config *config.AppConfig,
) AuthService {
	return &authService{
		authRepo:       authRepo,
		userRepo:       userRepo,
		passwordHasher: passwordHasher,
		tokenManager:   tokenManager,
		config:         config,
	}
}

func (s *authService) Register(ctx context.Context, req dto.RegisterRequest) error {
	authID := uuid.New()
	userID := uuid.New()

	hashedPassword, err := s.passwordHasher.Hash(req.Password)
	if err != nil {
		return constants.ErrInternalServer
	}

	_, err = s.authRepo.CreateAuthIdentity(ctx, db.CreateAuthIdentityParams{
		ID:           authID,
		UserID:       userID,
		Provider:     "local",
		Email:        req.Email,
		PasswordHash: helper.StringToPGText(hashedPassword),
	})
	if err != nil {
		logger.Log.Errorf("failed to create auth identity: %v", err)
		return err
	}

	// create user after auth identity created
	_, err = s.userRepo.CreateUser(ctx, db.CreateuserWithMetadataParams{
		CreateUserParams: db.CreateUserParams{
			ID:          userID,
			Email:       req.Email,
			FullName:    helper.StringToPGText(req.FullName),
			PhoneNumber: helper.StringToPGText(req.PhoneNumber),
			Role:        "user",
		},
		UserMetadata: db.UserMetadata{
			UserAgent: "testing",
		},
	})
	if err != nil {
		logger.Log.Errorf("failed to create user: %v", err)
		if err := s.authRepo.DeleteAuthIdentityByID(ctx, authID); err != nil {
			logger.Log.Errorf("failed to delete auth identity after failed to create user: %v", err)
		}
		return err
	}

	return nil
}

func (s *authService) Login(ctx context.Context, req dto.LoginRequest) (tokenResponse dto.LoginResponse, err error) {
	userIdentity, err := s.authRepo.GetAuthByEmail(ctx, req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errors.New(constants.SqlNoRows)
			return
		}
		logger.Log.Errorf("failed to get auth by email: %v", err)
		return
	}

	if errCompare := s.passwordHasher.Compare(userIdentity.PasswordHash.String, req.Password); errCompare != nil {
		logger.Log.Errorf("failed to compare password: %v", err)
		err = constants.ErrUnauthorized
		return
	}

	user, err := s.userRepo.GetUserByID(ctx, userIdentity.UserID)
	if err != nil {
		logger.Log.Errorf("failed to get user by id in login: %v", err)
		return
	}
	claims := util.CustomClaims{
		UserID: user.ID.String(),
		Email:  user.Email,
		Role:   user.Role,
	}

	token, claimsRes, err := s.tokenManager.GenerateAccessToken(claims)
	if err != nil {
		logger.Log.Errorf("failed to generate access token: %v", err)
		err = constants.ErrInternalServer
		return
	}

	refreshArg := db.CreateRefreshTokenParams{
		ID:           uuid.New(),
		UserID:       user.ID,
		Device:       helper.StringToPGText("testing"),
		UserAgent:    helper.StringToPGText(req.UserAgent),
		IpAddress:    helper.StringToPGText(req.IpAddress),
		RefreshToken: s.tokenManager.GenerateRefreshToken(),
		ExpiresAt:    helper.ToPGTimestamptz(time.Now().Add(s.config.JWT.RefreshExpiration)),
	}
	refresh, err := s.authRepo.CreateRefreshToken(ctx, refreshArg)
	if err != nil {
		logger.Log.Errorf("failed to create refresh token: %v", err)
		return
	}

	// generate csrf
	csrf, csrfClaims, err := s.tokenManager.GenerateCSRFToken(user.ID)
	if err != nil {
		logger.Log.Errorf("failed to generate csrf token: %v", err)
		return
	}

	tokenResponse = dto.LoginResponse{
		TokenResponse: dto.TokenResponse{
			AccessToken:  token,
			RefreshToken: refresh.RefreshToken,
			CsrfToken:    csrf,
		},
		AccessClaims:  claimsRes,
		RefreshClaims: &refreshArg,
		CsrfClaims:    &csrfClaims,
		User: dto.UserLoginResponse{
			ID:          user.ID,
			Email:       user.Email,
			FullName:    &user.FullName.String,
			PhoneNumber: &user.PhoneNumber.String,
			Role:        user.Role,
			AvatarUrl:   &user.AvatarUrl.String,
			CreatedAt:   user.CreatedAt.Time,
			UpdatedAt:   user.UpdatedAt.Time,
			DeletedAt:   &user.DeletedAt.Time,
		},
	}
	return
}

func (s *authService) RefreshToken(ctx context.Context, req dto.RequestRefreshToken) (tokenResponse dto.ResponseRefreshToken, err error) {
	// cari data RT di db
	rt, err := s.authRepo.GetRefreshTokenByToken(ctx, req.RefreshToken)
	if err != nil {
		err = constants.ErrUnauthorized
		if err == sql.ErrNoRows {
			logger.Log.Warnf("refresh token not found: %v", err)
			return
		}
		logger.Log.Errorf("failed to get refresh token by token: %v", err)
		return
	}

	// cek apa token udah expired
	if rt.ExpiresAt.Time.Before(time.Now()) || rt.RevokedAt.Valid {
		logger.Log.Errorf("refresh token expired: %v", err)
		return tokenResponse, constants.ErrUnauthorized
	}

	// get user dari userID
	user, err := s.userRepo.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return tokenResponse, constants.ErrUnauthorized
	}

	// buat AT baru
	claims := util.CustomClaims{
		UserID: user.ID.String(),
		Email:  user.Email,
		Role:   user.Role,
	}

	token, claimsAccess, err := s.tokenManager.GenerateAccessToken(claims)
	if err != nil {
		logger.Log.Errorf("failed to generate access token in RefreshToken service: %v", err)
		return tokenResponse, constants.ErrUnauthorized
	}

	// buat RT baru
	refreshArg := db.CreateRefreshTokenParams{
		ID:           uuid.New(),
		UserID:       user.ID,
		Device:       helper.StringToPGText("testing"),
		UserAgent:    helper.StringToPGText(req.UserAgent),
		IpAddress:    helper.StringToPGText(req.IpAddress),
		RefreshToken: s.tokenManager.GenerateRefreshToken(),
		ExpiresAt:    helper.ToPGTimestamptz(time.Now().Add(s.config.JWT.RefreshExpiration)),
	}

	refresh, err := s.authRepo.CreateRefreshToken(ctx, refreshArg)
	if err != nil {
		logger.Log.Errorf("failed to create refresh token in RefreshToken service : %v", err)
		return tokenResponse, constants.ErrUnauthorized
	}

	// revoke token lama biar ga bisa di pake ulang
	err = s.authRepo.RevokeRefreshTokenByToken(ctx, rt.RefreshToken)
	if err != nil { // log aja jangan di gagalin total karna bukan main bisnis ga sih?
		logger.Log.Warnf("failed to revoke old refresh token: %v", err)
	}

	// generate csrf
	csrf, csrfClaims, err := s.tokenManager.GenerateCSRFToken(user.ID)
	if err != nil {
		logger.Log.Errorf("failed to generate csrf token: %v", err)
		return
	}

	tokenResponse = dto.ResponseRefreshToken{
		TokenResponse: dto.TokenResponse{
			AccessToken:  token,
			RefreshToken: refresh.RefreshToken,
			CsrfToken:    csrf,
		},
		AccessClaims:  claimsAccess,
		RefreshClaims: &refreshArg,
		CsrfClaims:    &csrfClaims,
	}

	return
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	err := s.authRepo.RevokeRefreshTokenByToken(ctx, refreshToken)
	if err != nil {
		return constants.ErrUnauthorized
	}
	return nil
}

func (s *authService) LogoutAllOtherDevices(ctx context.Context, refreshToken string) error {
	rt, err := s.authRepo.GetRefreshTokenByToken(ctx, refreshToken)
	if err != nil {
		return constants.ErrUnauthorized
	}

	return s.authRepo.RevokeAllRefreshTokenExcept(ctx, db.RevokeAllRefreshTokenExceptParams{
		UserID: rt.UserID,
		ID:     rt.ID,
	})
}

func (s *authService) GetJWKS() (any, error) {
	pubKey := s.tokenManager.GetPublicKey()

	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": "booking-auth-key",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	return map[string]any{
		"keys": []any{jwk},
	}, nil
}
