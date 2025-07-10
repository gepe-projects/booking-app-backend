package dto

import (
	"time"

	db "booking-app/internal/db/sqlc"
	"booking-app/pkg/util"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type LoginRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required"`
	UserAgent    string
	IpAddress    string
	RefreshToken string
	ExpiresAt    time.Duration
}

type LoginResponse struct {
	TokenResponse
	User          UserLoginResponse            `json:"user"`
	AccessClaims  *util.CustomClaims           `json:"access_claims,omitempty"`
	RefreshClaims *db.CreateRefreshTokenParams `json:"refresh_claims,omitempty"`
	CsrfClaims    *jwt.RegisteredClaims        `json:"csrf_claims,omitempty"`
}

type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=6"`
	FullName    string `json:"full_name"`
	PhoneNumber string `json:"phone_number"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	CsrfToken    string `json:"csrf_token,omitempty"`
}

type UserLoginResponse struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	FullName    *string    `json:"full_name,omitempty"`
	PhoneNumber *string    `json:"phone_number,omitempty"`
	Role        string     `json:"role"`
	AvatarUrl   *string    `json:"avatar_url,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	Metadata    any        `json:"metadata,omitempty"`
}

type RequestRefreshToken struct {
	UserAgent    string
	IpAddress    string
	RefreshToken string `json:"refresh_token" validate:"required,uuid"`
}

type ResponseRefreshToken struct {
	TokenResponse
	AccessClaims  *util.CustomClaims           `json:"access_claims,omitempty"`
	RefreshClaims *db.CreateRefreshTokenParams `json:"refresh_claims,omitempty"`
	CsrfClaims    *jwt.RegisteredClaims
}

type RequestLogout struct {
	RefreshToken string `json:"refresh_token" validate:"required,uuid"`
}
