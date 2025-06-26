package user

import (
	"time"

	"github.com/google/uuid"
)

type CreateUserRequest struct {
	ID          uuid.UUID
	Email       string `json:"email" validate:"required,email"`
	FullName    string `json:"full_name"`
	PhoneNumber string `json:"phone_number"`
	AvatarURL   string `json:"avatar_url"`
}

type ListUsersRequest struct {
	Search string `validate:"omitempty"`
	Offset int32  `validate:"omitempty,gte=0"`
	Limit  int32  `validate:"omitempty,gte=1,lte=100"`
}

type UserResponse struct {
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
