package middleware

import (
	"net/http"

	"booking-app/pkg/util"
)

type Middleware interface {
	AuthMiddleware(next http.Handler) http.Handler
}

type middleware struct {
	tokenManager util.TokenManager
}

func NewMiddleware(tm util.TokenManager) Middleware {
	return &middleware{
		tokenManager: tm,
	}
}
