package middleware

import (
	"context"
	"net/http"
	"strings"

	"booking-app/pkg/constants"
	"booking-app/pkg/helper"
)

func (mw *middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. check if user is authenticated
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			helper.WriteError(w, http.StatusUnauthorized, map[string]any{
				"error": constants.ErrUnauthorized.Error(),
			})
			return
		}

		token := strings.Split(authorization, "Bearer ")[1]
		if token == "" {
			helper.WriteError(w, http.StatusUnauthorized, map[string]any{
				"error": constants.ErrUnauthorized.Error(),
			})
			return
		}

		claims, err := mw.tokenManager.ParseAccessToken(token)
		if err != nil {
			helper.WriteError(w, http.StatusUnauthorized, map[string]any{
				"error": constants.ErrUnauthorized.Error(),
			})
			return
		}

		// set claims to context
		ctx := context.WithValue(r.Context(), constants.CtxUser, claims)
		r = r.WithContext(ctx)

		// 2. if user is authenticated, call next
		next.ServeHTTP(w, r)
	})
}
