package handler

import (
	"booking-app/internal/auth/service"
	"booking-app/pkg/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

type authRoutes struct {
	mw          middleware.Middleware
	validate    *validator.Validate
	authService service.AuthService
}

func NewAuthRoutes(
	mw middleware.Middleware,
	validate *validator.Validate,
	authService service.AuthService,
) *authRoutes {
	return &authRoutes{
		validate:    validate,
		authService: authService,
		mw:          mw,
	}
}

func (ar *authRoutes) MountAuthRoutes(r chi.Router) {
	h := newAuthHandler(ar.validate, ar.authService)

	r.Route("/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(ar.mw.AuthMiddleware)
			r.Get("/me", h.Me)
			r.Post("/logout", h.Logout)
			r.Post("/logout-all-other-devices", h.LogoutFromOtherDevices)
		})

		r.Group(func(r chi.Router) {
			r.Post("/register", h.Register)
			r.Post("/login", h.Login)
			r.Post("/refresh", h.RefreshToken)

			r.Get("/.well-known/jwks.json", h.GetJWKS)
		})
	})
}
