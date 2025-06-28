package handler

import "github.com/go-chi/chi/v5"

func RegisterUserRoutes(r chi.Router, h *authHandler) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/refresh", h.RefreshToken)
		r.Post("/logout", h.Logout)
		r.Post("/logout-all-other-devices", h.LogoutFromOtherDevices)
	})
}
