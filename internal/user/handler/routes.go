package handler

import "github.com/go-chi/chi/v5"

func RegisterUserRoutes(r chi.Router, h *userHandler) {
	r.Route("/users", func(r chi.Router) {
		r.Post("/", h.CreateUser)
		r.Get("/", h.GetAllUsers)
		r.Get("/{id}", h.GetByID)
	})
}
