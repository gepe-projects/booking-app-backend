package handler

import (
	"booking-app/internal/user/service"
	"booking-app/pkg/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

type userRoutes struct {
	validate    *validator.Validate
	userService service.UserService
}

func NewUserRoutes(
	mw middleware.Middleware,
	validate *validator.Validate,
	userService service.UserService,
) *userRoutes {
	return &userRoutes{
		validate:    validate,
		userService: userService,
	}
}

func (ur *userRoutes) MountUserRoutes(r chi.Router) {
	h := newUserHandler(ur.validate, ur.userService)

	r.Route("/users", func(r chi.Router) {
		r.Post("/", h.CreateUser)
		r.Get("/", h.GetAllUsers)
		// r.Get("/me", h.GetUser)
		r.Get("/{id}", h.GetByID)
	})
}
