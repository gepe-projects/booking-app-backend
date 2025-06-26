package handler

import (
	"net/http"

	db "booking-app/internal/db/sqlc"
	dto "booking-app/internal/user/dto"
	userService "booking-app/internal/user/service"
	"booking-app/pkg/constants"
	"booking-app/pkg/helper"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type userHandler struct {
	validate    *validator.Validate
	userService userService.UserService
}

func NewUserHandler(validator *validator.Validate, userService userService.UserService) *userHandler {
	return &userHandler{
		validate:    validator,
		userService: userService,
	}
}

func (h *userHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateUserRequest
	if err := helper.BindRequest(r, &req); err != nil {
		helper.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		err := helper.GenerateMessage(err, constants.FromRequestBody)
		helper.WriteError(w, http.StatusBadRequest, err)
		return
	}

	req.ID = uuid.New()

	user, err := h.userService.CreateUser(r.Context(), req)
	if err != nil {
		helper.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	helper.WriteCreated(w, user)
}

func (h *userHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	req := dto.ListUsersRequest{
		Search: r.URL.Query().Get("search"),
		Offset: helper.ParseInt32(r.URL.Query().Get("offset"), 0),
		Limit:  helper.ParseInt32(r.URL.Query().Get("limit"), 10),
	}
	arg := db.ListUsersParams{
		Search: helper.StringToPGTextValid(req.Search),
		Offset: req.Offset,
		Limit:  req.Limit,
	}
	users, err := h.userService.ListUsers(r.Context(), arg)
	if err != nil {
		helper.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	helper.WriteSuccess(w, users)
}

func (h *userHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	uuid, err := helper.ParseUUID(chi.URLParam(r, "id"))
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, "UUID is not valid")
		return
	}
	user, err := h.userService.GetUserByID(r.Context(), uuid)
	if err != nil {
		helper.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	helper.WriteSuccess(w, user)
}
