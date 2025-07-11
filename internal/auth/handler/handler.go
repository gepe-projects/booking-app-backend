package handler

import (
	"net/http"

	"booking-app/internal/auth/dto"
	as "booking-app/internal/auth/service"
	"booking-app/pkg/constants"
	"booking-app/pkg/helper"
	"booking-app/pkg/util"

	"github.com/go-playground/validator/v10"
)

type authHandler struct {
	validate    *validator.Validate
	authService as.AuthService
}

func newAuthHandler(validator *validator.Validate, authService as.AuthService) *authHandler {
	return &authHandler{
		validate:    validator,
		authService: authService,
	}
}

func (h *authHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(constants.CtxUser).(*util.CustomClaims)
	if !ok {
		helper.WriteError(w, http.StatusInternalServerError, map[string]any{
			"error": "User not found",
		})
		return
	}
	helper.WriteSuccess(w, http.StatusOK, claims)
}

func (h *authHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if err := helper.BindRequest(r, &req); err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		err := helper.GenerateMessage(err, constants.FromRequestBody)
		helper.WriteError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.authService.Register(r.Context(), req); err != nil {
		helper.WriteError(w, http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
		})
		return
	}

	helper.WriteSuccess(w, http.StatusOK, helper.SuccessResponse{
		Status:  constants.Success,
		Message: "Register successfully",
	})
}

func (h *authHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := helper.BindRequest(r, &req); err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		err := helper.GenerateMessage(err, constants.FromRequestBody)
		helper.WriteError(w, http.StatusBadRequest, err)
		return
	}

	req.UserAgent = r.Header.Get("User-Agent")
	req.IpAddress = r.RemoteAddr

	responseLogin, err := h.authService.Login(r.Context(), req)
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}

	// set cookie token
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    responseLogin.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Expires:  responseLogin.AccessClaims.ExpiresAt.Time,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    responseLogin.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Expires:  responseLogin.RefreshClaims.ExpiresAt.Time,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    responseLogin.CsrfToken,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteDefaultMode,
		Expires:  responseLogin.CsrfClaims.ExpiresAt.Time,
	})

	helper.WriteSuccess(w, http.StatusOK, dto.LoginResponse{
		TokenResponse: dto.TokenResponse{
			AccessToken:  responseLogin.AccessToken,
			RefreshToken: responseLogin.RefreshToken,
		},
		User: responseLogin.User,
	})
}

func (h *authHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req dto.RequestRefreshToken
	if err := helper.BindRequest(r, &req); err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		err := helper.GenerateMessage(err, constants.FromRequestBody)
		helper.WriteError(w, http.StatusBadRequest, err)
		return
	}

	req.UserAgent = r.Header.Get("User-Agent")
	req.IpAddress = r.RemoteAddr
	res, err := h.authService.RefreshToken(r.Context(), req)
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}

	// set cookie token
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    res.TokenResponse.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Expires:  res.AccessClaims.ExpiresAt.Time,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    res.TokenResponse.AccessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		Expires:  res.RefreshClaims.ExpiresAt.Time,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    res.CsrfToken,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteDefaultMode,
		Expires:  res.CsrfClaims.ExpiresAt.Time,
	})

	helper.WriteSuccess(w, http.StatusOK, map[string]any{
		"access_token":  res.TokenResponse.AccessToken,
		"refresh_token": res.TokenResponse.RefreshToken,
	})
}

func (h *authHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// ambil token dari cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": "missing refresh token",
		})
		return
	}
	refreshToken := cookie.Value

	// revoke RT
	err = h.authService.Logout(r.Context(), refreshToken)
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}

	// clear cookie client pake response yang set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
		MaxAge:   -1,
	})

	helper.WriteSuccess(w, http.StatusOK, helper.SuccessResponse{
		Status:  constants.Success,
		Message: "Logout successfully",
	})
}

func (h *authHandler) LogoutFromOtherDevices(w http.ResponseWriter, r *http.Request) {
	// ambil token dari cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": "missing refresh token",
		})
		return
	}
	refreshToken := cookie.Value

	// revoke RT
	err = h.authService.LogoutAllOtherDevices(r.Context(), refreshToken)
	if err != nil {
		helper.WriteError(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}

	helper.WriteSuccess(w, http.StatusOK, helper.SuccessResponse{
		Status:  constants.Success,
		Message: "Logout from other devices successfully",
	})
}

func (h *authHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.authService.GetJWKS()
	if err != nil {
		helper.WriteError(w, http.StatusInternalServerError, map[string]any{
			"error": "failed to get JWKS",
		})
		return
	}
	helper.WriteSuccess(w, http.StatusOK, jwks)
}
