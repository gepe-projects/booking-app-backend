package helper

import (
	"encoding/json"
	"net/http"
)

type SuccessResponse struct {
	Status  string `json:"status"` // always "success"
	Data    any    `json:"data"`
	Message string `json:"message,omitempty"` // optional
}

type ErrorResponse struct {
	Status string `json:"status"` // always "error"
	Errors any    `json:"errors"`
}

func WriteJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(payload)
}

func WriteSuccess(w http.ResponseWriter, data any) {
	resp := SuccessResponse{
		Status: "success",
		Data:   data,
	}
	WriteJSON(w, http.StatusOK, resp)
}

func WriteCreated(w http.ResponseWriter, data any) {
	resp := SuccessResponse{
		Status: "success",
		Data:   data,
	}
	WriteJSON(w, http.StatusCreated, resp)
}

func WriteError(w http.ResponseWriter, statusCode int, err any) {
	resp := ErrorResponse{
		Status: "error",
		Errors: err,
	}
	WriteJSON(w, statusCode, resp)
}
