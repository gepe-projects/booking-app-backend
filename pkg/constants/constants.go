package constants

import "errors"

// Validation
const (
	FromRequestBody = "request body"
	FromQueryParams = "query params"
	UuidIsNotValid  = "UUID is not valid"
)

// Response
const (
	Success = "success"
	Error   = "error"
)

// error
var (
	ErrInternalServer = errors.New("internal server error")
	ErrUnauthorized   = errors.New("unauthorized")
)

// database
const (
	SqlNoRows        = "record not found"
	SqlAlreadyExists = "already exists"
)
