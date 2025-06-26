package helper

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()

func BindRequest(r *http.Request, dst interface{}) error {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	switch contentType {
	case "application/json":
		return json.NewDecoder(r.Body).Decode(dst)

	case "application/x-www-form-urlencoded", "multipart/form-data":
		if err := r.ParseForm(); err != nil {
			return err
		}
		decoder.IgnoreUnknownKeys(true)
		return decoder.Decode(dst, r.PostForm)

	default:
		return errors.New("unsupported Content-Type header")
	}
}
