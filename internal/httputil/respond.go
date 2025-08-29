// Package httputil contains small HTTP helpers (e.g., JSON responses).
package httputil

import ( // import block for packages used below
	"encoding/json" // for JSON encoding
	"net/http"      // for http.ResponseWriter and status codes
)

// JSON writes a JSON response with the given status code and value.
func JSON(w http.ResponseWriter, status int, v any) { // w: response writer, status: HTTP code, v: payload
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // declare JSON content type
	w.WriteHeader(status)                                             // set the HTTP status code
	_ = json.NewEncoder(w).Encode(v)                                  // encode v to JSON (ignore error on write)
}
