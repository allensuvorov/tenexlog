// Package auth provides middleware for HTTP Basic Authentication.
package auth

import (
	"crypto/subtle"   // for constant-time comparison of credentials (prevents timing attacks)
	"encoding/base64" // for decoding the "Authorization: Basic ..." header
	"net/http"        // core HTTP server types
	"os"              // to read BASIC_USER and BASIC_PASS from environment variables
	"strings"         // for string prefix checks and splitting user:pass
)

// EnvBasicAuth loads BASIC_USER and BASIC_PASS from environment variables
// and returns middleware that enforces Basic Auth using those values.
func EnvBasicAuth() func(http.Handler) http.Handler {
	user := os.Getenv("BASIC_USER") // read BASIC_USER from environment
	pass := os.Getenv("BASIC_PASS") // read BASIC_PASS from environment
	if user == "" || pass == "" {
		// fail fast: we don't want the server running without credentials configured
		panic("BASIC_USER/BASIC_PASS must be set")
	}
	// delegate to BasicAuth constructor with loaded credentials
	return BasicAuth(user, pass)
}

// BasicAuth returns a middleware function that wraps an http.Handler.
// It enforces Basic Authentication with the given username and password.
func BasicAuth(user, pass string) func(http.Handler) http.Handler {
	// convert expected username and password to byte slices
	// so we can use subtle.ConstantTimeCompare later
	uBytes := []byte(user)
	pBytes := []byte(pass)

	// return the actual middleware wrapper
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const prefix = "Basic " // expected prefix in Authorization header

			// extract the Authorization header
			authz := r.Header.Get("Authorization")
			// if it's missing or doesn't start with "Basic ", reject with 401
			if !strings.HasPrefix(authz, prefix) {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// remove "Basic " prefix and decode the base64 portion
			dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, prefix))
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// decoded form should be "username:password"
			parts := strings.SplitN(string(dec), ":", 2)
			if len(parts) != 2 {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// compare provided username and password against expected values
			// using constant-time compare to avoid leaking info via timing
			uOK := subtle.ConstantTimeCompare([]byte(parts[0]), uBytes) == 1
			pOK := subtle.ConstantTimeCompare([]byte(parts[1]), pBytes) == 1

			// reject if either doesn't match
			if !(uOK && pOK) {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// if credentials are valid, call the next handler in the chain
			next.ServeHTTP(w, r)
		})
	}
}
