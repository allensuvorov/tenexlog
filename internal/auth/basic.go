package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
)

func EnvBasicAuth() func(http.Handler) http.Handler {
	user := os.Getenv("BASIC_USER")
	pass := os.Getenv("BASIC_PASS")
	if user == "" || pass == "" {
		panic("BASIC_USER/BASIC_PASS must be set")
	}
	return BasicAuth(user, pass)
}

func BasicAuth(user, pass string) func(http.Handler) http.Handler {
	uBytes := []byte(user)
	pBytes := []byte(pass)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const prefix = "Basic "

			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, prefix) {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, prefix))
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(string(dec), ":", 2)
			if len(parts) != 2 {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			uOK := subtle.ConstantTimeCompare([]byte(parts[0]), uBytes) == 1
			pOK := subtle.ConstantTimeCompare([]byte(parts[1]), pBytes) == 1

			if !(uOK && pOK) {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
