// Package httputil contains small HTTP helpers and middlewares.
package httputil

import (
	"net/http" // HTTP types
	"strings"  // simple origin check
	// max-age headers
)

// CORS returns middleware that:
//   - allows requests from allowedOrigin (exact match)
//   - responds to OPTIONS preflight without hitting downstream handlers
//   - adds standard CORS response headers on actual requests
//
// Note: Place this middleware OUTSIDE auth so that browsers can perform
// preflight (OPTIONS) without credentials first.
func CORS(allowedOrigin string) func(http.Handler) http.Handler {
	// Canonicalize the allowed origin once.
	allowed := strings.TrimSpace(allowedOrigin)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin") // empty for non-CORS requests (e.g., curl)
			// If no Origin header, this is not a CORS request — just proceed.
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// If the request's Origin matches our allowed origin, set CORS headers.
			if origin == allowed {
				// Allow this specific origin. (Avoid wildcard when using credentials.)
				w.Header().Set("Access-Control-Allow-Origin", origin)
				// Tell the browser it CAN send credentials (Authorization header).
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				// Echo allowed request headers (add others if needed).
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				// Restrict methods we support.
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				// Cache preflight for a while to reduce OPTIONS chatter.
				w.Header().Set("Access-Control-Max-Age", "600") // seconds
				// Optionally, expose custom headers to browser JS (none for now).
				// w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
			}

			// Handle preflight requests directly (no auth, no next handler).
			if r.Method == http.MethodOptions {
				// 204 No Content is a good minimal success for preflight.
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// For actual CORS requests, pass to the next handler.
			next.ServeHTTP(w, r)
		})
	}
}
