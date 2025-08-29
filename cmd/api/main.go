package main

import (
	"log"
	"net/http"
	"os"

	"github.com/allensuvorov/tenexlog/internal/auth"     // Basic Auth middleware
	"github.com/allensuvorov/tenexlog/internal/httputil" // CORS middleware
	"github.com/allensuvorov/tenexlog/internal/upload"   // /api/upload handler
)

func main() {
	// Public (no auth)
	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", healthz)

	// Protected routes (require auth for actual requests)
	protected := http.NewServeMux()
	protected.HandleFunc("GET /ping", ping)
	protected.Handle("POST /api/upload", upload.Handler())

	// Compose middlewares:
	// 1) CORS OUTSIDE auth so browsers can preflight OPTIONS without credentials.
	// 2) Auth wraps actual requests after CORS.
	allowedOrigin := os.Getenv("CORS_ORIGIN") // e.g., "http://localhost:3000"
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:3000" // safe default for dev
	}
	protectedWithAuth := auth.EnvBasicAuth()(protected)
	protectedWithCORS := httputil.CORS(allowedOrigin)(protectedWithAuth)

	// Root mux combines public + protected trees.
	root := http.NewServeMux()
	root.Handle("GET /healthz", public) // stays public
	root.Handle("/", protectedWithCORS) // everything else behind CORS+Auth

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}
	log.Println("starting server on", addr, " (CORS origin:", allowedOrigin, ")")
	log.Fatal(http.ListenAndServe(addr, root))
}
