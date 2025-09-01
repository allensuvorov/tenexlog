package main

import (
	"log"
	"net/http"
	"os"

	"github.com/allensuvorov/tenexlog/internal/auth"
	"github.com/allensuvorov/tenexlog/internal/httputil"
	"github.com/allensuvorov/tenexlog/internal/upload"
)

func main() {
	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", healthz)

	protected := http.NewServeMux()
	protected.HandleFunc("GET /ping", ping)
	protected.Handle("POST /api/upload", upload.Handler())

	allowedOrigin := os.Getenv("CORS_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:3000"
	}
	protectedWithAuth := auth.EnvBasicAuth()(protected)
	protectedWithCORS := httputil.CORS(allowedOrigin)(protectedWithAuth)

	root := http.NewServeMux()
	root.Handle("GET /healthz", public)
	root.Handle("/", protectedWithCORS)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}
	log.Println("starting server on", addr, " (CORS origin:", allowedOrigin, ")")
	log.Fatal(http.ListenAndServe(addr, root))
}
