package main

import (
	"log"
	"net/http"
	"os"

	"github.com/allensuvorov/tenexlog/internal/auth"
)

func main() {
	public := http.NewServeMux()
	protected := http.NewServeMux()

	// public
	public.HandleFunc("GET /healthz", healthz)

	// protected
	protected.HandleFunc("GET /ping", ping)
	// (We’ll add /api/upload here next)

	// mount: everything except /healthz requires auth
	root := http.NewServeMux()
	root.Handle("GET /healthz", public)
	root.Handle("/", auth.EnvBasicAuth()(protected))

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	log.Println("starting server on", addr)
	log.Fatal(http.ListenAndServe(addr, root))
}
