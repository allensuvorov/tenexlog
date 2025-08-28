package main

import "net/http"

func initRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /ping", ping)
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent) // 204
}

func ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("pong\n"))
}
