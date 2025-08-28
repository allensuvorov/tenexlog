package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	initRoutes(mux)

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	log.Println("starting server on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
