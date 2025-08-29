package main

import ( // imports used in main
	"log"      // for startup logs
	"net/http" // HTTP server types
	"os"       // env for ADDR

	"github.com/allensuvorov/tenexlog/internal/auth"   // Basic Auth middleware
	"github.com/allensuvorov/tenexlog/internal/upload" // our new upload handler
)

func main() {
	// Public mux (no auth).
	public := http.NewServeMux()               // router for public endpoints
	public.HandleFunc("GET /healthz", healthz) // health check remains public

	// Protected mux (requires Basic Auth).
	protected := http.NewServeMux()                        // router for endpoints that need auth
	protected.HandleFunc("GET /ping", ping)                // already present ping endpoint
	protected.Handle("POST /api/upload", upload.Handler()) // NEW: secure upload endpoint

	// Root mux mounts both: /healthz stays public, everything else requires auth.
	root := http.NewServeMux()                       // top-level router
	root.Handle("GET /healthz", public)              // mount public subtree
	root.Handle("/", auth.EnvBasicAuth()(protected)) // wrap protected subtree with Basic Auth

	// Address binding (defaults to :8080; can override with ADDR).
	addr := ":8080"                      // default address/port
	if v := os.Getenv("ADDR"); v != "" { // check if ADDR is set
		addr = v // use custom address if provided
	}

	// Start the server.
	log.Println("starting server on", addr)    // log startup info
	log.Fatal(http.ListenAndServe(addr, root)) // block and serve (fatal on error)
}
