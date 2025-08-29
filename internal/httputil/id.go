package httputil // keep helpers together in httputil

import ( // imports for random bytes and hex formatting
	"crypto/rand"  // cryptographically secure random source
	"encoding/hex" // to hex-encode random bytes
)

// NewID returns a 16-byte random hex string (32 hex chars).
func NewID() string { // no params; returns a string
	var b [16]byte                  // fixed-size 16-byte array
	_, _ = rand.Read(b[:])          // fill with random bytes (ignore error for brevity)
	return hex.EncodeToString(b[:]) // return lowercase hex (e.g., "a3f1...")
}
