package analyze

import (
	"time"

	"github.com/allensuvorov/tenexlog/internal/parse"
)

// AnomalySQLi represents a detected SQL injection attempt pattern.
type AnomalySQLi struct {
	Kind       string    `json:"kind"`
	Category   string    `json:"category"` // e.g., "union_extract", "auth_bypass"
	SrcIP      string    `json:"srcIp"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Hits       int       `json:"hits"`
	Confidence float64   `json:"confidence"`
	Reason     string    `json:"reason"`
	Sample     string    `json:"sample"` // Example malicious path
}

// DetectSQLi analyzes events for SQL injection patterns.
// Returns anomalies for IPs that have at least minHits SQLi attempts.
func DetectSQLi(rows []parse.Event, minHits int) []AnomalySQLi {
	return nil // Stub - tests will fail
}
