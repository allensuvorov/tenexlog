package analyze

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
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

// SQLi pattern definitions
var sqliPatterns = []struct {
	Category string
	Regex    *regexp.Regexp
}{
	// 01: auth_bypass - Authentication bypass attempts
	{"auth_bypass", regexp.MustCompile(`(?i)'\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`)}, // ' OR 1=1, ' OR '1'='1
	{"auth_bypass", regexp.MustCompile(`(?i)'\s*(OR|AND)\s+['"][^'"]*['"]\s*=\s*['"]`)},   // ' OR 'a'='a
	{"auth_bypass", regexp.MustCompile(`(?i)'\s*--`)},                                      // '--  (comment after quote)
	{"auth_bypass", regexp.MustCompile(`(?i)'\s*#`)},                                       // '# (MySQL comment)
	// 02: union_extract - UNION SELECT statements
	{"union_extract", regexp.MustCompile(`(?i)UNION\s+(ALL\s+)?SELECT`)},
	// 07: destruction - DROP, DELETE, TRUNCATE
	{"destruction", regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|INDEX)`)},
	{"destruction", regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)},
	{"destruction", regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE\s+)?\w+`)},
}

// DetectSQLi analyzes events for SQL injection patterns.
// Returns anomalies for IPs that have at least minHits SQLi attempts.
func DetectSQLi(rows []parse.Event, minHits int) []AnomalySQLi {
	// Track hits per IP
	type ipData struct {
		hits      int
		firstSeen time.Time
		lastSeen  time.Time
		sample    string
		category  string
	}
	ipMap := make(map[string]*ipData)

	for _, ev := range rows {
		if ev.SrcIP == "" || ev.Path == "" {
			continue
		}

		// Decode and normalize path
		decoded := decodePath(ev.Path)
		normalized := normalizePath(decoded)

		// Check against patterns
		for _, p := range sqliPatterns {
			if p.Regex.MatchString(normalized) {
				data, exists := ipMap[ev.SrcIP]
				if !exists {
					data = &ipData{
						firstSeen: ev.TS,
						lastSeen:  ev.TS,
						sample:    ev.Path,
						category:  p.Category,
					}
					ipMap[ev.SrcIP] = data
				}
				data.hits++
				if ev.TS.Before(data.firstSeen) {
					data.firstSeen = ev.TS
				}
				if ev.TS.After(data.lastSeen) {
					data.lastSeen = ev.TS
				}
				break // Only count once per event
			}
		}
	}

	// Build results for IPs meeting threshold
	var out []AnomalySQLi
	for ip, data := range ipMap {
		if data.hits >= minHits {
			conf := 1 - expNeg(float64(data.hits)/3.0)
			out = append(out, AnomalySQLi{
				Kind:       "sqli",
				Category:   data.category,
				SrcIP:      ip,
				FirstSeen:  data.firstSeen,
				LastSeen:   data.lastSeen,
				Hits:       data.hits,
				Confidence: round2(conf),
				Reason:     buildSQLiReason(ip, data.category, data.hits),
				Sample:     data.sample,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// decodePath handles URL decoding, including double-encoding
func decodePath(path string) string {
	decoded := path
	for i := 0; i < 3; i++ { // Max 3 decode passes
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	return decoded
}

// normalizePath prepares path for pattern matching
func normalizePath(path string) string {
	// Remove inline comments used for obfuscation
	path = strings.ReplaceAll(path, "/**/", " ")
	return path
}

func buildSQLiReason(ip, category string, hits int) string {
	return "SQL injection attempt (" + category + ") from " + ip +
		": " + intToStr(hits) + " suspicious request(s) detected."
}
