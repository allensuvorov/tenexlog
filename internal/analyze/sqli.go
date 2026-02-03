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
	// 03: error_based - Error-based extraction
	{"error_based", regexp.MustCompile(`(?i)\bCONVERT\s*\([^,]+,`)},              // CONVERT(int,
	{"error_based", regexp.MustCompile(`(?i)\bEXTRACTVALUE\s*\(`)},               // EXTRACTVALUE(
	{"error_based", regexp.MustCompile(`(?i)\bUPDATEXML\s*\(`)},                  // UPDATEXML(
	// 04: blind_boolean - Boolean-based blind injection
	{"blind_boolean", regexp.MustCompile(`(?i)\bAND\s+\d+\s*=\s*\d+`)},  // AND 1=1, AND 1=2
	{"blind_boolean", regexp.MustCompile(`(?i)\bOR\s+\d+\s*=\s*\d+`)},   // OR 1=1
	// 05: blind_time - Time-based blind injection
	{"blind_time", regexp.MustCompile(`(?i)\bSLEEP\s*\(\s*\d+\s*\)`)},           // SLEEP(5)
	{"blind_time", regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`)},                   // BENCHMARK(
	{"blind_time", regexp.MustCompile(`(?i)\bpg_sleep\s*\(`)},                    // pg_sleep(
	{"blind_time", regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`)},                // WAITFOR DELAY
	// 14: whitespace - No space between tokens
	{"whitespace", regexp.MustCompile(`(?i)'\s*OR\s*\(`)},                        // 'OR(
	{"whitespace", regexp.MustCompile(`(?i)'\s*AND\s*\(`)},                       // 'AND(
	{"whitespace", regexp.MustCompile(`(?i)'\s*OR\s*\d`)},                        // 'OR1
	{"whitespace", regexp.MustCompile(`(?i)'\s*AND\s*\d`)},                       // 'AND1
	// 17: nosql - NoSQL injection patterns
	{"nosql", regexp.MustCompile(`\$\s*(gt|gte|lt|lte|ne|eq|regex|where|or|and)\b`)}, // $gt, $ne, etc.
	// 06: stacked - Semicolon followed by SQL statement
	{"stacked", regexp.MustCompile(`(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|WAITFOR)\b`)},
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
	// Remove inline comments used for obfuscation: /**/ and /*!...*/
	// First handle empty comments (/**/) - remove completely to rejoin split keywords
	path = strings.ReplaceAll(path, "/**/", "")
	// Handle MySQL conditional comments: /*!UNION*/ -> UNION
	path = removeConditionalComments(path)
	return path
}

// removeConditionalComments strips /*!...*/ MySQL conditional comments
func removeConditionalComments(s string) string {
	result := s
	for {
		start := strings.Index(result, "/*!")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "*/")
		if end == -1 {
			break
		}
		// Extract content between /*! and */
		content := result[start+3 : start+end]
		// Remove optional version number prefix (e.g., /*!50000SELECT*/)
		for len(content) > 0 && content[0] >= '0' && content[0] <= '9' {
			content = content[1:]
		}
		result = result[:start] + content + result[start+end+2:]
	}
	return result
}

func buildSQLiReason(ip, category string, hits int) string {
	return "SQL injection attempt (" + category + ") from " + ip +
		": " + intToStr(hits) + " suspicious request(s) detected."
}
