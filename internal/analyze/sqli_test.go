package analyze

import (
	"testing"
	"time"

	"github.com/allensuvorov/tenexlog/internal/parse"
)

// Helper to create test events
func makeEvent(ip, path string, ts time.Time) parse.Event {
	return parse.Event{
		TS:     ts,
		SrcIP:  ip,
		Dst:    "example.com",
		Method: "GET",
		Path:   path,
		Status: 200,
	}
}

func TestDetectSQLi_Categories(t *testing.T) {
	baseTime := time.Date(2025, 8, 28, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		category string
		ip       string
		paths    []string
	}{
		{
			name:     "01_auth_bypass",
			category: "auth_bypass",
			ip:       "6.6.6.1",
			paths: []string{
				"/login?user=admin'--",
				"/login?user=' OR '1'='1",
			},
		},
		{
			name:     "02_union_extract",
			category: "union_extract",
			ip:       "6.6.6.2",
			paths: []string{
				"/products?id=1 UNION SELECT password FROM users--",
				"/products?id=1 UNION ALL SELECT username,password FROM users--",
			},
		},
		{
			name:     "03_error_based",
			category: "error_based",
			ip:       "6.6.6.3",
			paths: []string{
				"/page?id=1 AND 1=CONVERT(int,@@version)--",
				"/page?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
			},
		},
		{
			name:     "04_blind_boolean",
			category: "blind_boolean",
			ip:       "6.6.6.4",
			paths: []string{
				"/page?id=1 AND 1=1--",
				"/page?id=1 AND 1=2--",
			},
		},
		{
			name:     "05_blind_time",
			category: "blind_time",
			ip:       "6.6.6.5",
			paths: []string{
				"/page?id=1; WAITFOR DELAY '0:0:5'--",
				"/page?id=1 AND SLEEP(5)--",
			},
		},
		{
			name:     "06_stacked",
			category: "stacked",
			ip:       "6.6.6.6",
			paths: []string{
				"/page?id=1; DROP TABLE users--",
				"/page?id=1; SELECT * FROM users--",
			},
		},
		{
			name:     "07_destruction",
			category: "destruction",
			ip:       "6.6.6.7",
			paths: []string{
				"/page?id=1; DELETE FROM users WHERE 1=1--",
				"/page?id=1; TRUNCATE TABLE logs--",
			},
		},
		{
			name:     "08_manipulation",
			category: "manipulation",
			ip:       "6.6.6.8",
			paths: []string{
				"/page?id=1; INSERT INTO users VALUES('hacker','pass')--",
				"/page?id=1; UPDATE users SET role='admin'--",
			},
		},
		{
			name:     "09_stored_proc",
			category: "stored_proc",
			ip:       "6.6.6.9",
			paths: []string{
				"/page?id=1; EXEC xp_cmdshell('dir')--",
				"/page?id=1; EXEC sp_makewebtask '/tmp/out','SELECT * FROM users'--",
			},
		},
		{
			name:     "10_oob_exfil",
			category: "oob_exfil",
			ip:       "6.6.6.10",
			paths: []string{
				"/page?id=1; SELECT LOAD_FILE('/etc/passwd')--",
				"/page?id=1; SELECT * INTO OUTFILE '/tmp/dump.txt'--",
			},
		},
		{
			name:     "11_comment_obfusc",
			category: "comment_obfusc",
			ip:       "6.6.6.11",
			paths: []string{
				"/products?id=1 UN/**/ION SEL/**/ECT * FROM users--",
				"/products?id=1 /*!UNION*/ /*!SELECT*/ password FROM users--",
			},
		},
		{
			name:     "12_encoding",
			category: "encoding",
			ip:       "6.6.6.12",
			paths: []string{
				"/login?user=%27%20OR%201%3D1--",
				"/login?user=%2527%20OR%201%3D1--",
			},
		},
		{
			name:     "13_case_manip",
			category: "case_manip",
			ip:       "6.6.6.13",
			paths: []string{
				"/products?id=1 uNiOn SeLeCt password FROM users--",
				"/products?id=1 UnIoN aLl SeLeCt * FROM users--",
			},
		},
		{
			name:     "14_whitespace",
			category: "whitespace",
			ip:       "6.6.6.14",
			paths: []string{
				"/login?user='OR(1=1)--",
				"/login?user='/**/OR/**/1=1--",
			},
		},
		{
			name:     "15_concat",
			category: "concat",
			ip:       "6.6.6.15",
			paths: []string{
				"/page?id=1 UNION SELECT CONCAT(username,':',password) FROM users--",
				"/page?id=1 AND 'x'='x'||'y'--",
			},
		},
		{
			name:     "16_second_order",
			category: "second_order",
			ip:       "6.6.6.16",
			paths: []string{
				"/register?name=admin'--",
				"/register?name=O'Reilly'; DROP TABLE users--",
			},
		},
		{
			name:     "17_nosql",
			category: "nosql",
			ip:       "6.6.6.17",
			paths: []string{
				`/api/users?filter={"$gt":""}`,
				`/api/users?filter={"$ne":null}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build events for this category
			var events []parse.Event
			for i, path := range tt.paths {
				events = append(events, makeEvent(tt.ip, path, baseTime.Add(time.Duration(i)*time.Minute)))
			}

			// Run detection
			anomalies := DetectSQLi(events, 1)

			// Verify we detected anomalies from this IP
			found := false
			for _, a := range anomalies {
				if a.SrcIP == tt.ip {
					found = true
					if a.Hits != len(tt.paths) {
						t.Errorf("expected %d hits, got %d", len(tt.paths), a.Hits)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected to detect SQLi from IP %s (category: %s)", tt.ip, tt.category)
			}
		})
	}
}

func TestDetectSQLi_CleanTraffic(t *testing.T) {
	baseTime := time.Date(2025, 8, 28, 10, 0, 0, 0, time.UTC)

	// Clean traffic should not trigger detection
	events := []parse.Event{
		makeEvent("1.1.1.1", "/index.html", baseTime),
		makeEvent("1.1.1.1", "/about.html", baseTime.Add(time.Minute)),
		makeEvent("1.1.1.1", "/products?id=123", baseTime.Add(2*time.Minute)),
		makeEvent("1.1.1.1", "/search?q=hello+world", baseTime.Add(3*time.Minute)),
	}

	anomalies := DetectSQLi(events, 1)

	for _, a := range anomalies {
		if a.SrcIP == "1.1.1.1" {
			t.Errorf("clean traffic from 1.1.1.1 should not trigger SQLi detection")
		}
	}
}

func TestDetectSQLi_MinHitsThreshold(t *testing.T) {
	baseTime := time.Date(2025, 8, 28, 10, 0, 0, 0, time.UTC)

	// Single SQLi attempt
	events := []parse.Event{
		makeEvent("2.2.2.2", "/login?user=admin'--", baseTime),
	}

	// With minHits=2, single attempt should not trigger
	anomalies := DetectSQLi(events, 2)

	for _, a := range anomalies {
		if a.SrcIP == "2.2.2.2" {
			t.Errorf("single hit should not trigger when minHits=2")
		}
	}
}
