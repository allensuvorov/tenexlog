// Package parse contains small, format-specific parsers for uploaded logs.
// This file focuses on extracting *rows* (events) from a TSV log.
//
// Expected minimal columns by index (tab-separated):
//
//	0: ts (RFC3339, e.g., 2025-08-28T10:00:00Z)
//	1: srcIP (string)
//	2: dst (hostname or IP)
//	3: method (e.g., GET)
//	4: path (e.g., /login)
//	5: status (int; e.g., 200)
//	6: bytes (int; response size)
//	7: ua (user-agent string)
//
// Any missing columns are tolerated (fields remain zero-values).
package parse

import ( // imports required here
	"bufio"   // buffered scanning of lines
	"os"      // opening files
	"strconv" // Atoi/ParseInt for numeric fields
	"strings" // strings.Split etc.
	"time"    // timestamp parsing
)

// Event is a single parsed log row suitable for table display in the UI.
type Event struct {
	TS     time.Time `json:"ts"`               // event timestamp (UTC)
	SrcIP  string    `json:"srcIp,omitempty"`  // source IP (if present)
	Dst    string    `json:"dst,omitempty"`    // destination host/IP
	Method string    `json:"method,omitempty"` // HTTP method
	Path   string    `json:"path,omitempty"`   // URL path
	Status int       `json:"status,omitempty"` // HTTP status code
	Bytes  int64     `json:"bytes,omitempty"`  // size in bytes
	UA     string    `json:"ua,omitempty"`     // user agent
}

// ParseTSVRows reads a TSV log and returns:
//   - Summary (overall stats),
//   - Timeline (per-minute buckets),
//   - Rows (first keepRows events for the table).
//
// The maxRows parameter limits how many lines are *scanned* (protects performance).
// The keepRows parameter limits how many parsed rows we *retain* (protects memory).
func ParseTSVRows(path string, maxRows, keepRows int) (Summary, []Bucket, []Event, error) {
	// First pass: reuse the minimal summary+timeline logic from ParseTSV.
	sum, timeline, err := ParseTSV(path, maxRows) // compute bounds and per-minute counts
	if err != nil {                               // bubble up error if file open/scan failed
		return Summary{}, nil, nil, err
	}

	// Second pass: collect row-level details (bounded by keepRows).
	f, err := os.Open(path) // open file again (simple + clear for now)
	if err != nil {         // if we cannot re-open, return with error
		return Summary{}, nil, nil, err
	}
	defer f.Close() // ensure descriptor is closed on return

	rows := make([]Event, 0, min(keepRows, 4096)) // pre-allocate up to a reasonable capacity
	sc := bufio.NewScanner(f)                     // scanner over file contents
	const maxLine = 1024 * 1024                   // allow up to 1 MiB lines
	buf := make([]byte, 0, 64*1024)               // initial 64 KiB buffer
	sc.Buffer(buf, maxLine)                       // set max token size

	seen := 0       // number of scanned lines (to enforce maxRows)
	for sc.Scan() { // iterate through lines
		seen++ // increment scanned counter
		if maxRows > 0 && seen > maxRows {
			break // stop scanning beyond cap
		}

		parts := strings.Split(sc.Text(), "\t") // split current line into fields
		var ev Event                            // zero-value event to fill

		// ts (idx 0)
		if len(parts) > 0 {
			if ts, err := time.Parse(time.RFC3339, parts[0]); err == nil {
				ev.TS = ts.UTC()
			}
		}
		// srcIP (idx 1)
		if len(parts) > 1 {
			ev.SrcIP = parts[1]
		}
		// dst (idx 2)
		if len(parts) > 2 {
			ev.Dst = parts[2]
		}
		// method (idx 3)
		if len(parts) > 3 {
			ev.Method = parts[3]
		}
		// path (idx 4)
		if len(parts) > 4 {
			ev.Path = parts[4]
		}
		// status (idx 5)
		if len(parts) > 5 {
			if n, err := strconv.Atoi(parts[5]); err == nil {
				ev.Status = n
			}
		}
		// bytes (idx 6)
		if len(parts) > 6 {
			if n, err := strconv.ParseInt(parts[6], 10, 64); err == nil {
				ev.Bytes = n
			}
		}
		// ua (idx 7)
		if len(parts) > 7 {
			ev.UA = parts[7]
		}

		// Keep only the first keepRows events to avoid large memory usage.
		if keepRows <= 0 || len(rows) < keepRows {
			rows = append(rows, ev)
		}
	}
	if err := sc.Err(); err != nil { // propagate scan errors (I/O or token too long)
		return Summary{}, nil, nil, err
	}

	return sum, timeline, rows, nil // success: return all three aggregates
}

// min is a tiny helper to return the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
