// Package parse contains small, format-specific parsers for uploaded logs.
package parse

import ( // imports used by this parser
	"bufio"   // efficient, buffered line scanning
	"os"      // file open
	"sort"    // to sort timeline buckets by time
	"strings" // splitting fields by tab
	"time"    // timestamp parsing + minute bucketing
)

// Summary holds high-level stats derived from the log file.
type Summary struct {
	Lines     int       `json:"lines"`     // total number of lines successfully read (not necessarily parsed)
	UniqueIPs int       `json:"uniqueIPs"` // distinct source IPs observed (very rough)
	Start     time.Time `json:"start"`     // earliest timestamp seen (UTC)
	End       time.Time `json:"end"`       // latest timestamp seen (UTC)
}

// Bucket represents a per-minute aggregation for the activity timeline.
type Bucket struct {
	T     time.Time `json:"t"`     // minute timestamp (UTC, truncated to :00 seconds)
	Count int       `json:"count"` // number of events falling into this minute
}

// ParseTSV opens a tab-separated log file and returns a minimal summary and a per-minute timeline.
// Expected minimal columns: ts (RFC3339) at index 0, srcIP at index 1. Extra columns are ignored.
// maxRows limits how many lines we parse to bound memory/CPU in prototypes (use 0 or negative for "no cap").
func ParseTSV(path string, maxRows int) (Summary, []Bucket, error) {
	// Initialize empty summary and structures needed during scan.
	var sum Summary                         // container for high-level stats
	seenIPs := make(map[string]struct{})    // set for counting distinct source IPs
	minuteCounts := make(map[time.Time]int) // map minute->count for building the timeline

	// Open the file for reading.
	f, err := os.Open(path) // attempt to open the provided path
	if err != nil {         // handle open error by returning it
		return Summary{}, nil, err
	}
	defer f.Close() // ensure file handle is closed on function exit

	// Prepare a buffered scanner for efficient line-by-line processing.
	sc := bufio.NewScanner(f) // new scanner over file
	// Optionally enlarge the buffer to handle long lines (e.g., big user agents).
	const maxLine = 1024 * 1024     // 1 MiB per line as an upper bound for this prototype
	buf := make([]byte, 0, 64*1024) // initial buffer (64 KiB)
	sc.Buffer(buf, maxLine)         // set max token size to prevent scan errors on long lines

	// Iterate over lines, respecting the optional maxRows cap.
	for sc.Scan() { // read next line into scanner
		line := sc.Text()                       // get current line content as string
		sum.Lines++                             // increment total line counter (counts all lines scanned)
		if maxRows > 0 && sum.Lines > maxRows { // stop if we've reached the parsing cap
			break // break out to keep prototype snappy on huge logs
		}

		// Split by tabs to extract minimal fields (ts at [0], srcIP at [1]).
		parts := strings.Split(line, "\t") // naive split; Zscaler-like feeds are tab-separated
		if len(parts) < 2 {                // require at least ts and srcIP positions
			continue // skip malformed rows quietly for now
		}

		// Parse timestamp in RFC3339 (e.g., "2025-08-28T10:00:00Z").
		ts, err := time.Parse(time.RFC3339, parts[0]) // attempt to parse the first column as time
		if err != nil {                               // if timestamp is invalid
			continue // skip this line
		}
		ts = ts.UTC() // normalize to UTC for consistent buckets

		// Track start/end bounds.
		if sum.Start.IsZero() || ts.Before(sum.Start) { // update earliest timestamp
			sum.Start = ts
		}
		if sum.End.IsZero() || ts.After(sum.End) { // update latest timestamp
			sum.End = ts
		}

		// Track unique source IPs (very rough metric).
		src := parts[1]                 // second column treated as source IP
		if _, ok := seenIPs[src]; !ok { // if not yet present in set
			seenIPs[src] = struct{}{} // insert into set
		}

		// Increment the per-minute bucket for timeline.
		min := ts.Truncate(time.Minute) // drop seconds/nanos → minute resolution
		minuteCounts[min]++             // bump count for this minute
	}
	// If the scanner itself encountered an I/O or token size error, return it.
	if err := sc.Err(); err != nil { // check scanner error
		return Summary{}, nil, err // bubble up error to caller
	}

	// Finalize unique IP count.
	sum.UniqueIPs = len(seenIPs) // number of distinct keys in the set

	// Convert the minuteCounts map into a sorted slice of buckets (ascending by time).
	if len(minuteCounts) == 0 { // if no valid timestamps were found
		return sum, nil, nil // return summary with empty timeline
	}
	keys := make([]time.Time, 0, len(minuteCounts)) // pre-size slice for keys
	for k := range minuteCounts {                   // collect all minute keys
		keys = append(keys, k) // append each key
	}
	sort.Slice(keys, func(i, j int) bool { // sort keys chronologically
		return keys[i].Before(keys[j]) // true if i occurs before j
	})
	timeline := make([]Bucket, 0, len(keys)) // build ordered buckets
	for _, k := range keys {                 // iterate in sorted order
		timeline = append(timeline, Bucket{ // append a new bucket
			T:     k,               // minute timestamp
			Count: minuteCounts[k], // count for that minute
		})
	}

	// Return computed summary and timeline to the caller.
	return sum, timeline, nil // success path
}
