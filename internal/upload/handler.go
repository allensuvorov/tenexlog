// Package upload exposes the HTTP handler for file uploads and analysis.
package upload

import ( // standard and local imports used by this file
	"io"            // io.Copy for streaming request → file
	"net/http"      // HTTP handler types and helpers
	"os"            // create/remove temp files
	"path/filepath" // build safe temp file path
	"time"          // timestamps for response and anomaly fields

	"github.com/allensuvorov/tenexlog/internal/analyze"  // anomaly detectors (rate spikes, sensitive paths)
	"github.com/allensuvorov/tenexlog/internal/httputil" // small HTTP helpers (JSON, ID generator)
	"github.com/allensuvorov/tenexlog/internal/parse"    // TSV parser (summary, timeline, rows)
)

// anyAnom is a small "union" JSON shape so the frontend can consume
// different anomaly kinds (rate_spike, sensitive_paths) from one array.
type anyAnom struct {
	Kind       string     `json:"kind"`                 // e.g., "rate_spike" or "sensitive_paths"
	SrcIP      string     `json:"srcIp"`                // source IP involved in the anomaly
	Minute     *time.Time `json:"minute,omitempty"`     // when anomaly minute applies (rate spike)
	FirstSeen  *time.Time `json:"firstSeen,omitempty"`  // first time a pattern seen (sensitive paths)
	LastSeen   *time.Time `json:"lastSeen,omitempty"`   // last time a pattern seen (sensitive paths)
	Count      *int       `json:"count,omitempty"`      // requests in that spike minute (rate)
	Baseline   *float64   `json:"baseline,omitempty"`   // mean/minute for that IP across file (rate)
	Z          *float64   `json:"z,omitempty"`          // z-score for the spike (rate)
	Hits       *int       `json:"hits,omitempty"`       // total sensitive-path hits (sensitive)
	UniquePref *int       `json:"uniquePref,omitempty"` // distinct sensitive prefixes probed (sensitive)
	Confidence float64    `json:"confidence"`           // 0..1 confidence (both detectors)
	Reason     string     `json:"reason"`               // human-readable explanation for UI
}

// Results is the JSON we return after accepting an upload and analyzing it.
type Results struct {
	JobID     string         `json:"jobId"`          // unique ID for this upload "job"
	Filename  string         `json:"filename"`       // original filename provided by the client
	SizeBytes int64          `json:"sizeBytes"`      // bytes successfully streamed to disk
	SavedTo   string         `json:"savedTo"`        // absolute temp-file path (handy during dev; remove later)
	Received  string         `json:"received"`       // RFC3339 timestamp when we handled the upload
	Summary   parse.Summary  `json:"summary"`        // high-level stats (lines, unique IPs, start/end)
	Timeline  []parse.Bucket `json:"timeline"`       // per-minute activity counts for quick charts
	Rows      []parse.Event  `json:"rows"`           // first N parsed rows for the results table
	Anomalies []anyAnom      `json:"anomalies"`      // merged anomalies (rate spikes + sensitive paths)
	Note      string         `json:"note,omitempty"` // optional transparency note (e.g., truncation)
}

// Handler returns an http.Handler that accepts multipart uploads at POST /api/upload,
// streams to /tmp, parses/analyses the file, and returns JSON with summary, timeline,
// rows, and merged anomalies. All non-/healthz endpoints should be wrapped by Basic Auth.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enforce method: only POST is allowed for uploads.
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)                         // advertise allowed method
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed) // return 405
			return                                                           // stop execution
		}

		// Extract the uploaded file part under form field "file".
		file, header, err := r.FormFile("file") // read "file" part from multipart form
		if err != nil {
			http.Error(w, "file field 'file' is required", http.StatusBadRequest) // 400 on missing/invalid part
			return
		}
		defer file.Close() // ensure request file stream is closed

		// Create a unique temp path in the OS temp dir to store the upload.
		jobID := httputil.NewID()                         // random job ID (hex)
		dest := filepath.Join(os.TempDir(), jobID+".log") // e.g., /tmp/<id>.log

		// Open the destination for writing; bail if the OS temp dir isn't writable.
		out, err := os.Create(dest) // create temp file
		if err != nil {
			http.Error(w, "could not create temp file", http.StatusInternalServerError) // 500 on create failure
			return
		}

		// Stream the upload into the destination file to avoid loading it all in memory.
		n, copyErr := io.Copy(out, file) // copy returns bytes written and error
		closeErr := out.Close()          // close file handle

		// If either the copy or close failed, clean up and report.
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(dest)                                                    // best-effort removal of partial file
			http.Error(w, "failed to save upload", http.StatusInternalServerError) // 500 on write/close error
			return
		}

		// Parse the saved TSV file: we’ll scan up to maxRowsScan lines, and keep keepRows rows for the table.
		const (
			maxRowsScan = 100_000 // cap scanned lines for performance in large files
			keepRows    = 5_000   // cap retained rows for memory and payload size
		)
		sum, timeline, rows, perr := parse.ParseTSVRows(dest, maxRowsScan, keepRows) // derive summary/timeline/rows
		if perr != nil {
			_ = os.Remove(dest)                                 // clean up temp file on parse error
			http.Error(w, "parse error", http.StatusBadRequest) // 400 for malformed or unsupported input
			return
		}

		// ---- Anomaly detection (two sources) ------------------------------------

		// 1) Rate spikes per IP (per-minute z-score or thresholded)
		const maxAnoms = 50                                   // cap total anomalies returned
		rateAnoms := analyze.DetectRateSpikes(rows, maxAnoms) // rate spike findings

		// 2) Sensitive path probing (repeated hits to admin/login/.git/etc.)
		const (
			minHits   = 5 // at least this many sensitive hits
			minUnique = 2 // or at least this many distinct sensitive prefixes
		)
		sensAnoms := analyze.DetectSensitivePaths(rows, minHits, minUnique) // sensitive-path findings

		// Merge both into a single, homogeneous JSON array for the UI.
		merged := make([]anyAnom, 0, len(rateAnoms)+len(sensAnoms)) // pre-allocate capacity

		// Append rate-spike anomalies (map fields into union shape).
		for _, a := range rateAnoms {
			m := a.Minute // take local copy to get a stable address
			c := a.Count  // same for ints/floats to take addresses below
			b := a.Baseline
			z := a.Z
			merged = append(merged, anyAnom{
				Kind:       a.Kind,       // "rate_spike"
				SrcIP:      a.SrcIP,      // offending IP
				Minute:     &m,           // minute during which spike occurred
				Count:      &c,           // requests in that minute
				Baseline:   &b,           // mean/minute across file
				Z:          &z,           // z-score
				Confidence: a.Confidence, // 0..1
				Reason:     a.Reason,     // explanation string
			})
		}

		// Append sensitive-path anomalies (map fields into union shape).
		for _, s := range sensAnoms {
			fs, ls := s.FirstSeen, s.LastSeen // first/last timestamps
			h, u := s.Hits, s.UniquePref      // counts for hits and unique prefixes
			merged = append(merged, anyAnom{
				Kind:       s.Kind,       // "sensitive_paths"
				SrcIP:      s.SrcIP,      // probing IP
				FirstSeen:  &fs,          // first time we saw a sensitive hit
				LastSeen:   &ls,          // last time we saw a sensitive hit
				Hits:       &h,           // total sensitive hits
				UniquePref: &u,           // distinct sensitive prefixes matched
				Confidence: s.Confidence, // 0..1 (derived from hits)
				Reason:     s.Reason,     // explanation string
			})
		}

		// Optionally cap total anomalies so responses stay small and snappy.
		if len(merged) > maxAnoms {
			merged = merged[:maxAnoms] // truncate to cap
		}

		// If there are zero anomalies, ensure we still return an empty array (not null).
		if merged == nil {
			merged = []anyAnom{} // force [] instead of null
		}

		// ---- Build response ------------------------------------------------------

		// Add an optional transparency note if we truncated rows in the response.
		note := ""
		if sum.Lines > keepRows {
			note = "Rows are truncated for display (showing first 5000). Summary/anomalies are computed over the scanned portion."
		}

		// Assemble the final response payload.
		resp := Results{
			JobID:     jobID,                                 // echo back job ID
			Filename:  header.Filename,                       // original filename
			SizeBytes: n,                                     // bytes written
			SavedTo:   dest,                                  // temp file location (debug)
			Received:  time.Now().UTC().Format(time.RFC3339), // server-side receipt time
			Summary:   sum,                                   // high-level stats
			Timeline:  timeline,                              // per-minute counts
			Rows:      rows,                                  // bounded table rows
			Anomalies: merged,                                // merged anomaly list
			Note:      note,                                  // optional truncation note
		}

		// Send JSON 200 OK with the results.
		httputil.JSON(w, http.StatusOK, resp) // write JSON response
	})
}
