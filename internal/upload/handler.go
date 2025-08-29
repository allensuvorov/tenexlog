// Package upload exposes the HTTP handler for file uploads.
package upload

import ( // imports required by the handler
	"io"            // for io.Copy
	"net/http"      // for HTTP handler signatures
	"os"            // for creating/removing files
	"path/filepath" // for building a path under /tmp
	"time"          // for timestamps in the response

	"github.com/allensuvorov/tenexlog/internal/analyze"  // NEW: anomaly detection
	"github.com/allensuvorov/tenexlog/internal/httputil" // local JSON helper and ID generator
	"github.com/allensuvorov/tenexlog/internal/parse"    // parser (summary, timeline, rows)
)

// Results is the JSON we return after accepting an upload and parsing it.
type Results struct {
	JobID     string            `json:"jobId"`          // unique ID for this upload "job"
	Filename  string            `json:"filename"`       // original filename (client-provided)
	SizeBytes int64             `json:"sizeBytes"`      // size we streamed to disk (in bytes)
	SavedTo   string            `json:"savedTo"`        // absolute path of the temp file (debug)
	Received  string            `json:"received"`       // RFC3339 timestamp when we handled the upload
	Summary   parse.Summary     `json:"summary"`        // high-level stats from the file
	Timeline  []parse.Bucket    `json:"timeline"`       // per-minute counts for quick charting
	Rows      []parse.Event     `json:"rows"`           // first N parsed events for table rendering
	Anomalies []analyze.Anomaly `json:"anomalies"`      // NEW: simple rate-spike findings
	Note      string            `json:"note,omitempty"` // optional transparency note
}

// Handler returns an http.Handler that accepts POST /api/upload (multipart form "file").
func Handler() http.Handler { // no state yet; stateless handler factory
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // wrap logic in a HandlerFunc
		// Enforce method: only POST allowed for uploads.
		if r.Method != http.MethodPost { // check HTTP method
			w.Header().Set("Allow", http.MethodPost)                         // advertise allowed method
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed) // 405 response
			return                                                           // stop execution
		}

		// Parse a single file part under the form-field name "file".
		file, header, err := r.FormFile("file") // read the uploaded file from multipart form
		if err != nil {                         // handle missing/invalid form part
			http.Error(w, "file field 'file' is required", http.StatusBadRequest) // 400 bad request
			return                                                                // stop execution
		}
		defer file.Close() // make sure we close file stream

		// Create a temporary destination path under the OS temp directory.
		jobID := httputil.NewID()                         // create a random job id
		dest := filepath.Join(os.TempDir(), jobID+".log") // e.g., /tmp/ab12cd.log

		// Create the destination file (fail if we can’t write to /tmp).
		out, err := os.Create(dest) // open file for writing
		if err != nil {             // handle create error
			http.Error(w, "could not create temp file", http.StatusInternalServerError) // 500 internal error
			return                                                                      // stop execution
		}

		// Stream-copy from the request body to the destination file (constant memory).
		n, copyErr := io.Copy(out, file) // copy returns number of bytes written and an error
		closeErr := out.Close()          // ensure the file handle is closed

		// Clean up and report any errors from copy/close.
		if copyErr != nil || closeErr != nil { // if either operation failed
			_ = os.Remove(dest)                                                    // best-effort remove partial file
			http.Error(w, "failed to save upload", http.StatusInternalServerError) // 500 internal error
			return                                                                 // stop execution
		}

		// Parse the saved file (summary, timeline, and a bounded number of rows).
		const (
			maxRowsScan = 100_000 // stop scanning after this many lines (performance guard)
			keepRows    = 5_000   // keep only the first N events for table (memory guard)
		)
		sum, timeline, rows, perr := parse.ParseTSVRows(dest, maxRowsScan, keepRows)
		if perr != nil {
			_ = os.Remove(dest)
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}

		// Run a tiny, explainable anomaly detector over the parsed rows.
		const maxAnoms = 50 // keep payload small; UI can highlight top findings
		anoms := analyze.DetectRateSpikes(rows, maxAnoms)

		// Optional transparency note if we truncated rows.
		note := ""
		if sum.Lines > keepRows {
			note = "Rows are truncated for display (showing first 5000). Summary/anomalies are computed over scanned portion."
		}

		// Build the response payload including anomalies.
		resp := Results{
			JobID:     jobID,
			Filename:  header.Filename,
			SizeBytes: n,
			SavedTo:   dest,
			Received:  time.Now().UTC().Format(time.RFC3339),
			Summary:   sum,
			Timeline:  timeline,
			Rows:      rows,
			Anomalies: anoms, // include anomaly findings
			Note:      note,
		}

		// Return 200 OK + JSON describing what we saved and what we parsed.
		httputil.JSON(w, http.StatusOK, resp) // marshal payload as JSON
	})
}
