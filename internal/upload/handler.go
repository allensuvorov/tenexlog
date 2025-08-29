// Package upload exposes the HTTP handler for file uploads.
package upload

import ( // imports required by the handler
	"io"            // for io.Copy
	"net/http"      // for HTTP handler signatures
	"os"            // for creating/removing files
	"path/filepath" // for building a path under /tmp
	"time"          // for timestamps in the response

	"github.com/allensuvorov/tenexlog/internal/httputil" // local JSON helper and ID generator
)

// Results is the minimal JSON we return after accepting an upload.
type Results struct { // public JSON struct (exported fields)
	JobID     string `json:"jobId"`     // unique ID for this upload "job"
	Filename  string `json:"filename"`  // original filename (client-provided)
	SizeBytes int64  `json:"sizeBytes"` // size we streamed to disk (in bytes)
	SavedTo   string `json:"savedTo"`   // absolute path of the temp file (for debugging; remove later if desired)
	Received  string `json:"received"`  // RFC3339 timestamp when we handled the upload
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

		// Build the response payload (stub for now; parsing will come next).
		resp := Results{ // initialize Results struct
			JobID:     jobID,                                 // echo the generated job ID
			Filename:  header.Filename,                       // original filename from client
			SizeBytes: n,                                     // number of bytes saved
			SavedTo:   dest,                                  // absolute path on disk (useful for manual testing)
			Received:  time.Now().UTC().Format(time.RFC3339), // standardized timestamp in UTC
		}

		// Return 200 OK + JSON describing what we saved.
		httputil.JSON(w, http.StatusOK, resp) // marshal payload as JSON
	})
}
