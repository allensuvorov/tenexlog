package upload

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/allensuvorov/tenexlog/internal/analyze"
	"github.com/allensuvorov/tenexlog/internal/httputil"
	"github.com/allensuvorov/tenexlog/internal/parse"
)

type anyAnom struct {
	Kind       string     `json:"kind"`
	SrcIP      string     `json:"srcIp"`
	Minute     *time.Time `json:"minute,omitempty"`
	FirstSeen  *time.Time `json:"firstSeen,omitempty"`
	LastSeen   *time.Time `json:"lastSeen,omitempty"`
	Count      *int       `json:"count,omitempty"`
	Baseline   *float64   `json:"baseline,omitempty"`
	Z          *float64   `json:"z,omitempty"`
	Hits       *int       `json:"hits,omitempty"`
	UniquePref *int       `json:"uniquePref,omitempty"`
	Confidence float64    `json:"confidence"`
	Reason     string     `json:"reason"`
}

type Results struct {
	JobID     string         `json:"jobId"`
	Filename  string         `json:"filename"`
	SizeBytes int64          `json:"sizeBytes"`
	SavedTo   string         `json:"savedTo"`
	Received  string         `json:"received"`
	Summary   parse.Summary  `json:"summary"`
	Timeline  []parse.Bucket `json:"timeline"`
	Rows      []parse.Event  `json:"rows"`
	Anomalies []anyAnom      `json:"anomalies"`
	Note      string         `json:"note,omitempty"`
}

// func Handler() http.Handler {
// return http.HandlerFunc(

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Println("Upload and analyse Handler - start")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file field 'file' is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	jobID := httputil.NewID()
	dest := filepath.Join(os.TempDir(), jobID+".log")

	out, err := os.Create(dest)
	if err != nil {
		http.Error(w, "could not create temp file", http.StatusInternalServerError)
		return
	}

	n, copyErr := io.Copy(out, file)
	closeErr := out.Close()

	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dest)
		http.Error(w, "failed to save upload", http.StatusInternalServerError)
		return
	}

	const (
		maxRowsScan = 100_000
		keepRows    = 5_000
	)
	sum, timeline, rows, perr := parse.ParseTSVRows(dest, maxRowsScan, keepRows)
	if perr != nil {
		_ = os.Remove(dest)
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}

	const maxAnoms = 50
	rateAnoms := analyze.DetectRateSpikes(rows, maxAnoms)

	const (
		minHits   = 5
		minUnique = 2
	)
	sensAnoms := analyze.DetectSensitivePaths(rows, minHits, minUnique)

	merged := make([]anyAnom, 0, len(rateAnoms)+len(sensAnoms))

	for _, a := range rateAnoms {
		m := a.Minute
		c := a.Count
		b := a.Baseline
		z := a.Z
		merged = append(merged, anyAnom{
			Kind:       a.Kind,
			SrcIP:      a.SrcIP,
			Minute:     &m,
			Count:      &c,
			Baseline:   &b,
			Z:          &z,
			Confidence: a.Confidence,
			Reason:     a.Reason,
		})
	}

	for _, s := range sensAnoms {
		fs, ls := s.FirstSeen, s.LastSeen
		h, u := s.Hits, s.UniquePref
		merged = append(merged, anyAnom{
			Kind:       s.Kind,
			SrcIP:      s.SrcIP,
			FirstSeen:  &fs,
			LastSeen:   &ls,
			Hits:       &h,
			UniquePref: &u,
			Confidence: s.Confidence,
			Reason:     s.Reason,
		})
	}

	if len(merged) > maxAnoms {
		merged = merged[:maxAnoms]
	}

	if merged == nil {
		merged = []anyAnom{}
	}

	note := ""
	if sum.Lines > keepRows {
		note = "Rows are truncated for display (showing first 5000). Summary/anomalies are computed over the scanned portion."
	}

	resp := Results{
		JobID:     jobID,
		Filename:  header.Filename,
		SizeBytes: n,
		SavedTo:   dest,
		Received:  time.Now().UTC().Format(time.RFC3339),
		Summary:   sum,
		Timeline:  timeline,
		Rows:      rows,
		Anomalies: merged,
		Note:      note,
	}

	httputil.JSON(w, http.StatusOK, resp)
	log.Println("Upload and analyse Handler - end")
}

// )
// }
