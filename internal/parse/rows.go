package parse

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	TS     time.Time `json:"ts"`
	SrcIP  string    `json:"srcIp,omitempty"`
	Dst    string    `json:"dst,omitempty"`
	Method string    `json:"method,omitempty"`
	Path   string    `json:"path,omitempty"`
	Status int       `json:"status,omitempty"`
	Bytes  int64     `json:"bytes,omitempty"`
	UA     string    `json:"ua,omitempty"`
}

func ParseTSVRows(path string, maxRows, keepRows int) (Summary, []Bucket, []Event, error) {
	sum, timeline, err := ParseTSV(path, maxRows)
	if err != nil {
		return Summary{}, nil, nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return Summary{}, nil, nil, err
	}
	defer f.Close()

	rows := make([]Event, 0, min(keepRows, 4096))
	sc := bufio.NewScanner(f)
	const maxLine = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	seen := 0
	for sc.Scan() {
		seen++
		if maxRows > 0 && seen > maxRows {
			break
		}

		parts := strings.Split(sc.Text(), "\t")
		var ev Event

		if len(parts) > 0 {
			if ts, err := time.Parse(time.RFC3339, parts[0]); err == nil {
				ev.TS = ts.UTC()
			}
		}
		if len(parts) > 1 {
			ev.SrcIP = parts[1]
		}
		if len(parts) > 2 {
			ev.Dst = parts[2]
		}
		if len(parts) > 3 {
			ev.Method = parts[3]
		}
		if len(parts) > 4 {
			ev.Path = parts[4]
		}
		if len(parts) > 5 {
			if n, err := strconv.Atoi(parts[5]); err == nil {
				ev.Status = n
			}
		}
		if len(parts) > 6 {
			if n, err := strconv.ParseInt(parts[6], 10, 64); err == nil {
				ev.Bytes = n
			}
		}
		if len(parts) > 7 {
			ev.UA = parts[7]
		}

		if keepRows <= 0 || len(rows) < keepRows {
			rows = append(rows, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return Summary{}, nil, nil, err
	}

	return sum, timeline, rows, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
