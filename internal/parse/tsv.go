package parse

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"time"
)

type Summary struct {
	Lines     int       `json:"lines"`
	UniqueIPs int       `json:"uniqueIPs"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
}

type Bucket struct {
	T     time.Time `json:"t"`
	Count int       `json:"count"`
}

func ParseTSV(path string, maxRows int) (Summary, []Bucket, error) {
	var sum Summary
	seenIPs := make(map[string]struct{})
	minuteCounts := make(map[time.Time]int)

	f, err := os.Open(path)
	if err != nil {
		return Summary{}, nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	const maxLine = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	for sc.Scan() {
		line := sc.Text()
		sum.Lines++
		if maxRows > 0 && sum.Lines > maxRows {
			break
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		ts, err := time.Parse(time.RFC3339, parts[0])
		if err != nil {
			continue
		}
		ts = ts.UTC()

		if sum.Start.IsZero() || ts.Before(sum.Start) {
			sum.Start = ts
		}
		if sum.End.IsZero() || ts.After(sum.End) {
			sum.End = ts
		}

		src := parts[1]
		if _, ok := seenIPs[src]; !ok {
			seenIPs[src] = struct{}{}
		}

		min := ts.Truncate(time.Minute)
		minuteCounts[min]++
	}
	if err := sc.Err(); err != nil {
		return Summary{}, nil, err
	}

	sum.UniqueIPs = len(seenIPs)

	if len(minuteCounts) == 0 {
		return sum, nil, nil
	}
	keys := make([]time.Time, 0, len(minuteCounts))
	for k := range minuteCounts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Before(keys[j])
	})
	timeline := make([]Bucket, 0, len(keys))
	for _, k := range keys {
		timeline = append(timeline, Bucket{
			T:     k,
			Count: minuteCounts[k],
		})
	}

	return sum, timeline, nil
}
