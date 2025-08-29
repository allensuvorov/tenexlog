// Package analyze contains tiny, explainable detectors for suspicious patterns.
// This file implements a simple "rate spike" detector per source IP per minute.
//
// Idea (fast & explainable):
//  1. Bucket events by minute and src IP → count(IP, minute).
//  2. For each IP, compute mean and stddev of its per-minute counts.
//  3. If a minute's count >= mean + 3*std (and >= a small absolute threshold), flag it.
//     - Confidence is a squashed function of z-score (bounded 0..1), easy to read.
//     - Reason is a plain-English string you can show in the UI.
package analyze

import (
	"math" // sqrt, pow
	"sort" // stable output order by time
	"strconv"
	"time" // minute timestamps

	"github.com/allensuvorov/tenexlog/internal/parse" // Event type (TS, SrcIP, etc.)
)

// Anomaly describes a single detection finding suitable for UI display.
type Anomaly struct {
	Kind       string    `json:"kind"`       // short label, e.g., "rate_spike"
	SrcIP      string    `json:"srcIp"`      // the IP we analyzed
	Minute     time.Time `json:"minute"`     // minute at which the spike occurred (UTC)
	Count      int       `json:"count"`      // requests seen in that minute
	Baseline   float64   `json:"baseline"`   // mean per-minute rate for this IP (over the file)
	Z          float64   `json:"z"`          // z-score of this minute's count vs baseline
	Confidence float64   `json:"confidence"` // 0..1 (derived from z)
	Reason     string    `json:"reason"`     // human-readable explanation
}

// DetectRateSpikes scans events and returns anomalies where an IP's per-minute rate
// is unusually high for that IP compared to its own baseline.
//
// keepTop limits the total number of anomalies returned (0 or negative = no cap).
func DetectRateSpikes(rows []parse.Event, keepTop int) []Anomaly {
	// Step 1: Build counts per IP per minute.
	type key struct {
		ip string
		m  time.Time
	}
	perMin := make(map[key]int)                  // (ip, minute) -> count
	perIPMinutes := make(map[string][]time.Time) // ip -> list of minutes observed (for stable iteration)

	for _, ev := range rows {
		if ev.SrcIP == "" || ev.TS.IsZero() {
			continue // skip rows without a source IP or timestamp
		}
		min := ev.TS.UTC().Truncate(time.Minute) // normalize to minute bucket
		k := key{ip: ev.SrcIP, m: min}
		perMin[k]++
		// Track minutes per IP (we'll sort later for stable output)
		perIPMinutes[ev.SrcIP] = append(perIPMinutes[ev.SrcIP], min)
	}

	// Deduplicate and sort minute lists per IP.
	for ip, mins := range perIPMinutes {
		perIPMinutes[ip] = uniqueSorted(mins)
	}

	// Step 2: For each IP, compute baseline mean and stddev over its minutes.
	var out []Anomaly
	const absFloor = 10 // small absolute threshold to avoid flagging tiny spikes on trivial traffic

	for ip, mins := range perIPMinutes {
		if len(mins) == 0 {
			continue
		}
		// Collect counts for this IP across all minutes.
		cnt := make([]float64, 0, len(mins))
		for _, m := range mins {
			cnt = append(cnt, float64(perMin[key{ip: ip, m: m}]))
		}
		mean, std := meanStd(cnt)

		// If std is 0 (flat series), only flag if minute count is at least 2x mean and above floor.
		for _, m := range mins {
			c := float64(perMin[key{ip: ip, m: m}])
			if c < absFloor {
				continue // below floor, ignore as noise for this prototype
			}

			var z float64
			if std > 0 {
				z = (c - mean) / std
				// OLD: if z < 3.0 { continue }
				// NEW (friendlier for small samples):
				if !(z >= 2.0 || c >= math.Max(math.Ceil(2.5*mean), absFloor)) {
					continue
				}
			} else {
				// no variance: require a clear jump
				if !(mean > 0 && c >= 2.5*mean && c >= absFloor) {
					continue
				}
				z = 3.0 // pseudo-z for confidence display
			}

			// Map z-score to [0,1] confidence using a smooth squash (1 - e^{-z/3}), clamped.
			conf := 1 - math.Exp(-z/3.0)
			if conf > 1 {
				conf = 1
			}

			// Human-readable reason.
			reason := formatReason(ip, m, int(c), mean, z)

			out = append(out, Anomaly{
				Kind:       "rate_spike",
				SrcIP:      ip,
				Minute:     m,
				Count:      int(c),
				Baseline:   round2(mean),
				Z:          round2(z),
				Confidence: round2(conf),
				Reason:     reason,
			})
		}
	}

	// Stable ordering: newest first (or choose oldest-first if you prefer).
	sort.Slice(out, func(i, j int) bool { return out[i].Minute.After(out[j].Minute) })

	// Optionally cap total anomalies to keep payloads small.
	if keepTop > 0 && len(out) > keepTop {
		out = out[:keepTop]
	}
	return out
}

// uniqueSorted returns a sorted list of unique minute timestamps.
func uniqueSorted(in []time.Time) []time.Time {
	if len(in) == 0 {
		return in
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Before(in[j]) })
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if !in[i].Equal(in[i-1]) {
			out = append(out, in[i])
		}
	}
	return out
}

// meanStd computes the arithmetic mean and (population) standard deviation of a series.
func meanStd(xs []float64) (mean, std float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	var ssq float64
	for _, x := range xs {
		d := x - mean
		ssq += d * d
	}
	std = math.Sqrt(ssq / float64(len(xs))) // population stddev is OK for this prototype
	return mean, std
}

// round2 rounds to two decimal places (for friendly JSON).
func round2(x float64) float64 {
	return math.Round(x*100) / 100
}

// formatReason builds a plain-English explanation string.
func formatReason(ip string, m time.Time, count int, mean, z float64) string {
	// Example: "Unusual request burst from 1.2.3.4 at 10:03 UTC: 120 req/min (baseline ≈ 8, z=3.4)."
	return "Unusual request burst from " + ip +
		" at " + m.UTC().Format("15:04") + " UTC: " +
		intToStr(count) + " req/min (baseline ≈ " + floatToStr(round2(mean)) +
		", z=" + floatToStr(round2(z)) + ")."
}

func intToStr(n int) string { return strconv.Itoa(n) }
func floatToStr(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
