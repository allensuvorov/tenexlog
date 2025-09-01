package analyze

import (
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/allensuvorov/tenexlog/internal/parse"
)

type Anomaly struct {
	Kind       string    `json:"kind"`
	SrcIP      string    `json:"srcIp"`
	Minute     time.Time `json:"minute"`
	Count      int       `json:"count"`
	Baseline   float64   `json:"baseline"`
	Z          float64   `json:"z"`
	Confidence float64   `json:"confidence"`
	Reason     string    `json:"reason"`
}

func DetectRateSpikes(rows []parse.Event, keepTop int) []Anomaly {
	type key struct {
		ip string
		m  time.Time
	}
	perMin := make(map[key]int)
	perIPMinutes := make(map[string][]time.Time)

	for _, ev := range rows {
		if ev.SrcIP == "" || ev.TS.IsZero() {
			continue
		}
		min := ev.TS.UTC().Truncate(time.Minute)
		k := key{ip: ev.SrcIP, m: min}
		perMin[k]++
		perIPMinutes[ev.SrcIP] = append(perIPMinutes[ev.SrcIP], min)
	}

	for ip, mins := range perIPMinutes {
		perIPMinutes[ip] = uniqueSorted(mins)
	}

	var out []Anomaly
	const absFloor = 10

	for ip, mins := range perIPMinutes {
		if len(mins) == 0 {
			continue
		}
		cnt := make([]float64, 0, len(mins))
		for _, m := range mins {
			cnt = append(cnt, float64(perMin[key{ip: ip, m: m}]))
		}
		mean, std := meanStd(cnt)

		for _, m := range mins {
			c := float64(perMin[key{ip: ip, m: m}])
			if c < absFloor {
				continue
			}

			var z float64
			if std > 0 {
				z = (c - mean) / std
				if !(z >= 2.0 || c >= math.Max(math.Ceil(2.5*mean), absFloor)) {
					continue
				}
			} else {
				if !(mean > 0 && c >= 2.5*mean && c >= absFloor) {
					continue
				}
				z = 3.0
			}

			conf := 1 - math.Exp(-z/3.0)
			if conf > 1 {
				conf = 1
			}
			if std == 0 && conf < 0.8 {
				conf = 0.8
			}

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

	sort.Slice(out, func(i, j int) bool { return out[i].Minute.After(out[j].Minute) })

	if keepTop > 0 && len(out) > keepTop {
		out = out[:keepTop]
	}
	return out
}

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
	std = math.Sqrt(ssq / float64(len(xs)))
	return mean, std
}

func round2(x float64) float64 {
	return math.Round(x*100) / 100
}

func formatReason(ip string, m time.Time, count int, mean, z float64) string {
	return "Unusual request burst from " + ip +
		" at " + m.UTC().Format("15:04") + " UTC: " +
		intToStr(count) + " req/min (baseline ≈ " + floatToStr(round2(mean)) +
		", z=" + floatToStr(round2(z)) + ")."
}

func intToStr(n int) string { return strconv.Itoa(n) }
func floatToStr(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
