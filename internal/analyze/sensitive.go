package analyze

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/allensuvorov/tenexlog/internal/parse"
)

var SensitivityList = []string{
	"/admin", "/login", "/wp-admin", "/wp-login", "/xmlrpc.php",
	"/.git", "/.env", "/.DS_Store", "/.well-known", "/server-status",
	"/phpmyadmin", "/manager", "/actuator", "/console",
}

type AnomalySensitive struct {
	Kind       string    `json:"kind"`
	SrcIP      string    `json:"srcIp"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Hits       int       `json:"hits"`
	UniquePref int       `json:"uniquePref"`
	Confidence float64   `json:"confidence"`
	Reason     string    `json:"reason"`
}

func DetectSensitivePaths(rows []parse.Event, minHits, minUnique int) []AnomalySensitive {
	type prefCount map[string]int
	ipToCounts := make(map[string]prefCount)
	ipFirst := make(map[string]time.Time)
	ipLast := make(map[string]time.Time)

	prefixes := make([]string, len(SensitivityList))
	for i, p := range SensitivityList {
		prefixes[i] = strings.ToLower(p)
	}

	for _, ev := range rows {
		if ev.SrcIP == "" || ev.Path == "" || ev.TS.IsZero() {
			continue
		}
		lpath := strings.ToLower(ev.Path)
		matched := ""
		for _, pref := range prefixes {
			if strings.HasPrefix(lpath, pref) {
				matched = pref
				break
			}
		}
		if matched == "" {
			continue
		}

		if _, ok := ipToCounts[ev.SrcIP]; !ok {
			ipToCounts[ev.SrcIP] = make(prefCount)
		}
		ipToCounts[ev.SrcIP][matched]++
		t := ev.TS.UTC()
		if ipFirst[ev.SrcIP].IsZero() || t.Before(ipFirst[ev.SrcIP]) {
			ipFirst[ev.SrcIP] = t
		}
		if ipLast[ev.SrcIP].IsZero() || t.After(ipLast[ev.SrcIP]) {
			ipLast[ev.SrcIP] = t
		}
	}

	out := make([]AnomalySensitive, 0)
	for ip, pc := range ipToCounts {
		var hits, uniq int
		for range pc {
			uniq++
		}
		for _, n := range pc {
			hits += n
		}
		if hits >= minHits || uniq >= minUnique {
			conf := 1 - expNeg(float64(hits)/10.0)
			reason := buildSensitiveReason(ip, hits, uniq, ipFirst[ip], ipLast[ip])
			out = append(out, AnomalySensitive{
				Kind:       "sensitive_paths",
				SrcIP:      ip,
				FirstSeen:  ipFirst[ip],
				LastSeen:   ipLast[ip],
				Hits:       hits,
				UniquePref: uniq,
				Confidence: round2(conf),
				Reason:     reason,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func expNeg(x float64) float64 {
	return math.Exp(-x)
}

func buildSensitiveReason(ip string, hits, uniq int, first, last time.Time) string {
	win := last.Sub(first).Minutes()
	if win < 0 {
		win = 0
	}
	return "Sensitive paths probed from " + ip +
		": " + intToStr(hits) + " hits across " + intToStr(uniq) +
		" sensitive prefixes over ~" + intToStr(int(win)) + " minute(s)."
}
