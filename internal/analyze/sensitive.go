// Package analyze: simple, explainable detectors.
// This file flags repeated access to "sensitive" paths (admin/login/git/etc.) from the same source IP.
//
// Rationale:
//
//	Repeated hits to sensitive endpoints (admin panels, login, hidden VCS dirs)
//	in a short window often indicate reconnaissance or brute-force attempts.
package analyze

import (
	"math"
	"sort"    // stable output
	"strings" // case-insensitive prefix checks
	"time"    // time windowing

	"github.com/allensuvorov/tenexlog/internal/parse" // Event rows (TS, SrcIP, Path, etc.)
)

// SensitivityList holds the path patterns we consider sensitive.
var SensitivityList = []string{
	"/admin", "/login", "/wp-admin", "/wp-login", "/xmlrpc.php",
	"/.git", "/.env", "/.DS_Store", "/.well-known", "/server-status",
	"/phpmyadmin", "/manager", "/actuator", "/console",
}

// AnomalySensitive describes a sensitive-path pattern hit by an IP.
type AnomalySensitive struct {
	Kind       string    `json:"kind"`       // "sensitive_paths"
	SrcIP      string    `json:"srcIp"`      // source IP
	FirstSeen  time.Time `json:"firstSeen"`  // first matching hit (UTC)
	LastSeen   time.Time `json:"lastSeen"`   // last matching hit (UTC)
	Hits       int       `json:"hits"`       // number of hits to sensitive paths
	UniquePref int       `json:"uniquePref"` // number of distinct sensitive prefixes matched
	Confidence float64   `json:"confidence"` // simple mapping from hit count (0..1)
	Reason     string    `json:"reason"`     // human explanation
}

// DetectSensitivePaths scans rows and, for each IP, counts hits to a curated list of sensitive prefixes.
// It returns findings where hits >= minHits or unique prefixes >= minUnique.
func DetectSensitivePaths(rows []parse.Event, minHits, minUnique int) []AnomalySensitive {
	// ip -> {prefix -> count}
	type prefCount map[string]int
	ipToCounts := make(map[string]prefCount)
	ipFirst := make(map[string]time.Time)
	ipLast := make(map[string]time.Time)

	// Normalize prefixes for case-insensitive startswith checks.
	prefixes := make([]string, len(SensitivityList))
	for i, p := range SensitivityList {
		prefixes[i] = strings.ToLower(p)
	}

	// Walk rows, collect hits per IP and track first/last timestamps.
	for _, ev := range rows {
		if ev.SrcIP == "" || ev.Path == "" || ev.TS.IsZero() {
			continue // need IP, path, ts
		}
		lpath := strings.ToLower(ev.Path)
		matched := "" // which prefix matched (if any)
		for _, pref := range prefixes {
			if strings.HasPrefix(lpath, pref) {
				matched = pref
				break
			}
		}
		if matched == "" {
			continue // not sensitive
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

	// Build anomalies based on thresholds.
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
			// Map hits to confidence (very simple: 1 - exp(-hits/10)).
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

	// Stable order: newest first.
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
