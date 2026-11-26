package logclassify

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	burstMinHits  = 5
	burstHighHits = 15
	burstWindow   = 5 * time.Minute
)

type burstEvent struct {
	idx   int
	ts    time.Time
	hasTS bool
}

func correlateBursts(entries []LogEntry) map[int][]RuleMatch {
	ipEvents := make(map[string][]burstEvent)
	svc5xxEvents := make(map[string][]burstEvent)

	for i, e := range entries {
		if e.Structured == nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.Timestamp))
		ev := burstEvent{idx: i, ts: ts, hasTS: err == nil}

		ip := strings.TrimSpace(e.Structured.ClientIP)
		st := e.Structured.Status
		if ip != "" && ip != "-" && (st == 401 || st == 403 || st == 404) {
			ipEvents[ip] = append(ipEvents[ip], ev)
		}
		if st >= 500 && st < 600 {
			svc := strings.TrimSpace(e.Service)
			if svc != "" {
				key := svc
				if h := strings.ToLower(strings.TrimSpace(e.Structured.Host)); h != "" && h != "-" {
					key = svc + "|" + h
				}
				svc5xxEvents[key] = append(svc5xxEvents[key], ev)
			}
		}
	}

	out := make(map[int][]RuleMatch)
	for ip, evs := range ipEvents {
		flagged, maxWindowCnt := evaluateBurstWindow(evs)
		if maxWindowCnt < burstMinHits {
			continue
		}
		sev := VerdictMedium
		weight := 3
		if maxWindowCnt >= burstHighHits {
			sev = VerdictHigh
			weight = 4
		}
		match := RuleMatch{
			Engine:      EngineBurst,
			RuleID:      "BURST-IP-4XX",
			Title:       fmt.Sprintf("Client IP generated %d HTTP 401/403/404 hits within 5m window", maxWindowCnt),
			Severity:    sev,
			Category:    CategoryBurstAbuse,
			Tags:        []string{"attack.discovery", "attack.t1595"},
			MatchedData: sanitizeMatchedData(fmt.Sprintf("client_ip=%s count=%d", ip, maxWindowCnt)),
			weight:      weight,
		}
		for _, idx := range flagged {
			out[idx] = append(out[idx], match)
		}
	}

	for svcKey, evs := range svc5xxEvents {
		flagged, maxWindowCnt := evaluateBurstWindow(evs)
		if maxWindowCnt < burstMinHits {
			continue
		}
		svcLabel := strings.ReplaceAll(svcKey, "|", " · ")
		match := RuleMatch{
			Engine:      EngineBurst,
			RuleID:      "BURST-SVC-5XX",
			Title:       fmt.Sprintf("Service %q emitted %d HTTP 5xx errors within 5m window", svcLabel, maxWindowCnt),
			Severity:    VerdictMedium,
			Category:    CategoryBurstAbuse,
			Tags:        []string{"attack.impact"},
			MatchedData: sanitizeMatchedData(fmt.Sprintf("target=%s count=%d", svcLabel, maxWindowCnt)),
			weight:      3,
		}
		for _, idx := range flagged {
			out[idx] = append(out[idx], match)
		}
	}

	return out
}

// evaluateBurstWindow returns the entry indices participating in any >= burstMinHits
// 5-minute window (or across untimestamped entries as a fallback) and the peak window count.
func evaluateBurstWindow(evs []burstEvent) ([]int, int) {
	if len(evs) < burstMinHits {
		return nil, 0
	}
	var timed, untimed []burstEvent
	for _, ev := range evs {
		if ev.hasTS {
			timed = append(timed, ev)
		} else {
			untimed = append(untimed, ev)
		}
	}

	maxCnt := 0
	flaggedSet := make(map[int]struct{})

	if len(timed) >= burstMinHits {
		sort.Slice(timed, func(i, j int) bool {
			if !timed[i].ts.Equal(timed[j].ts) {
				return timed[i].ts.Before(timed[j].ts)
			}
			return timed[i].idx < timed[j].idx
		})
		left := 0
		for right := 0; right < len(timed); right++ {
			for timed[right].ts.Sub(timed[left].ts) > burstWindow {
				left++
			}
			winLen := right - left + 1
			if winLen > maxCnt {
				maxCnt = winLen
			}
			if winLen >= burstMinHits {
				for k := left; k <= right; k++ {
					flaggedSet[timed[k].idx] = struct{}{}
				}
			}
		}
	}

	if len(untimed) >= burstMinHits {
		if len(untimed) > maxCnt {
			maxCnt = len(untimed)
		}
		for _, ev := range untimed {
			flaggedSet[ev.idx] = struct{}{}
		}
	}

	if maxCnt < burstMinHits {
		return nil, 0
	}
	flagged := make([]int, 0, len(flaggedSet))
	for idx := range flaggedSet {
		flagged = append(flagged, idx)
	}
	sort.Ints(flagged)
	return flagged, maxCnt
}
