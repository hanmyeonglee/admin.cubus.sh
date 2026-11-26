package logclassify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxAmberBatch     = 50
	MaxAmberItemChars = 1500
	MaxAmberItemBytes = 4096
	MaxAmberBodyBytes = 256 << 10

	amberMaxServiceBytes  = 64
	amberMaxLevelBytes    = 16
	amberMaxClientIPBytes = 64
	amberMaxHostBytes     = 128
	amberMaxRequestBytes  = 512
	amberMaxUABytes       = 256
	amberMaxRefererBytes  = 256
	amberMaxMsgBytes      = 400

	AmberPrompt = "Classify the security and operational risk category of this server container log entry."
)

// AmberLabels defines the 4-class security/operational label descriptions sent to Amber-150M.
var AmberLabels = map[string]string{
	"normal":            "Routine healthy HTTP request, normal healthcheck, or benign operational info log",
	"operational_error": "Application bug, timeout, database error, crash, or 5xx server failure without malicious intent",
	"suspicious_recon":  "Automated vulnerability scanner, hidden file probing such as .env or wp-login, or repeated auth failures",
	"malicious_attack":  "Active exploit attempt such as SQL injection, XSS, path traversal, command injection, SSRF, JNDI/Log4Shell, or CSRF/auth attack",
}

type amberBatchItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type amberBatchRequest struct {
	Prompt string            `json:"prompt"`
	Labels map[string]string `json:"labels"`
	Items  []amberBatchItem  `json:"items"`
}

type amberBatchResponse struct {
	Model   string `json:"model"`
	Results []struct {
		ID            string             `json:"id"`
		Choice        string             `json:"choice,omitempty"`
		Probabilities map[string]float64 `json:"probabilities,omitempty"`
		Error         string             `json:"error,omitempty"`
	} `json:"results"`
}

// BuildAmberText formats a sanitized, field-bounded, safely delimited representation of a log entry for Amber-150M.
func BuildAmberText(entry LogEntry) string {
	var parts []string
	if v := formatAmberToken(entry.Service, amberMaxServiceBytes); v != "" {
		parts = append(parts, "service="+v)
	}
	if v := formatAmberToken(strings.ToLower(entry.Level), amberMaxLevelBytes); v != "" {
		parts = append(parts, "level="+v)
	}
	omitMsg := false
	if entry.Structured != nil {
		st := entry.Structured
		if st.Status > 0 {
			parts = append(parts, "status="+strconv.Itoa(st.Status))
		}
		if h := strings.TrimSpace(st.Host); h != "" && h != "-" {
			if q := formatQuotedAmberField(h, amberMaxHostBytes); q != "" {
				parts = append(parts, "host="+q)
			}
		}
		if req := strings.TrimSpace(st.Request); req != "" {
			if q := formatQuotedAmberField(req, amberMaxRequestBytes); q != "" {
				parts = append(parts, "request="+q)
			}
			if strings.EqualFold(strings.TrimSpace(entry.Service), "nginx-proxy") {
				omitMsg = true
			}
		}
		if ip := strings.TrimSpace(st.ClientIP); ip != "" && ip != "-" {
			if tok := formatAmberToken(ip, amberMaxClientIPBytes); tok != "" {
				parts = append(parts, "client_ip="+tok)
			}
		}
		if ua := strings.TrimSpace(st.UserAgent); ua != "" && ua != "-" {
			if q := formatQuotedAmberField(ua, amberMaxUABytes); q != "" {
				parts = append(parts, "ua="+q)
			}
		}
		if ref := strings.TrimSpace(st.Referer); ref != "" && ref != "-" {
			if q := formatQuotedAmberField(ref, amberMaxRefererBytes); q != "" {
				parts = append(parts, "referer="+q)
			}
		}
	}
	if !omitMsg {
		if q := formatQuotedAmberField(entry.Message, amberMaxMsgBytes); q != "" {
			parts = append(parts, "msg="+q)
		}
	}
	joined := strings.TrimSpace(strings.Join(parts, " "))
	if joined == "" {
		return "empty log entry"
	}
	return clampBytes(truncateRunes(joined, MaxAmberItemChars), MaxAmberItemBytes)
}

func formatAmberToken(raw string, maxBytes int) string {
	clean := sanitizeSingleLine(raw)
	if clean == "" {
		return ""
	}
	// Strip whitespace, quotes, and '=' so token fields cannot forge adjacent key=value pairs.
	var b strings.Builder
	b.Grow(len(clean))
	for i := 0; i < len(clean); {
		r, size := utf8.DecodeRuneInString(clean[i:])
		if r == ' ' || r == '=' || r == '"' || r == '\\' {
			i += size
			continue
		}
		if b.Len()+size > maxBytes {
			break
		}
		b.WriteString(clean[i : i+size])
		i += size
	}
	return b.String()
}

func formatQuotedAmberField(raw string, maxBytes int) string {
	clean := sanitizeSingleLine(raw)
	if clean == "" {
		return ""
	}
	clean = clampBytes(clean, maxBytes)
	var b strings.Builder
	b.Grow(len(clean) + 2)
	b.WriteByte('"')
	for i := 0; i < len(clean); {
		r, size := utf8.DecodeRuneInString(clean[i:])
		if r == '"' || r == '\\' {
			if b.Len()+2 > maxBytes+1 {
				break
			}
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		} else {
			if b.Len()+size > maxBytes+1 {
				break
			}
			b.WriteString(clean[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
	return b.String()
}

// SelectAmberIndices selects up to limit entry indices, prioritizing rule-flagged entries,
// then error/warn entries, then newest entries by timestamp.
func SelectAmberIndices(entries []LogEntry, ruleResults []RuleResult, limit int) []int {
	if limit <= 0 || len(entries) == 0 {
		return nil
	}
	if len(entries) <= limit {
		out := make([]int, len(entries))
		for i := range entries {
			out[i] = i
		}
		return out
	}

	type candidate struct {
		idx       int
		ruleScore int
		levelRank int
		tsUnix    int64
	}

	cands := make([]candidate, len(entries))
	for i, e := range entries {
		score := 0
		if i < len(ruleResults) && ruleResults[i].Verdict != VerdictClean {
			score = ruleResults[i].Score
			if score <= 0 {
				score = severityRank(ruleResults[i].Verdict)
			}
		}
		lvlRank := 0
		switch strings.ToLower(strings.TrimSpace(e.Level)) {
		case "error", "fatal", "critical":
			lvlRank = 2
		case "warn", "warning":
			lvlRank = 1
		}
		if lvlRank == 0 && e.Structured != nil {
			if e.Structured.Status >= 500 {
				lvlRank = 2
			} else if e.Structured.Status >= 400 {
				lvlRank = 1
			}
		}

		var tsUnix int64
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.Timestamp)); err == nil {
			tsUnix = t.UnixNano()
		}

		cands[i] = candidate{
			idx:       i,
			ruleScore: score,
			levelRank: lvlRank,
			tsUnix:    tsUnix,
		}
	}

	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		aFlag := a.ruleScore > 0
		bFlag := b.ruleScore > 0
		if aFlag != bFlag {
			return aFlag
		}
		if a.ruleScore != b.ruleScore {
			return a.ruleScore > b.ruleScore
		}
		if a.levelRank != b.levelRank {
			return a.levelRank > b.levelRank
		}
		if a.tsUnix != b.tsUnix {
			return a.tsUnix > b.tsUnix
		}
		return a.idx < b.idx
	})

	selected := make([]int, limit)
	for i := 0; i < limit; i++ {
		selected[i] = cands[i].idx
	}
	sort.Ints(selected)
	return selected
}

// BuildAmberBatchRequest builds the JSON payload for choice POST /admin/v1/classify/batch
// using a strict per-item and total UTF-8/JSON byte budget so HTML/UTF-8 expansion cannot exceed MaxAmberBodyBytes.
func BuildAmberBatchRequest(entries []LogEntry, indices []int) ([]byte, error) {
	if len(indices) == 0 || len(indices) > MaxAmberBatch {
		return nil, fmt.Errorf("amber batch size %d out of range (1..%d)", len(indices), MaxAmberBatch)
	}
	baseRaw, err := marshalJSONNoEscapeHTML(amberBatchRequest{
		Prompt: AmberPrompt,
		Labels: AmberLabels,
		Items:  []amberBatchItem{},
	})
	if err != nil {
		return nil, err
	}
	const itemEnvelopeOverhead = 48
	remaining := MaxAmberBodyBytes - len(baseRaw)
	perItemBudget := remaining/len(indices) - itemEnvelopeOverhead
	if perItemBudget > MaxAmberItemBytes {
		perItemBudget = MaxAmberItemBytes
	}
	if perItemBudget < 64 {
		return nil, fmt.Errorf("amber batch payload exceeds %d bytes", MaxAmberBodyBytes)
	}

	items := make([]amberBatchItem, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(entries) {
			return nil, fmt.Errorf("amber item index %d out of range", idx)
		}
		text := clampJSONEncodedString(BuildAmberText(entries[idx]), perItemBudget)
		items = append(items, amberBatchItem{
			ID:   strconv.Itoa(idx),
			Text: text,
		})
	}
	payload := amberBatchRequest{
		Prompt: AmberPrompt,
		Labels: AmberLabels,
		Items:  items,
	}
	raw, err := marshalJSONNoEscapeHTML(payload)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxAmberBodyBytes {
		return nil, fmt.Errorf("amber batch payload exceeds %d bytes", MaxAmberBodyBytes)
	}
	return raw, nil
}

func marshalJSONNoEscapeHTML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// clampJSONEncodedString ensures that the JSON-encoded form of s (without HTML escaping)
// fits within maxJSONBytes while preserving valid UTF-8 rune boundaries.
func clampJSONEncodedString(s string, maxJSONBytes int) string {
	if maxJSONBytes <= 2 {
		return ""
	}
	encoded, err := marshalJSONNoEscapeHTML(s)
	if err == nil && len(encoded) <= maxJSONBytes {
		return s
	}
	// Binary search the longest UTF-8-valid prefix whose JSON encoding fits within maxJSONBytes.
	lo, hi := 0, len(s)
	best := ""
	for lo <= hi {
		mid := lo + (hi-lo)/2
		cand := clampBytes(s, mid)
		enc, err := marshalJSONNoEscapeHTML(cand)
		if err == nil && len(enc) <= maxJSONBytes {
			if len(cand) > len(best) {
				best = cand
			}
			lo = mid + 1
		} else {
			if mid == 0 {
				break
			}
			hi = mid - 1
		}
	}
	return best
}

// ParseAmberBatchResponse parses and maps choice's /admin/v1/classify/batch response by entry index.
func ParseAmberBatchResponse(raw []byte, selectedIndices []int) (string, map[int]AmberResult, error) {
	var resp amberBatchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", nil, fmt.Errorf("decode amber response: %w", err)
	}
	if len(resp.Results) == 0 {
		return resp.Model, nil, errors.New("amber classifier returned empty results")
	}

	allowed := make(map[int]struct{}, len(selectedIndices))
	for _, idx := range selectedIndices {
		allowed[idx] = struct{}{}
	}

	out := make(map[int]AmberResult, len(resp.Results))
	for _, item := range resp.Results {
		idx, err := strconv.Atoi(strings.TrimSpace(item.ID))
		if err != nil {
			continue
		}
		if _, ok := allowed[idx]; !ok {
			continue
		}
		if item.Error != "" {
			out[idx] = AmberResult{
				Evaluated: false,
				Error:     sanitizeSingleLine(item.Error),
			}
			continue
		}
		conf := 0.0
		if item.Probabilities != nil {
			if p, ok := item.Probabilities[item.Choice]; ok {
				conf = p
			} else {
				for _, p := range item.Probabilities {
					if p > conf {
						conf = p
					}
				}
			}
		}
		out[idx] = AmberResult{
			Choice:        item.Choice,
			Probabilities: item.Probabilities,
			Confidence:    conf,
			Evaluated:     item.Choice != "",
		}
	}
	if len(out) == 0 {
		return resp.Model, nil, errors.New("amber classifier returned no matching item IDs")
	}
	return resp.Model, out, nil
}
