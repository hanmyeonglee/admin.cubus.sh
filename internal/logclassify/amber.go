package logclassify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

	AmberDefaultModel = "amber-150m"

	amberMaxServiceBytes  = 64
	amberMaxLevelBytes    = 16
	amberMaxClientIPBytes = 64
	amberMaxHostBytes     = 128
	amberMaxRequestBytes  = 512
	amberMaxUABytes       = 256
	amberMaxRefererBytes  = 256
	amberMaxMsgBytes      = 400
	amberMaxErrorRunes    = 256

	AmberPrompt = "Classify the security and operational risk category of this server container log entry."
)

// AmberLabels defines the 4-class security/operational label descriptions sent to Amber-150M.
var AmberLabels = map[string]string{
	"normal":            "Routine healthy HTTP request, normal healthcheck, or benign operational info log",
	"operational_error": "Application bug, timeout, database error, crash, or 5xx server failure without malicious intent",
	"suspicious_recon":  "Automated vulnerability scanner, hidden file probing such as .env or wp-login, or repeated auth failures",
	"malicious_attack":  "Active exploit attempt such as SQL injection, XSS, path traversal, command injection, SSRF, JNDI/Log4Shell, or CSRF/auth attack",
}

type amberClassifyRequest struct {
	Model  string            `json:"model"`
	Input  []string          `json:"input"`
	Labels map[string]string `json:"labels"`
	Prompt string            `json:"prompt"`
}

type amberPrediction struct {
	Label string   `json:"label"`
	Score *float64 `json:"score"`
}

type amberClassifyDataItem struct {
	Object      string            `json:"object,omitempty"`
	Index       *int              `json:"index"`
	Prediction  string            `json:"prediction,omitempty"`
	Score       *float64          `json:"score,omitempty"`
	Predictions []amberPrediction `json:"predictions,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type amberClassifyResponse struct {
	Object string                  `json:"object,omitempty"`
	Model  string                  `json:"model"`
	Data   []amberClassifyDataItem `json:"data"`
	Usage  *AmberUsage             `json:"usage,omitempty"`
}

// AmberClassifyParsed holds the parsed result of choice POST /admin/v1/classify.
type AmberClassifyParsed struct {
	Model   string
	Results map[int]AmberResult
	Usage   *AmberUsage
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

// BuildAmberClassifyRequest builds the JSON payload for choice POST /admin/v1/classify
// using a strict per-item and total UTF-8/JSON byte budget so HTML/UTF-8 expansion cannot exceed MaxAmberBodyBytes.
// Input strings correspond 1:1 with indices.
func BuildAmberClassifyRequest(entries []LogEntry, indices []int, model string) ([]byte, error) {
	if len(indices) == 0 || len(indices) > MaxAmberBatch {
		return nil, fmt.Errorf("amber batch size %d out of range (1..%d)", len(indices), MaxAmberBatch)
	}
	model = sanitizeSingleLine(model)
	if model == "" {
		model = AmberDefaultModel
	}
	baseRaw, err := marshalJSONNoEscapeHTML(amberClassifyRequest{
		Model:  model,
		Input:  []string{},
		Labels: AmberLabels,
		Prompt: AmberPrompt,
	})
	if err != nil {
		return nil, err
	}
	const inputSeparatorOverhead = 2
	remaining := MaxAmberBodyBytes - len(baseRaw)
	perItemBudget := remaining/len(indices) - inputSeparatorOverhead
	if perItemBudget > MaxAmberItemBytes {
		perItemBudget = MaxAmberItemBytes
	}
	if perItemBudget < 64 {
		return nil, fmt.Errorf("amber classify payload exceeds %d bytes", MaxAmberBodyBytes)
	}

	seen := make(map[int]struct{}, len(indices))
	inputs := make([]string, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(entries) {
			return nil, fmt.Errorf("amber item index %d out of range", idx)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("duplicate amber item index %d", idx)
		}
		seen[idx] = struct{}{}
		text := clampJSONEncodedString(BuildAmberText(entries[idx]), perItemBudget)
		inputs = append(inputs, text)
	}
	payload := amberClassifyRequest{
		Model:  model,
		Input:  inputs,
		Labels: AmberLabels,
		Prompt: AmberPrompt,
	}
	raw, err := marshalJSONNoEscapeHTML(payload)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxAmberBodyBytes {
		return nil, fmt.Errorf("amber classify payload exceeds %d bytes", MaxAmberBodyBytes)
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

func validateAmberScore(v float64) (float64, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0.0 || v > 1.0 {
		return 0, fmt.Errorf("invalid amber score %v (expected finite value in [0, 1])", v)
	}
	if v == 0 {
		return 0, nil
	}
	return v, nil
}

func sanitizeAmberError(raw string) string {
	clean := sanitizeSingleLine(raw)
	if clean == "" {
		return "classification failed"
	}
	if utf8.RuneCountInString(clean) <= amberMaxErrorRunes {
		return clean
	}
	return truncateRunes(clean, amberMaxErrorRunes-3) + "..."
}

// ParseAmberClassifyResponse parses choice's POST /admin/v1/classify response and maps each data item's
// positional index back to selectedIndices[item.Index].
func ParseAmberClassifyResponse(raw []byte, selectedIndices []int) (AmberClassifyParsed, error) {
	var resp amberClassifyResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return AmberClassifyParsed{}, fmt.Errorf("decode amber response: %w", err)
	}
	return validateAndMapAmberResponse(resp, selectedIndices)
}

func validateAndMapAmberResponse(resp amberClassifyResponse, selectedIndices []int) (AmberClassifyParsed, error) {
	if len(selectedIndices) == 0 {
		return AmberClassifyParsed{}, errors.New("no selected indices provided")
	}
	seenEntry := make(map[int]struct{}, len(selectedIndices))
	for _, entryIdx := range selectedIndices {
		if entryIdx < 0 {
			return AmberClassifyParsed{}, fmt.Errorf("invalid selected entry index %d", entryIdx)
		}
		if _, dup := seenEntry[entryIdx]; dup {
			return AmberClassifyParsed{}, fmt.Errorf("duplicate selected entry index %d", entryIdx)
		}
		seenEntry[entryIdx] = struct{}{}
	}

	if obj := strings.TrimSpace(resp.Object); obj != "" && obj != "list" {
		return AmberClassifyParsed{}, fmt.Errorf("unexpected amber response object %q", obj)
	}

	model := sanitizeSingleLine(resp.Model)
	var usage *AmberUsage
	if resp.Usage != nil {
		if resp.Usage.PromptTokens < 0 || resp.Usage.TotalTokens < 0 {
			return AmberClassifyParsed{}, errors.New("amber classifier returned negative token usage")
		}
		u := *resp.Usage
		usage = &u
	}

	if len(resp.Data) == 0 {
		return AmberClassifyParsed{}, errors.New("amber classifier returned empty data")
	}
	if len(resp.Data) != len(selectedIndices) {
		return AmberClassifyParsed{}, fmt.Errorf("amber classifier returned %d items for %d inputs", len(resp.Data), len(selectedIndices))
	}

	seenIdx := make([]bool, len(selectedIndices))
	out := make(map[int]AmberResult, len(resp.Data))

	for i, item := range resp.Data {
		if item.Index == nil {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier data[%d] missing index", i)
		}
		idx := *item.Index
		if idx < 0 || idx >= len(selectedIndices) {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d out of range [0, %d)", idx, len(selectedIndices))
		}
		if seenIdx[idx] {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier returned duplicate item index %d", idx)
		}
		seenIdx[idx] = true
		entryIdx := selectedIndices[idx]

		if item.Error != "" {
			out[entryIdx] = AmberResult{
				Evaluated: false,
				Error:     sanitizeAmberError(item.Error),
			}
			continue
		}

		if obj := strings.TrimSpace(item.Object); obj != "" && obj != "classification" {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d has unexpected object %q", idx, obj)
		}

		choice := sanitizeSingleLine(item.Prediction)
		if choice == "" {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d missing prediction", idx)
		}

		var probs map[string]float64
		if len(item.Predictions) > 0 {
			probs = make(map[string]float64, len(item.Predictions))
			for j, p := range item.Predictions {
				lbl := sanitizeSingleLine(p.Label)
				if lbl == "" {
					return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d predictions[%d] missing label", idx, j)
				}
				if p.Score == nil {
					return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d predictions[%d] missing score", idx, j)
				}
				sc, err := validateAmberScore(*p.Score)
				if err != nil {
					return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d label %q: %w", idx, lbl, err)
				}
				if _, dup := probs[lbl]; dup {
					return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d has duplicate prediction label %q", idx, lbl)
				}
				probs[lbl] = sc
			}
			if _, ok := probs[choice]; !ok {
				return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d prediction %q missing from predictions", idx, choice)
			}
		}

		var conf float64
		if item.Score != nil {
			sc, err := validateAmberScore(*item.Score)
			if err != nil {
				return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d: %w", idx, err)
			}
			conf = sc
			if probs == nil {
				probs = map[string]float64{choice: conf}
			}
		} else if len(probs) > 0 {
			conf = probs[choice]
		} else {
			return AmberClassifyParsed{}, fmt.Errorf("amber classifier item index %d missing score and predictions", idx)
		}

		out[entryIdx] = AmberResult{
			Choice:        choice,
			Probabilities: probs,
			Confidence:    conf,
			Evaluated:     true,
		}
	}

	return AmberClassifyParsed{
		Model:   model,
		Results: out,
		Usage:   usage,
	}, nil
}
