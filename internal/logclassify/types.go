package logclassify

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	VerdictClean    = "clean"
	VerdictLow      = "low"
	VerdictMedium   = "medium"
	VerdictHigh     = "high"
	VerdictCritical = "critical"

	CategoryClean           = "clean"
	CategorySQLi            = "sqli"
	CategoryXSS             = "xss"
	CategoryLFITraversal    = "lfi_traversal"
	CategoryRCEInjection    = "rce_injection"
	CategoryScannerRecon    = "scanner_recon"
	CategoryAuthAbuse       = "auth_abuse"
	CategoryDBSecurity      = "db_security"
	CategoryServiceError    = "service_error"
	CategoryProtocolAnomaly = "protocol_anomaly"
	CategoryBurstAbuse      = "burst_abuse"

	EngineOWASPCRS = "owasp_crs"
	EngineSigma    = "sigma"
	EngineBurst    = "burst"

	maxMatchesPerEntry = 12
	maxMatchedDataLen  = 200
)

// StructuredLog mirrors the structured HTTP fields emitted by ops-agent.
type StructuredLog struct {
	Host        string   `json:"host,omitempty"`
	Status      int      `json:"status,omitempty"`
	Request     string   `json:"request,omitempty"`
	RequestTime *float64 `json:"request_time,omitempty"`
	ClientIP    string   `json:"client_ip,omitempty"`
	Upstream    string   `json:"upstream,omitempty"`
	CFRay       string   `json:"cf_ray,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
	Referer     string   `json:"referer,omitempty"`
}

// LogEntry mirrors the LogEntry JSON contract produced by ops-agent.
type LogEntry struct {
	Timestamp  string         `json:"ts"`
	Service    string         `json:"service"`
	Stream     string         `json:"stream"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Structured *StructuredLog `json:"structured,omitempty"`
}

// RuleMatch describes a single rule match from OWASP CRS, Sigma, or burst correlation.
type RuleMatch struct {
	Engine      string   `json:"engine"`
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags,omitempty"`
	MatchedData string   `json:"matched_data,omitempty"`

	weight int
}

// RuleResult holds the combined rule-based classification for a single log entry.
type RuleResult struct {
	Verdict  string      `json:"verdict"`
	Category string      `json:"category"`
	Score    int         `json:"score"`
	Engines  []string    `json:"engines,omitempty"`
	Matches  []RuleMatch `json:"matches,omitempty"`
}

// AmberResult holds the Amber-150M classification result for a single log entry.
type AmberResult struct {
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
	Error         string             `json:"error,omitempty"`
	Evaluated     bool               `json:"evaluated"`
}

// EntryClassification combines rule and optional Amber AI results per entry index.
type EntryClassification struct {
	Index int          `json:"index"`
	Rule  *RuleResult  `json:"rule,omitempty"`
	Amber *AmberResult `json:"amber,omitempty"`
}

// RuleEngineInfo describes the active rule engines and versions.
type RuleEngineInfo struct {
	CorazaVersion  string `json:"coraza_version"`
	CRSVersion     string `json:"crs_version"`
	SigmaRules     int    `json:"sigma_rules"`
	BurstDetection bool   `json:"burst_detection"`
}

// ClassifySummary aggregates verdict, category, and AI label counts across a batch.
type ClassifySummary struct {
	Total        int            `json:"total"`
	RuleFlagged  int            `json:"rule_flagged"`
	AmberFlagged int            `json:"amber_flagged"`
	FlaggedTotal int            `json:"flagged_total"`
	ByVerdict    map[string]int `json:"by_verdict"`
	ByCategory   map[string]int `json:"by_category"`
	ByAmber      map[string]int `json:"by_amber"`
}

func severityRank(sev string) int {
	switch sev {
	case VerdictCritical:
		return 4
	case VerdictHigh:
		return 3
	case VerdictMedium:
		return 2
	case VerdictLow:
		return 1
	default:
		return 0
	}
}

func engineRank(eng string) int {
	switch eng {
	case EngineOWASPCRS:
		return 3
	case EngineSigma:
		return 2
	case EngineBurst:
		return 1
	default:
		return 0
	}
}

func categoryPriority(cat string) int {
	switch cat {
	case CategoryRCEInjection:
		return 10
	case CategorySQLi:
		return 9
	case CategoryXSS:
		return 8
	case CategoryLFITraversal:
		return 7
	case CategoryAuthAbuse:
		return 6
	case CategoryDBSecurity:
		return 5
	case CategoryScannerRecon:
		return 4
	case CategoryProtocolAnomaly:
		return 3
	case CategoryServiceError:
		return 2
	case CategoryBurstAbuse:
		return 1
	default:
		return 0
	}
}

func sanitizeSingleLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if r == '\r' || r == '\n' || r == '\t' || unicode.IsControl(r) {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		if unicode.IsSpace(r) {
			if !lastSpace && b.Len() > 0 {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		b.WriteRune(r)
		lastSpace = false
	}
	return strings.TrimSpace(b.String())
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || s == "" {
		return ""
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i]
		}
		count++
	}
	return s
}

func sanitizeMatchedData(s string) string {
	clean := sanitizeSingleLine(s)
	if clean == "" {
		return ""
	}
	if utf8.RuneCountInString(clean) <= maxMatchedDataLen {
		return clean
	}
	return truncateRunes(clean, maxMatchedDataLen-3) + "..."
}
