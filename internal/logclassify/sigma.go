package logclassify

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/runreveal/sigmalite"
)

//go:embed rules/*.yml
var embeddedSigmaRulesFS embed.FS

var sigmaCategoryByID = map[string]string{
	"a1f04e10-8a7e-4b3c-9c12-100000000001": CategoryScannerRecon,
	"a1f04e10-8a7e-4b3c-9c12-100000000002": CategoryRCEInjection,
	"a1f04e10-8a7e-4b3c-9c12-100000000003": CategoryScannerRecon,
	"a1f04e10-8a7e-4b3c-9c12-100000000004": CategoryAuthAbuse,
	"a1f04e10-8a7e-4b3c-9c12-100000000005": CategoryDBSecurity,
	"a1f04e10-8a7e-4b3c-9c12-100000000006": CategoryServiceError,
	"a1f04e10-8a7e-4b3c-9c12-100000000007": CategoryServiceError,
	"a1f04e10-8a7e-4b3c-9c12-100000000008": CategoryAuthAbuse,
	"a1f04e10-8a7e-4b3c-9c12-100000000009": CategoryRCEInjection,
}

type sigmaRuleEntry struct {
	file     string
	rule     *sigmalite.Rule
	category string
	severity string
	weight   int
}

type sigmaInspector struct {
	rules []sigmaRuleEntry
}

func newSigmaInspector() (*sigmaInspector, error) {
	paths, err := fs.Glob(embeddedSigmaRulesFS, "rules/*.yml")
	if err != nil {
		return nil, fmt.Errorf("list embedded sigma rules: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no embedded sigma rules found")
	}
	sort.Strings(paths)

	warmupEntries := []*sigmalite.LogEntry{
		{
			Message: "healthcheck ok",
			Fields: map[string]string{
				"service":    "admin",
				"stream":     "stdout",
				"level":      "info",
				"message":    "healthcheck ok",
				"host":       "cubus.sh",
				"status":     "200",
				"request":    "GET /healthz HTTP/1.1",
				"method":     "GET",
				"uri":        "/healthz",
				"client_ip":  "127.0.0.1",
				"user_agent": "Healthcheck/1.0",
				"referer":    "",
				"cf_ray":     "warm",
			},
		},
		{
			Message: "INF Registered tunnel connection",
			Fields: map[string]string{
				"service": "cloudflared",
				"stream":  "stdout",
				"level":   "info",
				"message": "INF Registered tunnel connection",
			},
		},
		{
			Message: "database system is ready to accept connections",
			Fields: map[string]string{
				"service": "postgres",
				"stream":  "stderr",
				"level":   "info",
				"message": "database system is ready to accept connections",
			},
		},
		{
			Message: "401 admin.cubus.sh GET /favicon.ico HTTP/2",
			Fields: map[string]string{
				"service": "nginx-proxy",
				"stream":  "stdout",
				"level":   "warn",
				"message": "401 admin.cubus.sh GET /favicon.ico HTTP/2",
				"host":    "admin.cubus.sh",
				"status":  "401",
				"request": "GET /favicon.ico HTTP/2",
				"method":  "GET",
				"uri":     "/favicon.ico",
			},
		},
		{
			Message: "warn state check",
			Fields: map[string]string{
				"service": "admin",
				"stream":  "stdout",
				"level":   "warn",
				"message": "warn state check",
			},
		},
	}

	rules := make([]sigmaRuleEntry, 0, len(paths))
	for _, p := range paths {
		raw, err := embeddedSigmaRulesFS.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read sigma rule %s: %w", p, err)
		}
		rule, err := sigmalite.ParseRule(raw)
		if err != nil {
			return nil, fmt.Errorf("parse sigma rule %s: %w", p, err)
		}
		// Pre-compile all SearchAtom regexes/CIDRs across all rule branches at startup
		// before concurrent requests arrive.
		for _, we := range warmupEntries {
			_ = rule.Detection.Matches(we, nil)
		}

		sev, weight := mapSigmaSeverity(rule.Level)
		cat := mapSigmaCategory(rule)
		rules = append(rules, sigmaRuleEntry{
			file:     p,
			rule:     rule,
			category: cat,
			severity: sev,
			weight:   weight,
		})
	}
	return &sigmaInspector{rules: rules}, nil
}

func (s *sigmaInspector) count() int {
	return len(s.rules)
}

func (s *sigmaInspector) inspect(entry LogEntry) []RuleMatch {
	se := toSigmaEntry(entry)
	svc := strings.ToLower(strings.TrimSpace(entry.Service))
	var out []RuleMatch
	for _, item := range s.rules {
		if item.rule.LogSource != nil && item.rule.LogSource.Service != "" &&
			svc != strings.ToLower(strings.TrimSpace(item.rule.LogSource.Service)) {
			continue
		}
		if !item.rule.Detection.Matches(se, nil) {
			continue
		}
		ruleID := item.rule.ID
		if ruleID == "" {
			ruleID = item.file
		}
		var tags []string
		if len(item.rule.Tags) > 0 {
			limit := len(item.rule.Tags)
			if limit > 6 {
				limit = 6
			}
			tags = append([]string(nil), item.rule.Tags[:limit]...)
		}
		out = append(out, RuleMatch{
			Engine:      EngineSigma,
			RuleID:      ruleID,
			Title:       item.rule.Title,
			Severity:    item.severity,
			Category:    item.category,
			Tags:        tags,
			MatchedData: sanitizeMatchedData(sigmaMatchedSnippet(entry)),
			weight:      item.weight,
		})
	}
	return out
}

func toSigmaEntry(entry LogEntry) *sigmalite.LogEntry {
	msg := clampBytes(entry.Message, corazaMaxFieldBytes)
	fields := map[string]string{
		"service": strings.TrimSpace(entry.Service),
		"stream":  strings.TrimSpace(entry.Stream),
		"level":   strings.ToLower(strings.TrimSpace(entry.Level)),
		"message": msg,
	}

	if entry.Structured != nil {
		st := entry.Structured
		if h := strings.TrimSpace(st.Host); h != "" && h != "-" {
			fields["host"] = clampBytes(h, corazaMaxFieldBytes)
		}
		if st.Status > 0 {
			fields["status"] = strconv.Itoa(st.Status)
		}
		if req := strings.TrimSpace(st.Request); req != "" {
			fields["request"] = clampBytes(req, corazaMaxFieldBytes)
			method, uri, _, ok := parseRequestLine(req)
			if ok {
				fields["method"] = method
				fields["uri"] = uriWithDecodedHint(uri)
			}
		}
		if ip := strings.TrimSpace(st.ClientIP); ip != "" && ip != "-" {
			fields["client_ip"] = clampBytes(ip, 128)
		}
		if ua := strings.TrimSpace(st.UserAgent); ua != "" && ua != "-" {
			fields["user_agent"] = clampBytes(ua, corazaMaxFieldBytes)
		}
		if ref := strings.TrimSpace(st.Referer); ref != "" && ref != "-" {
			fields["referer"] = uriWithDecodedHint(clampBytes(ref, corazaMaxFieldBytes))
		}
		if ray := strings.TrimSpace(st.CFRay); ray != "" && ray != "-" {
			fields["cf_ray"] = clampBytes(ray, 128)
		}
	} else if method, uri, _, ok := extractHTTPRequest(entry); ok {
		fields["method"] = method
		fields["uri"] = uriWithDecodedHint(uri)
		fields["request"] = clampBytes(method+" "+uri, corazaMaxFieldBytes)
	}

	return &sigmalite.LogEntry{
		Message: msg,
		Fields:  fields,
	}
}

func uriWithDecodedHint(uri string) string {
	uri = clampBytes(uri, corazaMaxFieldBytes)
	decoded := safePercentDecode(uri)
	if decoded != "" && decoded != uri {
		// len(decoded) <= len(uri) <= corazaMaxFieldBytes, so combined is bounded to <= 2*corazaMaxFieldBytes+1
		// without truncating percent-decoded tails on 4-8 KiB padded URIs/Referers.
		return uri + " " + decoded
	}
	return uri
}

// safePercentDecode decodes valid %XX sequences while preserving invalid '%' tokens as literals.
func safePercentDecode(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteByte(' ')
		case '%':
			if i+2 < len(s) {
				if hi, ok1 := unhex(s[i+1]); ok1 {
					if lo, ok2 := unhex(s[i+2]); ok2 {
						b.WriteByte(hi<<4 | lo)
						i += 2
						continue
					}
				}
			}
			b.WriteByte('%')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func sigmaMatchedSnippet(entry LogEntry) string {
	if entry.Structured != nil {
		var parts []string
		if entry.Structured.Status > 0 {
			parts = append(parts, strconv.Itoa(entry.Structured.Status))
		}
		if entry.Structured.Host != "" && entry.Structured.Host != "-" {
			parts = append(parts, entry.Structured.Host)
		}
		if entry.Structured.Request != "" {
			parts = append(parts, entry.Structured.Request)
		}
		if entry.Structured.UserAgent != "" && entry.Structured.UserAgent != "-" {
			parts = append(parts, "ua="+entry.Structured.UserAgent)
		}
		if entry.Structured.Referer != "" && entry.Structured.Referer != "-" {
			parts = append(parts, "ref="+entry.Structured.Referer)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	return entry.Message
}

func mapSigmaSeverity(lvl sigmalite.Level) (string, int) {
	switch lvl {
	case sigmalite.Critical:
		return VerdictCritical, 5
	case sigmalite.High:
		return VerdictHigh, 4
	case sigmalite.Medium:
		return VerdictMedium, 3
	case sigmalite.Low:
		return VerdictLow, 2
	case sigmalite.Informational:
		return VerdictLow, 1
	default:
		return VerdictMedium, 3
	}
}

func mapSigmaCategory(rule *sigmalite.Rule) string {
	if cat, ok := sigmaCategoryByID[rule.ID]; ok {
		return cat
	}
	for _, t := range rule.Tags {
		switch {
		case strings.Contains(t, "t1190"):
			return CategoryRCEInjection
		case strings.Contains(t, "t1595"):
			return CategoryScannerRecon
		case strings.Contains(t, "t1078"), strings.Contains(t, "t1110"):
			return CategoryAuthAbuse
		}
	}
	if rule.LogSource != nil && rule.LogSource.Service == "postgres" {
		return CategoryDBSecurity
	}
	return CategoryServiceError
}
