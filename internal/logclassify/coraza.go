package logclassify

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	corazaMaxFieldBytes = 8192
)

var (
	httpRequestWithProtoRe = regexp.MustCompile(`(?i)(["']?)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(/[^\r\n]+?)\s+(HTTP/[0-9]+(?:\.[0-9]+)?)(?:["'\s,;)\]}]|$)`)
	httpRequestFallbackRe  = regexp.MustCompile(`(?i)(["']?)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(/\S+)`)
)

type corazaInspector struct {
	waf coraza.WAF
}

func newCorazaInspector() (*corazaInspector, error) {
	// Load embedded OWASP CRS v4.25.0 in DetectionOnly mode with body inspection disabled
	// because nginx access logs contain reconstructed request lines and headers only.
	// Configure tx.allowed_methods (id:900200) BEFORE loading @owasp_crs/*.conf so
	// phase-1 rule 911100 sees PUT/PATCH/DELETE, then remove header-presence rules AFTER loading.
	wafCfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectives(`
SecRuleEngine DetectionOnly
SecRequestBodyAccess Off
SecResponseBodyAccess Off
SecAuditEngine Off
SecAction "id:900200,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.25.0',setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
`).
		WithDirectivesFromFile("@owasp_crs/*.conf").
		WithDirectives(`
SecRuleRemoveById 920350 920280 920300 920320 920330 920290 920310 920311 920180
`)

	waf, err := coraza.NewWAF(wafCfg)
	if err != nil {
		return nil, fmt.Errorf("initialize coraza WAF with CRS v4: %w", err)
	}
	return &corazaInspector{waf: waf}, nil
}

func (c *corazaInspector) inspect(entry LogEntry) []RuleMatch {
	method, uri, proto, ok := extractHTTPRequest(entry)
	if !ok {
		return nil
	}

	clientIP := "0.0.0.0"
	host := "cubus.sh"
	ua := ""
	ref := ""

	if entry.Structured != nil {
		if ip := clampHeaderField(entry.Structured.ClientIP); ip != "" && ip != "-" {
			clientIP = ip
		}
		if h := clampHeaderField(entry.Structured.Host); h != "" && h != "-" {
			host = h
		}
		if u := clampHeaderField(entry.Structured.UserAgent); u != "" && u != "-" {
			ua = u
		}
		if r := clampHeaderField(entry.Structured.Referer); r != "" && r != "-" {
			ref = r
		}
	}

	tx := c.waf.NewTransaction()
	defer tx.Close()

	inspectedURI := uri
	if isAdminLogSearchSelfEntry(entry, method, uri) {
		// Skip inspecting the authenticated admin's own log search query string to prevent
		// self-triggering when searching for attack payloads, while still inspecting headers.
		inspectedURI = "/api/logs/search"
	}

	tx.ProcessConnection(clientIP, 0, host, 80)
	tx.ProcessURI(inspectedURI, method, proto)
	tx.SetServerName(host)
	tx.AddRequestHeader("Host", host)
	tx.AddRequestHeader("Accept", "*/*")
	if ua != "" {
		tx.AddRequestHeader("User-Agent", ua)
	}
	if ref != "" {
		tx.AddRequestHeader("Referer", ref)
	}

	tx.ProcessRequestHeaders()
	_, _ = tx.ProcessRequestBody()

	matched := tx.MatchedRules()
	if len(matched) == 0 {
		return nil
	}

	var out []RuleMatch
	for _, mr := range matched {
		rule := mr.Rule()
		id := rule.ID()
		if !isActionableCRSRule(id, mr.Message(), rule.Tags()) {
			continue
		}
		sev, weight := mapCRSSeverity(rule.Severity())
		out = append(out, RuleMatch{
			Engine:      EngineOWASPCRS,
			RuleID:      strconv.Itoa(id),
			Title:       sanitizeSingleLine(mr.Message()),
			Severity:    sev,
			Category:    mapCRSCategory(id, rule.Tags()),
			Tags:        filterCRSTags(rule.Tags()),
			MatchedData: sanitizeMatchedData(extractCRSMatchedData(mr)),
			weight:      weight,
		})
	}
	return out
}

func isAdminLogSearchSelfEntry(entry LogEntry, method, uri string) bool {
	if entry.Structured == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(entry.Service), "nginx-proxy") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(entry.Structured.Host), "admin.cubus.sh") {
		return false
	}
	if entry.Structured.Status != 200 || method != "GET" {
		return false
	}
	return uri == "/api/logs/search" || strings.HasPrefix(uri, "/api/logs/search?")
}

func extractHTTPRequest(entry LogEntry) (method, uri, proto string, ok bool) {
	if entry.Structured != nil {
		if req := strings.TrimSpace(entry.Structured.Request); req != "" && req != "-" {
			return parseRequestLine(req)
		}
		if (entry.Structured.UserAgent != "" && entry.Structured.UserAgent != "-") ||
			(entry.Structured.Referer != "" && entry.Structured.Referer != "-") {
			return "GET", "/", "HTTP/1.1", true
		}
	}
	if m := httpRequestWithProtoRe.FindStringSubmatch(entry.Message); len(m) > 0 {
		method = strings.ToUpper(strings.TrimSpace(m[2]))
		uri = strings.TrimSpace(m[3])
		if uri == "" {
			uri = "/"
		}
		uri = clampBytes(uri, corazaMaxFieldBytes)
		proto = strings.ToUpper(strings.TrimSpace(m[4]))
		if proto == "" {
			proto = "HTTP/1.1"
		}
		return method, uri, proto, true
	}
	m := httpRequestFallbackRe.FindStringSubmatch(entry.Message)
	if len(m) == 0 {
		return "", "", "", false
	}
	openQuote := m[1]
	method = strings.ToUpper(strings.TrimSpace(m[2]))
	uri = trimMatchingOuterQuote(strings.TrimSpace(m[3]), openQuote)
	if uri == "" {
		uri = "/"
	}
	uri = clampBytes(uri, corazaMaxFieldBytes)
	return method, uri, "HTTP/1.1", true
}

func trimMatchingOuterQuote(uri, openQuote string) string {
	if openQuote == "" {
		return uri
	}
	q := openQuote[0]
	for i := 0; i < len(uri); i++ {
		if uri[i] == '\\' {
			i++
			continue
		}
		if uri[i] == q {
			if i+1 == len(uri) {
				return uri[:i]
			}
			switch uri[i+1] {
			case ',', '}', ']', ';', ')':
				return uri[:i]
			}
		}
	}
	return uri
}

func parseRequestLine(raw string) (method, uri, proto string, ok bool) {
	// Keep raw control characters intact up to the byte limit so CRS control-byte/CRLF rules still see them.
	s := clampBytes(strings.TrimSpace(raw), corazaMaxFieldBytes)
	if s == "" {
		return "", "", "", false
	}
	firstSpace := strings.IndexByte(s, ' ')
	if firstSpace <= 0 {
		return "GET", s, "HTTP/1.1", true
	}
	method = strings.ToUpper(strings.TrimSpace(s[:firstSpace]))
	rest := strings.TrimSpace(s[firstSpace+1:])
	if rest == "" {
		return method, "/", "HTTP/1.1", true
	}

	// Preserve raw spaces inside malformed/unencoded attack URIs when trailing protocol exists.
	if lastSpace := strings.LastIndexByte(rest, ' '); lastSpace > 0 {
		tail := strings.ToUpper(strings.TrimSpace(rest[lastSpace+1:]))
		if strings.HasPrefix(tail, "HTTP/") {
			proto = tail
			uri = strings.TrimSpace(rest[:lastSpace])
			if uri == "" {
				uri = "/"
			}
			return method, uri, proto, true
		}
	}
	return method, rest, "HTTP/1.1", true
}

func clampHeaderField(s string) string {
	return clampBytes(strings.TrimSpace(s), corazaMaxFieldBytes)
}

func clampBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk back to a valid UTF-8 boundary so we never split a multi-byte rune.
	cut := maxBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func isActionableCRSRule(id int, msg string, tags []string) bool {
	if id < 910000 || id >= 949000 {
		return false
	}
	if strings.TrimSpace(msg) == "" {
		return false
	}
	for _, t := range tags {
		if t == "anomaly-evaluation" || t == "reporting" {
			return false
		}
	}
	return true
}

func mapCRSSeverity(sev types.RuleSeverity) (string, int) {
	switch sev {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical:
		return VerdictCritical, 5
	case types.RuleSeverityError:
		return VerdictHigh, 4
	case types.RuleSeverityWarning:
		return VerdictMedium, 3
	case types.RuleSeverityNotice:
		return VerdictLow, 2
	default:
		return VerdictLow, 1
	}
}

func mapCRSCategory(id int, tags []string) string {
	for _, tag := range tags {
		switch tag {
		case "attack-sqli", "OWASP_CRS/ATTACK-SQLI":
			return CategorySQLi
		case "attack-xss", "OWASP_CRS/ATTACK-XSS":
			return CategoryXSS
		case "attack-lfi", "attack-rfi", "OWASP_CRS/ATTACK-LFI", "OWASP_CRS/ATTACK-RFI":
			return CategoryLFITraversal
		case "attack-rce", "attack-injection-php", "attack-injection-java", "attack-injection-nodejs",
			"OWASP_CRS/ATTACK-RCE", "OWASP_CRS/ATTACK-PHP", "OWASP_CRS/ATTACK-JAVA", "OWASP_CRS/ATTACK-NODEJS":
			return CategoryRCEInjection
		case "attack-reputation-scanner", "OWASP_CRS/SCANNER-DETECTION":
			return CategoryScannerRecon
		case "attack-fixation", "OWASP_CRS/ATTACK-FIXATION":
			return CategoryAuthAbuse
		case "attack-protocol", "OWASP_CRS/PROTOCOL-ENFORCEMENT", "OWASP_CRS/PROTOCOL-ATTACK",
			"OWASP_CRS/METHOD-ENFORCEMENT", "OWASP_CRS/MULTIPART-ATTACK":
			return CategoryProtocolAnomaly
		}
	}
	switch id / 1000 {
	case 942:
		return CategorySQLi
	case 941:
		return CategoryXSS
	case 930, 931:
		return CategoryLFITraversal
	case 932, 933, 934, 944:
		return CategoryRCEInjection
	case 913:
		return CategoryScannerRecon
	case 943:
		return CategoryAuthAbuse
	default:
		return CategoryProtocolAnomaly
	}
}

func filterCRSTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		switch {
		case t == "",
			t == "OWASP_CRS",
			t == "application-multi",
			t == "language-multi",
			t == "platform-multi",
			strings.HasPrefix(t, "paranoia-level/"),
			strings.HasPrefix(t, "capec/"):
			continue
		default:
			out = append(out, t)
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

func extractCRSMatchedData(mr types.MatchedRule) string {
	if d := strings.TrimSpace(mr.Data()); d != "" {
		return d
	}
	mds := mr.MatchedDatas()
	if len(mds) == 0 {
		return ""
	}
	var parts []string
	for _, md := range mds {
		val := strings.TrimSpace(md.Value())
		if val == "" {
			continue
		}
		varName := md.Variable().Name()
		if k := md.Key(); k != "" {
			parts = append(parts, fmt.Sprintf("%s:%s=%s", varName, k, val))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", varName, val))
		}
		if len(parts) >= 2 {
			break
		}
	}
	return strings.Join(parts, "; ")
}
